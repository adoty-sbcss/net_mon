"""SNMP polling via the net-snmp CLI tools (snmpget / snmpbulkwalk).

We shell out to net-snmp rather than use a Python SNMP library. Rationale:
pysnmp's API has churned repeatedly — pysnmp 7.x removed the synchronous
hlapi (`from pysnmp.hlapi import CommunityData, getCmd, ...`) the collector
used to rely on, which silently disabled SNMP on every scan. net-snmp's CLI
is stable, ubiquitous, and matches how the rest of the collector already
drives proven tools (nmap, tshark, arp-scan, iw).

Behavior per candidate IP (unchanged from before):
1. Look up the device in snmp_credentials. If a community is cached, try it
   first. If it no longer works, re-trial.
2. Otherwise trial each configured community (NETMON_SNMP_COMMUNITIES) with a
   quick sysDescr GET. First to respond wins.
3. Cache the winning community so future scans skip the trial. On total
   failure, record it and back off for 24h after enough consecutive misses.

The candidate set is kept small (gateway + LLDP mgmt IPs + network-vendor
OUIs — see scan.py::_snmp_candidates) so the trial stays fast.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from typing import Any

import structlog

from ..config import get_settings
from ..db import (
    get_snmp_credential,
    record_snmp_failure,
    record_snmp_success,
)

log = structlog.get_logger(__name__)

# After this many consecutive failures, skip the device for a while.
MAX_FAILURES_BEFORE_BACKOFF = 5
BACKOFF_SECONDS = 24 * 3600  # 24h

# net-snmp -t (timeout secs per try) / -r (retries). Trial is cheap; the full
# poll gets a slightly longer budget since tables can be large.
PROBE_TIMEOUT = "1"
PROBE_RETRIES = "1"
POLL_TIMEOUT = "3"
POLL_RETRIES = "1"

SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"

# (name, oid, is_walk)
#
# The bridge OIDs below exist so the dashboard can map a host (IP+MAC) to the
# physical switch access port it lives on. The join chain is:
#   host MAC --[dot1dTpFdbTable.dot1dTpFdbPort]--> bridge port number
#            --[dot1dBasePortIfIndex]-----------> ifIndex
#            --[ifName / ifTable.ifDescr]--------> "GigabitEthernet1/0/12"
# dot1dTpFdbTable and ifTable (which carries ifDescr) already cover two legs;
# dot1dBasePortIfIndex and ifName supply the missing translation steps.
# dot1qTpFdbPort is the Q-BRIDGE per-VLAN FDB for switches that expose it
# (its index embeds the VLAN, unlike the classic per-VLAN-community dot1d FDB).
DEFAULT_OIDS: list[tuple[str, str, bool]] = [
    ("sysDescr",            "1.3.6.1.2.1.1.1.0",       False),
    ("sysName",             "1.3.6.1.2.1.1.5.0",       False),
    ("sysObjectID",         "1.3.6.1.2.1.1.2.0",       False),  # primary vendor+model key
    ("sysLocation",         "1.3.6.1.2.1.1.6.0",       False),
    ("sysContact",          "1.3.6.1.2.1.1.4.0",       False),
    ("sysServices",         "1.3.6.1.2.1.1.7.0",       False),  # layer bitmask: L2=2 L3=4 L7=64
    ("ifTable",             "1.3.6.1.2.1.2.2",         True),   # carries ifDescr
    ("ifName",              "1.3.6.1.2.1.31.1.1.1.1",  True),   # ifXTable: ifIndex -> port name
    ("ipNetToMediaTable",   "1.3.6.1.2.1.4.22",        True),
    ("dot1dTpFdbTable",     "1.3.6.1.2.1.17.4.3",      True),   # MAC -> bridge port (dot1dTpFdbPort)
    ("dot1dBasePortIfIndex","1.3.6.1.2.1.17.1.4.1.2",  True),   # bridge port -> ifIndex
    ("dot1qTpFdbPort",      "1.3.6.1.2.1.17.7.1.2.2",  True),   # Q-BRIDGE per-VLAN MAC -> bridge port
    ("dot1dStpPortTable",   "1.3.6.1.2.1.17.2.15",     True),

    # --- Device classification / inventory (vendor-neutral) --------------
    # The dashboard maps these to a device class (switch / router / AP /
    # printer / computer / phone / ...). sysObjectID + sysServices above are
    # the cheap primary signal; the tables below add hardware model + serial
    # and a type hint that works across vendors.
    #
    # ENTITY-MIB (RFC 4133) — physical entity inventory. A responsive agent
    # returns "No Such Object" fast when these are absent, so polling them on
    # gear that lacks the MIB is cheap (no timeout). entPhysicalClass is an
    # enum: chassis(3) module(9) port(10) powerSupply(6) sensor(8) ...
    ("entPhysicalDescr",     "1.3.6.1.2.1.47.1.1.1.1.2",  True),
    ("entPhysicalClass",     "1.3.6.1.2.1.47.1.1.1.1.5",  True),
    ("entPhysicalName",      "1.3.6.1.2.1.47.1.1.1.1.7",  True),
    ("entPhysicalSerialNum", "1.3.6.1.2.1.47.1.1.1.1.11", True),
    ("entPhysicalModelName", "1.3.6.1.2.1.47.1.1.1.1.13", True),
    # HOST-RESOURCES-MIB (RFC 2790) — present on general-purpose OSes
    # (PCs/servers) and many printers. hrDeviceType enum: processor(3)
    # network(4) printer(5) diskStorage(2) ... A box exposing processor/disk
    # rows is a computer; a printer row plus Printer-MIB below confirms print.
    ("hrDeviceType",         "1.3.6.1.2.1.25.3.2.1.2",    True),
    ("hrDeviceDescr",        "1.3.6.1.2.1.25.3.2.1.3",    True),
    # PRINTER-MIB (RFC 3805) — if prtGeneralPrinterName answers, it's a printer.
    ("prtGeneralPrinterName","1.3.6.1.2.1.43.5.1.1.16",   True),
]

# Lines net-snmp emits for absent objects — we skip these when parsing walks.
_SKIP_MARKERS = (
    "No Such Object",
    "No Such Instance",
    "No more variables",
    "End of MIB",
    "Timeout",
    "No Response",
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def poll(candidate_ips: list[str]) -> list[dict[str, Any]]:
    """Try SNMP against each candidate IP. Returns a flat list of poll rows."""
    settings = get_settings()
    if not settings.snmp_enabled:
        return []

    communities = list(settings.snmp_community_list)
    if not communities or not candidate_ips:
        return []

    if shutil.which("snmpget") is None or shutil.which("snmpbulkwalk") is None:
        log.warning("net-snmp tools not found in container (snmpget/snmpbulkwalk); "
                    "skipping SNMP — ensure the 'snmp' apt package is installed")
        return []

    out: list[dict[str, Any]] = []
    for ip in candidate_ips:
        community = _select_community(ip, communities)
        if community is None:
            continue
        out.extend(_poll_oids(ip, community))

    log.info("snmp poll complete", candidates=len(candidate_ips), rows=len(out))
    return out


# ---------------------------------------------------------------------------
# Community selection — cache-first, then trial
# ---------------------------------------------------------------------------


def _select_community(ip: str, communities: list[str]) -> str | None:
    """Return a community known to work for `ip`, or None if nothing works."""
    cached = get_snmp_credential(ip)

    # Backoff: skip devices that have failed too many times recently.
    if (cached and cached.get("community") is None
            and cached.get("failure_count", 0) >= MAX_FAILURES_BEFORE_BACKOFF):
        last = cached.get("last_attempt_at")
        if last is not None and (time.time() - last.timestamp()) < BACKOFF_SECONDS:
            log.debug("snmp backoff active, skipping device", ip=ip,
                      failures=cached["failure_count"])
            return None

    # 1. Cached community first.
    if cached and cached.get("community"):
        if _probe(ip, cached["community"]):
            log.debug("snmp cache hit", ip=ip)
            record_snmp_success(ip, cached["community"], cached.get("version") or "2c")
            return str(cached["community"])
        log.info("snmp cached community no longer works, re-trialing", ip=ip)

    # 2. Trial the configured list.
    for community in communities:
        if cached and community == cached.get("community"):
            continue  # already failed above
        if _probe(ip, community):
            log.info("snmp community matched", ip=ip)
            record_snmp_success(ip, community, "2c")
            return community

    # 3. Nothing worked.
    log.info("snmp all communities failed", ip=ip, tried=len(communities))
    record_snmp_failure(ip)
    return None


def _probe(ip: str, community: str) -> bool:
    """Quick sysDescr GET. True if the agent answers with a real value."""
    rc, out = _run_snmp([
        "snmpget", "-v2c", "-c", community,
        "-t", PROBE_TIMEOUT, "-r", PROBE_RETRIES,
        "-Oqv", ip, SYSDESCR_OID,
    ])
    if rc != 0:
        return False
    text = out.strip()
    if not text:
        return False
    return not any(marker in text for marker in _SKIP_MARKERS)


# ---------------------------------------------------------------------------
# OID polling
# ---------------------------------------------------------------------------


def _poll_oids(ip: str, community: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, oid, is_walk in DEFAULT_OIDS:
        tool = "snmpbulkwalk" if is_walk else "snmpget"
        rc, out = _run_snmp([
            tool, "-v2c", "-c", community,
            "-t", POLL_TIMEOUT, "-r", POLL_RETRIES,
            "-Oqn", ip, oid,   # -O q (no type/'=') n (numeric OIDs) => "<oid> <value>"
        ])
        if rc != 0:
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line or any(marker in line for marker in _SKIP_MARKERS):
                continue
            # -Oqn output is "<numeric-oid> <value>"; value may contain spaces.
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            oid_str, value = parts[0], parts[1]
            rows.append({
                "device_ip": ip,
                "oid": oid_str,
                "oid_name": name,
                "value": value,
            })
    return rows


def _run_snmp(cmd: list[str]) -> tuple[int, str]:
    """Run a net-snmp command. Returns (returncode, stdout+stderr).

    Wrong community on SNMPv2c usually yields no response (the agent silently
    drops it), so a bad community surfaces as a non-zero exit / timeout rather
    than an auth error.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, check=False,
        )
    except FileNotFoundError:
        return 1, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
