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

import re
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

# The HEAVY bulk OIDs — large (one row per interface / learned MAC / ARP entry)
# and slow-changing. Gated to a slow cadence (see scan._snmp_bulk_due): when not
# due, poll() skips these and walks only the small identity / STP / port OIDs.
# Identity OIDs (sys*, entPhysical*, hrDevice*, printer) stay every-scan so device
# classification is unaffected.
BULK_OID_NAMES = frozenset({
    "ifTable",
    "ipNetToMediaTable",
    "dot1dTpFdbTable",
    "dot1qTpFdbPort",
})

# Lines net-snmp emits for absent objects — we skip these when parsing walks.
_SKIP_MARKERS = (
    "No Such Object",
    "No Such Instance",
    "No more variables",
    "End of MIB",
    "Timeout",
    "No Response",
)

# A varbind line under -Oqn starts with a dotted-NUMERIC OID (n = numeric), e.g.
#   .1.3.6.1.2.1.1.1.0 Cisco IOS Software, ...
# Anything else is a CONTINUATION of the previous value: Cisco IOS/IOS-XE, Junos
# and ArubaOS all return a MULTI-LINE sysDescr, and lldpRemSysDesc /
# cdpCacheVersion carry the same text out of a walk. Treating every line as a new
# varbind truncated those values at line 1 AND minted bogus rows for any
# continuation that happened to contain a space ("Technical Support: ..." became
# an oid of "Technical").
_OID_LINE_RE = re.compile(r"^\.\d[\d.]*(?=\s|$)")


def _strip_wrapping_quotes(value: str) -> str:
    """net-snmp wraps multi-line string values in double quotes; strip them.

    Same rule as snmp_topology._strip_quotes (both ends must be quotes, so a
    value that merely starts with one is left alone)."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_oqn_output(text: str) -> list[tuple[str, str]]:
    """Parse `-Oqn` output into (numeric_oid, value) pairs.

    Handles multi-line values by folding continuation lines into the current
    varbind. A line carrying a _SKIP_MARKERS marker ends the current varbind and
    is dropped — that covers both "No Such Object" varbinds and the trailing
    "Timeout: No Response from <ip>" that _run_snmp merges in from stderr, which
    would otherwise be glued onto the last real value.
    """
    collected: list[tuple[str, list[str]]] = []
    current: list[str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if any(marker in line for marker in _SKIP_MARKERS):
            current = None
            continue
        match = _OID_LINE_RE.match(line)
        if match is None:
            if current is not None:
                current.append(line)
            continue
        current = [line[match.end():].strip()]
        collected.append((match.group(0), current))
    rows: list[tuple[str, str]] = []
    for oid_str, parts in collected:
        value = _strip_wrapping_quotes("\n".join(parts).strip())
        if not value:
            continue  # valueless varbind — nothing worth storing
        rows.append((oid_str, value))
    return rows


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


class _PollBudgetExceeded(Exception):
    pass


def _check_budget(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise _PollBudgetExceeded


def poll(
    candidate_ips: list[str],
    include_bulk: bool = True,
    *,
    status: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Try SNMP against each candidate IP. Returns a flat list of poll rows.

    include_bulk=False skips the heavy slow-changing bulk OIDs (BULK_OID_NAMES) —
    used on scans where the bulk walk isn't due (see scan._snmp_bulk_due)."""
    settings = get_settings()
    if not settings.snmp_enabled:
        return []

    communities = list(settings.snmp_community_list)
    if not communities or not candidate_ips:
        return []

    if shutil.which("snmpget") is None or shutil.which("snmpbulkwalk") is None:
        raise RuntimeError("net-snmp tools not found in container (snmpget/snmpbulkwalk)")

    unique_candidates = list(dict.fromkeys(candidate_ips))
    candidates = unique_candidates[: settings.snmp_poll_max_candidates]
    deadline = time.monotonic() + settings.snmp_poll_time_budget
    out: list[dict[str, Any]] = []
    attempted = 0
    completed = 0
    budget_exhausted = False
    for ip in candidates:
        try:
            _check_budget(deadline)
            attempted += 1
            community = _select_community(ip, communities, deadline=deadline)
            if community is not None:
                out.extend(
                    _poll_oids(
                        ip,
                        community,
                        include_bulk=include_bulk,
                        deadline=deadline,
                    )
                )
            completed += 1
        except _PollBudgetExceeded:
            budget_exhausted = True
            break

    truncated = len(candidates) < len(unique_candidates) or budget_exhausted
    if status is not None:
        status.update(
            {
                "candidates": len(unique_candidates),
                "attempted": attempted,
                "completed": completed,
                "candidate_cap": settings.snmp_poll_max_candidates,
                "time_budget_sec": settings.snmp_poll_time_budget,
                "truncated": truncated,
            }
        )

    log.info("snmp poll complete", candidates=len(unique_candidates), attempted=attempted,
             completed=completed, rows=len(out), include_bulk=include_bulk,
             truncated=truncated)
    return out


# ---------------------------------------------------------------------------
# Community selection — cache-first, then trial
# ---------------------------------------------------------------------------


def _select_community(
    ip: str, communities: list[str], *, deadline: float = float("inf")
) -> str | None:
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
        _check_budget(deadline)
        if _probe(ip, cached["community"]):
            log.debug("snmp cache hit", ip=ip)
            record_snmp_success(ip, cached["community"], cached.get("version") or "2c")
            return str(cached["community"])
        log.info("snmp cached community no longer works, re-trialing", ip=ip)

    # 2. Trial the configured list.
    for community in communities:
        _check_budget(deadline)
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


def _poll_oids(
    ip: str,
    community: str,
    include_bulk: bool = True,
    *,
    deadline: float = float("inf"),
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, oid, is_walk in DEFAULT_OIDS:
        _check_budget(deadline)
        if not include_bulk and name in BULK_OID_NAMES:
            continue  # heavy bulk walk not due this scan
        tool = "snmpbulkwalk" if is_walk else "snmpget"
        rc, out = _run_snmp([
            tool, "-v2c", "-c", community,
            "-t", POLL_TIMEOUT, "-r", POLL_RETRIES,
            "-Oqn", ip, oid,   # -O q (no type/'=') n (numeric OIDs) => "<oid> <value>"
        ])
        if rc != 0:
            continue
        # -Oqn output is "<numeric-oid> <value>"; the value may contain spaces
        # AND newlines (sysDescr on Cisco/Junos), so fold continuation lines in.
        for oid_str, value in parse_oqn_output(out):
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
