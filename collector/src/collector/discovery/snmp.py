"""SNMP polling with multi-community trial and per-device credential cache.

Behavior per candidate IP:

1. Look up the device in the `snmp_credentials` table.
   - If we have a cached community, try that first. On success, poll OIDs.
   - On failure with the cached community, fall through to step 2 and
     re-trial — the operator may have rotated the string.
2. Iterate NETMON_SNMP_COMMUNITIES in order. First one that responds wins.
3. On success, persist the working community to the cache so future scans
   skip the trial. On total failure, record a failure so backoff kicks in.

We deliberately keep the candidate list small (gateway + LLDP mgmt IPs by
default) so a fresh box doesn't take 5 minutes blasting SNMP at every host.
"""
from __future__ import annotations

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
# Backoff in seconds — we won't re-attempt a device that's hit MAX_FAILURES
# until at least this much wall-clock time has passed since the last attempt.
BACKOFF_SECONDS = 24 * 3600  # 24h

# Per-attempt probe budget. Trial is sysDescr only — short and cheap.
PROBE_TIMEOUT_SEC = 1.5
PROBE_RETRIES = 0  # we iterate communities ourselves, no need to retry within pysnmp

# Full poll OID set (after a working community is identified).
DEFAULT_OIDS: list[dict[str, Any]] = [
    {"name": "sysDescr",          "oid": "1.3.6.1.2.1.1.1.0"},
    {"name": "sysName",           "oid": "1.3.6.1.2.1.1.5.0"},
    {"name": "sysObjectID",       "oid": "1.3.6.1.2.1.1.2.0"},
    {"name": "sysLocation",       "oid": "1.3.6.1.2.1.1.6.0"},
    {"name": "sysContact",        "oid": "1.3.6.1.2.1.1.4.0"},
    {"name": "ifTable",           "oid": "1.3.6.1.2.1.2.2",     "walk": True},
    {"name": "ipNetToMediaTable", "oid": "1.3.6.1.2.1.4.22",    "walk": True},
    {"name": "dot1dTpFdbTable",   "oid": "1.3.6.1.2.1.17.4.3",  "walk": True},
    {"name": "dot1dStpPortTable", "oid": "1.3.6.1.2.1.17.2.15", "walk": True},
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def poll(candidate_ips: list[str]) -> list[dict[str, Any]]:
    """Try SNMP against each candidate IP. Returns flat list of poll rows."""
    settings = get_settings()
    if not settings.snmp_enabled:
        return []

    communities = list(settings.snmp_community_list)
    if not communities:
        log.info("snmp enabled but no communities configured, skipping")
        return []

    if not candidate_ips:
        return []

    # pysnmp import is deferred so the rest of the system still works in
    # environments where snmp libs aren't installed.
    try:
        from pysnmp.hlapi import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
            nextCmd,
        )
    except Exception as exc:
        log.warning("pysnmp unavailable, skipping SNMP", error=str(exc))
        return []

    engine = SnmpEngine()
    out: list[dict[str, Any]] = []

    for ip in candidate_ips:
        community = _select_community(
            ip, communities,
            SnmpEngine=SnmpEngine, CommunityData=CommunityData,
            ContextData=ContextData, ObjectIdentity=ObjectIdentity,
            ObjectType=ObjectType, UdpTransportTarget=UdpTransportTarget,
            getCmd=getCmd, engine=engine,
        )
        if community is None:
            continue

        # We have a working community — do the full poll.
        rows = _poll_oids(
            ip, community, DEFAULT_OIDS,
            CommunityData=CommunityData, ContextData=ContextData,
            ObjectIdentity=ObjectIdentity, ObjectType=ObjectType,
            UdpTransportTarget=UdpTransportTarget,
            getCmd=getCmd, nextCmd=nextCmd, engine=engine,
        )
        out.extend(rows)

    log.info("snmp poll complete",
             candidates=len(candidate_ips),
             rows=len(out))
    return out


# ---------------------------------------------------------------------------
# Community selection — cache-first, then trial
# ---------------------------------------------------------------------------


def _select_community(
    ip: str,
    communities: list[str],
    *,
    SnmpEngine, CommunityData, ContextData, ObjectIdentity, ObjectType,
    UdpTransportTarget, getCmd, engine,
) -> str | None:
    """Return a community known to work for `ip`, or None if nothing works."""
    cached = get_snmp_credential(ip)

    # Backoff: skip if we've failed too many times recently.
    if cached and cached.get("community") is None and cached.get("failure_count", 0) >= MAX_FAILURES_BEFORE_BACKOFF:
        last = cached.get("last_attempt_at")
        if last is not None:
            age = time.time() - last.timestamp()
            if age < BACKOFF_SECONDS:
                log.debug("snmp backoff active, skipping device", ip=ip,
                          failures=cached["failure_count"], age_seconds=int(age))
                return None

    # 1. Try the cached community first.
    if cached and cached.get("community"):
        if _probe(ip, cached["community"],
                  CommunityData=CommunityData, ContextData=ContextData,
                  ObjectIdentity=ObjectIdentity, ObjectType=ObjectType,
                  UdpTransportTarget=UdpTransportTarget,
                  getCmd=getCmd, engine=engine):
            log.debug("snmp cache hit", ip=ip, community=cached["community"])
            record_snmp_success(ip, cached["community"], cached.get("version") or "2c")
            return cached["community"]
        else:
            log.info("snmp cached community no longer works, re-trialing",
                     ip=ip, community=cached["community"])

    # 2. Trial through the configured list.
    for community in communities:
        # Skip re-trying the cached one (already failed above).
        if cached and community == cached.get("community"):
            continue
        if _probe(ip, community,
                  CommunityData=CommunityData, ContextData=ContextData,
                  ObjectIdentity=ObjectIdentity, ObjectType=ObjectType,
                  UdpTransportTarget=UdpTransportTarget,
                  getCmd=getCmd, engine=engine):
            log.info("snmp community matched", ip=ip, community=community)
            record_snmp_success(ip, community, "2c")
            return community

    # 3. Nothing worked — remember the failure.
    log.info("snmp all communities failed", ip=ip, tried=len(communities))
    record_snmp_failure(ip)
    return None


def _probe(
    ip: str, community: str,
    *,
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    UdpTransportTarget, getCmd, engine,
) -> bool:
    """Single short sysDescr GET. True if we get a non-error response."""
    try:
        iterator = getCmd(
            engine,
            CommunityData(community, mpModel=1),  # v2c
            UdpTransportTarget((ip, 161),
                               timeout=PROBE_TIMEOUT_SEC,
                               retries=PROBE_RETRIES),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
        )
        err_indication, err_status, _err_idx, varbinds = next(iterator)
        if err_indication or err_status:
            return False
        return bool(varbinds)
    except StopIteration:
        return False
    except Exception as exc:
        log.debug("snmp probe exception", ip=ip, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# OID polling once we know the community
# ---------------------------------------------------------------------------


def _poll_oids(
    ip: str, community: str, oids: list[dict[str, Any]],
    *,
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    UdpTransportTarget, getCmd, nextCmd, engine,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for entry in oids:
        name = entry.get("name") or entry["oid"]
        oid = entry["oid"]
        walk = bool(entry.get("walk"))
        try:
            if walk:
                iterator = nextCmd(
                    engine,
                    CommunityData(community, mpModel=1),
                    UdpTransportTarget((ip, 161), timeout=3, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False,
                )
            else:
                iterator = getCmd(
                    engine,
                    CommunityData(community, mpModel=1),
                    UdpTransportTarget((ip, 161), timeout=3, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            for err_indication, err_status, _err_idx, varbinds in iterator:
                if err_indication or err_status:
                    log.debug("snmp poll error",
                              ip=ip, oid=name,
                              indication=str(err_indication),
                              status=str(err_status))
                    break
                for vb in varbinds:
                    results.append({
                        "device_ip": ip,
                        "oid":       str(vb[0]),
                        "oid_name":  name,
                        "value":     str(vb[1]),
                    })
        except Exception as exc:
            log.debug("snmp poll exception", ip=ip, oid=name, error=str(exc))
            continue
    return results
