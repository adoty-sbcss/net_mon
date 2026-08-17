"""SNMP-based topology crawl.

Starting from one or more seed devices (typically the default gateway plus
any LLDP-advertised mgmt IP), we SNMP-walk each device's LLDP remote table
to find its neighbors, then recurse into each neighbor whose management IP
we can reach. CDP cache is walked too for Cisco gear that doesn't speak
LLDP. The crawl is bounded by a max-depth limit and a wall-clock budget so a
slow or huge fabric never blows up scan duration.

Inputs (per call):
    seed_ips     — IPs to start from (gateway, LLDP mgmt IPs, anything else
                   the caller wants to seed with).
    communities  — list of SNMP v2c read communities to trial. Same list
                   discovery/snmp.py uses; per-device winners are cached
                   in snmp_credentials so a second pass costs nothing extra.
    exclude_ips  — management IPs to skip entirely: never polled and never
                   recursed THROUGH, so the crawl stays inside the intended
                   boundary. Pushed from the dashboard when an operator purges
                   a device from inventory (NETMON_SNMP_EXCLUDE).

Output:
    {
      "nodes": [{chassis_id, system_name, system_description, mgmt_ips,
                 discovered_via_ip, source, capabilities}, ...],
      "edges": [{local_chassis_id, local_port_id, local_port_desc,
                 remote_chassis_id, remote_port_id, remote_port_desc,
                 via ('lldp'|'cdp'), discovered_via_ip}, ...],
      "stats": {"visited_ips": int, "elapsed_sec": float,
                "budget_exhausted": bool},
    }

This module deliberately reuses snmp.py's community selection + cache logic
(via the module-private helpers) so credentials are tried once per device
across both polling AND topology crawl.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import time
from typing import Any

import structlog

# Reuse the community-trial + cache logic from the polling module so a single
# scan doesn't re-trial communities once a winner is known.
from . import snmp as _snmp

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# OID constants
# ---------------------------------------------------------------------------

# SNMPv2-MIB
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME  = "1.3.6.1.2.1.1.5.0"

# LLDP-MIB (IEEE 802.1AB)
LLDP_LOC_CHASSIS_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.1.0"
LLDP_LOC_CHASSIS_ID         = "1.0.8802.1.1.2.1.3.2.0"
LLDP_LOC_SYS_NAME           = "1.0.8802.1.1.2.1.3.3.0"
LLDP_LOC_SYS_CAP_ENABLED    = "1.0.8802.1.1.2.1.3.6.0"   # lldpLocSysCapEnabled

# IEEE 802.1AB system-capability bitmap (LldpSystemCapabilitiesMap). The octet
# string is a BITS field: bit 0 is the MSB of the first octet. Tagging a node
# bridge/router/wlan-ap/telephone is a strong, vendor-neutral device-class hint.
_LLDP_CAP_BITS = (
    "other", "repeater", "bridge", "wlan-ap", "router",
    "telephone", "docsis", "station", "cvlan", "svlan", "two-port-mac-relay",
)

# CISCO-CDP-MIB cdpCacheCapabilities — a 4-byte bitmask. Unlike the LLDP BITS
# field above, this is LSB-first: bit 0 (0x01) is router, bit 3 (0x08) switch,
# etc. "switch" and "host" have no LLDP equivalent and are useful extra hints
# (a CDP neighbor advertising "host" is an endpoint, not infrastructure).
_CDP_CAP_BITS = (
    "router",               # 0x001
    "bridge",               # 0x002 transparent bridge
    "source-route-bridge",  # 0x004
    "switch",               # 0x008
    "host",                 # 0x010
    "igmp",                 # 0x020
    "repeater",             # 0x040
    "telephone",            # 0x080 VoIP phone
    "remotely-managed",     # 0x100
    "cvta",                 # 0x200
    "two-port-mac-relay",   # 0x400
)

LLDP_REM_TABLE   = "1.0.8802.1.1.2.1.4.1.1"      # lldpRemTable rows
LLDP_REM_MAN_TBL = "1.0.8802.1.1.2.1.4.2.1"      # lldpRemManAddrTable rows

# lldpRemTable columns (suffix after the table OID)
LLDP_REM_COLS = {
    "4":  "chassis_id_subtype",
    "5":  "chassis_id",
    "6":  "port_id_subtype",
    "7":  "port_id",
    "8":  "port_desc",
    "9":  "sys_name",
    "10": "sys_desc",
    "11": "capabilities_supported",
    "12": "capabilities_enabled",
}

# CISCO-CDP-MIB
CDP_CACHE_TABLE = "1.3.6.1.4.1.9.9.23.1.2.1.1"
CDP_CACHE_COLS = {
    "4":  "address",         # cdpCacheAddress (IP)
    "6":  "device_id",       # cdpCacheDeviceId
    "7":  "device_port",     # cdpCacheDevicePort
    "8":  "platform",        # cdpCachePlatform
    "9":  "cap_raw",         # cdpCacheCapabilities (4-byte bitmap)
}
# The CDP cache row index is (cdpCacheIfIndex, cdpCacheDeviceIndex) — so idx[0] is
# the LOCAL ifIndex the neighbor sits on (used to match the uplink port in spine
# mode). The LLDP remote index is (time_mark, local_port, rem_idx); on Cisco
# lldpRemLocalPortNum == ifIndex, which we use best-effort for the same match.

# BRIDGE-MIB — used only in spine mode to find the uplink port toward the gateway.
DOT1D_TPFDB_PORT       = "1.3.6.1.2.1.17.4.3.1.2"   # dot1dTpFdbPort: MAC-octet suffix -> bridge port
DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"   # dot1dBasePortIfIndex: bridgePort -> ifIndex
DOT1D_STP_ROOT_PORT    = "1.3.6.1.2.1.17.2.7.0"     # dot1dStpRootPort: bridge port toward the STP root

# CORE-2: per-interface health (MAP-4) + STP port roles (MAP-3). Collected once
# per POLLED node and stored on the node's `interfaces` map (ifIndex -> health).
DOT1D_STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"    # dot1dStpPortState (per bridge port)
IF_OPER_STATUS       = "1.3.6.1.2.1.2.2.1.8"        # ifOperStatus
IF_IN_ERRORS         = "1.3.6.1.2.1.2.2.1.14"       # ifInErrors
IF_OUT_ERRORS        = "1.3.6.1.2.1.2.2.1.20"       # ifOutErrors
IF_NAME              = "1.3.6.1.2.1.31.1.1.1.1"     # ifName (ifXTable)
IF_HIGH_SPEED        = "1.3.6.1.2.1.31.1.1.1.15"    # ifHighSpeed (Mbps)
# PERF-3: 64-bit octet counters, sampled ONLY for the resolved uplink ifIndex so
# the dashboard can compute utilization (counter deltas across scans) vs an
# admin-set committed/provisioned rate. HC (Counter64) avoids 32-bit wrap at speed.
IF_HC_IN_OCTETS      = "1.3.6.1.2.1.31.1.1.1.6"     # ifHCInOctets  (ifXTable)
IF_HC_OUT_OCTETS     = "1.3.6.1.2.1.31.1.1.1.10"    # ifHCOutOctets (ifXTable)

# INV: extra per-port detail for the device page — operator port label, admin
# (config) state, and negotiated duplex. All indexed by ifIndex like the above.
IF_ALIAS             = "1.3.6.1.2.1.31.1.1.1.18"    # ifAlias (operator description)
IF_ADMIN_STATUS      = "1.3.6.1.2.1.2.2.1.7"        # ifAdminStatus
DOT3_DUPLEX          = "1.3.6.1.2.1.10.7.2.1.19"    # dot3StatsDuplexStatus (EtherLike-MIB)

# INV: PoE — POWER-ETHERNET-MIB (RFC 3621), pethPsePortTable. Indexed by
# (pethPsePortGroupIndex, pethPsePortIndex) i.e. "group.port", NOT ifIndex — there
# is no standard PsePort->ifIndex OID, so we best-effort join via ifName below.
# pethPsePortEntry = ...105.1.1.1 (index {groupIndex, portIndex}); columns hang
# directly off it. NOTE: these were ...105.1.1.1.1.<col> (an extra .1, pointing
# under the groupIndex column) → every walk returned 0, so per-port PoE was
# silently empty on ALL switches. Corrected to ...105.1.1.1.<col> per RFC 3621.
PETH_ADMIN           = "1.3.6.1.2.1.105.1.1.1.3"  # pethPsePortAdminEnable (TruthValue)
PETH_DETECT          = "1.3.6.1.2.1.105.1.1.1.6"  # pethPsePortDetectionStatus
PETH_CLASS           = "1.3.6.1.2.1.105.1.1.1.7"  # pethPsePortPowerClassifications
# Per-port consumed power (mW). Vendor-specific (best-effort): Cisco
# CISCO-POWER-ETHERNET-EXT-MIB AUGMENTS pethPsePortTable so it shares the index.
CPE_EXT_PWR          = "1.3.6.1.4.1.9.9.402.1.2.1.7"  # cpeExtPsePortPwrConsumption (mW)

_STP_STATE = {
    "1": "disabled", "2": "blocking", "3": "listening",
    "4": "learning", "5": "forwarding", "6": "broken",
}
_IF_OPER = {
    "1": "up", "2": "down", "3": "testing", "4": "unknown",
    "5": "dormant", "6": "notPresent", "7": "lowerLayerDown",
}
_IF_ADMIN = {"1": "up", "2": "down", "3": "testing"}
_DUPLEX = {"1": "unknown", "2": "half", "3": "full"}
# pethPsePortDetectionStatus (RFC 3621)
_PETH_DETECT = {
    "1": "disabled", "2": "searching", "3": "deliveringPower",
    "4": "fault", "5": "test", "6": "otherFault",
}
# pethPsePortPowerClassifications (RFC 3621): class0(1)..class4(5)
_PETH_CLASS = {"1": "class0", "2": "class1", "3": "class2", "4": "class3", "5": "class4"}
# Cap interfaces recorded per switch so a big chassis can't bloat the bundle.
_IFACE_CAP = 400

# Recursion gate (spine + full): which advertised capabilities mark a device we
# should crawl THROUGH. Endpoints (phones/APs/hosts) are recorded but not recursed.
_FORWARDER_CAPS = {"bridge", "router", "switch", "source-route-bridge", "two-port-mac-relay"}
_ENDPOINT_CAPS = {"telephone", "station", "wlan-ap", "host", "docsis"}


def _should_recurse(caps: list[str] | None) -> bool:
    """Recurse THROUGH a neighbor only when it isn't clearly an endpoint. Unknown
    or empty caps → recurse (conservative: never block a device that just doesn't
    advertise caps); a forwarder cap → recurse; an endpoint-only cap → stop."""
    if not caps:
        return True
    if any(c in _FORWARDER_CAPS for c in caps):
        return True
    if any(c in _ENDPOINT_CAPS for c in caps):
        return False
    return True


def _gateway_mac_fdb_suffix(gateway_mac: str | None) -> str | None:
    """'aa:bb:cc:dd:ee:ff' -> '170.187.204.221.238.255' (the decimal-octet OID
    suffix dot1dTpFdbPort is keyed by). None if the MAC isn't 6 valid hex bytes."""
    if not gateway_mac:
        return None
    parts = gateway_mac.replace("-", ":").split(":")
    if len(parts) != 6:
        return None
    try:
        return ".".join(str(int(p, 16)) for p in parts)
    except ValueError:
        return None


def _resolve_uplink_ifindex(
    ip: str, community: str, gateway_mac: str | None,
) -> int | None:
    """The local ifIndex pointing toward the internet for switch `ip`:
    gateway-MAC FDB port → bridge port → ifIndex; STP root port as fallback.
    Returns None when neither resolves (caller treats as 'ambiguous')."""
    base_to_ifindex: dict[str, int] = {}

    def _ifindex_for_bridge_port(bp: str) -> int | None:
        if not base_to_ifindex:
            for oid, val in _snmp_walk(ip, community, DOT1D_BASEPORT_IFINDEX):
                suffix = oid.strip(".").split(".")[-1]
                try:
                    base_to_ifindex[suffix] = int(val)
                except (ValueError, TypeError):
                    continue
        return base_to_ifindex.get(bp)

    # 1) Gateway-MAC FDB → the bridge port the egress MAC is learned on.
    suffix = _gateway_mac_fdb_suffix(gateway_mac)
    if suffix:
        for oid, val in _snmp_walk(ip, community, DOT1D_TPFDB_PORT):
            if oid.strip(".").endswith("." + suffix):
                try:
                    bp = str(int(val))
                except (ValueError, TypeError):
                    break
                if bp and bp != "0":
                    idx = _ifindex_for_bridge_port(bp)
                    if idx is not None:
                        return idx
                break

    # 2) STP root port → the bridge port toward the spanning-tree root (the core).
    root_bp = _snmp_get(ip, community, DOT1D_STP_ROOT_PORT)
    if root_bp:
        try:
            bp = str(int(root_bp.strip()))
        except (ValueError, TypeError):
            bp = ""
        if bp and bp != "0":
            idx = _ifindex_for_bridge_port(bp)
            if idx is not None:
                return idx
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def crawl(
    seed_ips: list[str],
    communities: list[str],
    *,
    max_depth: int = 5,
    time_budget_sec: int = 60,
    exclude_ips: set[str] | None = None,
    scope: str = "full",
    gateway_ip: str | None = None,
    gateway_mac: str | None = None,
    max_nodes: int = 600,
    fanout_cap: int = 40,
    overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Recursively SNMP-walk LLDP/CDP tables outward from `seed_ips`.

    scope='full' (default): omnidirectional walk. scope='spine': from each switch
    follow only the uplink toward the internet (gateway-MAC FDB port → STP root →
    toward-gateway); stop at the L3 edge (gateway). Both scopes capability-gate
    recursion (don't crawl through phones/APs/hosts) and honor max_nodes / fanout_cap.

    `overrides` are per-device community overrides (ip → community), passed
    straight through to the shared selector so a switch on its own string is
    crawled here exactly as it is polled — a topology crawl that couldn't
    authenticate to an overridden switch would silently truncate the map at it.
    """
    spine = scope == "spine"
    # An override is a credential source on its own, so an empty shared list is
    # only fatal when there are no overrides either.
    if not seed_ips or (not communities and not overrides):
        return {"nodes": [], "edges": [], "stats": {
            "visited_ips": 0, "elapsed_sec": 0.0, "budget_exhausted": False,
        }}

    if shutil.which("snmpget") is None or shutil.which("snmpbulkwalk") is None:
        log.warning("net-snmp tools missing; topology crawl skipped")
        return {"nodes": [], "edges": [], "stats": {
            "visited_ips": 0, "elapsed_sec": 0.0, "budget_exhausted": False,
        }}

    started = time.monotonic()
    deadline = started + time_budget_sec

    # Operator-excluded management IPs (purged from inventory): never poll them
    # and never recurse THROUGH them, so the crawl stops at the boundary.
    exclude = {ip.strip() for ip in (exclude_ips or set()) if ip and ip.strip()}

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    visited_ips: set[str] = set()
    queue: list[tuple[str, int]] = [(ip, 0) for ip in seed_ips if ip not in exclude]
    budget_exhausted = False
    # Spine/guard bookkeeping for the stats block + safety backstops.
    stat_uplink_resolved = 0
    stat_uplink_ambiguous = 0
    stat_truncated = False

    def _can_enqueue() -> bool:
        nonlocal stat_truncated
        if len(visited_ips) + len(queue) >= max_nodes:
            stat_truncated = True
            return False
        return True

    while queue:
        if time.monotonic() >= deadline:
            budget_exhausted = True
            log.info("topology crawl: time budget reached", budget=time_budget_sec)
            break

        ip, depth = queue.pop(0)
        if ip in exclude:
            continue
        if ip in visited_ips:
            continue
        visited_ips.add(ip)
        if depth > max_depth:
            continue

        # Reuse the polling module's community selection so a winning
        # community gets cached + reused; failures hit the same backoff.
        community = _snmp._select_community(ip, communities, overrides=overrides)
        if community is None:
            log.debug("topology crawl: no community for", ip=ip, depth=depth)
            continue

        # Identify the device itself.
        local_chassis = _normalize_chassis(_snmp_get(ip, community, LLDP_LOC_CHASSIS_ID))
        sys_name = _strip_quotes(_snmp_get(ip, community, SYS_NAME))
        sys_desc = _strip_quotes(_snmp_get(ip, community, SYS_DESCR))
        if not local_chassis:
            # LLDP not enabled here; still record the node keyed by IP so
            # any edges discovered from elsewhere have somewhere to land.
            local_chassis = f"ip:{ip}"

        local_caps = _decode_lldp_caps(_snmp_get(ip, community, LLDP_LOC_SYS_CAP_ENABLED))
        node = nodes.setdefault(local_chassis, {
            "chassis_id":         local_chassis,
            "system_name":        sys_name,
            "system_description": sys_desc,
            "mgmt_ips":           [],
            "discovered_via_ip":  ip,
            "source":             "snmp",
            "capabilities":       local_caps,
        })
        if ip not in node["mgmt_ips"]:
            node["mgmt_ips"].append(ip)
        # Fill caps if the node was first seen as an LLDP remote (no local poll).
        if local_caps and not node.get("capabilities"):
            node["capabilities"] = local_caps

        # CORE-2: per-interface health + STP port roles for this polled switch
        # (MAP-3/MAP-4). Best-effort — never fail the crawl over enrichment.
        try:
            iface_health = _collect_interface_health(ip, community)
            if iface_health:
                node["interfaces"] = iface_health
        except Exception:  # noqa: BLE001
            log.debug("interface health collect failed", ip=ip)

        # Spine mode: which local port (ifIndex) leads toward the internet, and is
        # THIS the L3 edge (the gateway) where we stop? An unresolved uplink falls
        # back to a normal (capability-gated) crawl from this switch.
        is_l3_edge = spine and gateway_ip is not None and ip == gateway_ip
        uplink_ifindex: int | None = None
        if spine and not is_l3_edge:
            uplink_ifindex = _resolve_uplink_ifindex(ip, community, gateway_mac)
            if uplink_ifindex is not None:
                stat_uplink_resolved += 1
                # PERF-3: sample the uplink's octet counters for utilization.
                # Best-effort — never fail the crawl over an enrichment GET.
                try:
                    iface = (node.get("interfaces") or {}).get(str(uplink_ifindex))
                    uplink_rec = _collect_uplink_counters(
                        ip, community, uplink_ifindex, iface,
                    )
                    if uplink_rec:
                        node["uplink"] = uplink_rec
                except Exception:  # noqa: BLE001
                    log.debug("uplink counter collect failed", ip=ip)
            else:
                stat_uplink_ambiguous += 1
        fanout = 0  # neighbors enqueued from THIS device (fanout_cap backstop)

        def _consider(
            mgmt_ip: str | None,
            caps: list[str] | None,
            local_ifindex: int | None,
            *,
            # Bind the per-iteration loop vars as defaults (B023): the closure is
            # only ever called synchronously within this iteration, so capturing
            # their current values here is correct and keeps ruff happy.
            is_l3_edge: bool = is_l3_edge,
            uplink_ifindex: int | None = uplink_ifindex,
            depth: int = depth,
        ) -> None:
            nonlocal fanout, stat_truncated
            if not mgmt_ip or mgmt_ip in visited_ips or mgmt_ip in exclude:
                return
            if is_l3_edge:
                return  # at the gateway → don't recurse toward the WAN
            if not _should_recurse(caps):
                return  # endpoint (phone/AP/host) → record it, don't crawl through it
            if spine and uplink_ifindex is not None and mgmt_ip != gateway_ip:
                # Directional: only follow the port toward the internet.
                if local_ifindex != uplink_ifindex:
                    return
            if fanout >= fanout_cap:
                stat_truncated = True
                return
            if not _can_enqueue():
                return
            queue.append((mgmt_ip, depth + 1))
            fanout += 1

        # --- LLDP remote table -------------------------------------------
        rem_rows = _snmp_walk(ip, community, LLDP_REM_TABLE)
        rem_by_idx = _parse_indexed_table(rem_rows, LLDP_REM_TABLE, LLDP_REM_COLS)

        # Management addresses for those remotes (index_key shares
        # time_mark.local_port.rem_idx prefix).
        addr_rows = _snmp_walk(ip, community, LLDP_REM_MAN_TBL)
        rem_mgmt_by_idx = _parse_lldp_rem_man_addrs(addr_rows)

        for idx, row in rem_by_idx.items():
            chassis_raw = row.get("chassis_id")
            chassis_norm = _normalize_chassis(chassis_raw)
            if not chassis_norm:
                continue
            mgmt_ips = rem_mgmt_by_idx.get(idx, [])

            rem_caps = _decode_lldp_caps(row.get("capabilities_enabled"))
            n = nodes.setdefault(chassis_norm, {
                "chassis_id":         chassis_norm,
                "system_name":        _strip_quotes(row.get("sys_name")),
                "system_description": _strip_quotes(row.get("sys_desc")),
                "mgmt_ips":           [],
                "discovered_via_ip":  ip,
                "source":             "lldp",
                "capabilities":       rem_caps,
            })
            for mip in mgmt_ips:
                if mip not in n["mgmt_ips"]:
                    n["mgmt_ips"].append(mip)
            if rem_caps and not n.get("capabilities"):
                n["capabilities"] = rem_caps

            edges.append({
                "local_chassis_id":  local_chassis,
                "local_port_id":     idx[1] if len(idx) > 1 else None,
                "local_port_desc":   None,
                "remote_chassis_id": chassis_norm,
                "remote_port_id":    _strip_quotes(row.get("port_id")),
                "remote_port_desc":  _strip_quotes(row.get("port_desc")),
                "via":               "lldp",
                "discovered_via_ip": ip,
            })

            # Recurse via management IPs — capability-gated + (in spine mode)
            # only toward the uplink port. lldpRemLocalPortNum (idx[1]) == ifIndex
            # on Cisco; best-effort elsewhere (ambiguous → full fallback).
            local_ifindex = None
            if len(idx) > 1:
                try:
                    local_ifindex = int(idx[1])
                except (ValueError, TypeError):
                    local_ifindex = None
            for mip in mgmt_ips:
                _consider(mip, rem_caps, local_ifindex)

        # --- CDP cache table (Cisco) -------------------------------------
        cdp_rows = _snmp_walk(ip, community, CDP_CACHE_TABLE)
        cdp_by_idx = _parse_indexed_table(cdp_rows, CDP_CACHE_TABLE, CDP_CACHE_COLS)
        for idx, row in cdp_by_idx.items():
            device_id = _strip_quotes(row.get("device_id"))
            if not device_id:
                continue
            # CDP doesn't give us a chassis MAC; use device-id as the key.
            chassis_key = f"cdp:{device_id}"
            mgmt_ip = _normalize_cdp_address(row.get("address"))
            cdp_caps = _decode_cdp_caps(row.get("cap_raw"))

            n = nodes.setdefault(chassis_key, {
                "chassis_id":         chassis_key,
                "system_name":        device_id,
                "system_description": _strip_quotes(row.get("platform")),
                "mgmt_ips":           [mgmt_ip] if mgmt_ip else [],
                "discovered_via_ip":  ip,
                "source":             "cdp",
                "capabilities":       cdp_caps,
            })
            if mgmt_ip and mgmt_ip not in n["mgmt_ips"]:
                n["mgmt_ips"].append(mgmt_ip)
            if cdp_caps and not n.get("capabilities"):
                n["capabilities"] = cdp_caps

            edges.append({
                "local_chassis_id":  local_chassis,
                "local_port_id":     idx[0] if idx else None,
                "local_port_desc":   None,
                "remote_chassis_id": chassis_key,
                "remote_port_id":    _strip_quotes(row.get("device_port")),
                "remote_port_desc":  None,
                "via":               "cdp",
                "discovered_via_ip": ip,
            })
            # CDP cache index is (cdpCacheIfIndex, deviceIndex) — idx[0] is the
            # local ifIndex, a clean uplink-port match in spine mode.
            cdp_ifindex = None
            if idx:
                try:
                    cdp_ifindex = int(idx[0])
                except (ValueError, TypeError):
                    cdp_ifindex = None
            _consider(mgmt_ip, cdp_caps, cdp_ifindex)

    # INV-8: collapse `cdp:`/`ip:` placeholders onto the real device BEFORE emitting,
    # so a duplicate entity is never created downstream in the first place.
    folded = _fold_synthetic_nodes(nodes, edges)

    elapsed = time.monotonic() - started
    log.info("topology crawl done",
             scope=scope, nodes=len(nodes), edges=len(edges),
             visited=len(visited_ips), elapsed_sec=round(elapsed, 1),
             budget_exhausted=budget_exhausted, truncated=stat_truncated,
             uplink_resolved=stat_uplink_resolved, uplink_ambiguous=stat_uplink_ambiguous,
             synthetic_folded=folded)
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "scope":             scope,
            "visited_ips":       len(visited_ips),
            "elapsed_sec":       round(elapsed, 2),
            "budget_exhausted":  budget_exhausted,
            "truncated_by_budget": stat_truncated,
            "uplink_resolved":   stat_uplink_resolved,
            "uplink_ambiguous":  stat_uplink_ambiguous,
            "synthetic_folded":  folded,
        },
    }


# ---------------------------------------------------------------------------
# Indexed-table parsing
# ---------------------------------------------------------------------------


def _parse_indexed_table(
    walk_rows: list[tuple[str, str]],
    table_oid: str,
    columns: dict[str, str],
) -> dict[tuple[str, ...], dict[str, str]]:
    """Group lldp/cdp table walk output by index suffix.

    Each row's OID is `<table_oid>.<column>.<index1>.<index2>...`. We
    split off the column number, take everything after as the index tuple,
    and collect the column values into a dict per index.
    """
    out: dict[tuple[str, ...], dict[str, str]] = {}
    prefix = table_oid.strip(".")
    for oid, value in walk_rows:
        bare = oid.strip(".")
        if not bare.startswith(prefix + "."):
            continue
        suffix = bare[len(prefix) + 1:]
        parts = suffix.split(".")
        if not parts:
            continue
        col = parts[0]
        idx = tuple(parts[1:]) if len(parts) > 1 else ()
        if col not in columns:
            continue
        row = out.setdefault(idx, {})
        row[columns[col]] = value
    return out


def _parse_lldp_rem_man_addrs(walk_rows: list[tuple[str, str]]) -> dict[tuple[str, ...], list[str]]:
    """Pull out the management IPs (column 3 = lldpRemManAddrIfSubtype is the
    presence marker; the address itself is encoded in the OID suffix).

    The lldpRemManAddrEntry index is:
        time_mark . local_port . rem_idx . addr_subtype . addr_len . addr_bytes
    For an IPv4 management address, addr_subtype=1, addr_len=4, and the
    last 4 components are the dotted-quad. We surface the addr bytes for
    every row keyed by the lldpRem index prefix (first 3 components) so
    the caller can match it against the neighbor row.
    """
    out: dict[tuple[str, ...], list[str]] = {}
    prefix = LLDP_REM_MAN_TBL.strip(".")
    for oid, _value in walk_rows:
        bare = oid.strip(".")
        if not bare.startswith(prefix + "."):
            continue
        # column.<time_mark>.<local_port>.<rem_idx>.<addr_subtype>.<addr_len>.<addr_bytes>
        suffix = bare[len(prefix) + 1:].split(".")
        if len(suffix) < 7:
            continue
        # We don't care which column it was — the address is in the index.
        time_mark, local_port, rem_idx = suffix[1], suffix[2], suffix[3]
        addr_subtype = suffix[4]
        addr_len = suffix[5]
        addr_bytes = suffix[6: 6 + int(addr_len)] if addr_len.isdigit() else []
        # IPv4 only for now.
        if addr_subtype != "1" or len(addr_bytes) != 4:
            continue
        # The octets are raw OID-suffix tokens from an untrusted agent; accept only
        # a well-formed IPv4 (each octet numeric and 0-255) before treating it as a
        # management IP that later becomes a net-snmp host argument.
        try:
            ip = str(ipaddress.IPv4Address(".".join(addr_bytes)))
        except ValueError:
            continue
        rem_idx_key = (time_mark, local_port, rem_idx)
        out.setdefault(rem_idx_key, [])
        if ip not in out[rem_idx_key]:
            out[rem_idx_key].append(ip)
    return out


# ---------------------------------------------------------------------------
# Value normalization
# ---------------------------------------------------------------------------


def _strip_quotes(value: str | None) -> str | None:
    """net-snmp wraps strings in double quotes; strip them."""
    if value is None:
        return None
    return _snmp._strip_wrapping_quotes(value.strip()) or None


_SYNTHETIC_KEY = re.compile(r"^(?:cdp|ip):", re.IGNORECASE)
_ADDRESS_SHAPED = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# An identity string we trust must be at least as long as a MAC (12 hex digits);
# shorter normalized forms collide too easily to fold two nodes on.
_IDENTITY_MIN_LEN = 12
# A sysName is weaker evidence than a chassis id, but still has to be a real name.
_NAME_MIN_LEN = 3


def _usable_mgmt_ip(ip: object) -> bool:
    """Is this management address specific enough to prove two nodes are one device?

    Real gear advertises junk here. Prod carries a switch listing `0.0.0.0` among its
    management addresses (seen 2026-08-16 on `T34W44DBD28A3AC7`), and 0.0.0.0 is not an
    address — it is "unset". Loopback, link-local (a DHCP failure), multicast and the
    reserved 240/4 block are the same story: many unrelated boxes can present them, so
    folding on one would fuse devices that merely share a placeholder.
    """
    if not isinstance(ip, str) or not ip.strip():
        return False
    try:
        a = ipaddress.IPv4Address(ip.strip())
    except ValueError:
        return False
    return not (
        a.is_unspecified or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
    )


def _identity_key(s: str) -> str:
    """Collapse separators + case so two spellings of ONE identity compare equal.

    `D0 3D 52 0D 28 BC` (a CDP device-id) and `d0:3d:52:0d:28:bc` (the same box's
    LLDP chassis id) are the same MAC written two ways.
    """
    return re.sub(r"[\s:.\-_]", "", s).lower()


def _fold_synthetic_nodes(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
) -> int:
    """Fold NetMon-manufactured placeholder nodes into the real device (INV-8).

    A device that only a neighbour saw gets keyed `cdp:<device-id>`, and one that
    answered SNMP without an LLDP chassis id gets keyed `ip:<addr>`. When the SAME
    crawl also identified that box by its real chassis id, we emitted two nodes for
    one device — and because the dashboard upserts on (district, chassis_id), that
    became two permanent `entities_switch` rows that a nightly job then had to
    detect and merge back. Reconciling here means the duplicate is never created.

    Measured on prod 2026-08-16, one district carried 356 such pairs: 135 where the
    CDP device-id WAS the chassis id verbatim, 88 where it was the same MAC with
    spaces instead of colons, and 133 where the placeholder was named for the
    management address it already shared.

    Same charter as the dashboard matcher: a WRONG fold is worse than a duplicate,
    so every rule demands exactly ONE candidate and refuses on ambiguity. Only
    placeholders are ever folded away — a real chassis node is never removed.

    One thing this gets that the dashboard cannot: everything here happened inside a
    single crawl, minutes apart, so a shared management address cannot be explained
    by the address changing hands. That makes IP the strong signal it isn't later.

    Returns the number of placeholder nodes folded away.
    """
    real_keys = [k for k in nodes if not _SYNTHETIC_KEY.match(k)]
    if not real_keys:
        return 0

    by_identity: dict[str, list[str]] = {}
    by_name: dict[str, list[str]] = {}
    by_ip: dict[str, list[str]] = {}
    for k in real_keys:
        n = nodes[k]
        by_identity.setdefault(_identity_key(k), []).append(k)
        name = n.get("system_name")
        if isinstance(name, str) and name.strip():
            by_name.setdefault(_identity_key(name), []).append(k)
        for ip in n.get("mgmt_ips") or []:
            if _usable_mgmt_ip(ip):
                by_ip.setdefault(ip, []).append(k)

    def _sole(bucket: dict[str, list[str]], key: str) -> str | None:
        hits = bucket.get(key) or []
        return hits[0] if len(hits) == 1 else None

    remap: dict[str, str] = {}
    for key in list(nodes):
        if not _SYNTHETIC_KEY.match(key):
            continue
        node = nodes[key]
        raw_name = node.get("system_name") or key.split(":", 1)[1]
        name = raw_name.strip() if isinstance(raw_name, str) else ""
        # A name that is just an address says nothing about identity — it is the
        # address we already know. Never let it stand in for one.
        usable_name = name if name and not _ADDRESS_SHAPED.match(name) else ""

        target: str | None = None

        # 1. The placeholder is NAMED FOR a real node's chassis id (the 135 + 88).
        if usable_name:
            ident = _identity_key(usable_name)
            if len(ident) >= _IDENTITY_MIN_LEN:
                target = _sole(by_identity, ident)

        # 2. Exactly one real node claims a management address this placeholder
        #    claims. Two real claimants means a shared virtual address (HSRP/VRRP)
        #    and we must not guess which box is behind it.
        if target is None:
            owners = {
                o
                for ip in node.get("mgmt_ips") or []
                if _usable_mgmt_ip(ip)
                for o in by_ip.get(ip, [])
            }
            if len(owners) == 1:
                target = next(iter(owners))

        # 3. The placeholder's name IS a real node's sysName. Weaker than a chassis
        #    id, so it needs uniqueness among the real nodes in this crawl.
        if target is None and usable_name:
            ident = _identity_key(usable_name)
            if len(ident) >= _NAME_MIN_LEN:
                target = _sole(by_name, ident)

        if target is not None and target != key:
            remap[key] = target

    if not remap:
        return 0

    for src, dst in remap.items():
        placeholder = nodes.pop(src)
        keeper = nodes[dst]
        for ip in placeholder.get("mgmt_ips") or []:
            if ip not in keeper["mgmt_ips"]:
                keeper["mgmt_ips"].append(ip)
        # FILL ONLY. The real node's own identity always wins — a placeholder's
        # "system_name" is frequently just its IP, and letting that overwrite a
        # real sysName would rename the device in inventory.
        for field in ("system_name", "system_description", "capabilities",
                      "interfaces", "uplink"):
            if not keeper.get(field) and placeholder.get(field):
                keeper[field] = placeholder[field]

    # Re-point every edge at the surviving node, drop the self-loops that folding
    # necessarily creates (the two keys were the same device facing itself), and
    # collapse edges that are now identical.
    seen: set[tuple[Any, ...]] = set()
    kept: list[dict[str, Any]] = []
    for e in edges:
        e["local_chassis_id"] = remap.get(e["local_chassis_id"], e["local_chassis_id"])
        e["remote_chassis_id"] = remap.get(e["remote_chassis_id"], e["remote_chassis_id"])
        if e["local_chassis_id"] == e["remote_chassis_id"]:
            continue
        sig = (e["local_chassis_id"], e.get("local_port_id"),
               e["remote_chassis_id"], e.get("remote_port_id"), e.get("via"))
        if sig in seen:
            continue
        seen.add(sig)
        kept.append(e)
    edges[:] = kept

    return len(remap)


def _normalize_chassis(raw: str | None) -> str | None:
    """Best-effort: present chassis IDs as canonical colon-separated MAC
    when they look like 6 bytes; otherwise the trimmed string."""
    if raw is None:
        return None
    v = _strip_quotes(raw) or ""
    if not v:
        return None
    # Common net-snmp formats for octet strings:
    #   "00 11 22 33 44 55"  (space-separated hex)
    #   "0x001122334455"     (0x prefix)
    #   "00:11:22:33:44:55"  (already colons)
    # split() (not replace(" ")) because quick-print hex WRAPS at 16 bytes/line, so
    # anything longer than a MAC arrives with embedded newlines.
    cleaned = "".join(v.split()).replace(":", "").replace("-", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) == 12 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return ":".join(cleaned[i:i + 2].lower() for i in range(0, 12, 2))
    return v


def _normalize_cdp_address(raw: str | None) -> str | None:
    """cdpCacheAddress is a hex-encoded octet string; for IPv4 we get 4
    bytes. Format like "0x0A080264" -> "10.8.2.100"."""
    if raw is None:
        return None
    v = _strip_quotes(raw) or ""
    # split() over replace(" ") — quick-print hex wraps at 16 bytes/line.
    cleaned = "".join(v.split()).replace(":", "").lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) == 8 and all(c in "0123456789abcdef" for c in cleaned):
        return ".".join(str(int(cleaned[i:i + 2], 16)) for i in range(0, 8, 2))
    # Some agents already return dotted-quad; accept it ONLY if it parses as a
    # real IPv4 literal. cdpCacheAddress is attacker-controlled neighbor data and
    # the result is later used as a net-snmp host argument, so a junk value like
    # "-On.1.2.3" (which satisfies count(".")==3) must not pass through.
    try:
        return str(ipaddress.IPv4Address(v.strip()))
    except ValueError:
        return None


def _decode_lldp_caps(raw: str | None) -> list[str] | None:
    """Decode an LLDP system-capabilities octet string into a list of tags.

    net-snmp renders the 1-2 byte BITS field as hex — "28 00", "0x2800", or
    similar. Bit 0 is the MSB of the first octet (e.g. bridge=bit2=0x2000,
    router=bit4=0x0800, so a bridge+router reads 0x2800 -> ['bridge','router']).
    """
    if raw is None:
        return None
    v = _strip_quotes(raw) or ""
    # split() over replace(" ") — quick-print hex wraps at 16 bytes/line.
    cleaned = "".join(v.split()).replace(":", "").lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
        return None
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return None
    bits_total = len(data) * 8
    value = int.from_bytes(data, "big")
    caps = [
        name for i, name in enumerate(_LLDP_CAP_BITS)
        if i < bits_total and value & (1 << (bits_total - 1 - i))
    ]
    return caps or None


def _decode_cdp_caps(raw: str | None) -> list[str] | None:
    """Decode a CISCO-CDP-MIB cdpCacheCapabilities octet string into tags.

    net-snmp renders the 4-byte field as hex ("00 00 00 28", "0x00000028").
    The bitmask is LSB-first (router=0x01, switch=0x08, host=0x10, ...), so
    0x28 = switch+igmp -> ['switch', 'igmp'].
    """
    if raw is None:
        return None
    v = _strip_quotes(raw) or ""
    # split() over replace(" ") — quick-print hex wraps at 16 bytes/line.
    cleaned = "".join(v.split()).replace(":", "").lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
        return None
    try:
        value = int(cleaned, 16)
    except ValueError:
        return None
    caps = [
        name for i, name in enumerate(_CDP_CAP_BITS)
        if value & (1 << i)
    ]
    return caps or None


# ---------------------------------------------------------------------------
# Thin net-snmp wrappers
# ---------------------------------------------------------------------------


def _snmp_get(ip: str, community: str, oid: str) -> str | None:
    rc, out, err = _snmp._run_snmp([
        "snmpget", "-v2c", "-c", community,
        "-t", "2", "-r", "1",
        "-Oqv", ip, oid,
    ])
    if rc != 0:
        return None
    # Single -Oqv value: read both streams so a diagnostic trips the marker check.
    text = (out + err).strip()
    if not text or any(m in text for m in _snmp._SKIP_MARKERS):
        return None
    return text


def _snmp_walk(ip: str, community: str, base_oid: str) -> list[tuple[str, str]]:
    rc, out, _err = _snmp._run_snmp([
        "snmpbulkwalk", "-v2c", "-c", community,
        "-t", "3", "-r", "1",
        "-Oqn", ip, base_oid,
    ])
    if rc != 0:
        return []
    # Shared with snmp._poll_oids so both paths fold multi-line values the same
    # way — lldpRemSysDesc and cdpCacheVersion are multi-line on Cisco/Junos.
    return _snmp.parse_oqn_output(out)


def _walk_col(ip: str, community: str, base_oid: str) -> dict[str, str]:
    """Walk a single-column table; return {index_suffix: value}.

    For tables indexed by a single integer (ifIndex, bridge port), the suffix
    after the column base IS the index.
    """
    out: dict[str, str] = {}
    prefix = base_oid.strip(".")
    for oid, value in _snmp_walk(ip, community, base_oid):
        bare = oid.strip(".")
        if not bare.startswith(prefix + "."):
            continue
        out[bare[len(prefix) + 1:]] = value
    return out


def _walk_columns(
    ip: str, community: str, col_oids: tuple[str, ...],
) -> dict[str, dict[str, str]]:
    """Fetch several single-integer-indexed table columns in ONE snmpbulkwalk.

    All `col_oids` must be columns of the SAME table entry (their OID minus the
    last component — the column number). We walk that shared entry once and
    demultiplex by column, returning {column_oid: {index_suffix: value}} — the
    exact maps `_walk_col` would return one subprocess at a time. PERF: replaces
    N per-column walks (N process spawns + SNMP sessions) with a single subtree
    walk on the per-switch interface-health / PoE hot path. Columns we didn't ask
    for are walked-over-the-wire but dropped, so the output is byte-identical.
    """
    bare = {oid: oid.strip(".") for oid in col_oids}
    entries = {b.rsplit(".", 1)[0] for b in bare.values()}
    if len(entries) != 1:
        raise ValueError(
            f"_walk_columns: OIDs span multiple table entries: {sorted(entries)}"
        )
    entry = entries.pop()
    by_colnum = {b.rsplit(".", 1)[1]: oid for oid, b in bare.items()}
    result: dict[str, dict[str, str]] = {oid: {} for oid in col_oids}
    for oid, value in _snmp_walk(ip, community, entry):
        b = oid.strip(".")
        if not b.startswith(entry + "."):
            continue
        colnum, dot, idx = b[len(entry) + 1:].partition(".")
        if dot and colnum in by_colnum:
            result[by_colnum[colnum]][idx] = value
    return result


def _as_int(v: str | None) -> int | None:
    if v is None:
        return None
    v = v.strip()
    return int(v) if v.isdigit() else None


def _collect_interface_health(ip: str, community: str) -> dict[str, dict]:
    """Per-interface health for a polled switch (MAP-4) + STP port role (MAP-3).

    Keyed by ifIndex: {name, alias?, speed_mbps, oper_status, admin_status?,
    duplex?, in_errors, out_errors, stp_state?, poe?}. Returns {} when the box
    exposes no ifName (not a switch / no SNMP view) so older boxes + endpoints
    stay empty. Bounded by _IFACE_CAP. Utilization needs counter deltas across
    scans — a follow-up, not here.
    """
    # ifXTable (name/speed/alias) in ONE walk + ifTable (oper/admin/errors) in
    # ONE walk, instead of 7 per-column subprocess walks (see _walk_columns).
    ifx = _walk_columns(ip, community, (IF_NAME, IF_HIGH_SPEED, IF_ALIAS))
    names = ifx[IF_NAME]
    if not names:
        return {}
    speeds = ifx[IF_HIGH_SPEED]
    alias = ifx[IF_ALIAS]
    iftab = _walk_columns(
        ip, community, (IF_OPER_STATUS, IF_ADMIN_STATUS, IF_IN_ERRORS, IF_OUT_ERRORS)
    )
    oper = iftab[IF_OPER_STATUS]
    admin = iftab[IF_ADMIN_STATUS]
    in_err = iftab[IF_IN_ERRORS]
    out_err = iftab[IF_OUT_ERRORS]
    duplex = _walk_col(ip, community, DOT3_DUPLEX)  # lone dot3StatsTable column

    # STP state is keyed by bridge port; map bridge port -> ifIndex to align it.
    stp_by_bp = _walk_col(ip, community, DOT1D_STP_PORT_STATE)
    bp_ifindex = _walk_col(ip, community, DOT1D_BASEPORT_IFINDEX)
    stp_by_ifindex: dict[str, str] = {}
    for bp, state in stp_by_bp.items():
        ifidx = bp_ifindex.get(bp)
        if ifidx:
            stp_by_ifindex[ifidx] = _STP_STATE.get(state.strip(), state.strip())

    out: dict[str, dict] = {}
    for ifidx, raw_name in list(names.items())[:_IFACE_CAP]:
        rec: dict = {"name": _strip_quotes(raw_name) or raw_name}
        al = _strip_quotes(alias.get(ifidx))
        if al:
            rec["alias"] = al
        rec["speed_mbps"] = _as_int(speeds.get(ifidx))
        op = (oper.get(ifidx) or "").strip()
        rec["oper_status"] = _IF_OPER.get(op, op or None)
        ad = (admin.get(ifidx) or "").strip()
        if ad:
            rec["admin_status"] = _IF_ADMIN.get(ad, ad)
        dx = (duplex.get(ifidx) or "").strip()
        if dx:
            rec["duplex"] = _DUPLEX.get(dx, dx)
        rec["in_errors"] = _as_int(in_err.get(ifidx))
        rec["out_errors"] = _as_int(out_err.get(ifidx))
        stp = stp_by_ifindex.get(ifidx)
        if stp:
            rec["stp_state"] = stp
        out[ifidx] = rec

    # INV: PoE — best-effort join of the (group.port)-keyed PoE table onto ifIndex.
    poe = _collect_poe(ip, community)
    if poe:
        unmatched = _attach_poe(out, poe)
        if unmatched:
            log.debug("poe ports unmatched to ifindex",
                      ip=ip, unmatched=unmatched, poe_total=len(poe))
    return out


def _collect_poe(ip: str, community: str) -> dict[str, dict]:
    """PoE per PSE port from POWER-ETHERNET-MIB, keyed by "group.port".

    {admin: bool, status: str, class: str, power_w: float?}. Empty when the box
    isn't PoE / doesn't expose the MIB. power_w is best-effort (Cisco watts).
    """
    # pethPsePortTable admin/detect/class in ONE walk (was 3 per-column walks).
    peth = _walk_columns(ip, community, (PETH_ADMIN, PETH_DETECT, PETH_CLASS))
    admin = peth[PETH_ADMIN]
    detect = peth[PETH_DETECT]
    pclass = peth[PETH_CLASS]
    if not (admin or detect or pclass):
        return {}
    watts = _walk_col(ip, community, CPE_EXT_PWR)  # best-effort, Cisco-only
    out: dict[str, dict] = {}
    for key in set(admin) | set(detect) | set(pclass):
        rec: dict = {}
        av = (admin.get(key) or "").strip().lower()
        if av:
            rec["admin"] = av in ("1", "true", "true(1)")
        st = (detect.get(key) or "").strip()
        status = _PETH_DETECT.get(st, st or None)
        if status:
            rec["status"] = status
        cl = (pclass.get(key) or "").strip()
        klass = _PETH_CLASS.get(cl, cl or None)
        if klass:
            rec["class"] = klass
        mw = _as_int(watts.get(key))
        if mw is not None:
            rec["power_w"] = round(mw / 1000.0, 1)
        if rec:
            out[key] = rec
    return out


def _attach_poe(interfaces: dict[str, dict], poe: dict[str, dict]) -> int:
    """Best-effort map PoE rows (keyed "group.port") onto interface records by
    matching the numbers parsed from each ifName — there is no standard
    PsePort->ifIndex OID. Mutates `interfaces`; returns the count of PoE rows
    that couldn't be matched to an ifIndex (logged by the caller)."""
    tokens: list[tuple[list[int], str]] = []
    for ifidx, rec in interfaces.items():
        nums = [int(n) for n in re.findall(r"\d+", rec.get("name") or "")]
        if nums:
            tokens.append((nums, ifidx))
    unmatched = 0
    for key, prec in poe.items():
        parts = key.split(".")
        try:
            grp, port = int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            unmatched += 1
            continue
        match: str | None = None
        # 1) ifName ends with the PoE port AND contains the group earlier
        #    (e.g. "GigabitEthernet1/0/12" -> tokens [1,0,12] matches group 1 port 12).
        for nums, ifidx in tokens:
            if nums[-1] == port and grp in nums[:-1]:
                match = ifidx
                break
        # 2) single interface whose ifName ends with the port (single-group box).
        if match is None:
            cands = [ifidx for nums, ifidx in tokens if nums[-1] == port]
            if len(cands) == 1:
                match = cands[0]
        # 3) Fallback: the pethPsePortIndex IS the ifIndex. True on ArubaOS-CX,
        #    where the port index is stack-GLOBAL (member 2 port 1 = index 65 =
        #    ifIndex 65, member 3 +128, member 4 +192), so the ifName-number
        #    heuristics above match only member 1 and drop the rest. This only
        #    fires when (1)+(2) found nothing, so it can't override a name match
        #    on switches where the two indices differ (e.g. Cisco stacks).
        if match is None and str(port) in interfaces:
            match = str(port)
        if match is not None:
            interfaces[match]["poe"] = prec
        else:
            unmatched += 1
    return unmatched


def _collect_uplink_counters(
    ip: str, community: str, ifindex: int, iface: dict | None,
) -> dict | None:
    """PERF-3: sample the uplink interface's 64-bit octet counters + a wall-clock
    timestamp so the dashboard can compute uplink utilization (counter deltas
    across scans) against an admin-set committed rate.

    Only the single resolved uplink ifIndex is sampled (two targeted GETs), not
    the whole table. `iface` is this ifIndex's health record (for name/speed, if
    already collected). Returns None when neither counter is readable.
    """
    idx = str(ifindex)
    in_oct = _as_int(_snmp_get(ip, community, f"{IF_HC_IN_OCTETS}.{idx}"))
    out_oct = _as_int(_snmp_get(ip, community, f"{IF_HC_OUT_OCTETS}.{idx}"))
    if in_oct is None and out_oct is None:
        return None
    rec: dict = {
        "ifindex": ifindex,
        "in_octets": in_oct,
        "out_octets": out_oct,
        "counter_ts": time.time(),  # epoch seconds at sample time
    }
    if iface:
        rec["name"] = iface.get("name")
        rec["speed_mbps"] = iface.get("speed_mbps")
    return rec
