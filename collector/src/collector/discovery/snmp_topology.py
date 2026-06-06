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
) -> dict[str, Any]:
    """Recursively SNMP-walk LLDP/CDP tables outward from `seed_ips`.

    scope='full' (default): omnidirectional walk. scope='spine': from each switch
    follow only the uplink toward the internet (gateway-MAC FDB port → STP root →
    toward-gateway); stop at the L3 edge (gateway). Both scopes capability-gate
    recursion (don't crawl through phones/APs/hosts) and honor max_nodes / fanout_cap.
    """
    spine = scope == "spine"
    if not seed_ips or not communities:
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
        community = _snmp._select_community(ip, communities)
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

        # Spine mode: which local port (ifIndex) leads toward the internet, and is
        # THIS the L3 edge (the gateway) where we stop? An unresolved uplink falls
        # back to a normal (capability-gated) crawl from this switch.
        is_l3_edge = spine and gateway_ip is not None and ip == gateway_ip
        uplink_ifindex: int | None = None
        if spine and not is_l3_edge:
            uplink_ifindex = _resolve_uplink_ifindex(ip, community, gateway_mac)
            if uplink_ifindex is not None:
                stat_uplink_resolved += 1
            else:
                stat_uplink_ambiguous += 1
        fanout = 0  # neighbors enqueued from THIS device (fanout_cap backstop)

        def _consider(mgmt_ip: str | None, caps: list[str] | None, local_ifindex: int | None) -> None:
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

    elapsed = time.monotonic() - started
    log.info("topology crawl done",
             scope=scope, nodes=len(nodes), edges=len(edges),
             visited=len(visited_ips), elapsed_sec=round(elapsed, 1),
             budget_exhausted=budget_exhausted, truncated=stat_truncated,
             uplink_resolved=stat_uplink_resolved, uplink_ambiguous=stat_uplink_ambiguous)
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
        ip = ".".join(addr_bytes)
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
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v or None


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
    cleaned = v.replace(" ", "").replace(":", "").replace("-", "")
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
    cleaned = v.replace(" ", "").replace(":", "").lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) == 8 and all(c in "0123456789abcdef" for c in cleaned):
        return ".".join(str(int(cleaned[i:i + 2], 16)) for i in range(0, 8, 2))
    # Some agents already return dotted-quad; pass through if it looks IP-ish.
    if v.count(".") == 3:
        return v
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
    cleaned = v.replace(" ", "").replace(":", "").lower()
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
    cleaned = v.replace(" ", "").replace(":", "").lower()
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
    rc, out = _snmp._run_snmp([
        "snmpget", "-v2c", "-c", community,
        "-t", "2", "-r", "1",
        "-Oqv", ip, oid,
    ])
    if rc != 0:
        return None
    text = out.strip()
    if not text or any(m in text for m in _snmp._SKIP_MARKERS):
        return None
    return text


def _snmp_walk(ip: str, community: str, base_oid: str) -> list[tuple[str, str]]:
    rc, out = _snmp._run_snmp([
        "snmpbulkwalk", "-v2c", "-c", community,
        "-t", "3", "-r", "1",
        "-Oqn", ip, base_oid,
    ])
    if rc != 0:
        return []
    rows: list[tuple[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or any(m in line for m in _snmp._SKIP_MARKERS):
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        rows.append((parts[0], parts[1]))
    return rows
