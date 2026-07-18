"""Authoritative DHCP server intel over MS-DHCPM RPC — the WinRM/WMI fallback (DHCP-9).

The primary DHCP-intel path drives the Windows **DhcpServer** PowerShell module
over WinRM (see ``dhcp_server.py``). That path crosses four independently-ACL'd
gates — Kerberos, the WinRM RootSDDL, the local "DHCP Users" group, and
WMI/DCOM — and hardened servers close the WMI/DCOM gate to non-admins. This
module is the escape hatch: it talks straight to the DHCP service's own RPC
interface (**MS-DHCPM**) via impacket, authorizing on the **"DHCP Users"** group
ALONE — no WinRM, no WMI, no admin. It emits the SAME parsed shape the PowerShell
probe produces, so ``dhcp_server._collect_one`` merges it identically.

Validated live against a hardened Server Core 2022 DHCP server (485 scopes),
DHCP-Users-only. Notes baked into the calls below:
  * **TWO interfaces.** Scopes + options are on ``DHCPSRV``; the V5 client/element
    calls (leases, ranges, reservations) are on ``DHCPSRV2`` — calling them on the
    wrong interface returns ``rpc_x_bad_stub_data``.
  * **Utilization** = in-use from ``EnumSubnetClientsV5`` (``ClientsTotal``) over
    total from ``EnumSubnetElementsV5`` IP-ranges. An empty subnet raises
    ``ERROR_NO_MORE_ITEMS`` — treated as 0.
  * impacket 0.13.1 ships the ``EnumSubnetElementsV5`` structs BROKEN. Corrected
    classes are rebuilt in ``_element_types`` and used explicitly (never
    ``dce.request``, which would resolve impacket's buggy response class). The
    decisive fix: the ``DHCP_SUBNET_ELEMENT_TYPE`` discriminant is a **2-byte** NDR
    enum (plus a separate ``ElementType`` field), NOT a 4-byte ULONG — the old
    4-byte tag worked for ranges only by accident (type 0 zeros both halves) and
    read reservations (type 2) as tag 0x00020002.
  * Reservations (element type 2) are collected per scope and joined to the scope's
    live leases for name / holding-MAC / conflict. A reserved client-UID that ENDS
    WITH the reserved IP (little-endian) is a server-synthesized bad-address/IP-only
    id, not a hardware MAC — ``_hw_mac`` suppresses those so they don't read as a
    bogus conflict.

Auth reuses the Kerberos ccache ``dhcp_server._kinit`` writes (impacket reads
``KRB5CCNAME`` when ``set_kerberos(True)`` is used). NTLM only when the caller
passes ``use_kerberos=False``. impacket is imported lazily so the module (and its
unit tests) import cleanly on a box without it.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from datetime import UTC, datetime
from typing import Any

# MS-DHCPM DHCP_SUBNET_STATE -> the PowerShell probe's "Active"/"Inactive" vocab.
_SUBNET_STATE = {0: "Active", 1: "Inactive", 2: "Active", 3: "Inactive", 4: "Invalid"}


def _num(v: Any) -> int:
    """Python int from an impacket scalar. Struct members already come back as int;
    bare NDR array elements (the subnet list) need ['Data']."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return int(v["Data"])


def _ip(dword: Any) -> str:
    """DHCP_IP_ADDRESS (host-order 32-bit int) -> dotted-quad."""
    try:
        return socket.inet_ntoa(struct.pack(">I", _num(dword) & 0xFFFFFFFF))
    except Exception:  # noqa: BLE001
        return str(dword)


def _wstr(v: Any) -> str:
    """impacket LPWSTR -> str; NULL/None -> '' (trailing NUL stripped)."""
    if v is None:
        return ""
    s = str(v)
    return "" if s == "NULL" else s.rstrip("\x00")


def _fmt_mac(raw: bytes) -> str:
    """Colon-separated lowercase MAC from a hardware-address / client-UID byte string.
    Windows reservation UIDs are often 11 bytes (client-id prefix + MAC); take the
    trailing 6. A shorter blob is used as-is."""
    b = raw[-6:] if len(raw) >= 6 else raw
    return ":".join(f"{x:02x}" for x in b)


def _hw_mac(raw: bytes, ip_int: int) -> str:
    """Hardware MAC (colon-lowercase) from a client-UID / lease hardware address, or ""
    when there is no real MAC. Windows synthesizes IP-based client ids for bad-address
    and IP-only reservations — those UIDs END WITH the reserved IP (little-endian), so
    the trailing 6 bytes are prefix+IP, not a MAC. Detecting that (rather than assuming
    a UID length) keeps a real MAC while suppressing the synthetic garbage that would
    otherwise read as a bogus conflict."""
    if len(raw) < 6:
        return ""
    if raw.endswith(struct.pack("<I", ip_int & 0xFFFFFFFF)):
        return ""
    return _fmt_mac(raw)


def _filetime_iso(lo: int, hi: int) -> str | None:
    """Windows FILETIME (dwLowDateTime/dwHighDateTime, 100ns since 1601) -> ISO-8601
    UTC. 0 / max (infinite lease — how reservations present) -> None."""
    ft = (hi << 32) | lo
    if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return datetime.fromtimestamp(ft / 1e7 - 11644473600, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _opt_value_strings(option_data: Any) -> list[str]:
    """Decode a DHCP_OPTION_DATA (typed element array) to strings, matching how the
    PowerShell probe stringifies option values (via the OptionType union tag)."""
    out: list[str] = []
    try:
        elements = option_data["Elements"]
    except Exception:  # noqa: BLE001
        return out
    for el in elements or []:
        try:
            t = _num(el["OptionType"])
            e = el["Element"]
            if t == 4:  # IpAddress
                out.append(_ip(e["IpAddressOption"]))
            elif t == 5:  # String
                out.append(_wstr(e["StringDataOption"]))
            elif t == 0:  # Byte
                out.append(str(_num(e["ByteOption"])))
            elif t == 1:  # Word
                out.append(str(_num(e["WordOption"])))
            elif t == 2:  # DWord
                out.append(str(_num(e["DWordOption"])))
            elif t == 8:  # Ipv6
                out.append(_wstr(e["Ipv6AddressDataOption"]))
            # binary / encapsulated: no useful text — skip.
        except Exception:  # noqa: BLE001
            continue
    return out


def _options_from_enum(resp: Any) -> list[dict[str, Any]]:
    """Flatten a DhcpEnumOptionValuesResponse -> [{id, name, value:[...]}]."""
    out: list[dict[str, Any]] = []
    try:
        arr = resp["OptionValues"]
        values = arr["Values"] if arr else None
    except Exception:  # noqa: BLE001
        return out
    for ov in values or []:
        try:
            out.append({
                "id": _num(ov["OptionID"]),
                "name": "",  # dashboard maps id->name (dhcp-intel.ts OPT_NAMES)
                "value": _opt_value_strings(ov["Value"]),
            })
        except Exception:  # noqa: BLE001
            continue
    return out


def _extract_elements(resp: Any) -> list[dict[str, Any]]:
    """Pull ranges / reservations out of a (corrected) EnumSubnetElementsV5 response.
    Works on impacket objects and plain dicts (for tests): every access is ['key'].
    Ranges/exclusions carry int start/end; reservations carry an int ip + mac hex."""
    out: list[dict[str, Any]] = []
    try:
        info = resp["EnumElementInfo"]
        if not info:
            return out
        n = _num(info["NumElements"])
        arr = info["Elements"]
    except Exception:  # noqa: BLE001 — empty / null / misparse
        return out
    for i in range(n):
        try:
            u = arr[i]["Element"]
            tag = _num(u["tag"])
            if tag in (0, 5, 6, 7):  # DhcpIpRanges (+ dhcp/bootp subtypes)
                r = u["IpRange"]
                out.append({"kind": "range", "start": _num(r["StartAddress"]), "end": _num(r["EndAddress"])})
            elif tag == 2:  # DhcpReservedIps
                rv = u["ReservedIp"]
                uid = rv["ReservedForClient"]
                nb = _num(uid["DataLength"])
                raw = b"".join(bytes(uid["Data_"][j]) for j in range(nb))
                # emit the full client-UID; _hw_mac() derives the hardware MAC (or ""
                # for server-synthesized IP-based ids) once the reserved IP is known.
                out.append({"kind": "reservation", "ip": _num(rv["ReservedIpAddress"]), "uid": raw.hex()})
            elif tag == 3:  # DhcpExcludedIpRanges
                r = u["ExcludeIpRange"]
                out.append({"kind": "exclude", "start": _num(r["StartAddress"]), "end": _num(r["EndAddress"])})
        except Exception:  # noqa: BLE001
            continue
    return out


# ---------------------------------------------------------------------------
# Corrected MS-DHCPM element structs (impacket 0.13.1 ships them broken).
# Built once, lazily, so the module imports without impacket (unit tests).
# ---------------------------------------------------------------------------
_ELEM: dict[str, Any] | None = None


def _element_types() -> dict[str, Any]:
    global _ELEM
    if _ELEM is not None:
        return _ELEM
    from impacket.dcerpc.v5.dtypes import BYTE, DWORD, LPDWORD, LPWSTR, NULL, ULONG
    from impacket.dcerpc.v5.enum import Enum
    from impacket.dcerpc.v5.ndr import (
        NDRCALL,
        NDRENUM,
        NDRPOINTER,
        NDRSTRUCT,
        NDRUNION,
        NDRUniConformantArray,
    )

    DHCP_IP_ADDRESS = DWORD
    DHCP_SRV_HANDLE = LPWSTR

    class DHCP_SUBNET_ELEMENT_TYPE(NDRENUM):
        class enumItems(Enum):
            DhcpIpRanges = 0
            DhcpSecondaryHosts = 1
            DhcpReservedIps = 2
            DhcpExcludedIpRanges = 3
            DhcpIpUsedClusters = 4
            DhcpIpRangesDhcpOnly = 5
            DhcpIpRangesDhcpBootp = 6
            DhcpIpRangesBootpOnly = 7

    class DHCP_HOST_INFO(NDRSTRUCT):
        structure = (('IpAddress', DHCP_IP_ADDRESS), ('NetBiosName', LPWSTR), ('HostName', LPWSTR))
    class LPDHCP_HOST_INFO(NDRPOINTER):
        referent = (('Data', DHCP_HOST_INFO),)

    class BYTE_ARRAY(NDRUniConformantArray):
        item = 'c'
    class PBYTE_ARRAY(NDRPOINTER):
        referent = (('Data', BYTE_ARRAY),)
    class DHCP_BINARY_DATA(NDRSTRUCT):  # DHCP_CLIENT_UID is a typedef of this
        structure = (('DataLength', DWORD), ('Data_', PBYTE_ARRAY))
    class LPDHCP_CLIENT_UID(NDRPOINTER):  # FIXED: ReservedForClient is a POINTER on the wire
        referent = (('Data', DHCP_BINARY_DATA),)

    class DHCP_BOOTP_IP_RANGE(NDRSTRUCT):  # FIXED: 4 fields, no duplicate
        structure = (('StartAddress', DHCP_IP_ADDRESS), ('EndAddress', DHCP_IP_ADDRESS),
                     ('BootpAllocated', ULONG), ('MaxBootpAllowed', ULONG))
    class LPDHCP_BOOTP_IP_RANGE(NDRPOINTER):
        referent = (('Data', DHCP_BOOTP_IP_RANGE),)

    class DHCP_IP_RANGE(NDRSTRUCT):
        structure = (('StartAddress', DHCP_IP_ADDRESS), ('EndAddress', DHCP_IP_ADDRESS))
    class LPDHCP_IP_RANGE(NDRPOINTER):
        referent = (('Data', DHCP_IP_RANGE),)

    class DHCP_IP_RESERVATION_V4(NDRSTRUCT):
        structure = (('ReservedIpAddress', DHCP_IP_ADDRESS), ('ReservedForClient', LPDHCP_CLIENT_UID),
                     ('bAllowedClientTypes', BYTE))
    class LPDHCP_IP_RESERVATION_V4(NDRPOINTER):
        referent = (('Data', DHCP_IP_RESERVATION_V4),)

    class DHCP_IP_CLUSTER(NDRSTRUCT):
        structure = (('ClusterAddress', DHCP_IP_ADDRESS), ('ClusterMask', DWORD))
    class LPDHCP_IP_CLUSTER(NDRPOINTER):
        referent = (('Data', DHCP_IP_CLUSTER),)

    class DHCP_SUBNET_ELEMENT_UNION_V5(NDRUNION):
        # FIXED: the discriminant is a 2-BYTE NDR enum, not a 4-byte ULONG. The old
        # ULONG tag happened to work for ranges ONLY because type 0 zeros both halves;
        # reservations (type 2) read 0x00020002 = "Unknown tag 131074". INT keys; arms
        # are POINTERs.
        commonHdr = (('tag', DHCP_SUBNET_ELEMENT_TYPE),)
        union = {
            0: ('IpRange', LPDHCP_BOOTP_IP_RANGE),
            5: ('IpRange', LPDHCP_BOOTP_IP_RANGE),
            6: ('IpRange', LPDHCP_BOOTP_IP_RANGE),
            7: ('IpRange', LPDHCP_BOOTP_IP_RANGE),
            1: ('SecondaryHost', LPDHCP_HOST_INFO),
            2: ('ReservedIp', LPDHCP_IP_RESERVATION_V4),
            3: ('ExcludeIpRange', LPDHCP_IP_RANGE),
            4: ('IpUsedCluster', LPDHCP_IP_CLUSTER),
        }

    class DHCP_SUBNET_ELEMENT_DATA_V5(NDRSTRUCT):
        # FIXED: ElementType is a separate 2-byte enum field that precedes the union
        # (which re-transmits its own 2-byte discriminant) — matches the wire layout.
        structure = (('ElementType', DHCP_SUBNET_ELEMENT_TYPE), ('Element', DHCP_SUBNET_ELEMENT_UNION_V5))
    class DHCP_SUBNET_ELEMENT_DATA_V5_ARRAY(NDRUniConformantArray):
        item = DHCP_SUBNET_ELEMENT_DATA_V5
    class PDHCP_SUBNET_ELEMENT_DATA_V5_ARRAY(NDRPOINTER):
        referent = (('Data', DHCP_SUBNET_ELEMENT_DATA_V5_ARRAY),)
    class DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5(NDRSTRUCT):
        structure = (('NumElements', DWORD), ('Elements', PDHCP_SUBNET_ELEMENT_DATA_V5_ARRAY))
    class LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5(NDRPOINTER):  # FIXED: trailing comma
        referent = (('Data', DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5),)

    class DhcpEnumSubnetElementsV5(NDRCALL):
        opnum = 38
        structure = (('ServerIpAddress', DHCP_SRV_HANDLE), ('SubnetAddress', DHCP_IP_ADDRESS),
                     ('EnumElementType', DHCP_SUBNET_ELEMENT_TYPE), ('ResumeHandle', LPDWORD),
                     ('PreferredMaximum', DWORD))
    class DhcpEnumSubnetElementsV5Response(NDRCALL):
        structure = (('ResumeHandle', DWORD), ('EnumElementInfo', LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5),
                     ('ElementsRead', DWORD), ('ElementsTotal', DWORD), ('ErrorCode', ULONG))

    _ELEM = {"Request": DhcpEnumSubnetElementsV5, "Response": DhcpEnumSubnetElementsV5Response, "NULL": NULL}
    return _ELEM


def _enum_elements(dce2: Any, sid: int, element_type: int) -> list[dict[str, Any]]:
    """Issue EnumSubnetElementsV5 (dhcpsrv2) with the corrected structs and return the
    decoded elements. Empty subnets (ERROR_NO_MORE_ITEMS) and any misparse -> []."""
    try:
        et = _element_types()
        req = et["Request"]()
        req["ServerIpAddress"] = et["NULL"]
        req["SubnetAddress"] = sid
        req["EnumElementType"] = element_type
        req["ResumeHandle"] = et["NULL"]
        req["PreferredMaximum"] = 0xFFFFFFFF
        dce2.call(req.opnum, req)
        resp = et["Response"](dce2.recv())
    except Exception:  # noqa: BLE001
        return []
    return _extract_elements(resp)


def _scope_range(dce2: Any, sid: int) -> tuple[str, str, int]:
    """(start_range, end_range, total_addresses) for a scope, from its IP ranges."""
    ranges = [e for e in _enum_elements(dce2, sid, 0) if e.get("kind") == "range"]
    if not ranges:
        return "", "", 0
    lo = min(r["start"] for r in ranges)
    hi = max(r["end"] for r in ranges)
    total = sum(max(0, r["end"] - r["start"] + 1) for r in ranges)
    return _ip(lo), _ip(hi), total


def _scope_clients(dce2: Any, dhcpm: Any, sid: int) -> tuple[int | None, dict[int, dict[str, Any]]]:
    """One EnumSubnetClientsV5 full-pull (dhcpsrv2) → (in_use_count, {ip_int: lease}).
    We ask for every client (PreferredMaximum=0xFFFFFFFF) and read ClientsTotal off
    the successful response — a zero-read request returns an INT_MAX sentinel, so the
    full pull is the only reliable count; its payload is small per K-12 scope. The
    same pull yields the per-lease records we join reservations against (name /
    holding-MAC / expiry). Empty subnet (ERROR_NO_MORE_ITEMS) -> (0, {}); any other
    failure -> (None, {})."""
    try:
        resp = dhcpm.hDhcpEnumSubnetClientsV5(dce2, sid, 0xFFFFFFFF)
    except Exception as exc:  # noqa: BLE001
        return (0 if "NO_MORE_ITEMS" in str(exc) else None), {}
    leases: dict[int, dict[str, Any]] = {}
    try:
        count = _num(resp["ClientsTotal"])
    except Exception:  # noqa: BLE001
        count = None
    try:
        ci = resp["ClientsInfo"]
        n = _num(ci["NumElements"]) if ci else 0
    except Exception:  # noqa: BLE001 — empty / null / misparse
        return count, leases
    # Per-RECORD guard (mirrors _extract_elements): one malformed client must not
    # discard every lease after it — the old single wrapping try/except dropped the
    # rest of the scope's leases on the first bad record.
    for i in range(n):
        try:
            d = ci["Clients"][i]["Data"]
            ip_int = _num(d["ClientIpAddress"])
            hw = d["ClientHardwareAddress"]
            nb = _num(hw["DataLength"])
            mac = b"".join(bytes(hw["Data_"][j]) for j in range(nb))
            dt = d["ClientLeaseExpires"]
            leases[ip_int] = {
                "mac": _hw_mac(mac, ip_int),
                "name": _wstr(d["ClientName"]),
                "expiry": _filetime_iso(_num(dt["dwLowDateTime"]), _num(dt["dwHighDateTime"])),
            }
        except Exception:  # noqa: BLE001
            continue
    return count, leases


def _scope_reservations(dce2: Any, sid: int, leases: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Reservations for a scope (ElementsV5 type=2, dhcpsrv2), each enriched by joining
    the reserved IP against the scope's live leases: `active` = a lease exists for the
    reserved IP; `client_mac` = who currently holds it (a real MAC ≠ the reserved MAC ⇒
    conflict); `name`/`lease_expiry` from that lease; `bad_address` = the server flagged
    the address as in-use by an unknown host. The dashboard turns these into health
    states (active / never-used / conflict / bad) and cross-refs the MAC against passive
    sightings for "last actually seen"."""
    out: list[dict[str, Any]] = []
    for e in _enum_elements(dce2, sid, 2):
        if e.get("kind") != "reservation":
            continue
        ip_int = e["ip"]
        lease = leases.get(ip_int)
        out.append({
            "ip": _ip(ip_int),
            "mac": _hw_mac(bytes.fromhex(e["uid"]), ip_int),
            "name": lease["name"] if lease else "",
            "active": lease is not None,
            "client_mac": lease["mac"] if lease else "",
            "lease_expiry": lease["expiry"] if lease else None,
            "bad_address": bool(lease and lease["name"] == "BAD_ADDRESS"),
        })
    return out


def _one_scope(dce1: Any, dce2: Any, dhcpm: Any, sid: int) -> dict[str, Any] | None:
    try:
        info = dhcpm.hDhcpGetSubnetInfo(dce1, sid)["SubnetInfo"]
    except Exception:  # noqa: BLE001
        return None
    options: list[dict[str, Any]] = []
    try:
        options = _options_from_enum(
            dhcpm.hDhcpEnumOptionValues(dce1, dhcpm.DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions, options=sid)
        )
    except Exception:  # noqa: BLE001
        pass

    in_use: int | None = None
    start_range = end_range = ""
    total = 0
    reservations: list[dict[str, Any]] = []
    if dce2 is not None:
        in_use, leases = _scope_clients(dce2, dhcpm, sid)
        start_range, end_range, total = _scope_range(dce2, sid)
        reservations = _scope_reservations(dce2, sid, leases)

    # Match the WinRM/PowerShell path's domain: the server computes these within the
    # scope range, so free is never negative and pct never exceeds 100. A scope with
    # more leases than its (shrunk) range simply reads as full (free 0, 100%).
    free = max(0, total - in_use) if (in_use is not None and total) else None
    pct = round(min(100.0, (in_use / total) * 100), 2) if (in_use is not None and total) else None
    return {
        "scope_id": _ip(sid),
        "name": _wstr(info["SubnetName"]),
        "state": _SUBNET_STATE.get(_num(info["SubnetState"]), "Unknown"),
        "start_range": start_range,
        "end_range": end_range,
        "subnet_mask": _ip(info["SubnetMask"]),
        "lease_duration_sec": None,  # not on DHCP_SUBNET_INFO; option 51 is a v-next detail
        "description": _wstr(info["SubnetComment"]),
        "addresses_in_use": in_use,
        "addresses_free": free,
        "percentage_in_use": pct,
        "reserved": len(reservations) if dce2 is not None else None,
        "reservations": reservations,
        "options": options,
    }


def collect(
    fqdn: str,
    user: str,
    password: str,
    *,
    kdc: str | None = None,
    use_kerberos: bool = True,
    timeout: int = 30,
) -> dict[str, Any]:
    """Query one Windows DHCP server over MS-DHCPM RPC and return the parsed shape
    (hostname / server_stats / server_options / failover / scopes[...]). Raises on a
    connection/auth/bind error — the caller turns that into a clean status dict."""
    from impacket.dcerpc.v5 import dhcpm, epm, transport
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    domain, username = "", user
    if "@" in user:
        username, domain = user.split("@", 1)
    elif "\\" in user:
        domain, username = user.split("\\", 1)

    def _hept_map(uuid: Any) -> Any:
        """Resolve the interface's dynamic port via the endpoint mapper (tcp/135).

        hept_map opens its OWN connection and exposes NO timeout knob (set_connect_timeout
        below only bounds the RESOLVED port's binding), so a firewalled/dead server blocks
        here for the OS connect timeout — ~1-2 min PER bind, which alone blows the pass's
        wall-clock budget. The process-wide default is the only lever impacket leaves us;
        it's set for this call only and restored either way."""
        prev = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return epm.hept_map(fqdn, uuid, protocol="ncacn_ip_tcp")
        finally:
            socket.setdefaulttimeout(prev)

    def _bind(uuid: Any) -> Any:
        string_binding = _hept_map(uuid)
        rpc = transport.DCERPCTransportFactory(string_binding)
        if hasattr(rpc, "set_connect_timeout"):
            rpc.set_connect_timeout(timeout)
        rpc.set_credentials(username, password, domain, "", "", "")
        if use_kerberos:
            rpc.set_kerberos(True, kdcHost=kdc)
        dce = rpc.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        try:
            dce.bind(uuid)
        except Exception:  # noqa: BLE001 — never leak the CONNECTED transport
            # bind() raising left the socket open and unreachable (we neither return
            # nor disconnect it) — one leaked socket per poll on a bind-failing
            # server, e.g. the dhcpsrv2 interface the caller tolerates below.
            try:
                dce.disconnect()
            except Exception:  # noqa: BLE001
                pass
            raise
        return dce

    # dhcpsrv = scopes + options; dhcpsrv2 = leases/ranges (utilization). If the
    # second interface can't bind, still return scopes + options (no utilization).
    dce1 = _bind(dhcpm.MSRPC_UUID_DHCPSRV)
    dce2: Any = None
    try:
        dce2 = _bind(dhcpm.MSRPC_UUID_DHCPSRV2)
    except Exception:  # noqa: BLE001
        dce2 = None
    try:
        return _collect_over_dce(dce1, dce2, dhcpm, fqdn)
    finally:
        for d in (dce1, dce2):
            if d is not None:
                try:
                    d.disconnect()
                except Exception:  # noqa: BLE001
                    pass


def _server_options(dce1: Any, dhcpm: Any) -> list[dict[str, Any]]:
    """Server-level (global) option values — the inherited baseline the dashboard tags
    scope options against (matches the WinRM path's server-level
    Get-DhcpServerv4OptionValue). These are DhcpGlobalOptions (scope type 1), but
    impacket's hDhcpEnumOptionValues helper is BROKEN for it: it sets the struct
    ScopeType to 1 yet skips the union discriminant (leaving tag 0), so the server
    rejects the ScopeType/tag mismatch as rpc_x_bad_stub_data. We instead build a valid
    DhcpDefaultOptions request (which the helper marshals correctly) and byte-patch the
    ScopeType + union tag 0 -> 1 to make it a well-formed Global request. Needs the
    account to have option-read access (DHCP Administrators on hardened servers, where
    plain DHCP Users is access-denied for option enums); returns [] otherwise."""
    try:
        base = dhcpm.DhcpEnumOptionValues()
        base["ServerIpAddress"] = dhcpm.NULL
        base["ScopeInfo"]["ScopeType"] = 0  # Default: the one scope type the helper marshals correctly
        base["ResumeHandle"] = dhcpm.NULL
        base["PreferredMaximum"] = 0xFFFFFFFF
        raw = bytearray(base.getData())
        # wire layout: [ServerIp ptr:4][ScopeType:2][union tag:2][ResumeHandle:4][max:4].
        # Bail rather than send a malformed request if the marshaling isn't what we expect.
        if len(raw) < 8 or raw[4:8] != b"\x00\x00\x00\x00":
            return []
        raw[4] = 1  # ScopeType: DhcpDefaultOptions(0) -> DhcpGlobalOptions(1)
        raw[6] = 1  # union discriminant: match ScopeType (the helper's bug is leaving this 0)
        patched = bytes(raw)

        class _RawGlobalReq(dhcpm.DhcpEnumOptionValues):
            def getData(self, soFar: int = 0) -> bytes:  # noqa: ARG002
                return patched

        dce1.call(base.opnum, _RawGlobalReq())
        return _options_from_enum(dhcpm.DhcpEnumOptionValuesResponse(dce1.recv()))
    except Exception:  # noqa: BLE001
        return []


def _hostname(fqdn: str) -> str | None:
    """Short hostname from the target the caller dialed, or None when it can't be
    derived. The RPC path is dialed BY IP (dhcp_server._collect_via_rpc passes the
    target's ip), and splitting an IP on "." yields a bogus hostname of "10"/"192" —
    so an IP literal reports NO hostname rather than a fabricated one. The dashboard
    falls back to the server_ip / label for the display name."""
    value = (fqdn or "").strip()
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value.split(".", 1)[0].upper()
    return None  # an IP literal carries no hostname


def _collect_over_dce(dce1: Any, dce2: Any, dhcpm: Any, fqdn: str) -> dict[str, Any]:
    server_options = _server_options(dce1, dhcpm)

    subnet_ints: list[int] = []
    try:
        for e in dhcpm.hDhcpEnumSubnets(dce1)["EnumInfo"]["Elements"] or []:
            subnet_ints.append(_num(e))
    except Exception as exc:  # noqa: BLE001
        # A genuinely EMPTY server answers ERROR_NO_MORE_ITEMS — an ok, zero-scope
        # result (the same convention _scope_clients uses). Any OTHER failure
        # (access denied, a broken/hardened service) is REAL and must not be
        # swallowed into an "ok" with total_scopes: 0 that reads identically to an
        # empty server while hiding the actual reason. Raise: collect()'s contract
        # is that the caller (dhcp_server._collect_via_rpc) renders status="error".
        if "NO_MORE_ITEMS" not in str(exc):
            raise
        subnet_ints = []

    scopes: list[dict[str, Any]] = []
    total_addr = 0
    total_in_use = 0
    have_util = False
    for sid in subnet_ints:
        sc = _one_scope(dce1, dce2, dhcpm, sid)
        if sc is None:
            continue
        scopes.append(sc)
        if sc.get("addresses_in_use") is not None and sc.get("addresses_free") is not None:
            have_util = True
            total_in_use += sc["addresses_in_use"]
            total_addr += sc["addresses_in_use"] + sc["addresses_free"]

    pct = round((total_in_use / total_addr) * 100, 2) if total_addr else None
    return {
        "hostname": _hostname(fqdn),
        "is_authorized": None,   # not exposed over the MS-DHCPM enum surface
        "is_domain_joined": None,
        "server_stats": {
            "total_scopes": len(scopes),
            "total_addresses": float(total_addr) if have_util else None,
            "addresses_in_use": float(total_in_use) if have_util else None,
            "addresses_available": float(total_addr - total_in_use) if have_util else None,
            "percentage_in_use": pct,
        },
        "failover": [],          # MS-DHCPM failover enum deferred
        "server_options": server_options,
        "scopes": scopes,
        "transport_detail": "rpc",
    }
