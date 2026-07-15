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
  * impacket 0.13.1 ships the ``EnumSubnetElementsV5`` structs BROKEN (referent
    comma, a duplicated BOOTP-range field, union arms must be pointers, union keys
    must be plain ints, ``Elements`` must be a pointer). Corrected classes are
    rebuilt here in ``_element_types`` and used explicitly (never ``dce.request``,
    which would resolve impacket's buggy response class).
  * Reservations decode via the same corrected structs (element type 2) but are
    deferred (``reserved=None``) until the reservation UI feature lands.

Auth reuses the Kerberos ccache ``dhcp_server._kinit`` writes (impacket reads
``KRB5CCNAME`` when ``set_kerberos(True)`` is used). NTLM only when the caller
passes ``use_kerberos=False``. impacket is imported lazily so the module (and its
unit tests) import cleanly on a box without it.
"""
from __future__ import annotations

import socket
import struct
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
                mac = b"".join(bytes(uid["Data_"][j]) for j in range(nb))
                out.append({"kind": "reservation", "ip": _num(rv["ReservedIpAddress"]), "mac": mac.hex()})
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
    class DHCP_BINARY_DATA(NDRSTRUCT):
        structure = (('DataLength', DWORD), ('Data_', PBYTE_ARRAY))
    DHCP_CLIENT_UID = DHCP_BINARY_DATA

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
        structure = (('ReservedIpAddress', DHCP_IP_ADDRESS), ('ReservedForClient', DHCP_CLIENT_UID),
                     ('bAllowedClientTypes', BYTE))
    class LPDHCP_IP_RESERVATION_V4(NDRPOINTER):
        referent = (('Data', DHCP_IP_RESERVATION_V4),)

    class DHCP_IP_CLUSTER(NDRSTRUCT):
        structure = (('ClusterAddress', DHCP_IP_ADDRESS), ('ClusterMask', DWORD))
    class LPDHCP_IP_CLUSTER(NDRPOINTER):
        referent = (('Data', DHCP_IP_CLUSTER),)

    class DHCP_SUBNET_ELEMENT_UNION_V5(NDRUNION):  # 4-byte tag == element type; INT keys; POINTER arms
        commonHdr = (('tag', ULONG),)
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
        structure = (('Element', DHCP_SUBNET_ELEMENT_UNION_V5),)
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


def _scope_inuse(dce2: Any, dhcpm: Any, sid: int) -> int | None:
    """Leases in use for a scope, from EnumSubnetClientsV5 (dhcpsrv2). We ask for
    every client (PreferredMaximum=0xFFFFFFFF) and read ClientsTotal off the
    successful response — a zero-read request instead returns an INT_MAX sentinel
    for ClientsTotal, so the full pull is the only reliable count. The lease
    payload is small in practice (a handful of leases per K-12 scope). An empty
    subnet raises ERROR_NO_MORE_ITEMS -> 0; any other failure -> None."""
    try:
        return _num(dhcpm.hDhcpEnumSubnetClientsV5(dce2, sid, 0xFFFFFFFF)["ClientsTotal"])
    except Exception as exc:  # noqa: BLE001
        return 0 if "NO_MORE_ITEMS" in str(exc) else None


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
    if dce2 is not None:
        in_use = _scope_inuse(dce2, dhcpm, sid)
        start_range, end_range, total = _scope_range(dce2, sid)

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
        "reserved": None,  # reservation list deferred to the reservation UI feature
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

    def _bind(uuid: Any) -> Any:
        string_binding = epm.hept_map(fqdn, uuid, protocol="ncacn_ip_tcp")
        rpc = transport.DCERPCTransportFactory(string_binding)
        if hasattr(rpc, "set_connect_timeout"):
            rpc.set_connect_timeout(timeout)
        rpc.set_credentials(username, password, domain, "", "", "")
        if use_kerberos:
            rpc.set_kerberos(True, kdcHost=kdc)
        dce = rpc.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(uuid)
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


def _collect_over_dce(dce1: Any, dce2: Any, dhcpm: Any, fqdn: str) -> dict[str, Any]:
    server_options: list[dict[str, Any]] = []
    try:
        server_options = _options_from_enum(
            dhcpm.hDhcpEnumOptionValues(dce1, dhcpm.DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions)
        )
    except Exception:  # noqa: BLE001
        pass

    subnet_ints: list[int] = []
    try:
        for e in dhcpm.hDhcpEnumSubnets(dce1)["EnumInfo"]["Elements"] or []:
            subnet_ints.append(_num(e))
    except Exception:  # noqa: BLE001
        pass

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
        "hostname": fqdn.split(".", 1)[0].upper(),
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
