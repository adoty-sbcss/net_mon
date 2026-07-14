"""Authoritative DHCP server intel over MS-DHCPM RPC — the WinRM/WMI fallback (DHCP-9).

The primary DHCP-intel path drives the Windows **DhcpServer** PowerShell module
over WinRM (see ``dhcp_server.py``). That path crosses four independently-ACL'd
gates — Kerberos, the WinRM RootSDDL, the local "DHCP Users" group, and
WMI/DCOM — and hardened servers close the WMI/DCOM gate to non-admins, which
forces a local-admin grant. This module is the escape hatch: it talks straight
to the DHCP service's own RPC interface (**MS-DHCPM**) via impacket, which
authorizes on the **"DHCP Users"** group ALONE — no WinRM, no WMI, no admin.

It returns the SAME parsed shape the PowerShell probe produces (hostname /
server_stats / server_options / failover / scopes[...]), so
``dhcp_server._collect_one`` merges it identically and nothing downstream
(bundle, dashboard) changes.

Validated live against a hardened Server Core 2022 DHCP server (485 scopes) with
DHCP-Users-only rights. Notes from that validation, baked into the calls below:
  * impacket struct members auto-unwrap to int/str, but bare NDR *array* elements
    (subnet list) need ``['Data']`` — see ``_num``.
  * ``EnumOptionValues`` (opnum 14) is used for options; ``GetAllOptionValues``
    (opnum 30), ``EnumSubnetElementsV5``, and ``EnumSubnetClientsV5`` are rejected
    as bad stubs by the hardened server, so per-scope **utilization is deferred to
    v2** (the WinRM path still carries it). Scopes + options + names come through.

Auth: reuses the Kerberos ccache ``dhcp_server._kinit`` writes (impacket reads
``KRB5CCNAME`` when ``set_kerberos(True)`` is used). NTLM only when the caller
passes ``use_kerberos=False``. impacket is imported lazily.
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
    """Flatten a DhcpEnumOptionValuesResponse -> [{id, name, value:[...]}].
    resp['OptionValues'] -> DHCP_OPTION_VALUE_ARRAY {Values: [DHCP_OPTION_VALUE
    {OptionID, Value}]}."""
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


def _one_scope(dce: Any, dhcpm: Any, sid: int) -> dict[str, Any] | None:
    try:
        info = dhcpm.hDhcpGetSubnetInfo(dce, sid)["SubnetInfo"]
    except Exception:  # noqa: BLE001
        return None
    options: list[dict[str, Any]] = []
    try:
        options = _options_from_enum(
            dhcpm.hDhcpEnumOptionValues(
                dce, dhcpm.DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions, options=sid
            )
        )
    except Exception:  # noqa: BLE001
        pass
    return {
        "scope_id": _ip(sid),
        "name": _wstr(info["SubnetName"]),
        "state": _SUBNET_STATE.get(_num(info["SubnetState"]), "Unknown"),
        "start_range": "",
        "end_range": "",
        "subnet_mask": _ip(info["SubnetMask"]),
        "lease_duration_sec": None,
        "description": _wstr(info["SubnetComment"]),
        # Per-scope utilization needs the client/element enums the hardened RPC
        # surface rejects (bad stub) — deferred to v2; the WinRM path carries it.
        "addresses_in_use": None,
        "addresses_free": None,
        "percentage_in_use": None,
        "reserved": None,
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
    (hostname / server_stats / server_options / failover / scopes[...]). Raises on
    any connection/auth error — the caller turns that into a clean status dict.
    When ``use_kerberos`` is True the ambient ccache (KRB5CCNAME) set up by the
    caller's kinit is used."""
    from impacket.dcerpc.v5 import dhcpm, epm, transport
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    # Split DOMAIN\user or user@REALM into (domain, username) for impacket.
    domain, username = "", user
    if "@" in user:
        username, domain = user.split("@", 1)
    elif "\\" in user:
        domain, username = user.split("\\", 1)

    # Endpoint-map the DHCP RPC interface to its dynamic ncacn_ip_tcp port (via 135).
    string_binding = epm.hept_map(fqdn, dhcpm.MSRPC_UUID_DHCPSRV, protocol="ncacn_ip_tcp")
    rpc = transport.DCERPCTransportFactory(string_binding)
    if hasattr(rpc, "set_connect_timeout"):
        rpc.set_connect_timeout(timeout)
    rpc.set_credentials(username, password, domain, "", "", "")
    if use_kerberos:
        rpc.set_kerberos(True, kdcHost=kdc)

    dce = rpc.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(dhcpm.MSRPC_UUID_DHCPSRV)
    try:
        return _collect_over_dce(dce, dhcpm, fqdn)
    finally:
        try:
            dce.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _collect_over_dce(dce: Any, dhcpm: Any, fqdn: str) -> dict[str, Any]:
    # Server-level (default) options.
    server_options: list[dict[str, Any]] = []
    try:
        server_options = _options_from_enum(
            dhcpm.hDhcpEnumOptionValues(dce, dhcpm.DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions)
        )
    except Exception:  # noqa: BLE001
        pass

    # Enumerate scopes, then detail each.
    subnet_ints: list[int] = []
    try:
        for e in dhcpm.hDhcpEnumSubnets(dce)["EnumInfo"]["Elements"] or []:
            subnet_ints.append(_num(e))
    except Exception:  # noqa: BLE001
        pass

    scopes = [sc for sid in subnet_ints if (sc := _one_scope(dce, dhcpm, sid)) is not None]

    return {
        "hostname": fqdn.split(".", 1)[0].upper(),
        "is_authorized": None,   # not exposed over the MS-DHCPM enum surface (v1)
        "is_domain_joined": None,
        "server_stats": {
            "total_scopes": len(scopes),
            "total_addresses": None,   # utilization deferred to v2 (see module doc)
            "addresses_in_use": None,
            "addresses_available": None,
            "percentage_in_use": None,
        },
        "failover": [],          # MS-DHCPM failover enum deferred to v2
        "server_options": server_options,
        "scopes": scopes,
        "transport_detail": "rpc",
    }
