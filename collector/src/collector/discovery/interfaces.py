from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import structlog

from ..models import InterfaceState

log = structlog.get_logger(__name__)

# The kernel's 802.1Q table: one "<name> | <vid> | <parent>" row per VLAN device.
# /proc/net is per network namespace; the collector runs with host networking, so
# this is the host's table.
PROC_VLAN_CONFIG = Path("/proc/net/vlan/config")

_DOTTED_VLAN_RE = re.compile(r"^(.+)\.(\d{1,4})$")


def vlan_of(interface: str) -> tuple[int | None, str | None]:
    """(vlan_id, parent) of a VLAN sub-interface, else (None, None).

    The kernel's own table first, so a sub-interface named independently of its
    parent (lib/trunk.sh names it vlan<id> when <parent>.<id> would pass the
    15-byte limit) is still attributed to its VLAN and full parent. Falls back to
    the historical <parent>.<vid> name ('eth0.10' -> (10, 'eth0')) when the table
    is unreadable or does not list the interface.
    """
    try:
        for line in PROC_VLAN_CONFIG.read_text().splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) == 3 and parts[0] == interface and parts[1].isdigit():
                vid = int(parts[1])
                if 1 <= vid <= 4094 and parts[2]:
                    return vid, parts[2]
    except OSError:
        pass
    m = _DOTTED_VLAN_RE.match(interface)
    if not m:
        return None, None
    vid = int(m.group(2))
    return (vid, m.group(1)) if 1 <= vid <= 4094 else (None, None)


def snapshot(*, exclude_prefixes: tuple[str, ...] = ()) -> list[InterfaceState]:
    """Return the current state of every interesting interface."""
    raw = _run_ip_json(["ip", "-j", "addr", "show"])
    states: list[InterfaceState] = []
    for iface in raw or []:
        name = iface.get("ifname")
        if not name:
            continue
        if any(name == p or name.startswith(p) for p in exclude_prefixes):
            continue
        flags = iface.get("flags", []) or []
        is_up = "UP" in flags
        operstate = (iface.get("operstate") or "").lower()
        has_carrier = operstate in {"up", "unknown"}  # unknown is common on tunnels w/ carrier
        mac = iface.get("address")
        v4 = [
            f"{a['local']}/{a['prefixlen']}"
            for a in iface.get("addr_info", [])
            if a.get("family") == "inet" and a.get("scope") == "global"
        ]
        st = InterfaceState(
            name=name,
            is_up=is_up,
            has_carrier=has_carrier,
            mac=mac,
            ipv4_addrs=v4,
        )
        if st.has_usable_ip:
            gw, gw_mac = _default_route_via(name)
            st.gateway_ip = gw
            st.gateway_mac = gw_mac
        states.append(st)
    return states


def get_one(name: str) -> InterfaceState | None:
    for st in snapshot():
        if st.name == name:
            return st
    return None


def primary_interface() -> str | None:
    """Return the name of the interface that owns the default route.

    This is the box's primary uplink — how it reaches the dashboard and the
    internet. Auto-detected (not configured) so it survives NIC renaming
    across different hardware. Returns None if there's no default route yet.
    """
    routes = _run_ip_json(["ip", "-j", "route", "show", "default"]) or []
    for r in routes:
        if r.get("dev") and r.get("gateway"):
            return r["dev"]
    return None


def _default_route_via(iface: str) -> tuple[str | None, str | None]:
    """Find the default gateway IP and MAC for traffic leaving `iface`."""
    routes = _run_ip_json(["ip", "-j", "route", "show", "default"]) or []
    gw_ip: str | None = None
    for r in routes:
        if r.get("dev") == iface and r.get("gateway"):
            gw_ip = r["gateway"]
            break
    if not gw_ip:
        return None, None
    gw_mac = _arp_lookup(gw_ip, iface)
    return gw_ip, gw_mac


def _arp_lookup(ip: str, iface: str) -> str | None:
    """Resolve `ip` to a MAC via the kernel neighbor table; ping once to populate."""
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", "-I", iface, ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
        )
    except Exception:
        pass
    neighs = _run_ip_json(["ip", "-j", "neigh", "show", "to", ip]) or []
    for n in neighs:
        mac = n.get("lladdr")
        state = n.get("state", [])
        if mac and "FAILED" not in state:
            return mac
    return None


def _run_ip_json(cmd: list[str]) -> list[dict] | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except FileNotFoundError:
        log.warning("ip command not available")
        return None
    if out.returncode != 0:
        log.warning("ip command failed", cmd=cmd, stderr=out.stderr.strip())
        return None
    try:
        return json.loads(out.stdout) if out.stdout.strip() else []
    except json.JSONDecodeError as exc:
        log.warning("ip JSON parse failed", error=str(exc))
        return None


def read_counters(name: str) -> dict[str, int]:
    """Read available /sys/class/net/<name>/statistics counters as a dict.

    Missing or unreadable counters are omitted so callers do not mistake an I/O
    failure for a real zero and calculate a negative traffic delta.
    """
    base = Path(f"/sys/class/net/{name}/statistics")
    if not base.is_dir():
        return {}
    keys = [
        "rx_packets", "rx_bytes", "rx_errors", "rx_dropped",
        "tx_packets", "tx_bytes", "tx_errors", "tx_dropped",
        "multicast",
    ]
    out: dict[str, int] = {}
    for k in keys:
        p = base / k
        try:
            out[k] = int(p.read_text().strip())
        except (FileNotFoundError, ValueError, PermissionError):
            continue
    return out
