from __future__ import annotations

import json
import subprocess
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def fetch_neighbors() -> list[dict[str, Any]]:
    """Query lldpd's lldpcli for current neighbor state."""
    cmd = ["lldpcli", "-f", "json", "show", "neighbors"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except FileNotFoundError:
        log.warning("lldpcli not found")
        return []
    if out.returncode != 0:
        log.warning("lldpcli failed", stderr=out.stderr.strip())
        return []
    try:
        data = json.loads(out.stdout) if out.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        log.warning("lldpcli JSON parse failed", error=str(exc))
        return []
    return _flatten(data)


def _flatten(data: dict[str, Any]) -> list[dict[str, Any]]:
    """lldpcli JSON is awkwardly nested; flatten to per-neighbor records."""
    results: list[dict[str, Any]] = []
    lldp = data.get("lldp", {}) if isinstance(data, dict) else {}
    interfaces = lldp.get("interface")
    if interfaces is None:
        return results
    # lldpcli sometimes wraps single items as objects keyed by name, sometimes as lists.
    if isinstance(interfaces, dict):
        iface_items = list(interfaces.items())
    elif isinstance(interfaces, list):
        iface_items = []
        for entry in interfaces:
            if not isinstance(entry, dict):
                continue
            for name, payload in entry.items():
                iface_items.append((name, payload))
    else:
        return results

    for local_port, payload in iface_items:
        if not isinstance(payload, dict):
            continue
        protocol = (payload.get("via") or "").lower() or "lldp"

        chassis = payload.get("chassis", {})
        if isinstance(chassis, dict) and len(chassis) == 1 and isinstance(next(iter(chassis.values())), dict):
            system_name = next(iter(chassis.keys()))
            chassis_body = next(iter(chassis.values()))
        else:
            system_name = _first_str(chassis.get("name") if isinstance(chassis, dict) else None)
            chassis_body = chassis if isinstance(chassis, dict) else {}

        chassis_id = _first_str(chassis_body.get("id"))
        sys_desc = _first_str(chassis_body.get("descr"))
        mgmt_ip = _first_str(chassis_body.get("mgmt-ip"))
        caps_raw = chassis_body.get("capability") or []
        if isinstance(caps_raw, dict):
            caps_raw = [caps_raw]
        capabilities = [
            c.get("type") for c in caps_raw
            if isinstance(c, dict) and c.get("enabled") in (True, "on", "yes")
        ]

        port = payload.get("port") or {}
        port_id = _first_str(port.get("id"))
        port_desc = _first_str(port.get("descr"))

        vlan = payload.get("vlan") or {}
        vlan_id = None
        if isinstance(vlan, dict):
            vid = vlan.get("vlan-id") or vlan.get("vid")
            try:
                vlan_id = int(vid) if vid is not None else None
            except (TypeError, ValueError):
                vlan_id = None

        results.append({
            "local_port": local_port,
            "protocol": protocol,
            "chassis_id": chassis_id,
            "port_id": port_id,
            "system_name": system_name,
            "system_description": sys_desc,
            "port_description": port_desc,
            "vlan_id": vlan_id,
            "mgmt_ip": mgmt_ip,
            "capabilities": [c for c in capabilities if c],
        })
    return results


def _first_str(v: Any) -> str | None:
    """lldpcli often nests scalar values as {'value': '...'}."""
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and "value" in v:
        return _first_str(v["value"])
    if isinstance(v, list) and v:
        return _first_str(v[0])
    return str(v)
