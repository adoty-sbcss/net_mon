from __future__ import annotations

import csv
import io
import json
import socket
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from .config import get_settings
from .db import fetch_scan, fetch_table_for_scan
from .prompts import get_bundle_readme

log = structlog.get_logger(__name__)


def build_bundle(scan_id: int, output_path: str | None = None) -> Path:
    """Build an evidence bundle ZIP for the given scan id. Returns its path."""
    settings = get_settings()
    scan = fetch_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan id {scan_id} not found")

    devices = fetch_table_for_scan("devices", scan_id)
    neighbors = fetch_table_for_scan("neighbors", scan_id)
    arp = fetch_table_for_scan("arp_entries", scan_id)
    dhcp = fetch_table_for_scan("dhcp_observations", scan_id)
    stp = fetch_table_for_scan("stp_events", scan_id)
    traffic = fetch_table_for_scan("traffic_stats", scan_id)
    snmp = fetch_table_for_scan("snmp_polls", scan_id)
    findings = fetch_table_for_scan("findings", scan_id)

    if output_path is None:
        settings.bundle_dir.mkdir(parents=True, exist_ok=True)
        ts = _stamp(scan.get("started_at"))
        host = socket.gethostname()
        output_path = settings.bundle_dir / f"network-scan-{host}-{ts}.zip"
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    summary_md = _build_summary_md(scan, devices, neighbors, arp, dhcp, stp, traffic, snmp, findings)
    topology = _build_topology(scan, devices, neighbors, arp)
    metrics = _build_metrics(traffic, dhcp, stp)
    timeline = _build_timeline(dhcp, stp)

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.md", get_bundle_readme())
        z.writestr("summary.md", summary_md)
        z.writestr("findings.json", _jsonify(findings))
        z.writestr("topology.json", json.dumps(topology, indent=2, default=_default))
        z.writestr("devices.csv", _devices_csv(devices))
        z.writestr("metrics.json", json.dumps(metrics, indent=2, default=_default))
        z.writestr("timeline.json", json.dumps(timeline, indent=2, default=_default))
        z.writestr("raw/scan.json", _jsonify(scan))
        z.writestr("raw/lldp-neighbors.json", _jsonify(neighbors))
        z.writestr("raw/arp-table.json", _jsonify(arp))
        z.writestr("raw/dhcp-observed.json", _jsonify(dhcp))
        z.writestr("raw/stp-events.json", _jsonify(stp))
        z.writestr("raw/snmp-polls.json", _jsonify(snmp))
        z.writestr("raw/traffic-stats.json", _jsonify(traffic))

    log.info("bundle written", path=str(out), size_bytes=out.stat().st_size)
    return out


def _build_summary_md(
    scan: dict[str, Any],
    devices: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    arp: list[dict[str, Any]],
    dhcp: list[dict[str, Any]],
    stp: list[dict[str, Any]],
    traffic: list[dict[str, Any]],
    snmp: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> str:
    lines = []
    lines.append(f"# App_Mon scan #{scan['id']}")
    lines.append("")
    lines.append(f"- **Started:** {scan.get('started_at')}")
    lines.append(f"- **Completed:** {scan.get('completed_at')}")
    lines.append(f"- **Duration:** {scan.get('duration_sec')} seconds")
    lines.append(f"- **Trigger:** {scan.get('trigger_reason')}")
    lines.append(f"- **Mode:** {scan.get('mode')}")
    lines.append(f"- **Interface:** {scan.get('interface')}")
    lines.append(f"- **Subnet (CIDR):** {scan.get('interface_cidr')}")
    lines.append(f"- **Gateway IP:** {scan.get('gateway_ip')}")
    lines.append(f"- **Gateway MAC:** {scan.get('gateway_mac')}")
    if scan.get("error"):
        lines.append(f"- **Error:** {scan['error']}")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    lines.append(f"- Devices discovered: **{len(devices)}**")
    lines.append(f"- LLDP/CDP neighbors: **{len(neighbors)}**")
    lines.append(f"- ARP entries: **{len(arp)}**")
    lines.append(f"- DHCP messages observed: **{len(dhcp)}**")
    lines.append(f"- STP events: **{len(stp)}**")
    lines.append(f"- SNMP rows: **{len(snmp)}**")
    lines.append(f"- Pre-built findings: **{len(findings)}**")
    lines.append("")

    if neighbors:
        lines.append("## Upstream switch / port (LLDP/CDP)")
        lines.append("")
        for n in neighbors:
            lines.append(
                f"- `{n.get('local_port')}` ← **{n.get('system_name') or n.get('chassis_id')}** "
                f"port `{n.get('port_id')}` "
                f"({n.get('protocol')}, vlan={n.get('vlan_id')}, mgmt={n.get('mgmt_ip')})"
            )
        lines.append("")

    if traffic:
        t = traffic[0]
        rxp = t.get("rx_packets") or 0
        bp = t.get("broadcast_packets") or 0
        mp = t.get("multicast_packets") or 0
        bp_pct = (100 * bp / rxp) if rxp else 0.0
        mp_pct = (100 * mp / rxp) if rxp else 0.0
        lines.append("## Traffic during capture")
        lines.append("")
        lines.append(f"- RX packets: {rxp:,} ({t.get('rx_bytes', 0):,} bytes)")
        lines.append(f"- Broadcast: {bp:,} ({bp_pct:.2f}%)")
        lines.append(f"- Multicast: {mp:,} ({mp_pct:.2f}%)")
        lines.append(f"- RX errors: {t.get('rx_errors', 0):,}  /  RX dropped: {t.get('rx_dropped', 0):,}")
        lines.append("")

    if dhcp:
        servers = {}
        for d in dhcp:
            if d.get("server_ip"):
                servers.setdefault((d["server_ip"], d.get("server_mac")), 0)
                servers[(d["server_ip"], d.get("server_mac"))] += 1
        if servers:
            lines.append("## DHCP servers seen")
            lines.append("")
            for (ip, mac), count in servers.items():
                lines.append(f"- {ip} (mac {mac}) — {count} message(s)")
            lines.append("")

    if findings:
        lines.append("## Findings (pre-built)")
        lines.append("")
        for f in findings:
            lines.append(f"- **[{f.get('severity')}] {f.get('title')}** — {f.get('detail')}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Open `README.md` in this bundle for the Claude prompt to use.")
    lines.append("")
    return "\n".join(lines)


def _build_topology(
    scan: dict[str, Any],
    devices: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    arp: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def node_id(prefix: str, key: str) -> str:
        return f"{prefix}:{key}"

    self_id = node_id("self", scan.get("interface") or "scanner")
    nodes[self_id] = {
        "id": self_id,
        "type": "scanner",
        "label": f"App_Mon ({scan.get('interface')})",
        "ip": str(scan.get("interface_cidr") or ""),
    }

    if scan.get("gateway_ip"):
        gw_id = node_id("gw", str(scan["gateway_ip"]))
        nodes[gw_id] = {
            "id": gw_id, "type": "gateway",
            "label": f"gateway {scan['gateway_ip']}",
            "ip": str(scan["gateway_ip"]),
            "mac": str(scan.get("gateway_mac") or ""),
        }
        edges.append({"source": self_id, "target": gw_id, "kind": "default_route"})

    for n in neighbors:
        nid = node_id("switch", n.get("chassis_id") or n.get("system_name") or f"port-{n.get('local_port')}")
        nodes.setdefault(nid, {
            "id": nid,
            "type": "switch",
            "label": n.get("system_name") or n.get("chassis_id"),
            "description": n.get("system_description"),
            "mgmt_ip": n.get("mgmt_ip"),
            "capabilities": n.get("capabilities") or [],
        })
        edges.append({
            "source": self_id, "target": nid, "kind": n.get("protocol") or "lldp",
            "local_port": n.get("local_port"),
            "remote_port": n.get("port_id"),
            "vlan": n.get("vlan_id"),
        })

    for d in devices:
        if not d.get("ip") and not d.get("mac"):
            continue
        key = str(d.get("ip") or d.get("mac"))
        did = node_id("host", key)
        nodes.setdefault(did, {
            "id": did,
            "type": "host",
            "label": d.get("hostname") or key,
            "ip": str(d.get("ip") or ""),
            "mac": str(d.get("mac") or ""),
            "vendor": d.get("vendor"),
            "source": d.get("source"),
        })
        edges.append({"source": self_id, "target": did, "kind": "l3_seen"})

    return {
        "scan_id": scan.get("id"),
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def _build_metrics(traffic: list[dict[str, Any]], dhcp: list[dict[str, Any]],
                   stp: list[dict[str, Any]]) -> dict[str, Any]:
    if not traffic:
        return {"traffic": None, "dhcp_count": len(dhcp), "stp_event_count": len(stp)}
    t = traffic[0]
    window = 0.0
    if t.get("bucket_start") and t.get("bucket_end"):
        window = (t["bucket_end"] - t["bucket_start"]).total_seconds()
    rxp = t.get("rx_packets") or 0
    bp = t.get("broadcast_packets") or 0
    mp = t.get("multicast_packets") or 0
    pps = (rxp / window) if window > 0 else 0.0
    bpps = (bp / window) if window > 0 else 0.0
    mpps = (mp / window) if window > 0 else 0.0
    return {
        "window_seconds": window,
        "rx_packets": rxp,
        "rx_bytes": t.get("rx_bytes"),
        "rx_errors": t.get("rx_errors"),
        "rx_dropped": t.get("rx_dropped"),
        "broadcast_packets": bp,
        "multicast_packets": mp,
        "rx_pps": round(pps, 2),
        "broadcast_pps": round(bpps, 2),
        "multicast_pps": round(mpps, 2),
        "broadcast_pct_of_rx": round((100 * bp / rxp), 4) if rxp else 0.0,
        "multicast_pct_of_rx": round((100 * mp / rxp), 4) if rxp else 0.0,
        "dhcp_count": len(dhcp),
        "stp_event_count": len(stp),
    }


def _build_timeline(dhcp: list[dict[str, Any]], stp: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for d in dhcp:
        events.append({"ts": d.get("seen_at"), "kind": "dhcp", "detail": {
            "message_type": d.get("message_type"),
            "server_ip": d.get("server_ip"),
            "offered_ip": d.get("offered_ip"),
            "client_mac": d.get("client_mac"),
        }})
    for s in stp:
        events.append({"ts": s.get("seen_at"), "kind": "stp", "detail": {
            "bpdu_type": s.get("bpdu_type"),
            "root_bridge_id": s.get("root_bridge_id"),
            "bridge_id": s.get("bridge_id"),
            "topology_change": s.get("topology_change"),
        }})
    events.sort(key=lambda e: (e.get("ts") is None, e.get("ts")))
    return events


def _devices_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fieldnames = ["id", "ip", "mac", "hostname", "vendor", "source", "first_seen_at", "last_seen_at"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: ("" if r.get(k) is None else str(r.get(k))) for k in fieldnames})
    return buf.getvalue()


def _jsonify(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=_default, sort_keys=False)


def _default(o: Any) -> Any:
    if isinstance(o, datetime):
        if o.tzinfo is None:
            o = o.replace(tzinfo=timezone.utc)
        return o.isoformat()
    return str(o)


def _stamp(dt: Any) -> str:
    if isinstance(dt, datetime):
        return dt.strftime("%Y%m%d-%H%M%S")
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
