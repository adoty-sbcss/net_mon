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
from .db import (
    fetch_scan,
    fetch_table_for_scan,
    fetch_table_for_wifi_scan,
    fetch_wifi_scan,
)
from .prompts import get_bundle_readme, get_bundle_readme_hourly

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Single-scan bundle (manual `bundle <id>` command)
# ---------------------------------------------------------------------------


def build_bundle(scan_id: int, output_path: str | None = None) -> Path:
    """Build an evidence bundle ZIP for one scan id. Returns its path."""
    settings = get_settings()
    scan = fetch_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan id {scan_id} not found")

    payload = _scan_payload(scan_id)

    if output_path is None:
        settings.bundle_dir.mkdir(parents=True, exist_ok=True)
        ts = _stamp(scan.get("started_at"))
        host = socket.gethostname()
        output_path = settings.bundle_dir / f"network-scan-{host}-{ts}.zip"
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.md", get_bundle_readme())
        for name, content in payload.items():
            z.writestr(name, content)

    log.info("bundle written", path=str(out), size_bytes=out.stat().st_size)
    return out


# ---------------------------------------------------------------------------
# Hourly multi-scan bundle (uploader)
# ---------------------------------------------------------------------------


def build_hourly_bundle(
    scan_ids: list[int],
    output_path: Path,
    *,
    device_name: str,
    window_start: datetime,
    window_end: datetime,
    wifi_scan_ids: list[int] | None = None,
) -> Path:
    """Build a single ZIP rolling up every scan that completed in the hour.

    Wired and Wi-Fi scans are both included; the ZIP gets `scans/scan_<id>/`
    folders for wired and `wifi/wifi_scan_<id>/` folders for Wi-Fi.
    """
    wifi_scan_ids = wifi_scan_ids or []
    if not scan_ids and not wifi_scan_ids:
        raise ValueError("build_hourly_bundle called with no scan_ids and no wifi_scan_ids")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = _build_hourly_summary(
        scan_ids=scan_ids,
        wifi_scan_ids=wifi_scan_ids,
        device_name=device_name,
        window_start=window_start,
        window_end=window_end,
    )

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.md", get_bundle_readme_hourly())
        z.writestr("HOURLY_SUMMARY.md", summary)
        for sid in scan_ids:
            payload = _scan_payload(sid)
            for name, content in payload.items():
                z.writestr(f"scans/scan_{sid}/{name}", content)
        for wsid in wifi_scan_ids:
            payload = _wifi_scan_payload(wsid)
            for name, content in payload.items():
                z.writestr(f"wifi/wifi_scan_{wsid}/{name}", content)

    log.info("hourly bundle written", path=str(output_path),
             scans=len(scan_ids), wifi_scans=len(wifi_scan_ids),
             size_bytes=output_path.stat().st_size)
    return output_path


def _wifi_scan_payload(wifi_scan_id: int) -> dict[str, str]:
    """All files for one Wi-Fi scan, keyed by relative path inside the bundle."""
    scan = fetch_wifi_scan(wifi_scan_id)
    if scan is None:
        raise ValueError(f"wifi_scan id {wifi_scan_id} not found")

    aps = fetch_table_for_wifi_scan("wifi_aps", wifi_scan_id)
    stations = fetch_table_for_wifi_scan("wifi_stations", wifi_scan_id)
    channels = fetch_table_for_wifi_scan("wifi_channel_stats", wifi_scan_id)
    events = fetch_table_for_wifi_scan("wifi_events", wifi_scan_id)

    return {
        "summary.md": _build_wifi_summary_md(scan, aps, channels, events),
        "aps.csv": _wifi_aps_csv(aps),
        "stations.csv": _wifi_stations_csv(stations),
        "channels.json": _jsonify(channels),
        "events.json": _jsonify(events),
        "raw/wifi_scan.json": _jsonify(scan),
    }


def _build_wifi_summary_md(
    scan: dict[str, Any],
    aps: list[dict[str, Any]],
    channels: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append(f"# Wi-Fi scan #{scan.get('id')}")
    lines.append("")
    lines.append(f"- **Started:** {scan.get('started_at')}")
    lines.append(f"- **Completed:** {scan.get('completed_at')}")
    lines.append(f"- **Duration:** {scan.get('duration_sec')} seconds")
    lines.append(f"- **Trigger:** {scan.get('trigger_reason')}")
    lines.append(f"- **Profile:** {scan.get('profile')}")
    lines.append(f"- **Interface:** {scan.get('interface')}")
    lines.append(f"- **Channels touched:** {scan.get('channels_scanned')}")
    if scan.get("error"):
        lines.append(f"- **Error:** {scan['error']}")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    lines.append(f"- APs visible: **{len(aps)}**")
    lines.append(f"- Channels with stats: **{len(channels)}**")
    lines.append(f"- Findings (anomalies): **{len(events)}**")
    lines.append("")

    # Security breakdown.
    if aps:
        from collections import Counter
        priv = Counter((ap.get("privacy") or "?").upper() for ap in aps)
        lines.append("## Security breakdown")
        lines.append("")
        for k, v in sorted(priv.items(), key=lambda x: -x[1]):
            lines.append(f"- {k}: {v}")
        lines.append("")

    # Band breakdown.
    if aps:
        from collections import Counter
        bands = Counter(ap.get("band") or "?" for ap in aps)
        lines.append("## Band breakdown")
        lines.append("")
        for k, v in sorted(bands.items(), key=lambda x: -x[1]):
            lines.append(f"- {k}: {v}")
        lines.append("")

    if events:
        lines.append("## Findings (anomalies)")
        lines.append("")
        for ev in events:
            lines.append(f"- **[{ev.get('severity')}] {ev.get('title')}** — {ev.get('detail')}")
        lines.append("")

    return "\n".join(lines)


def _wifi_aps_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fieldnames = ["id", "bssid", "essid", "channel", "frequency_mhz", "band",
                  "privacy", "cipher", "auth", "signal_dbm", "vendor",
                  "first_seen_at", "last_seen_at"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: ("" if r.get(k) is None else str(r.get(k))) for k in fieldnames})
    return buf.getvalue()


def _wifi_stations_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fieldnames = ["id", "station_mac", "associated_bssid", "signal_dbm",
                  "frame_count", "vendor", "probed_essids",
                  "first_seen_at", "last_seen_at"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: ("" if r.get(k) is None else str(r.get(k))) for k in fieldnames})
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Per-scan payload — shared between single and hourly bundles
# ---------------------------------------------------------------------------


def _scan_payload(scan_id: int) -> dict[str, str]:
    """All files for one scan, keyed by relative path inside the bundle."""
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

    return {
        "summary.md": _build_summary_md(scan, devices, neighbors, arp, dhcp, stp, traffic, snmp, findings),
        "findings.json": _jsonify(findings),
        "topology.json": json.dumps(_build_topology(scan, devices, neighbors, arp),
                                    indent=2, default=_default),
        "devices.csv": _devices_csv(devices),
        "metrics.json": json.dumps(_build_metrics(traffic, dhcp, stp),
                                   indent=2, default=_default),
        "timeline.json": json.dumps(_build_timeline(dhcp, stp),
                                    indent=2, default=_default),
        "raw/scan.json": _jsonify(scan),
        "raw/lldp-neighbors.json": _jsonify(neighbors),
        "raw/arp-table.json": _jsonify(arp),
        "raw/dhcp-observed.json": _jsonify(dhcp),
        "raw/stp-events.json": _jsonify(stp),
        "raw/snmp-polls.json": _jsonify(snmp),
        "raw/traffic-stats.json": _jsonify(traffic),
    }


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------


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
    lines.append(f"# NetMon scan #{scan['id']}")
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
        total = t.get("tshark_total_packets") or 0
        bp_pct = (100 * bp / total) if total else 0.0
        mp_pct = (100 * mp / total) if total else 0.0
        window = 0.0
        if t.get("bucket_start") and t.get("bucket_end"):
            window = (t["bucket_end"] - t["bucket_start"]).total_seconds()
        bpps = (bp / window) if window > 0 else 0.0
        mpps = (mp / window) if window > 0 else 0.0
        lines.append("## Traffic during capture")
        lines.append("")
        lines.append(f"- Total packets seen by capture: {total:,}")
        lines.append(f"- Broadcast: {bp:,} ({bp_pct:.2f}% of capture, {bpps:.2f} pps)")
        lines.append(f"- Multicast: {mp:,} ({mp_pct:.2f}% of capture, {mpps:.2f} pps)")
        lines.append(f"- RX packets (kernel-accepted): {rxp:,} ({t.get('rx_bytes', 0):,} bytes)")
        lines.append(f"- RX errors: {t.get('rx_errors', 0):,}  /  RX dropped: {t.get('rx_dropped', 0):,}")
        lines.append("")

    if dhcp:
        servers: dict[tuple[Any, Any], int] = {}
        for d in dhcp:
            if d.get("server_ip"):
                key = (d["server_ip"], d.get("server_mac"))
                servers[key] = servers.get(key, 0) + 1
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

    return "\n".join(lines)


def _build_hourly_summary(
    *,
    scan_ids: list[int],
    device_name: str,
    window_start: datetime,
    window_end: datetime,
    wifi_scan_ids: list[int] | None = None,
) -> str:
    wifi_scan_ids = wifi_scan_ids or []
    lines = []
    lines.append(f"# NetMon hourly rollup — {device_name}")
    lines.append("")
    lines.append(f"- **Window:** {window_start.isoformat()} → {window_end.isoformat()}")
    lines.append(f"- **Device:** {device_name}")
    lines.append(f"- **Wired scans in this hour:** {len(scan_ids)}")
    lines.append(f"- **Wi-Fi scans in this hour:** {len(wifi_scan_ids)}")
    lines.append("")
    if scan_ids:
        lines.append("## Wired scans")
        lines.append("")
        lines.append("| ID | Interface | CIDR | Gateway | Trigger | Duration |")
        lines.append("|---:|-----------|------|---------|---------|---------:|")
        for sid in scan_ids:
            scan = fetch_scan(sid) or {}
            lines.append(
                f"| {sid} "
                f"| {scan.get('interface') or '-'} "
                f"| {scan.get('interface_cidr') or '-'} "
                f"| {scan.get('gateway_ip') or '-'} "
                f"| {scan.get('trigger_reason') or '-'} "
                f"| {scan.get('duration_sec') or '-'}s |"
            )
        lines.append("")
        lines.append("Open each `scans/scan_<id>/summary.md` for per-scan detail.")
        lines.append("")
    if wifi_scan_ids:
        lines.append("## Wi-Fi scans")
        lines.append("")
        lines.append("| ID | Interface | Profile | Trigger | Duration |")
        lines.append("|---:|-----------|---------|---------|---------:|")
        for wsid in wifi_scan_ids:
            wsc = fetch_wifi_scan(wsid) or {}
            lines.append(
                f"| {wsid} "
                f"| {wsc.get('interface') or '-'} "
                f"| {wsc.get('profile') or '-'} "
                f"| {wsc.get('trigger_reason') or '-'} "
                f"| {wsc.get('duration_sec') or '-'}s |"
            )
        lines.append("")
        lines.append("Open each `wifi/wifi_scan_<id>/summary.md` for per-scan detail.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Topology / metrics / timeline helpers
# ---------------------------------------------------------------------------


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
        "label": f"NetMon ({scan.get('interface')})",
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
    total = t.get("tshark_total_packets") or 0
    pps = (rxp / window) if window > 0 else 0.0
    bpps = (bp / window) if window > 0 else 0.0
    mpps = (mp / window) if window > 0 else 0.0
    total_pps = (total / window) if window > 0 else 0.0
    # Percentages use total tshark-observed packets (promiscuous capture),
    # which is the right peer to broadcast/multicast counts. rx_packets from
    # /proc/net/dev only counts kernel-accepted frames and would give bogus
    # > 100% values on any segment with traffic not destined to this host.
    return {
        "window_seconds": window,
        "rx_packets_kernel": rxp,
        "rx_bytes_kernel": t.get("rx_bytes"),
        "rx_errors": t.get("rx_errors"),
        "rx_dropped": t.get("rx_dropped"),
        "tshark_total_packets": total,
        "broadcast_packets": bp,
        "multicast_packets": mp,
        "rx_pps_kernel": round(pps, 2),
        "tshark_total_pps": round(total_pps, 2),
        "broadcast_pps": round(bpps, 2),
        "multicast_pps": round(mpps, 2),
        "broadcast_pct_of_observed": round((100 * bp / total), 4) if total else 0.0,
        "multicast_pct_of_observed": round((100 * mp / total), 4) if total else 0.0,
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
