from __future__ import annotations

import csv
import io
import json
import socket
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from .config import get_settings
from .db import (
    fetch_scan,
    fetch_table_for_scan,
    inventory_counts,
    list_inventory,
    list_snmp_credentials,
)
from .discovery import device_config, dhcp_server
from .discovery import wifi as wifi_mod
from .discovery import wifi_experience as wifi_exp_mod
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
        out = settings.bundle_dir / f"network-scan-{host}-{ts}.zip"
    else:
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
) -> Path:
    """Build a single ZIP rolling up every scan that completed in the hour."""
    if not scan_ids:
        raise ValueError("build_hourly_bundle called with no scan_ids")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Persistent inventory is cross-scan, so it lives once at the bundle root —
    # not duplicated under every scans/scan_<id>/ folder.
    inventory = list_inventory()
    inv_counts = inventory_counts()

    summary = _build_hourly_summary(
        scan_ids=scan_ids,
        device_name=device_name,
        window_start=window_start,
        window_end=window_end,
        inv_counts=inv_counts,
    )

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.md", get_bundle_readme_hourly())
        z.writestr("HOURLY_SUMMARY.md", summary)
        z.writestr("inventory.csv", _inventory_csv(inventory))
        z.writestr("inventory.json", json.dumps(
            {"counts": inv_counts, "devices": inventory},
            indent=2, default=_default))
        # Per-device SNMP credential cache (which read community works per device)
        # — box-global, so it lives once at the bundle root like inventory.
        z.writestr("snmp_credentials.json", json.dumps(
            {"devices": list_snmp_credentials()},
            indent=2, default=_default))
        # Every OPTIONAL artifact below is best-effort and individually guarded: the
        # loaders only catch (OSError, JSONDecodeError), so a valid-JSON-but-non-object
        # envelope raises AttributeError on .get() and would abort the WHOLE hourly
        # bundle — losing every scan in that hour over a side artifact (A1 audit).
        # Wi-Fi RF/AP survey (WIFI-2) — box-global like inventory. Read + normalize
        # the host-written envelope (scripts/netmon-wifi-survey.sh) via discovery/
        # wifi.py. Present ONLY when NETMON_WIFI_SURVEY_ENABLED and an envelope
        # exists, so a missing file means the survey is off / no Wi-Fi NIC.
        try:
            wifi = wifi_mod.survey()
            if wifi.get("available"):
                z.writestr("wifi_survey.json", json.dumps(wifi, indent=2, default=_default))
        except Exception as exc:  # noqa: BLE001 — never fail the bundle for this artifact
            log.warning("could not add wifi_survey to bundle", error=str(exc))
        # WIFI-3: the host-side client-experience battery (join -> measure -> leave),
        # box-global like the survey. Present only when wifi-join is enabled + the
        # battery has run.
        try:
            wifi_exp = wifi_exp_mod.load()
            if wifi_exp.get("available"):
                z.writestr("wifi_experience.json", json.dumps(wifi_exp, indent=2, default=_default))
        except Exception as exc:  # noqa: BLE001 — never fail the bundle for this artifact
            log.warning("could not add wifi_experience to bundle", error=str(exc))
        # Authoritative DHCP server intelligence (DHCP-2) — box-global like the
        # Wi-Fi survey. Present ONLY when active collection is on AND at least one
        # authorized server was queried, so a missing file means the feature is
        # off. Contains server config the operator owns, no credentials.
        try:
            dhcp = dhcp_server.load()
            if dhcp and dhcp.get("servers"):
                z.writestr("dhcp_intel.json", json.dumps(dhcp, indent=2, default=_default))
        except Exception as exc:  # noqa: BLE001 — never fail the bundle for this artifact
            log.warning("could not add dhcp_intel to bundle", error=str(exc))
        # Network DEVICE config backup (NCM-1) — box-global, REDACTED configs only
        # (no plaintext secrets). Present ONLY when the feature is on and at least one
        # device was backed up, so a missing file means the feature is off.
        # Optional + best-effort: a corrupt artifact or a serialization error must
        # NEVER fail the whole hourly bundle (that would lose the scan data — A1 audit).
        try:
            dev_cfg = device_config.load()
            if dev_cfg and dev_cfg.get("devices"):
                z.writestr("device_configs.json", json.dumps(dev_cfg, indent=2, default=_default))
        except Exception as exc:  # noqa: BLE001 — never fail the bundle for this artifact
            log.warning("could not add device_configs to bundle", error=str(exc))
        for sid in scan_ids:
            payload = _scan_payload(sid)
            for name, content in payload.items():
                z.writestr(f"scans/scan_{sid}/{name}", content)

    log.info("hourly bundle written", path=str(output_path),
             scans=len(scan_ids), size_bytes=output_path.stat().st_size)
    return output_path


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
    topo_nodes = fetch_table_for_scan("topology_nodes", scan_id)
    topo_edges = fetch_table_for_scan("topology_edges", scan_id)
    dns = fetch_table_for_scan("dns_probes", scan_id)
    reachability = fetch_table_for_scan("network_reachability", scan_id)
    services = fetch_table_for_scan("service_discovery", scan_id)

    return {
        "summary.md": _build_summary_md(scan, devices, neighbors, arp, dhcp, stp,
                                        traffic, snmp, findings, dns, reachability,
                                        services),
        "findings.json": _jsonify(findings),
        "topology.json": json.dumps(_build_topology(scan, devices, neighbors, arp),
                                    indent=2, default=_default),
        # SNMP-discovered fabric topology — separate file from the local-only
        # topology.json above. Present only when topology crawl is enabled
        # AND it surfaced anything; an empty crawl still ships an empty file
        # so a missing one means "feature off."
        "snmp_topology.json": json.dumps({"nodes": topo_nodes, "edges": topo_edges},
                                         indent=2, default=_default),
        "devices.csv": _devices_csv(devices),
        "metrics.json": json.dumps(_build_metrics(traffic, dhcp, stp),
                                   indent=2, default=_default),
        "timeline.json": json.dumps(_build_timeline(dhcp, stp),
                                    indent=2, default=_default),
        "dns_health.json": json.dumps(_build_dns_health(dns),
                                      indent=2, default=_default),
        # Network-device reachability: per infrastructure candidate, ping +
        # SNMP-response + traceroute. The dashboard renders this as the
        # "switches out there / SNMP reachability" view.
        "net_reachability.json": json.dumps({"devices": reachability},
                                            indent=2, default=_default),
        "raw/net-reachability.json": _jsonify(reachability),
        # mDNS/SSDP service discovery: AirPrint/Apple TV/Chromecast/Sonos/Roku/
        # cameras/UPnP media — the service-advertising devices ARP/nmap miss.
        "service_discovery.json": json.dumps({"devices": services},
                                             indent=2, default=_default),
        "raw/service-discovery.json": _jsonify(services),
        "raw/scan.json": _jsonify(scan),
        "raw/lldp-neighbors.json": _jsonify(neighbors),
        "raw/arp-table.json": _jsonify(arp),
        "raw/dhcp-observed.json": _jsonify(dhcp),
        "raw/stp-events.json": _jsonify(stp),
        "raw/snmp-polls.json": _jsonify(snmp),
        "raw/snmp-topology-nodes.json": _jsonify(topo_nodes),
        "raw/snmp-topology-edges.json": _jsonify(topo_edges),
        "raw/traffic-stats.json": _jsonify(traffic),
        "raw/dns-probes.json": _jsonify(dns),
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
    dns: list[dict[str, Any]],
    reachability: list[dict[str, Any]] | None = None,
    services: list[dict[str, Any]] | None = None,
) -> str:
    lines = []
    lines.append(f"# NetMon scan #{scan['id']}")
    lines.append("")
    lines.append(f"- **Started:** {scan.get('started_at')}")
    lines.append(f"- **Completed:** {scan.get('completed_at')}")
    lines.append(f"- **Duration:** {scan.get('duration_sec')} seconds")
    lines.append(f"- **Trigger:** {scan.get('trigger_reason')}")
    _role = "primary uplink" if scan.get("is_primary") else "secondary (monitored)"
    lines.append(f"- **Interface:** {scan.get('interface')} ({_role})")
    if scan.get("vlan_id") is not None:
        lines.append(f"- **VLAN:** {scan.get('vlan_id')} (trunk {scan.get('parent_interface') or '?'})")
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
    lines.append(f"- DNS probes: **{len(dns)}**")
    if services:
        lines.append(f"- mDNS/SSDP service responders: **{len({s.get('ip') for s in services})}**")
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

    if reachability:
        snmp_ok = [r for r in reachability if r.get("snmp_responded")]
        ping_only = [r for r in reachability
                     if r.get("ping_alive") and not r.get("snmp_responded")]
        dead = [r for r in reachability if not r.get("ping_alive")]
        lines.append("## Network device reachability")
        lines.append("")
        lines.append(f"- Infrastructure candidates probed: **{len(reachability)}**")
        lines.append(f"- Answered SNMP: **{len(snmp_ok)}**")
        lines.append(f"- Ping-only (SNMP not answering — ACL or SNMP off): **{len(ping_only)}**")
        lines.append(f"- Unreachable (no ping): **{len(dead)}**")
        lines.append("")
        lines.append("| IP | Host | Vendor | Ping | RTT ms | SNMP | Hops |")
        lines.append("|---|---|---|---|---:|---|---:|")
        for r in reachability:
            ping = "up" if r.get("ping_alive") else "down"
            snmpv = "yes" if r.get("snmp_responded") else "no"
            rtt = r.get("ping_rtt_ms")
            hops = r.get("traceroute_hops")
            lines.append(
                f"| {r.get('ip')} | {r.get('hostname') or '-'} | {r.get('vendor') or '-'} "
                f"| {ping} | {f'{rtt:.1f}' if isinstance(rtt, (int, float)) else '-'} "
                f"| {snmpv} | {hops if hops is not None else '-'} |"
            )
        lines.append("")

    if services:
        # Group responders by hint for a quick "what's out there" rollup.
        by_ip: dict[Any, dict[str, Any]] = {}
        for s in services:
            ip = s.get("ip")
            entry = by_ip.setdefault(ip, {"hint": None, "host": None,
                                          "svcs": set(), "srcs": set()})
            entry["hint"] = entry["hint"] or s.get("device_hint")
            entry["host"] = entry["host"] or s.get("hostname")
            entry["svcs"].update(s.get("service_types") or [])
            entry["srcs"].add(s.get("source"))
        lines.append("## Service discovery (mDNS / SSDP)")
        lines.append("")
        lines.append(f"- Responders found: **{len(by_ip)}** "
                     "(devices advertising Bonjour/UPnP services)")
        lines.append("")
        lines.append("| IP | Host | Likely type | Via | Services |")
        lines.append("|---|---|---|---|---|")
        for ip, e in by_ip.items():
            svcs = ", ".join(sorted(e["svcs"]))[:80] or "-"
            srcs = "+".join(sorted(x for x in e["srcs"] if x))
            lines.append(
                f"| {ip} | {e['host'] or '-'} | {e['hint'] or '-'} | {srcs} | {svcs} |")
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

    if dns:
        # Per-resolver rollup: mean latency, status mix, NXDOMAIN-rewrite flag.
        agg = _aggregate_dns(dns)
        lines.append("## DNS health")
        lines.append("")
        lines.append("| Resolver | Source | Probes | OK | Errors | Mean ms | NXDOMAIN rewrite? |")
        lines.append("|---|---|---:|---:|---:|---:|---|")
        for row in agg:
            lines.append(
                f"| {row['resolver_ip']} | {row['resolver_source']} | "
                f"{row['probes']} | {row['ok']} | {row['errors']} | "
                f"{row['mean_ms']:.0f} | "
                f"{'YES' if row['nxdomain_rewrite'] else 'no'} |"
            )
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
    inv_counts: dict[str, int] | None = None,
) -> str:
    lines = []
    lines.append(f"# NetMon hourly rollup — {device_name}")
    lines.append("")
    lines.append(f"- **Window:** {window_start.isoformat()} → {window_end.isoformat()}")
    lines.append(f"- **Device:** {device_name}")
    lines.append(f"- **Scans in this hour:** {len(scan_ids)}")
    lines.append("")

    if inv_counts is not None:
        lines.append("## Persistent inventory (all networks this box monitors)")
        lines.append("")
        lines.append(f"- Known devices (lifetime): **{inv_counts.get('total', 0)}**")
        lines.append(f"- First seen in last 24h: **{inv_counts.get('new_24h', 0)}**")
        lines.append(f"- Seen in last 24h: **{inv_counts.get('seen_24h', 0)}**")
        lines.append("")
        lines.append("Full device list in `inventory.csv` / `inventory.json` at the bundle root.")
        lines.append("")

    lines.append("## Scans")
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


def _aggregate_dns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-resolver rollup over a scan's dns_probes rows.

    NXDOMAIN-rewrite detection: any probe with expected_status='NXDOMAIN' that
    came back as NOERROR with answers is a likely ad/filter rewrite — the
    name was a random ".invalid" the resolver couldn't possibly know.
    """
    by_resolver: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = (str(r.get("resolver_ip") or ""), str(r.get("resolver_source") or ""))
        entry = by_resolver.setdefault(key, {
            "resolver_ip": key[0],
            "resolver_source": key[1],
            "probes": 0,
            "ok": 0,
            "errors": 0,
            "latencies": [],
            "nxdomain_rewrite": False,
        })
        entry["probes"] += 1
        status = r.get("status") or ""
        if status == "NOERROR":
            entry["ok"] += 1
        elif status == "NXDOMAIN":
            # NXDOMAIN itself is a valid answer; not counted as error.
            pass
        else:
            entry["errors"] += 1
        qt = r.get("query_time_ms")
        if isinstance(qt, int):
            entry["latencies"].append(qt)
        if (r.get("expected_status") == "NXDOMAIN"
                and status == "NOERROR"
                and (r.get("answer_count") or 0) > 0):
            entry["nxdomain_rewrite"] = True

    out: list[dict[str, Any]] = []
    for entry in by_resolver.values():
        latencies = entry.pop("latencies")
        entry["mean_ms"] = (sum(latencies) / len(latencies)) if latencies else 0.0
        out.append(entry)
    out.sort(key=lambda e: (e["resolver_source"], e["resolver_ip"]))
    return out


def _build_dns_health(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Structured DNS health payload for dns_health.json in the bundle."""
    return {
        "probe_count": len(rows),
        "by_resolver": _aggregate_dns(rows),
        "probes": rows,
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


def _inventory_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fieldnames = [
        "mac", "last_ip", "hostname", "vendor", "device_class",
        "first_seen_at", "last_seen_at", "times_seen",
        "last_network_id", "last_interface",
    ]
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
            o = o.replace(tzinfo=UTC)
        return o.isoformat()
    return str(o)


def _stamp(dt: Any) -> str:
    if isinstance(dt, datetime):
        return dt.strftime("%Y%m%d-%H%M%S")
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
