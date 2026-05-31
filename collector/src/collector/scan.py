from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .config import get_settings
from .db import (
    complete_scan_run,
    insert_many,
    insert_scan_run,
    last_topology_crawl,
    recent_network_scan,
)
from .discovery import arp as arp_mod
from .discovery import dns_health as dns_mod
from .discovery import interfaces as iface_mod
from .discovery import lldp as lldp_mod
from .discovery import nmap as nmap_mod
from .discovery import snmp as snmp_mod
from .discovery import tshark as tshark_mod
from .logging_setup import audit
from .models import ScanContext

log = structlog.get_logger(__name__)


def _network_id(gateway_mac: str | None, cidr: str | None) -> str | None:
    if not cidr:
        return None
    return hashlib.sha256(f"{gateway_mac or 'no-gw'}|{cidr}".encode()).hexdigest()[:16]


def _topology_due(net_id: str | None, interval_sec: int) -> bool:
    """Whether an SNMP topology crawl is due for this network.

    True if interval is disabled (<=0), the network is unknown, we've never
    crawled it, or the last crawl was longer ago than interval_sec.
    """
    if interval_sec <= 0 or not net_id:
        return True
    last = last_topology_crawl(net_id)
    if last is None:
        return True
    age = time.time() - last.timestamp()
    if age < interval_sec:
        log.info("topology crawl not due, skipping",
                 network_id=net_id, age_sec=int(age), interval_sec=interval_sec)
        return False
    return True


def run_scan(*, interface: str, trigger_reason: str, force: bool,
             is_primary: bool = False) -> int | None:
    """Run a single scan against `interface`. Returns the scan id on success."""
    settings = get_settings()

    state = iface_mod.get_one(interface)
    if state is None:
        log.warning("interface not found", interface=interface)
        return None
    if not state.has_usable_ip:
        log.warning("interface has no usable IP, skipping",
                    interface=interface, is_up=state.is_up,
                    has_carrier=state.has_carrier, addrs=state.ipv4_addrs)
        return None

    net_id = _network_id(state.gateway_mac, state.primary_cidr)
    # Anti-flap floor: even though the poller already gates on rescan_interval,
    # refuse to scan the same network twice within cooldown_seconds. Protects
    # against link flaps and a manual scan colliding with a periodic one.
    # `force=True` (manual `./netmon scan`) bypasses it.
    if not force and net_id:
        recent = recent_network_scan(net_id, settings.cooldown_seconds)
        if recent:
            log.info("cooldown active, skipping", network_id=net_id, last_scan=recent["id"])
            return None

    scan_id = insert_scan_run(
        trigger_reason=trigger_reason,
        interface=state.name,
        interface_cidr=state.primary_cidr,
        gateway_ip=state.gateway_ip,
        gateway_mac=state.gateway_mac,
        network_id=net_id,
        is_primary=is_primary,
    )
    log.info("scan started",
             scan_id=scan_id, interface=state.name,
             cidr=state.primary_cidr, gateway=state.gateway_ip)
    audit("scan_started",
          scan_id=scan_id, interface=state.name,
          cidr=state.primary_cidr, gateway=state.gateway_ip,
          trigger=trigger_reason)

    ctx = ScanContext(
        scan_id=scan_id,
        interface=state.name,
        interface_cidr=state.primary_cidr,
        gateway_ip=state.gateway_ip,
        gateway_mac=state.gateway_mac,
        network_id=net_id,
        started_monotonic=time.monotonic(),
    )

    error: str | None = None
    try:
        # 1. Counter snapshot pre-capture
        pre_counters = iface_mod.read_counters(state.name)

        # 2. Long-running passive capture (blocks for capture_seconds)
        log.info("starting capture", seconds=settings.capture_seconds)
        cap_results = tshark_mod.run_capture(
            interface=state.name,
            seconds=settings.capture_seconds,
        )
        ctx.raw_outputs["tshark"] = cap_results.raw

        # 3. Counter snapshot post-capture for delta
        post_counters = iface_mod.read_counters(state.name)

        # 4. LLDP / CDP neighbors
        lldp_neighbors = lldp_mod.fetch_neighbors()
        ctx.raw_outputs["lldp"] = lldp_neighbors

        # 5. ARP sweep
        arp_results = arp_mod.run(state.name)
        ctx.raw_outputs["arp_scan"] = arp_results

        # 6. nmap host discovery (ping sweep only)
        cidr = state.primary_cidr
        if cidr:
            nmap_results = nmap_mod.host_discovery(cidr)
            ctx.raw_outputs["nmap"] = nmap_results
        else:
            nmap_results = []

        # 7. Optional SNMP polling
        snmp_results: list[dict[str, Any]] = []
        snmp_candidates_list: list[str] = []
        if settings.snmp_enabled:
            try:
                snmp_candidates_list = _snmp_candidates(
                    state.gateway_ip, lldp_neighbors, arp_results, nmap_results,
                    include_all_hosts=settings.snmp_poll_all_hosts)
                log.info("snmp candidate set", count=len(snmp_candidates_list),
                         ips=snmp_candidates_list)
                snmp_results = snmp_mod.poll(snmp_candidates_list)
                ctx.raw_outputs["snmp"] = snmp_results
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("snmp poll failed", error=str(exc))

        # 7b. Optional SNMP topology crawl. Reuses the same candidate IPs as
        # seeds (gateway + LLDP mgmt IPs + network-vendor OUIs) and the same
        # community list. Off by default — flip NETMON_SNMP_TOPOLOGY_ENABLED.
        #
        # Interval-gated: topology (physical cabling + switch config) changes
        # far slower than the hourly host inventory, so we crawl at most once
        # per snmp_topology_interval per network. A manual `./netmon scan`
        # (force=True) always crawls — an on-demand "rediscover now" override.
        topology: dict[str, Any] | None = None
        topology_due = force or _topology_due(net_id, settings.snmp_topology_interval)
        if (settings.snmp_enabled and settings.snmp_topology_enabled
                and snmp_candidates_list and topology_due):
            try:
                from .discovery import snmp_topology as topo_mod
                topology = topo_mod.crawl(
                    seed_ips=snmp_candidates_list,
                    communities=list(settings.snmp_community_list),
                    max_depth=settings.snmp_topology_max_depth,
                    time_budget_sec=settings.snmp_topology_time_budget,
                )
                ctx.raw_outputs["snmp_topology"] = topology
                log.info("snmp topology",
                         nodes=len(topology.get("nodes", [])),
                         edges=len(topology.get("edges", [])),
                         stats=topology.get("stats"))
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("snmp topology crawl failed", error=str(exc))

        # 7c. DNS health probes. Cheap (~1s of UDP), runs every scan when
        # enabled. Measures path to public DNS *and* whatever the DHCP/static
        # config gave us, so we can spot ISP DNS issues and resolver hijacking.
        dns_results: list[dns_mod.DnsProbeResult] = []
        if settings.dns_enabled:
            try:
                dns_results = dns_mod.probe_all()
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("dns probes failed", error=str(exc))

        # 8. Persist everything
        _persist(
            ctx,
            pre_counters=pre_counters,
            post_counters=post_counters,
            cap_results=cap_results,
            lldp_neighbors=lldp_neighbors,
            arp_results=arp_results,
            nmap_results=nmap_results,
            snmp_results=snmp_results,
            topology=topology,
            dns_results=dns_results,
        )

    except Exception as exc:
        log.exception("scan failed", scan_id=scan_id, error=str(exc))
        audit("scan_failed", scan_id=scan_id, error=str(exc))
        error = str(exc)
    finally:
        duration = int(time.monotonic() - ctx.started_monotonic)
        complete_scan_run(scan_id, duration_sec=duration, error=error)
        log.info("scan complete", scan_id=scan_id, duration_sec=duration, error=error)
        audit("scan_completed", scan_id=scan_id, duration_sec=duration,
              error=error or "none")

    return scan_id


_NETWORK_VENDOR_HINTS = (
    "cisco", "aruba", "hp inc.", "hewlett", "juniper", "extreme", "arista",
    "fortinet", "palo alto", "ubiquiti", "mikrotik", "ruckus", "meraki",
    "brocade", "huawei", "netgear", "tp-link", "tplink", "dlink", "d-link",
    "watchguard", "sonicwall", "checkpoint", "f5",
)


def _snmp_candidates(
    gateway_ip: str | None,
    lldp_neighbors: list[dict[str, Any]],
    arp_results: list[dict[str, Any]],
    nmap_results: list[dict[str, Any]],
    *,
    include_all_hosts: bool = False,
) -> list[str]:
    """Set of IPs to try SNMP against.

    Default (narrow) includes:
      * The default gateway (almost always a router with SNMP).
      * Any LLDP/CDP-discovered management IPs (switches, APs).
      * Any ARP/nmap entry whose vendor OUI looks like a network vendor.

    Deliberately excludes random hosts (laptops, phones, printers, IoT):
    a trial with N communities × T timeout against 50 hosts can easily eat
    minutes; narrowing the set keeps scans fast.

    When `include_all_hosts` is set (NETMON_SNMP_POLL_ALL_HOSTS), every
    discovered ARP/nmap host is added too, so printers / PCs / IoT get
    classified via SNMP (Printer-MIB, Host-Resources). Per-device community
    caching + 24h backoff keep the repeat cost down after the first scan.
    """
    ips: list[str] = []
    seen: set[str] = set()

    def add(ip: str | None) -> None:
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)

    if gateway_ip:
        add(gateway_ip)
    for n in lldp_neighbors:
        add(n.get("mgmt_ip"))

    def looks_like_network_gear(vendor: str | None) -> bool:
        if not vendor:
            return False
        v = vendor.lower()
        return any(hint in v for hint in _NETWORK_VENDOR_HINTS)

    for r in arp_results:
        if include_all_hosts or looks_like_network_gear(r.get("vendor")):
            add(r.get("ip"))
    for r in nmap_results:
        if include_all_hosts or looks_like_network_gear(r.get("vendor")):
            add(r.get("ip"))
    return ips


def _persist(
    ctx: ScanContext,
    *,
    pre_counters: dict[str, int],
    post_counters: dict[str, int],
    cap_results: tshark_mod.CaptureResult,
    lldp_neighbors: list[dict[str, Any]],
    arp_results: list[dict[str, Any]],
    nmap_results: list[dict[str, Any]],
    snmp_results: list[dict[str, Any]],
    topology: dict[str, Any] | None = None,
    dns_results: list[dns_mod.DnsProbeResult] | None = None,
) -> None:
    # Devices: merge unique by (ip, mac), recording the discovery source.
    seen: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    for r in arp_results:
        key = (r.get("ip"), r.get("mac"))
        seen.setdefault(key, {
            "scan_run_id": ctx.scan_id,
            "ip": r.get("ip"),
            "mac": r.get("mac"),
            "hostname": None,
            "vendor": r.get("vendor"),
            "source": "arp-scan",
            "extra": "{}",
        })
    for r in nmap_results:
        key = (r.get("ip"), r.get("mac"))
        if key in seen:
            if r.get("hostname") and not seen[key].get("hostname"):
                seen[key]["hostname"] = r.get("hostname")
            continue
        seen[key] = {
            "scan_run_id": ctx.scan_id,
            "ip": r.get("ip"),
            "mac": r.get("mac"),
            "hostname": r.get("hostname"),
            "vendor": r.get("vendor"),
            "source": "nmap",
            "extra": "{}",
        }
    for n in lldp_neighbors:
        if n.get("mgmt_ip"):
            key = (n["mgmt_ip"], n.get("chassis_id"))
            if key not in seen:
                seen[key] = {
                    "scan_run_id": ctx.scan_id,
                    "ip": n["mgmt_ip"],
                    "mac": n.get("chassis_id") if _looks_like_mac(n.get("chassis_id")) else None,
                    "hostname": n.get("system_name"),
                    "vendor": None,
                    "source": "lldp",
                    "extra": "{}",
                }
    insert_many("devices", list(seen.values()))

    insert_many("neighbors", [
        {**n, "scan_run_id": ctx.scan_id, "extra": "{}",
         "capabilities": n.get("capabilities") or None}
        for n in lldp_neighbors
    ])

    insert_many("arp_entries", [
        {
            "scan_run_id": ctx.scan_id,
            "ip": r.get("ip"),
            "mac": r.get("mac"),
            "interface": ctx.interface,
            "vendor": r.get("vendor"),
        }
        for r in arp_results
        if r.get("ip") and r.get("mac")
    ])

    insert_many("dhcp_observations", [
        {**d, "scan_run_id": ctx.scan_id} for d in cap_results.dhcp
    ])

    insert_many("stp_events", [
        {**s, "scan_run_id": ctx.scan_id} for s in cap_results.stp
    ])

    insert_many("snmp_polls", [
        {**p, "scan_run_id": ctx.scan_id} for p in snmp_results
    ])

    # Traffic counters delta — a single row covering the capture window.
    bucket = {
        "scan_run_id": ctx.scan_id,
        "interface": ctx.interface,
        "bucket_start": cap_results.started_at,
        "bucket_end": cap_results.completed_at,
        "rx_packets": post_counters.get("rx_packets", 0) - pre_counters.get("rx_packets", 0),
        "rx_bytes": post_counters.get("rx_bytes", 0) - pre_counters.get("rx_bytes", 0),
        "rx_errors": post_counters.get("rx_errors", 0) - pre_counters.get("rx_errors", 0),
        "rx_dropped": post_counters.get("rx_dropped", 0) - pre_counters.get("rx_dropped", 0),
        "tx_packets": post_counters.get("tx_packets", 0) - pre_counters.get("tx_packets", 0),
        "tx_bytes": post_counters.get("tx_bytes", 0) - pre_counters.get("tx_bytes", 0),
        "broadcast_packets": cap_results.broadcast_packets,
        "multicast_packets": cap_results.multicast_packets,
        "tshark_total_packets": cap_results.total_packets,
    }
    insert_many("traffic_stats", [bucket])

    # Topology crawl results, if any. Persisted as nodes + edges so they
    # land in the bundle alongside the per-scan tables.
    if topology and (topology.get("nodes") or topology.get("edges")):
        from .db import insert_topology
        insert_topology(
            ctx.scan_id,
            topology.get("nodes", []),
            topology.get("edges", []),
        )

    # DNS health probe rows. Per-(resolver, query_name), recorded as one row
    # each so the dashboard / Claude can group by resolver_source.
    if dns_results:
        insert_many("dns_probes", [
            {
                "scan_run_id": ctx.scan_id,
                "resolver_ip": r.resolver_ip,
                "resolver_source": r.resolver_source,
                "query_name": r.query_name,
                "query_type": r.query_type,
                "expected_status": r.expected_status,
                "status": r.status,
                "query_time_ms": r.query_time_ms,
                "answer_count": r.answer_count,
                "answers_text": r.answers_text,
                "error": r.error,
            }
            for r in dns_results
        ])


def _looks_like_mac(s: str | None) -> bool:
    if not s:
        return False
    parts = s.replace("-", ":").split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)
