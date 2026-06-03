from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import structlog

from .config import get_settings
from .db import (
    complete_scan_run,
    get_snmp_credential,
    insert_many,
    insert_scan_run,
    last_topology_crawl,
    recent_network_scan,
)
from .discovery import arp as arp_mod
from .discovery import dns_health as dns_mod
from .discovery import interfaces as iface_mod
from .discovery import lldp as lldp_mod
from .discovery import mdns_ssdp as mdns_mod
from .discovery import nmap as nmap_mod
from .discovery import rdns as rdns_mod
from .discovery import reachability as reach_mod
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

        # Infrastructure candidate set (gateway + LLDP mgmt IPs + network-vendor
        # OUIs). Computed unconditionally — reused by SNMP polling, topology
        # seeds, AND the reachability probe (which runs even when SNMP is off).
        snmp_candidates_list = _snmp_candidates(
            state.gateway_ip, lldp_neighbors, arp_results, nmap_results,
            include_all_hosts=settings.snmp_poll_all_hosts)
        log.info("network device candidate set", count=len(snmp_candidates_list),
                 ips=snmp_candidates_list)

        # 7. Optional SNMP polling
        snmp_results: list[dict[str, Any]] = []
        if settings.snmp_enabled and snmp_candidates_list:
            try:
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

        # 7d. Network-device reachability — ping + traceroute + SNMP-response for
        # the infrastructure candidate set. Surfaces which switches are out there
        # and which answer SNMP vs. only ping (the common ACL/SNMP-off case).
        reachability: list[dict[str, Any]] = []
        if settings.reachability_enabled and snmp_candidates_list:
            try:
                reachability = _probe_reachability(
                    snmp_candidates_list, state.gateway_ip, lldp_neighbors,
                    arp_results, nmap_results, snmp_results,
                )
                ctx.raw_outputs["reachability"] = reachability
                log.info("reachability probe", count=len(reachability),
                         snmp_ok=sum(1 for r in reachability if r.get("snmp_responded")),
                         ping_ok=sum(1 for r in reachability if r.get("ping_alive")))
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("reachability probe failed", error=str(exc))

        # 7e. mDNS (Bonjour) + SSDP (UPnP) service discovery. A few small
        # multicast queries surface the service-advertising devices ARP/nmap
        # miss (AirPrint printers, Apple TV, Chromecast, Sonos, Roku, cameras).
        # Time-bounded and best-effort.
        services: list[dict[str, Any]] = []
        if settings.mdns_enabled:
            try:
                bind_ip = state.primary_cidr.split("/")[0] if state.primary_cidr else None
                services = mdns_mod.discover(
                    bind_ip=bind_ip,
                    mdns_seconds=settings.mdns_seconds,
                    ssdp_seconds=settings.ssdp_seconds,
                )
                ctx.raw_outputs["service_discovery"] = services
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("service discovery failed", error=str(exc))

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
            reachability=reachability,
            services=services,
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
    # Operator-registered SNMP targets pushed from the dashboard registry — always
    # polled even if the OUI/heuristic selection above would miss them.
    for ip in get_settings().snmp_extra_target_list:
        add(ip)
    return ips


def _probe_reachability(
    candidate_ips: list[str],
    gateway_ip: str | None,
    lldp_neighbors: list[dict[str, Any]],
    arp_results: list[dict[str, Any]],
    nmap_results: list[dict[str, Any]],
    snmp_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build reachability targets from the candidate set + per-IP metadata, then
    ping/traceroute them. SNMP-responded is derived from this scan's poll rows
    plus the cached credential (a known-working community)."""
    settings = get_settings()

    # ip -> (hostname, vendor) from this scan's discovery, best-effort.
    meta: dict[str, dict[str, Any]] = {}
    for r in arp_results + nmap_results:
        ip = r.get("ip")
        if ip and ip not in meta:
            meta[ip] = {"hostname": r.get("hostname"), "vendor": r.get("vendor")}
    lldp_mgmt: set[str] = set()
    for n in lldp_neighbors:
        ip = n.get("mgmt_ip")
        if ip:
            lldp_mgmt.add(ip)
            meta.setdefault(ip, {"hostname": n.get("system_name"), "vendor": None})

    snmp_ok = {p.get("device_ip") for p in snmp_results}

    targets: list[dict[str, Any]] = []
    for ip in candidate_ips:
        cred = get_snmp_credential(ip)
        responded = (ip in snmp_ok) or bool(cred and cred.get("community"))
        if ip == gateway_ip:
            source = "gateway"
        elif ip in lldp_mgmt:
            source = "lldp"
        else:
            source = "oui"
        m = meta.get(ip, {})
        targets.append({
            "ip": ip,
            "hostname": m.get("hostname"),
            "vendor": m.get("vendor"),
            "source": source,
            "snmp_responded": responded,
            "snmp_version": (cred or {}).get("version") if responded else None,
        })

    return reach_mod.probe(
        targets,
        traceroute=settings.reachability_traceroute,
        max_hops=settings.reachability_max_hops,
    )


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
    reachability: list[dict[str, Any]] | None = None,
    services: list[dict[str, Any]] | None = None,
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

    # Backfill hostnames from DHCP option 12 (the name a client advertises in its
    # DISCOVER/REQUEST). This works even when the site has no reverse-DNS (PTR)
    # records — which is the common case for client subnets — so endpoints that
    # nmap couldn't name still get a hostname. Matched by MAC, case-insensitive.
    dhcp_hostnames: dict[str, str] = {}
    for d in cap_results.dhcp:
        mac = (d.get("client_mac") or "").lower()
        hn = d.get("client_hostname")
        if mac and hn and mac not in dhcp_hostnames:
            dhcp_hostnames[mac] = hn
    if dhcp_hostnames:
        for dev in seen.values():
            mac = (dev.get("mac") or "").lower()
            if mac and not dev.get("hostname") and mac in dhcp_hostnames:
                dev["hostname"] = dhcp_hostnames[mac]

    # Reverse DNS (PTR) for anything still unnamed, querying the LOCAL site
    # resolvers (DHCP-assigned DNS + gateway) — nmap only used the container's
    # resolver, which is usually public DNS with no internal records.
    settings = get_settings()
    if settings.rdns_enabled:
        resolvers: list[str] = []
        for d in cap_results.dhcp:
            ds = d.get("dns_servers")
            if ds:
                resolvers += [x for x in re.split(r"[\s,]+", str(ds)) if x]
        if ctx.gateway_ip:
            resolvers.append(ctx.gateway_ip)
        # de-dup, preserve order
        resolvers = list(dict.fromkeys(resolvers))
        need = [
            dev["ip"]
            for dev in seen.values()
            if dev.get("ip") and not dev.get("hostname")
        ]
        if need and resolvers:
            ptr = rdns_mod.resolve_ptr(need, resolvers, timeout=settings.rdns_timeout_sec)
            for dev in seen.values():
                ip = dev.get("ip")
                if ip and not dev.get("hostname") and ip in ptr:
                    dev["hostname"] = ptr[ip]
                    dev["source"] = (dev.get("source") or "") + "+rdns"

    # mDNS/SSDP service-discovery enrichment: backfill hostnames + attach a
    # device hint and the observed service types for IPs we already saw, and add
    # service-only IPs (devices that answered Bonjour/UPnP but were invisible to
    # ARP/nmap). All of these flow into the devices table + persistent inventory.
    if services:
        svc_by_ip: dict[str, dict[str, Any]] = {}
        for s in services:
            ip = s.get("ip")
            if not ip:
                continue
            e = svc_by_ip.setdefault(
                ip, {"hostname": None, "hint": None, "services": set(), "sources": set()})
            if s.get("hostname") and not e["hostname"]:
                e["hostname"] = s["hostname"]
            if s.get("device_hint") and not e["hint"]:
                e["hint"] = s["device_hint"]
            e["services"].update(s.get("services") or [])
            if s.get("source"):
                e["sources"].add(s["source"])
        existing_ips = {d.get("ip") for d in seen.values()}
        for dev in seen.values():
            ip = dev.get("ip")
            if ip and ip in svc_by_ip:
                info = svc_by_ip[ip]
                if not dev.get("hostname") and info["hostname"]:
                    dev["hostname"] = info["hostname"]
                dev["extra"] = _merge_extra(dev.get("extra"), {
                    "service_hint": info["hint"],
                    "services": sorted(info["services"]),
                })
                dev["source"] = (dev.get("source") or "") + "+svc"
        for ip, info in svc_by_ip.items():
            if ip in existing_ips:
                continue
            seen[(ip, None)] = {
                "scan_run_id": ctx.scan_id,
                "ip": ip,
                "mac": None,
                "hostname": info["hostname"],
                "vendor": None,
                "source": "+".join(sorted(s for s in info["sources"] if s)) or "mdns",
                "extra": _merge_extra("{}", {
                    "service_hint": info["hint"],
                    "services": sorted(info["services"]),
                }),
            }

    insert_many("devices", list(seen.values()))

    # Persistent MAC-keyed inventory rollup. The per-scan `devices` rows above
    # answer "what did this scan see"; this upsert maintains the durable
    # cross-scan "what devices exist on the networks this box monitors" inventory
    # that the discovery/security/fleet features build on. Best-effort: a failure
    # here must not fail the scan or lose the per-scan tables already committed.
    if settings.inventory_enabled:
        try:
            inv_rows = _inventory_rows(seen.values(), ctx)
            if inv_rows:
                from .db import upsert_inventory_devices
                upserted, new = upsert_inventory_devices(inv_rows)
                log.info("inventory updated", scan_id=ctx.scan_id,
                         upserted=upserted, new=new)
        except Exception as exc:  # pragma: no cover — defensive
            log.warning("inventory upsert failed", error=str(exc))

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

    # Network-device reachability rows (ping + traceroute + SNMP-response).
    if reachability:
        insert_many("network_reachability", [
            {
                "scan_run_id": ctx.scan_id,
                "ip": r.get("ip"),
                "hostname": r.get("hostname"),
                "vendor": r.get("vendor"),
                "source": r.get("source"),
                "ping_alive": r.get("ping_alive"),
                "ping_rtt_ms": r.get("ping_rtt_ms"),
                "ping_loss_pct": r.get("ping_loss_pct"),
                "snmp_responded": r.get("snmp_responded"),
                "snmp_version": r.get("snmp_version"),
                "traceroute_hops": r.get("traceroute_hops"),
                "traceroute_path": json.dumps(r.get("traceroute_path") or []),
            }
            for r in reachability
        ])

    # mDNS/SSDP service-discovery rows (one per responder IP + protocol).
    if services:
        insert_many("service_discovery", [
            {
                "scan_run_id": ctx.scan_id,
                "ip": s.get("ip"),
                "source": s.get("source"),
                "hostname": s.get("hostname"),
                "service_types": s.get("services") or None,
                "device_hint": s.get("device_hint"),
                "details": json.dumps(s.get("details") or {}),
            }
            for s in services
            if s.get("ip")
        ])


def _merge_extra(extra: Any, add: dict[str, Any]) -> str:
    """Merge `add` into a device's JSONB `extra` (stored as a JSON string),
    dropping empty values. Tolerates extra being a JSON string, a dict, or None."""
    base: dict[str, Any] = {}
    if isinstance(extra, str) and extra.strip():
        try:
            loaded = json.loads(extra)
            if isinstance(loaded, dict):
                base = loaded
        except (ValueError, TypeError):
            base = {}
    elif isinstance(extra, dict):
        base = dict(extra)
    for k, v in add.items():
        if v not in (None, [], {}, ""):
            base[k] = v
    return json.dumps(base)


def _inventory_rows(
    devices: Any, ctx: ScanContext
) -> list[dict[str, Any]]:
    """Collapse this scan's discovered devices into one inventory upsert row per
    MAC. Rows without a MAC are dropped (MAC is the inventory key). When the same
    MAC shows up under several IPs in one scan, keep the first and fill in any
    hostname / IP / vendor the later duplicates supply."""
    settings = get_settings()
    by_mac: dict[str, dict[str, Any]] = {}
    for d in devices:
        mac = d.get("mac")
        if not mac:
            continue
        norm = str(mac).lower()
        existing = by_mac.get(norm)
        if existing is None:
            by_mac[norm] = {
                "mac": mac,
                "last_ip": d.get("ip"),
                "hostname": d.get("hostname"),
                "vendor": d.get("vendor"),
                # device_class is populated later by the fingerprint/SNMP
                # classifiers; None here means "leave any existing value alone"
                # (the upsert COALESCEs it).
                "device_class": None,
                "last_source": d.get("source"),
                "last_network_id": ctx.network_id,
                "last_interface": ctx.interface,
                "last_scan_run_id": ctx.scan_id,
                "district_slug": settings.district_slug or None,
                "school_slug": settings.school_slug or None,
                "device_slug": settings.device_slug or None,
            }
        else:
            if not existing.get("hostname") and d.get("hostname"):
                existing["hostname"] = d.get("hostname")
            if not existing.get("last_ip") and d.get("ip"):
                existing["last_ip"] = d.get("ip")
            if not existing.get("vendor") and d.get("vendor"):
                existing["vendor"] = d.get("vendor")
    return list(by_mac.values())


def _looks_like_mac(s: str | None) -> bool:
    if not s:
        return False
    parts = s.replace("-", ":").split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)
