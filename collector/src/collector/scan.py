from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import structlog

from .config import get_settings
from .db import (
    DbConnection,
    complete_scan_run,
    connect,
    dumps_jsonb,
    get_snmp_credentials,
    insert_many,
    insert_scan_run,
    insert_topology,
    last_dns_probe,
    last_snmp_bulk,
    last_topology_crawl,
    recent_network_scan,
    try_scan_lock,
    upsert_inventory_devices,
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


def _vlan_of(interface: str) -> tuple[int | None, str | None]:
    """Derive (vlan_id, parent) from a VLAN sub-interface name:
    'eth0.10' -> (10, 'eth0'); 'enp0s31f6.100' -> (100, 'enp0s31f6'); a plain
    NIC -> (None, None). Matches the `parent.vid` naming the trunk wizard
    generates via netplan, so trunk scans are attributable to their VLAN."""
    m = re.match(r"^(.+)\.(\d{1,4})$", interface)
    if not m:
        return None, None
    vid = int(m.group(2))
    return (vid, m.group(1)) if 1 <= vid <= 4094 else (None, None)


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


def _snmp_bulk_due(net_id: str | None, interval_sec: int) -> bool:
    """Whether the HEAVY bulk SNMP OIDs (FDB / ifTable / ARP cache) are due for
    this network. Mirrors _topology_due: True if disabled (<=0), the network is
    unknown, we've never walked them, or the last walk was longer ago than
    interval_sec. Off-cadence scans poll only the small identity/STP/port OIDs."""
    if interval_sec <= 0 or not net_id:
        return True
    last = last_snmp_bulk(net_id)
    if last is None:
        return True
    age = time.time() - last.timestamp()
    if age < interval_sec:
        log.info("snmp bulk walk not due, polling identity OIDs only",
                 network_id=net_id, age_sec=int(age), interval_sec=interval_sec)
        return False
    return True


def _dns_due(interval_sec: int) -> bool:
    """Whether box-wide DNS probes are due — run at most once per interval across
    ALL networks/VLANs (the resolver path is identical, so per-scan is redundant).
    True if disabled (<=0), never run, or the last run was longer ago than the
    interval."""
    if interval_sec <= 0:
        return True
    last = last_dns_probe()
    if last is None:
        return True
    return (time.time() - last.timestamp()) >= interval_sec


def run_scan(*, interface: str, trigger_reason: str, force: bool,
             is_primary: bool = False, light: bool = False) -> int | None:
    """Run a single scan against `interface`. Returns the scan id on success.

    When `light` is True this is a capture-only pass: it runs the passive
    tshark capture + a quick ARP sweep (so the scan still carries a device
    list) and SKIPS the heavier discovery — LLDP, nmap, SNMP (+ topology
    crawl), DNS health, reachability, and mDNS/SSDP. The poller uses it to
    sample DHCP/STP between full scans without paying the full-scan cost.
    """
    with try_scan_lock() as acquired:
        if not acquired:
            log.warning(
                "scan already running, skipping overlapping trigger",
                interface=interface,
                trigger_reason=trigger_reason,
            )
            return None
        return _run_scan_locked(
            interface=interface,
            trigger_reason=trigger_reason,
            force=force,
            is_primary=is_primary,
            light=light,
        )


def _run_scan_locked(*, interface: str, trigger_reason: str, force: bool,
                     is_primary: bool = False, light: bool = False) -> int | None:
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
    #
    # require_success=False so the floor counts EVERY recent attempt, not just
    # successful ones. The poller's freshness gate is (correctly) success-only,
    # so a failed scan is due for retry immediately — but without this floor that
    # retry would fire every poll tick (~30s) with no backoff, hammering a box
    # whose scan keeps failing. This bounds the failure retry to once per cooldown.
    if not force and net_id:
        recent = recent_network_scan(
            net_id, settings.cooldown_seconds, require_success=False)
        if recent:
            log.info("cooldown active, skipping", network_id=net_id, last_scan=recent["id"])
            return None

    vlan_id, parent_iface = _vlan_of(state.name)
    scan_id = insert_scan_run(
        trigger_reason=trigger_reason,
        interface=state.name,
        interface_cidr=state.primary_cidr,
        gateway_ip=state.gateway_ip,
        gateway_mac=state.gateway_mac,
        network_id=net_id,
        is_primary=is_primary,
        vlan_id=vlan_id,
        parent_interface=parent_iface,
    )
    log.info("scan started",
             scan_id=scan_id, interface=state.name, vlan_id=vlan_id,
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
    section_errors: dict[str, str] = {}
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

        # 4. LLDP / CDP neighbors (skipped on a light capture-only pass)
        lldp_neighbors = [] if light else lldp_mod.fetch_neighbors()
        ctx.raw_outputs["lldp"] = lldp_neighbors

        # 5. ARP sweep
        arp_results = arp_mod.run(state.name)
        ctx.raw_outputs["arp_scan"] = arp_results

        # 6. nmap host discovery (ping sweep only) — skipped on a light pass.
        # Enrichment, NOT a required source: ARP + the passive capture already
        # carry the device list (nmap is even skipped entirely on light passes),
        # and nmap -sn on a large/filtered subnet is the most timeout-prone step.
        # So a failure here DEGRADES the scan (section error) rather than failing
        # it — otherwise one nmap timeout would discard the whole scan (capture,
        # ARP, SNMP, topology) and ship nothing for that hour.
        cidr = state.primary_cidr
        nmap_results: list[dict[str, Any]] = []
        if not light and cidr:
            try:
                nmap_results = nmap_mod.host_discovery(cidr)
                ctx.raw_outputs["nmap"] = nmap_results
            except Exception as exc:
                log.warning("nmap host discovery failed", error=str(exc))
                section_errors["nmap"] = str(exc)

        # Infrastructure candidate set (gateway + LLDP mgmt IPs + network-vendor
        # OUIs). Reused by SNMP polling, topology seeds, AND the reachability
        # probe. Empty on a light pass, which short-circuits all three.
        snmp_candidates_list = [] if light else _snmp_candidates(
            state.gateway_ip, lldp_neighbors, arp_results, nmap_results,
            include_all_hosts=settings.snmp_poll_all_hosts)
        if not light:
            log.info("network device candidate set", count=len(snmp_candidates_list),
                     ips=snmp_candidates_list)

        # 7. Optional SNMP polling. The heavy bulk OIDs (FDB / ifTable / ARP cache)
        # are gated to a slow cadence (snmp_bulk_interval, default daily) — they
        # change far slower than the hourly scan; identity OIDs stay every-scan.
        snmp_results: list[dict[str, Any]] = []
        if settings.snmp_enabled and snmp_candidates_list:
            include_bulk = force or _snmp_bulk_due(net_id, settings.snmp_bulk_interval)
            try:
                snmp_status: dict[str, Any] = {}
                snmp_results = snmp_mod.poll(
                    snmp_candidates_list,
                    include_bulk=include_bulk,
                    status=snmp_status,
                )
                ctx.raw_outputs["snmp"] = snmp_results
                ctx.raw_outputs["snmp_status"] = snmp_status
                if snmp_status.get("truncated"):
                    section_errors["snmp"] = (
                        "poll truncated: "
                        f"attempted={snmp_status.get('attempted')}/"
                        f"{snmp_status.get('candidates')}"
                    )
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("snmp poll failed", error=str(exc))
                section_errors["snmp"] = str(exc)

        # 7b. Optional SNMP topology crawl. Reuses the same candidate IPs as
        # seeds (gateway + LLDP mgmt IPs + network-vendor OUIs) and the same
        # community list. Off by default — flip NETMON_SNMP_TOPOLOGY_ENABLED.
        #
        # Interval-gated: topology (physical cabling + switch config) changes
        # far slower than the hourly host inventory, so we crawl at most once
        # per snmp_topology_interval per network. A manual `./netmon scan`
        # (force=True) always crawls — an on-demand "rediscover now" override.
        topology: dict[str, Any] | None = None
        topology_due = (not light) and (force or _topology_due(net_id, settings.snmp_topology_interval))
        if (settings.snmp_enabled and settings.snmp_topology_enabled
                and snmp_candidates_list and topology_due):
            try:
                from .discovery import snmp_topology as topo_mod
                topology = topo_mod.crawl(
                    seed_ips=snmp_candidates_list,
                    communities=list(settings.snmp_community_list),
                    max_depth=settings.snmp_topology_max_depth,
                    time_budget_sec=settings.snmp_topology_time_budget,
                    exclude_ips=set(settings.snmp_exclude_list),
                    scope=settings.snmp_topology_scope,
                    gateway_ip=state.gateway_ip,
                    gateway_mac=state.gateway_mac,
                    max_nodes=settings.snmp_topology_max_nodes,
                    fanout_cap=settings.snmp_topology_fanout_cap,
                )
                ctx.raw_outputs["snmp_topology"] = topology
                log.info("snmp topology",
                         nodes=len(topology.get("nodes", [])),
                         edges=len(topology.get("edges", [])),
                         stats=topology.get("stats"))
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("snmp topology crawl failed", error=str(exc))
                section_errors["snmp_topology"] = str(exc)

        # 7c. DNS health probes. Cheap (~1s of UDP). Run at most once per
        # rescan_interval BOX-WIDE — the resolver path (public list + the box's
        # resolv.conf) is identical across VLANs/networks, so per-scan probes were
        # pure duplication. Measures path to public DNS *and* whatever the
        # DHCP/static config gave us — spots ISP DNS issues + resolver hijacking.
        dns_results: list[dns_mod.DnsProbeResult] = []
        if not light and settings.dns_enabled and (force or _dns_due(settings.rescan_interval)):
            try:
                dns_results = dns_mod.probe_all()
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("dns probes failed", error=str(exc))
                section_errors["dns"] = str(exc)

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
                section_errors["reachability"] = str(exc)

        # 7e. mDNS (Bonjour) + SSDP (UPnP) service discovery. A few small
        # multicast queries surface the service-advertising devices ARP/nmap
        # miss (AirPrint printers, Apple TV, Chromecast, Sonos, Roku, cameras).
        # Time-bounded and best-effort.
        services: list[dict[str, Any]] = []
        if not light and settings.mdns_enabled:
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
                section_errors["service_discovery"] = str(exc)

        # 8. Persist everything
        with connect() as connection:
            _persist(
                ctx,
                connection=connection,
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
        notes = (
            dumps_jsonb({"section_errors": section_errors}, sort_keys=True)
            if section_errors
            else None
        )
        complete_scan_run(scan_id, duration_sec=duration, error=error, notes=notes)
        log.info("scan complete", scan_id=scan_id, duration_sec=duration, error=error)
        audit("scan_completed", scan_id=scan_id, duration_sec=duration,
              error=error or "none", section_errors=section_errors)

    return scan_id if error is None else None


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

    # Cached SNMP credentials for the whole candidate set in ONE query (was a
    # fresh DB connection per candidate IP).
    creds = get_snmp_credentials(list(candidate_ips))

    targets: list[dict[str, Any]] = []
    for ip in candidate_ips:
        cred = creds.get(ip)
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


def _counter_delta(
    before: dict[str, int], after: dict[str, int], key: str
) -> int | None:
    """Return a trustworthy monotonic counter delta, otherwise NULL."""
    before_value = before.get(key)
    after_value = after.get(key)
    if before_value is None or after_value is None or after_value < before_value:
        return None
    return after_value - before_value


def _persist(
    ctx: ScanContext,
    *,
    connection: DbConnection,
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

    insert_many("devices", list(seen.values()), connection=connection)

    # Persistent MAC-keyed inventory rollup. The per-scan `devices` rows above
    # answer "what did this scan see"; this upsert maintains the durable
    # cross-scan "what devices exist on the networks this box monitors" inventory
    # that the discovery/security/fleet features build on. It shares the scan's
    # transaction, so a failure rolls back every per-scan and inventory write.
    if settings.inventory_enabled:
        inv_rows = _inventory_rows(seen.values(), ctx)
        if inv_rows:
            upserted, new = upsert_inventory_devices(inv_rows, connection=connection)
            log.info("inventory updated", scan_id=ctx.scan_id,
                     upserted=upserted, new=new)

    insert_many("neighbors", [
        {**n, "scan_run_id": ctx.scan_id, "extra": "{}",
         "capabilities": n.get("capabilities") or None}
        for n in lldp_neighbors
    ], connection=connection)

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
    ], connection=connection)

    insert_many("dhcp_observations", [
        {**d, "scan_run_id": ctx.scan_id} for d in cap_results.dhcp
    ], connection=connection)

    insert_many("stp_events", [
        {**s, "scan_run_id": ctx.scan_id} for s in cap_results.stp
    ], connection=connection)

    insert_many("snmp_polls", [
        {**p, "scan_run_id": ctx.scan_id} for p in snmp_results
    ], connection=connection)

    # Traffic counters delta — a single row covering the capture window.
    bucket = {
        "scan_run_id": ctx.scan_id,
        "interface": ctx.interface,
        "bucket_start": cap_results.started_at,
        "bucket_end": cap_results.completed_at,
        "rx_packets": _counter_delta(pre_counters, post_counters, "rx_packets"),
        "rx_bytes": _counter_delta(pre_counters, post_counters, "rx_bytes"),
        "rx_errors": _counter_delta(pre_counters, post_counters, "rx_errors"),
        "rx_dropped": _counter_delta(pre_counters, post_counters, "rx_dropped"),
        "tx_packets": _counter_delta(pre_counters, post_counters, "tx_packets"),
        "tx_bytes": _counter_delta(pre_counters, post_counters, "tx_bytes"),
        "broadcast_packets": cap_results.broadcast_packets,
        "multicast_packets": cap_results.multicast_packets,
        "tshark_total_packets": cap_results.total_packets,
    }
    insert_many("traffic_stats", [bucket], connection=connection)

    # Topology crawl results, if any. Persisted as nodes + edges so they
    # land in the bundle alongside the per-scan tables.
    if topology and (topology.get("nodes") or topology.get("edges")):
        insert_topology(
            ctx.scan_id,
            topology.get("nodes", []),
            topology.get("edges", []),
            connection=connection,
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
        ], connection=connection)

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
                "traceroute_path": dumps_jsonb(r.get("traceroute_path") or []),
            }
            for r in reachability
        ], connection=connection)

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
                "details": dumps_jsonb(s.get("details") or {}),
            }
            for s in services
            if s.get("ip")
        ], connection=connection)


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
    return dumps_jsonb(base)


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
