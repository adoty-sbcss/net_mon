from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .config import get_settings
from .db import complete_scan_run, insert_many, insert_scan_run, recent_network_scan
from .discovery import arp as arp_mod
from .discovery import interfaces as iface_mod
from .discovery import lldp as lldp_mod
from .discovery import nmap as nmap_mod
from .discovery import snmp as snmp_mod
from .discovery import tshark as tshark_mod
from .models import ScanContext

log = structlog.get_logger(__name__)


def _network_id(gateway_mac: str | None, cidr: str | None) -> str | None:
    if not cidr:
        return None
    return hashlib.sha256(f"{gateway_mac or 'no-gw'}|{cidr}".encode()).hexdigest()[:16]


def run_scan(*, interface: str, trigger_reason: str, force: bool) -> int | None:
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
    if not force and settings.mode == "field" and net_id:
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
        mode=settings.mode,
    )
    log.info("scan started",
             scan_id=scan_id, interface=state.name,
             cidr=state.primary_cidr, gateway=state.gateway_ip)

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
        if settings.snmp_enabled:
            try:
                candidates = _snmp_candidates(state.gateway_ip, lldp_neighbors,
                                              arp_results, nmap_results)
                log.info("snmp candidate set", count=len(candidates), ips=candidates)
                snmp_results = snmp_mod.poll(candidates)
                ctx.raw_outputs["snmp"] = snmp_results
            except Exception as exc:  # pragma: no cover — defensive
                log.warning("snmp poll failed", error=str(exc))

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
        )

    except Exception as exc:
        log.exception("scan failed", scan_id=scan_id, error=str(exc))
        error = str(exc)
    finally:
        duration = int(time.monotonic() - ctx.started_monotonic)
        complete_scan_run(scan_id, duration_sec=duration, error=error)
        log.info("scan complete", scan_id=scan_id, duration_sec=duration, error=error)

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
) -> list[str]:
    """Narrow set of IPs likely to actually speak SNMP.

    Includes:
      * The default gateway (almost always a router with SNMP).
      * Any LLDP/CDP-discovered management IPs (switches, APs).
      * Any ARP/nmap entry whose vendor OUI looks like a network vendor.

    Deliberately excludes random hosts (laptops, phones, printers, IoT).
    A trial with N communities × T timeout against 50 hosts can easily eat
    minutes; narrowing the set keeps scans fast.
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
        if looks_like_network_gear(r.get("vendor")):
            add(r.get("ip"))
    for r in nmap_results:
        if looks_like_network_gear(r.get("vendor")):
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


def _looks_like_mac(s: str | None) -> bool:
    if not s:
        return False
    parts = s.replace("-", ":").split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)
