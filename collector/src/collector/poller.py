from __future__ import annotations

import hashlib
import signal
import time

import structlog

from .config import get_settings
from .db import purge_old_scans, recent_network_scan
from .discovery import interfaces as iface_mod
from .scan import _vlan_of, run_scan

log = structlog.get_logger(__name__)

_stop = False
_last_purge: float | None = None


def _handle_signal(signum, frame):  # noqa: ANN001
    global _stop
    log.info("signal received, stopping", signum=signum)
    _stop = True


def _network_id(gateway_mac: str | None, cidr: str | None) -> str | None:
    if not cidr:
        return None
    key = f"{gateway_mac or 'no-gw'}|{cidr}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _maybe_purge(settings) -> None:  # noqa: ANN001
    """Local-DB retention: at most once/day, drop scan_runs (and cascaded per-scan
    tables) older than the configured window so the collector's own Postgres can't
    grow unbounded. A restart just runs it once on the next tick — harmless."""
    global _last_purge
    if settings.local_retention_days <= 0:
        return
    now = time.monotonic()
    if _last_purge is not None and (now - _last_purge) < 24 * 3600:
        return
    _last_purge = now
    try:
        n = purge_old_scans(settings.local_retention_days)
        if n:
            log.info("local retention: purged old scans",
                     deleted=n, retention_days=settings.local_retention_days)
    except Exception as exc:  # pragma: no cover — keep loop alive
        log.warning("local retention purge failed", error=str(exc))


def run_poller() -> None:
    settings = get_settings()
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("poller started",
             poll_interval=settings.poll_interval,
             rescan_interval=settings.rescan_interval)

    while not _stop:
        try:
            tick()
        except Exception as exc:  # pragma: no cover — keep loop alive
            log.exception("poller tick failed", error=str(exc))
        # Sleep in small slices so SIGTERM is handled quickly.
        for _ in range(settings.poll_interval):
            if _stop:
                break
            time.sleep(1)


def tick() -> None:
    """Scan every active interface whose current network hasn't been scanned
    within the rescan interval.

    This single DB-backed rule does everything we need:
      - A newly plugged-in network has no recent scan -> scanned on the next
        tick (within poll_interval seconds of link-up).
      - A stable network gets re-scanned once the rescan interval elapses,
        producing fresh hourly data for the uploader to bundle.
      - State lives in the DB (scan_runs), so a collector restart doesn't
        reset the schedule or cause a thundering re-scan.

    All interfaces with a usable IP are treated equally — the box's primary
    uplink and any secondary connections (Wi-Fi, future VLAN sub-interfaces)
    are each scanned on their own cadence. The primary is labeled in the
    scan record but not scanned any differently.
    """
    settings = get_settings()
    _maybe_purge(settings)
    states = iface_mod.snapshot(exclude_prefixes=settings.exclude_prefixes)
    primary = iface_mod.primary_interface()

    for st in states:
        if not st.has_usable_ip:
            continue

        # Skip VLANs the operator excluded (NETMON_EXCLUDE_VLANS) — e.g. noisy or
        # irrelevant VLANs on a monitored trunk. A manual `scan` ignores this.
        vlan_id, _ = _vlan_of(st.name)
        if vlan_id is not None and vlan_id in settings.exclude_vlan_set:
            continue

        net_id = _network_id(st.gateway_mac, st.primary_cidr)

        # Due for a scan if this network has NOT been scanned within the
        # rescan interval. recent_network_scan returns the most recent scan
        # row for net_id inside the window, or None.
        if net_id is not None:
            recent = recent_network_scan(net_id, settings.rescan_interval)
            if recent is not None:
                continue  # scanned recently enough; not due yet

        is_primary = (st.name == primary)
        log.info("triggering scan",
                 interface=st.name, cidr=st.primary_cidr,
                 gateway=st.gateway_ip, is_primary=is_primary,
                 reason="due_for_scan")
        run_scan(
            interface=st.name,
            trigger_reason="periodic" if net_id else "link_up",
            force=False,
            is_primary=is_primary,
        )
