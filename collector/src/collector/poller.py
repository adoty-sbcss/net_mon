from __future__ import annotations

import hashlib
import signal
import time

import structlog

from .config import get_settings
from .db import purge_heavy_snmp_polls, purge_old_scans, recent_network_scan
from .discovery import device_config, dhcp_server
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
    grow unbounded, then purge the HEAVY topology SNMP rows on their own, shorter
    window — they alone were ~92% of a live box's entire db (see
    db.HEAVY_SNMP_OID_NAMES). A restart just runs it once on the next tick —
    harmless. Each knob disables independently at <=0."""
    global _last_purge
    if settings.local_retention_days <= 0 and settings.snmp_bulk_retention_days <= 0:
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
    # Separate try: a failure purging the heavy rows must not mask the scan purge
    # above, and vice versa.
    try:
        n = purge_heavy_snmp_polls(settings.snmp_bulk_retention_days)
        if n:
            log.info("local retention: purged heavy SNMP topology rows",
                     deleted=n, retention_days=settings.snmp_bulk_retention_days)
    except Exception as exc:  # pragma: no cover — keep loop alive
        log.warning("heavy SNMP retention purge failed", error=str(exc))


def run_poller() -> None:
    settings = get_settings()
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("poller started",
             poll_interval=settings.poll_interval,
             rescan_interval=settings.rescan_interval)

    # A light capture pass goes through run_scan(force=False), so it is subject to
    # the cooldown_seconds anti-flap floor: set capture_interval BELOW cooldown and
    # EVERY light pass is silently rejected ("cooldown active, skipping") — the
    # feature reads as enabled but never runs. The defaults (900 > 300) are safe, so
    # this only fires on a real misconfig; name both values so it's actionable.
    if 0 < settings.capture_interval < settings.cooldown_seconds:
        log.warning(
            "capture_interval is below cooldown_seconds — light capture passes will "
            "be skipped by the cooldown; raise NETMON_CAPTURE_INTERVAL above "
            "NETMON_COOLDOWN_SECONDS (or lower the cooldown) for it to take effect",
            capture_interval=settings.capture_interval,
            cooldown_seconds=settings.cooldown_seconds,
        )

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


def _is_excluded_vlan(iface_name: str, settings) -> bool:
    """True if this interface is a VLAN the operator excluded (NETMON_EXCLUDE_VLANS).

    One predicate, used by BOTH the scan loop and the capture-budget warning below,
    so the count the warning reasons about can never drift from the set of
    interfaces actually scanned.
    """
    vlan_id, _ = _vlan_of(iface_name)
    return vlan_id is not None and vlan_id in settings.exclude_vlan_set


# Latched so a standing misconfiguration logs once, not every poll tick (~30s);
# cleared when the condition clears, so a later regression is reported again.
_capture_budget_warned = False


def _warn_capture_budget(settings, monitored: int) -> None:
    """Warn when the capture window, MULTIPLIED across monitored interfaces, no
    longer fits in the light-capture interval.

    capture_seconds is a per-scan number, but run_scan blocks for its full length
    and tick() walks the interfaces sequentially — so the real cost of a pass is
    monitored x capture_seconds. On a trunk carrying several VLANs that product
    quietly outgrows capture_interval, and light passes then run continuously and
    still fall behind. Nothing bounds it at config time because the VLAN count is
    only known at runtime, which is exactly why it has to be said out loud here:
    this product has repeatedly shipped budgets that were silently exceeded with no
    message naming the limit that bound.
    """
    global _capture_budget_warned
    if not settings.capture_interval or monitored <= 0:
        return
    total = monitored * settings.capture_seconds
    if total < settings.capture_interval:
        _capture_budget_warned = False
        return
    if _capture_budget_warned:
        return
    _capture_budget_warned = True
    log.warning(
        "capture window x monitored interfaces exceeds capture_interval — light "
        "capture passes cannot keep their cadence and will run back-to-back; lower "
        "NETMON_CAPTURE_SECONDS, exclude VLANs (NETMON_EXCLUDE_VLANS), or raise "
        "NETMON_CAPTURE_INTERVAL",
        monitored_interfaces=monitored,
        capture_seconds=settings.capture_seconds,
        total_capture_seconds=total,
        capture_interval=settings.capture_interval,
    )


def tick() -> None:
    """Scan every active interface whose current network hasn't been scanned
    within the rescan interval.

    This single DB-backed rule does everything we need:
      - A newly plugged-in network has no recent scan -> scanned on the next
        tick (within poll_interval seconds of link-up).
      - A stable network gets re-scanned once the rescan interval elapses,
        producing fresh hourly data for the uploader to bundle.
      - Between those full re-scans, a lighter capture-only pass (passive
        tshark + ARP, no SNMP/reachability/DNS/mDNS) runs every
        capture_interval, so sporadic DHCP/STP is sampled far more often than
        the hourly full scan without paying for the full discovery each time.
      - State lives in the DB (scan_runs), so a collector restart doesn't
        reset the schedule or cause a thundering re-scan.

    All interfaces with a usable IP are treated equally — the box's primary
    uplink and any secondary connections (Wi-Fi, future VLAN sub-interfaces)
    are each scanned on their own cadence. The primary is labeled in the
    scan record but not scanned any differently.
    """
    settings = get_settings()
    _maybe_purge(settings)
    # Authoritative DHCP server intel (DHCP-2): gated periodic WinRM pass to any
    # authorized server the operator enabled collection on. Self-gates on the
    # enable flag + interval + presence of a target list, and is wall-clock
    # budgeted, so a slow/unreachable server can't stall the tick. try/except so
    # a collection error never kills the poll loop (like the retention purge).
    try:
        dhcp_server.collect_and_store(settings)
    except Exception as exc:  # pragma: no cover — keep loop alive
        log.warning("dhcp intel collect failed", error=str(exc))
    # NCM-1 device config backup — same gated-periodic pattern; isolated so a
    # backup error never kills the poll loop.
    try:
        device_config.collect_and_store(settings)
    except Exception as exc:  # pragma: no cover — keep loop alive
        log.warning("device config backup failed", error=str(exc))
    states = iface_mod.snapshot(exclude_prefixes=settings.exclude_prefixes)
    primary = iface_mod.primary_interface()

    _warn_capture_budget(
        settings,
        sum(1 for st in states
            if st.has_usable_ip and not _is_excluded_vlan(st.name, settings)),
    )

    for st in states:
        if not st.has_usable_ip:
            continue

        # Skip VLANs the operator excluded (NETMON_EXCLUDE_VLANS) — e.g. noisy or
        # irrelevant VLANs on a monitored trunk. A manual `scan` ignores this.
        if _is_excluded_vlan(st.name, settings):
            continue

        net_id = _network_id(st.gateway_mac, st.primary_cidr)
        is_primary = (st.name == primary)

        # No stable network id yet (e.g. just linked up, no gateway) -> full scan.
        if net_id is None:
            log.info("triggering scan", interface=st.name, cidr=st.primary_cidr,
                     gateway=st.gateway_ip, is_primary=is_primary, reason="link_up")
            run_scan(interface=st.name, trigger_reason="link_up",
                     force=False, is_primary=is_primary)
            continue

        # Due for a FULL scan if this network has NOT had a full scan within the
        # rescan interval. exclude_capture=True is essential: the light capture
        # pass below writes a scan_runs row every capture_interval, and without
        # this filter those rows would keep satisfying the (longer) rescan window
        # and starve the full scan forever once light passes are enabled.
        if recent_network_scan(
                net_id, settings.rescan_interval, exclude_capture=True) is None:
            log.info("triggering scan", interface=st.name, cidr=st.primary_cidr,
                     gateway=st.gateway_ip, is_primary=is_primary, reason="due_for_scan")
            run_scan(interface=st.name, trigger_reason="periodic",
                     force=False, is_primary=is_primary)
            continue

        # Not due for a full scan. Run a LIGHT capture-only pass if the network
        # hasn't had ANY scan within capture_interval -> samples DHCP/STP far more
        # often than the hourly full scan without paying for full discovery. A
        # full scan also captures, so it resets this clock too.
        if settings.capture_interval > 0 and (
                recent_network_scan(net_id, settings.capture_interval) is None):
            log.info("triggering light capture", interface=st.name,
                     cidr=st.primary_cidr, is_primary=is_primary, reason="capture_due")
            run_scan(interface=st.name, trigger_reason="capture",
                     force=False, is_primary=is_primary, light=True)
