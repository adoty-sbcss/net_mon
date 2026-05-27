"""Background scheduler that fires a Wi-Fi scan once per hour for boxes in
the `monitor` profile. The `survey` profile doesn't auto-schedule — those
boxes scan only on manual trigger (`./netmon wifi-scan`).

The scheduler thread sleeps until the configured minute-of-hour, runs a
scan, and loops. Sleeps in short slices so SIGTERM is handled quickly.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta

import structlog

from .config import get_settings
from .logging_setup import audit
from .wifi_scan import run_wifi_scan

log = structlog.get_logger(__name__)

_stop_event = threading.Event()


def request_stop() -> None:
    _stop_event.set()


def _local_now() -> datetime:
    return datetime.now().astimezone()


def _next_scheduled_run() -> datetime:
    """Next occurrence of `wifi_hourly_minute` minutes past the hour."""
    s = get_settings()
    minute = max(0, min(59, int(s.wifi_hourly_minute)))
    now = _local_now()
    target = now.replace(minute=minute, second=0, microsecond=0)
    if target <= now:
        target = target + timedelta(hours=1)
    return target


def _run_loop() -> None:
    s = get_settings()
    if s.profile != "monitor":
        log.info("wifi scheduler not running — profile is not 'monitor'",
                 profile=s.profile)
        return
    if not s.wifi_enabled:
        log.info("wifi scheduler not running — NETMON_WIFI_ENABLED=false")
        return
    if not s.wifi_interface:
        log.warning("wifi scheduler not running — NETMON_WIFI_INTERFACE not set")
        return

    log.info("wifi scheduler started",
             interface=s.wifi_interface, hourly_minute=s.wifi_hourly_minute)

    while not _stop_event.is_set():
        target = _next_scheduled_run()
        log.debug("wifi scheduler sleeping until next run", target=target.isoformat())
        while not _stop_event.is_set():
            remaining = (target - _local_now()).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(60.0, remaining))
        if _stop_event.is_set():
            return
        try:
            run_wifi_scan(trigger_reason="hourly")
        except Exception as exc:
            log.exception("wifi scheduler tick failed", error=str(exc))
            audit("wifi_scheduler_error", error=str(exc))


def start_in_background() -> threading.Thread | None:
    """Spawn the scheduler as a daemon thread. Returns it (or None if skipped)."""
    s = get_settings()
    if s.profile != "monitor" or not s.wifi_enabled or not s.wifi_interface:
        return None
    t = threading.Thread(target=_run_loop, name="netmon-wifi-scheduler", daemon=True)
    t.start()
    return t
