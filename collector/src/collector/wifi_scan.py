"""Wi-Fi scan orchestration — separate from scan.py (wired) but follows the
same shape: open a `wifi_scans` row, run discovery, persist, close it out.

Triggered by:
  - Manual CLI: `./netmon wifi-scan` -> python -m collector wifi-scan
  - Hourly scheduler (monitor profile, see uploader-adjacent scheduler)
  - First-boot wizard's optional "test now" step
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

import structlog

from .config import get_settings
from .db import (
    complete_wifi_scan,
    insert_wifi_rows,
    insert_wifi_scan,
)
from .discovery import wifi as wifi_disc
from .logging_setup import audit
from . import wifi_anomalies

log = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def _oui_parser():
    try:
        from manuf import manuf
        return manuf.MacParser()
    except Exception as exc:
        log.warning("manuf unavailable; AP vendor lookups disabled", error=str(exc))
        return None


def run_wifi_scan(*, trigger_reason: str, interface: str | None = None) -> int | None:
    """Run a single Wi-Fi scan. Returns the wifi_scans.id on success, else None."""
    settings = get_settings()
    if not settings.wifi_enabled:
        log.info("wifi disabled (NETMON_WIFI_ENABLED=false), skipping")
        return None

    iface = interface or settings.wifi_interface
    if not iface:
        log.warning("no Wi-Fi interface configured (NETMON_WIFI_INTERFACE empty)")
        return None

    duration = settings.effective_wifi_scan_seconds
    wifi_scan_id = insert_wifi_scan(
        trigger_reason=trigger_reason,
        interface=iface,
        profile=settings.profile,
    )
    audit("wifi_scan_started",
          wifi_scan_id=wifi_scan_id, interface=iface,
          profile=settings.profile, duration=duration,
          trigger=trigger_reason)
    log.info("wifi scan started",
             wifi_scan_id=wifi_scan_id, interface=iface,
             profile=settings.profile, duration=duration)

    started = time.monotonic()
    error: str | None = None
    notes: str | None = None
    channels_scanned: list[int] = []

    try:
        # iw scan dominates the runtime; pass the profile-driven scan_timeout.
        # In Phase 1 we don't actually hop channels ourselves — `iw scan`
        # already sweeps every supported channel. The duration param caps the
        # subprocess timeout.
        result = wifi_disc.run_wifi_scan(iface, scan_timeout=duration)
        if result.error:
            error = result.error
            log.warning("iw scan reported error", interface=iface, error=error)

        # Decorate APs with vendor OUI lookups.
        parser = _oui_parser()
        for ap in result.aps:
            if parser and ap.get("bssid"):
                try:
                    ap["vendor"] = parser.get_manuf_long(ap["bssid"])
                except Exception:
                    pass

        # Persist APs.
        ap_rows: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        for ap in result.aps:
            ap_rows.append({
                "bssid": ap.get("bssid"),
                "essid": ap.get("essid"),
                "channel": ap.get("channel"),
                "frequency_mhz": ap.get("frequency_mhz"),
                "band": ap.get("band"),
                "privacy": ap.get("privacy"),
                "cipher": ap.get("cipher"),
                "auth": ap.get("auth"),
                "signal_dbm": ap.get("signal_dbm"),
                "beacon_count": ap.get("beacon_count"),
                "data_count": None,
                "vendor": ap.get("vendor"),
                "first_seen_at": now,
                "last_seen_at": now,
                "extra": "{}",   # JSONB; keep simple for Phase 1
            })
        insert_wifi_rows("wifi_aps", wifi_scan_id, ap_rows)

        # Persist channel stats and remember which channels we touched.
        ch_rows: list[dict[str, Any]] = []
        for row in result.channel_stats:
            ch_rows.append({
                "channel": row.get("channel"),
                "frequency_mhz": row.get("frequency_mhz"),
                "band": row.get("band"),
                "ap_count": row.get("ap_count") or 0,
                "noise_dbm": row.get("noise_dbm"),
                "active_ms": row.get("active_ms"),
                "busy_ms": row.get("busy_ms"),
                "busy_pct": row.get("busy_pct"),
            })
            if row.get("channel") is not None:
                channels_scanned.append(int(row["channel"]))
        insert_wifi_rows("wifi_channel_stats", wifi_scan_id, ch_rows)

        # Apply anomaly rules and persist findings.
        events = wifi_anomalies.detect(result.aps, result.channel_stats)
        # Coerce evidence dict to JSON-loadable text for the JSONB column.
        import json as _json
        event_rows: list[dict[str, Any]] = []
        for ev in events:
            event_rows.append({
                "kind": ev["kind"],
                "severity": ev["severity"],
                "title": ev["title"],
                "detail": ev.get("detail"),
                "evidence": _json.dumps(ev.get("evidence") or {}),
            })
        insert_wifi_rows("wifi_events", wifi_scan_id, event_rows)

        notes = (f"ap_count={len(ap_rows)}; channel_rows={len(ch_rows)}; "
                 f"events={len(event_rows)}")

        if events:
            for ev in events:
                audit("wifi_finding",
                      wifi_scan_id=wifi_scan_id,
                      kind=ev["kind"], severity=ev["severity"],
                      title=ev["title"])

    except Exception as exc:
        log.exception("wifi scan failed", wifi_scan_id=wifi_scan_id, error=str(exc))
        audit("wifi_scan_failed", wifi_scan_id=wifi_scan_id, error=str(exc))
        error = str(exc)
    finally:
        duration_sec = int(time.monotonic() - started)
        complete_wifi_scan(
            wifi_scan_id,
            duration_sec=duration_sec,
            channels_scanned=sorted(set(channels_scanned)) or None,
            error=error,
            notes=notes,
        )
        log.info("wifi scan complete",
                 wifi_scan_id=wifi_scan_id,
                 duration_sec=duration_sec, error=error)
        audit("wifi_scan_completed",
              wifi_scan_id=wifi_scan_id, duration_sec=duration_sec,
              error=error or "none", notes=notes or "")

    return wifi_scan_id
