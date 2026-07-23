from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import structlog

from .bundle import build_hourly_bundle
from .config import get_settings
from .db import (
    bundle_build_lock,
    get_bundle_rows,
    list_completed_scan_times_since,
    list_pending_bundles,
    list_scan_runs_in_window,
    list_uploaded_bundles_older_than,
    mark_bundle_gave_up,
    mark_bundles_gave_up,
    record_bundle_built,
    record_bundle_upload_failure,
    record_bundle_uploaded,
)
from .logging_setup import audit

# How long we keep successfully-uploaded ZIPs on local disk before pruning.
# Adjust by editing here; not surfaced as env to keep config simple for v1.
LOCAL_BUNDLE_RETENTION_DAYS = 30

# --- Catch-up (F-COL-19) ----------------------------------------------------
# How far back a startup/hourly catch-up pass looks for hours that have scans but
# no complete bundle. The collector purges local scans at local_retention_days
# (default 14), so a 48h horizon is always well inside retention — we can never
# be asked to bundle an hour whose scans are already gone. It also comfortably
# covers the two real outage shapes: the nightly auto-update straddling the top
# of the hour, and a box that was powered off overnight.
CATCHUP_HORIZON_HOURS = 48
# Ceiling on builds per pass so a box returning from a long outage spreads the
# CPU/disk cost over several ticks instead of one multi-hour stall. Newest hours
# are built first, so the freshest data always ships in the first pass.
CATCHUP_MAX_BUILDS_PER_PASS = 12
# Fire the tick slightly AFTER the boundary. A scan that completes at 13:59:59.8
# can commit at 14:00:00.2; without the grace we'd query [13:00,14:00) before
# that row is visible and drop it from the bundle forever.
BOUNDARY_GRACE_SEC = 15

# --- Bounded flush (F-COL-20) -----------------------------------------------
# Ceiling on upload attempts per tick: a deep backlog drains over several ticks
# rather than one tick running for hours (and ignoring request_stop() while it
# does).
UPLOAD_MAX_ATTEMPTS_PER_TICK = 30
# Circuit breaker: N consecutive failures means the transport/depot is down, not
# that one bundle is bad. Stop hammering it and let the next tick retry.
UPLOAD_BREAKER_CONSECUTIVE_FAILURES = 3
# When to stop retrying a bundle for good. The age cap is the one that binds in
# practice (and bounds local disk at ~7d x 24h = ~168 ZIPs); the retry cap is a
# backstop for a bundle that somehow fails much faster than the backoff.
BUNDLE_GIVE_UP_DAYS = 7
BUNDLE_GIVE_UP_RETRIES = 60

log = structlog.get_logger(__name__)


def _local_now() -> datetime:
    """Local-time tz-aware now, using whatever zone the container is configured for."""
    return datetime.now().astimezone()


def _next_hour_boundary(now: datetime | None = None) -> datetime:
    n = now or _local_now()
    return n.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)


def device_name() -> str:
    """Human-readable device label for bundle metadata. Falls back to hostname."""
    s = get_settings()
    if s.device_name:
        return s.device_name
    return socket.gethostname()


def _identity_slugs() -> tuple[str, str, str] | None:
    """Return (district, school, device) slugs if all three are set, else None.
    Pre-wizard boxes have empty slugs and fall back to legacy flat uploads."""
    s = get_settings()
    if s.district_slug and s.school_slug and s.device_slug:
        return s.district_slug, s.school_slug, s.device_slug
    return None


def _active_transport(s) -> str | None:
    """Which upload verb this box uses this hour, or None (keep bundles local).

    'blob' (HTTPS to the depot via a dashboard-minted SAS) is the only transport;
    any other bundle_transport value leaves the box in the pre-install staging
    state with uploads OFF. blob_upload raises cleanly if enrollment / dashboard
    URL is missing, so the bundle just stays queued and retries.
    """
    return "blob" if s.bundle_transport == "blob" else None


def _filename_for(window_end: datetime) -> str:
    """Filename for the bundle covering the hour that just completed.

    With identity set:  <device_slug>_YYYY_MM_DD_HH.zip
    Legacy fallback:    <device_name>_YYYY_MM_DD_HH.zip

    The slug variant avoids spaces in filenames and stays consistent with the
    hierarchical depot path that contains the same slug.
    """
    completed_hour = window_end - timedelta(hours=1)
    stamp = completed_hour.strftime('%Y_%m_%d_%H')
    slugs = _identity_slugs()
    if slugs is not None:
        _, _, device_slug = slugs
        return f"{device_slug}_{stamp}.zip"
    return f"{device_name()}_{stamp}.zip"


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def _build_hour(window_end: datetime) -> tuple[str, int] | None:
    """Build (or REBUILD) the bundle for the hour ending at window_end.

    Returns (filename, scan_count), or None when the hour has no scans to
    bundle. Unconditional: the caller owns the "should we build this hour?"
    decision — catch-up applies the staleness predicate, an operator's manual
    upload-now deliberately re-ships.
    """
    settings = get_settings()
    window_start = window_end - timedelta(hours=1)
    filename = _filename_for(window_end)
    with bundle_build_lock(filename):
        # The query belongs inside the lock. A builder that waited for another
        # process must take a fresh snapshot, never overwrite it with an older one.
        runs = list_scan_runs_in_window(window_start, window_end)
        if not runs:
            log.info("no scans in this hour, nothing new to bundle",
                     start=window_start.isoformat(), end=window_end.isoformat())
            return None

        scan_ids = [int(r["id"]) for r in runs]
        bundle_path = settings.bundle_dir / filename
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        build_hourly_bundle(
            scan_ids,
            bundle_path,
            device_name=device_name(),
            window_start=window_start,
            window_end=window_end,
        )
        try:
            size = bundle_path.stat().st_size
        except OSError:
            size = 0
        record_bundle_built(filename, str(bundle_path), size)
        audit("bundle_built", filename=filename, size_bytes=size, scans=len(scan_ids))
        return filename, len(scan_ids)


def _hour_windows_with_scans(now: datetime | None = None) -> list[datetime]:
    """Every fully-elapsed hour window (newest first) inside the catch-up horizon
    that has at least one completed scan, i.e. every hour that OWES a bundle.

    Grouping happens here rather than in SQL on purpose — see
    db.list_completed_scan_times_since. Only windows that have actually CLOSED
    (window_end <= now) are returned; bundling a still-open hour would produce a
    partial bundle and burn the filename.
    """
    n = now or _local_now()
    windows: set[datetime] = set()
    for completed_at in list_completed_scan_times_since(CATCHUP_HORIZON_HOURS):
        # Bundle filenames are stamped in collector-local time, so bucket in it.
        local = completed_at.astimezone()
        window_end = local.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        if window_end <= n:
            windows.add(window_end)
    return sorted(windows, reverse=True)


def _catch_up_missed_hours(now: datetime | None = None) -> int:
    """Build any closed hour that has scans but no complete bundle. Returns the
    number of bundles built.

    This is the F-COL-19 fix. The old scheduler was forward-only: an hour the
    collector slept through (the nightly auto-update straddles the boundary, and
    every dashboard config-push recreates the container) was NEVER bundled, and
    its scans were silently deleted at local_retention_days. Nobody found out —
    the dashboard just had a hole.

    Eligibility per hour, from the bundle_uploads row:
      - no row            -> build   (we were down across the boundary)
      - gave_up_at set    -> skip    (terminal for automation; manual only)
      - built_at < we     -> build   (PARTIAL: built mid-hour by an upload-now,
                                      so it's missing the rest of the hour)
      - otherwise         -> skip    (complete; possibly already ingested)

    The built_at >= window_end check is the idempotency guarantee: a complete
    hour is never auto-rebuilt, so we never re-ship an hour the dashboard has
    already ingested. It also self-limits — after one rebuild built_at >= we, so
    the next pass skips it. No loop.
    """
    n = now or _local_now()
    # DST fall-back: the two absolute 01:00-02:00 hours share one local stamp and
    # therefore one filename, so one of them wins this dict and the other is not
    # bundled. Accepted: the real fix is a UTC filename contract, which is a
    # cross-repo (collector + dashboard dedupe key) change and out of scope here.
    by_name = {_filename_for(we): we for we in _hour_windows_with_scans(n)}
    if not by_name:
        return 0

    rows = get_bundle_rows(list(by_name))
    to_build: list[datetime] = []
    for filename, window_end in by_name.items():
        row = rows.get(filename)
        if row is None:
            to_build.append(window_end)
        elif row.get("gave_up_at") is not None:
            continue
        elif row["built_at"] < window_end:
            to_build.append(window_end)

    if not to_build:
        return 0

    # Newest first: if we're capped, the freshest data ships this pass and the
    # rest follows next tick.
    to_build.sort(reverse=True)
    if len(to_build) > CATCHUP_MAX_BUILDS_PER_PASS:
        log.info("catch-up capped, remaining hours will build next tick",
                 eligible=len(to_build), cap=CATCHUP_MAX_BUILDS_PER_PASS)

    built = 0
    for window_end in to_build[:CATCHUP_MAX_BUILDS_PER_PASS]:
        if _stop_event.is_set():
            break
        try:
            result = _build_hour(window_end)
        except Exception as exc:
            # One unbuildable hour (corrupt scan row, disk hiccup) must not block
            # the others — that would reintroduce the data loss we're fixing.
            log.exception("catch-up build failed for hour",
                          window_end=window_end.isoformat(), error=str(exc))
            continue
        if result is None:
            continue
        filename, scans = result
        audit("bundle_catchup_built", filename=filename, scans=scans,
              window_end=window_end.isoformat())
        built += 1
    if built:
        log.info("catch-up built missed hours", count=built)
    return built


# ---------------------------------------------------------------------------
# Uploading
# ---------------------------------------------------------------------------


@dataclass
class _FlushCounters:
    """What one _flush_pending pass did. Drives build_and_upload_hour's result."""

    attempted: int = 0          # uploads actually tried (success or failure)
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0            # deferred by retry backoff
    gave_up: int = 0            # tombstoned this pass
    last_error: str | None = None
    current_remote_path: str | None = None
    breaker_tripped: bool = False


def _retry_delay(retry_count: int) -> timedelta:
    """How long a bundle must wait before its next upload attempt.

    Fast retries for a transient blip, then back off hard: a depot outage lasting
    days shouldn't have every bundle re-trying every hour forever.
    """
    if retry_count < 3:
        return timedelta(0)
    if retry_count < 8:
        return timedelta(hours=4)
    return timedelta(hours=12)


def _flush_pending(
    transport: str,
    now: datetime | None = None,
    current_filename: str | None = None,
) -> _FlushCounters:
    """Upload pending bundles, bounded. Returns what happened.

    This is the F-COL-20 fix. The old flush re-tried EVERY pending bundle on
    EVERY tick, serially, with no backoff, no cap, and no give-up: a persistent
    upload outage grew the pending set without bound, and each tick took longer
    than the last re-failing the whole queue, all while ignoring request_stop().

    Bounds, in order: give up on hopeless bundles (frees disk), skip anything in
    backoff, stop after UPLOAD_MAX_ATTEMPTS_PER_TICK attempts, and trip a breaker
    after UPLOAD_BREAKER_CONSECUTIVE_FAILURES consecutive failures.
    """
    counters = _FlushCounters()
    n = now or _local_now()

    # 1. Give-up sweep FIRST — it unlinks ZIPs, so a disk-pressured box reclaims
    # space even if every upload below fails.
    try:
        for row in mark_bundles_gave_up(BUNDLE_GIVE_UP_DAYS, BUNDLE_GIVE_UP_RETRIES):
            try:
                Path(row["local_path"]).unlink(missing_ok=True)
            except OSError as exc:
                log.warning("could not delete given-up bundle file",
                            filename=row["filename"], error=str(exc))
            counters.gave_up += 1
            log.warning("gave up on bundle, it will never be uploaded",
                        filename=row["filename"], retry_count=row["retry_count"],
                        last_error=row["last_error"])
            audit("bundle_gave_up", filename=row["filename"],
                  built_at=row["built_at"].isoformat() if row["built_at"] else None,
                  retry_count=row["retry_count"], reason="too old or too many retries",
                  last_error=row["last_error"])
    except Exception as exc:
        # A failed sweep must not stop us from uploading.
        log.warning("bundle give-up sweep failed", error=str(exc))

    pending = list_pending_bundles()
    if not pending:
        return counters

    log.info("uploading pending bundles", count=len(pending), transport=transport)
    # Guard the missing-file give-up: if the whole bundle dir is gone (unmounted
    # volume, bad deploy) we'd otherwise tombstone the entire queue in one pass.
    bundle_dir_present = get_settings().bundle_dir.is_dir()
    consecutive_failures = 0

    for row in pending:
        if _stop_event.is_set():
            log.info("stop requested, ending flush early",
                     attempted=counters.attempted)
            break
        if counters.attempted >= UPLOAD_MAX_ATTEMPTS_PER_TICK:
            log.info("upload attempt cap reached, rest will retry next tick",
                     cap=UPLOAD_MAX_ATTEMPTS_PER_TICK, pending=len(pending))
            break
        if consecutive_failures >= UPLOAD_BREAKER_CONSECUTIVE_FAILURES:
            counters.breaker_tripped = True
            log.warning("upload breaker tripped, transport looks down",
                        consecutive_failures=consecutive_failures,
                        transport=transport, pending=len(pending))
            audit("bundle_upload_breaker_tripped", transport=transport,
                  consecutive_failures=consecutive_failures, pending=len(pending))
            break

        filename = row["filename"]
        last_attempt_at = row.get("last_attempt_at")
        retry_count = int(row.get("retry_count") or 0)
        if last_attempt_at is not None and (n - last_attempt_at) < _retry_delay(retry_count):
            counters.skipped += 1
            continue

        path = Path(row["local_path"])
        if not path.exists():
            # Not a transport problem — retrying can never fix it, so don't burn
            # an attempt (or the breaker) on it.
            if bundle_dir_present:
                log.warning("pending bundle file missing on disk, giving up on it",
                            filename=filename, path=str(path))
                mark_bundle_gave_up(filename, "local file missing")
                counters.gave_up += 1
                audit("bundle_gave_up", filename=filename, reason="local file missing")
            else:
                log.warning("bundle dir missing, not giving up on pending bundles",
                            bundle_dir=str(get_settings().bundle_dir), filename=filename)
                counters.skipped += 1
            continue

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        counters.attempted += 1
        try:
            from . import blob_upload
            remote = blob_upload.upload_file_blob(path)
        except Exception as exc:
            err = str(exc)
            log.exception("bundle upload failed", transport=transport,
                          filename=filename, error=err)
            record_bundle_upload_failure(filename, err)
            audit("bundle_upload_failed", filename=filename, transport=transport, error=err)
            counters.failed += 1
            counters.last_error = err
            consecutive_failures += 1
            continue

        record_bundle_uploaded(filename, remote)
        audit("bundle_uploaded", filename=filename, remote_path=remote,
              transport=transport, size_bytes=size)
        counters.succeeded += 1
        consecutive_failures = 0
        if filename == current_filename:
            counters.current_remote_path = remote

    return counters


def build_and_upload_hour(window_end: datetime) -> dict[str, str | None]:
    """Build a bundle for the hour ending at window_end and upload it.
    Also retries any prior bundle whose upload failed, and prunes old
    successfully-uploaded local files.

    Returns dict with: local_path, remote_path, status, message, scans.

    This is the MANUAL path (`netmon upload-now` and the dashboard's upload-now
    command). It deliberately rebuilds and re-ships the hour unconditionally —
    that's the operator asking for it. The hourly scheduler does NOT call this;
    it uses _catch_up_missed_hours + _flush_pending, which never re-ship an hour
    that already has a complete bundle.
    """
    settings = get_settings()
    window_start = window_end - timedelta(hours=1)
    result: dict[str, str | None] = {
        "local_path": None, "remote_path": None,
        "status": "skipped", "message": None,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "scans": "0",
        "retried": "0",
    }

    # 1. Build the current-hour bundle (if there's anything to bundle).
    built = _build_hour(window_end)
    current_filename: str | None = None
    if built is not None:
        current_filename, scans = built
        result["scans"] = str(scans)
        result["local_path"] = str(settings.bundle_dir / current_filename)

    # 2. Try to upload every pending bundle (today's plus anything orphaned
    # from earlier failed runs).
    transport = _active_transport(settings)
    if transport is None:
        result["status"] = "saved_only"
        result["message"] = (
            "no upload transport active (bundle_transport != blob); "
            "bundles kept locally"
        )
        return result

    counters = _flush_pending(transport, current_filename=current_filename)
    result["remote_path"] = counters.current_remote_path

    # 3. Result summary. `retried` counts the pending bundles we attempted that
    # were NOT the one we just built for this hour.
    result["retried"] = str(max(0, counters.attempted - (1 if built is not None else 0)))
    if counters.succeeded and not counters.failed:
        result["status"] = "uploaded"
        result["message"] = f"uploaded {counters.succeeded} bundle(s)"
    elif counters.succeeded and counters.failed:
        result["status"] = "partial"
        result["message"] = (f"{counters.succeeded} bundle(s) uploaded, "
                             f"{counters.failed} failed (last error: {counters.last_error})")
    elif counters.failed:
        result["status"] = "upload_failed"
        result["message"] = counters.last_error or "all uploads failed"
    elif built is not None:
        # Nothing attempted but we did build: another process already shipped it.
        result["status"] = "uploaded"
        result["message"] = "current bundle was the only pending one and it shipped"
    elif counters.skipped:
        # status stays "skipped" — nothing is wrong, the queue is just in backoff.
        result["message"] = f"{counters.skipped} pending bundle(s) waiting on retry backoff"
    elif counters.gave_up:
        result["message"] = f"gave up on {counters.gave_up} unshippable bundle(s)"
    else:
        result["message"] = "nothing pending to upload"

    # 4. Disk hygiene.
    _prune_old_uploaded_bundles()
    return result


def _prune_old_uploaded_bundles() -> None:
    """Delete local bundle files that were uploaded > N days ago."""
    try:
        rows = list_uploaded_bundles_older_than(LOCAL_BUNDLE_RETENTION_DAYS)
    except Exception as exc:
        log.warning("prune query failed", error=str(exc))
        return
    if not rows:
        return
    n = 0
    for row in rows:
        p = Path(row["local_path"])
        if p.exists():
            try:
                p.unlink()
                n += 1
            except OSError as exc:
                log.warning("could not delete bundle file",
                            filename=row["filename"], error=str(exc))
    if n:
        log.info("pruned old uploaded bundles", count=n,
                 retention_days=LOCAL_BUNDLE_RETENTION_DAYS)
        audit("bundles_pruned", count=n, retention_days=LOCAL_BUNDLE_RETENTION_DAYS)


# ---------------------------------------------------------------------------
# Hourly scheduler thread
# ---------------------------------------------------------------------------


_stop_event = threading.Event()


def request_stop() -> None:
    _stop_event.set()


def _tick(startup: bool = False) -> None:
    """One uploader pass: bundle whatever owes a bundle, ship what's pending,
    prune what's safe to delete.

    Note there's no window argument. The tick doesn't build "the hour that just
    ended" — it asks which hours are MISSING a bundle and builds those. That's
    what makes a missed boundary self-healing: a tick that runs late (or not at
    all) leaves work for the next tick instead of losing it, because nothing is
    keyed on the tick firing at the right moment.
    """
    transport = _active_transport(get_settings())
    if transport is None:
        # Transport was turned off under us by a config-push; keep the loop alive
        # so turning it back on doesn't need a restart.
        log.info("no active transport, skipping tick", startup=startup)
        return
    _catch_up_missed_hours()
    _flush_pending(transport)
    _prune_old_uploaded_bundles()


def _run_scheduler_loop() -> None:
    s = get_settings()
    transport = _active_transport(s)
    if transport is None:
        log.info("uploader disabled (no active transport), scheduler not running")
        return
    log.info("uploader scheduler started",
             transport=transport, device=device_name(),
             identity_set=_identity_slugs() is not None)

    # Startup catch-up BEFORE arming the forward loop. This is the whole point of
    # F-COL-19: we just came up, and the reason we were down (nightly auto-update,
    # config-push container recreate, reboot) is exactly what makes us miss a
    # boundary. Without this, an hour we slept through is lost for good.
    try:
        _tick(startup=True)
    except Exception as exc:
        log.exception("startup uploader tick failed", error=str(exc))

    while not _stop_event.is_set():
        target = _next_hour_boundary()
        # Fire just after the boundary so a scan that completed at :59:59.x has
        # certainly committed and lands in its own hour's bundle.
        fire_at = target + timedelta(seconds=BOUNDARY_GRACE_SEC)
        log.debug("uploader sleeping until next top-of-hour",
                  target=target.isoformat(), fire_at=fire_at.isoformat())
        # Wake on the hour, but check every 60s in case the process is stopping.
        while not _stop_event.is_set():
            remaining = (fire_at - _local_now()).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(60.0, remaining))
        if _stop_event.is_set():
            return
        try:
            _tick()
        except Exception as exc:
            log.exception("hourly upload tick failed", error=str(exc))


def start_in_background() -> threading.Thread | None:
    """Spawn the scheduler as a daemon thread. Returns the thread (or None if disabled)."""
    s = get_settings()
    if _active_transport(s) is None:
        log.info("uploader disabled (no active transport), not spawning scheduler thread")
        return None
    t = threading.Thread(target=_run_scheduler_loop, name="netmon-uploader", daemon=True)
    t.start()
    return t
