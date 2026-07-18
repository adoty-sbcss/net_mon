"""Guards the hourly-bundle data-loss cluster (F-COL-19 catch-up + F-COL-20
bounded flush).

What these protect, concretely:

F-COL-19 — the collector used to bundle forward-only, on a timer. If it wasn't
running at the top of the hour (the nightly auto-update straddles it; every
dashboard config-push recreates the container), that hour was NEVER bundled and
its scans were silently deleted at local_retention_days. The catch-up asks "which
closed hours have scans but no complete bundle?" instead of trusting the tick to
fire, so a missed boundary heals instead of losing data. The tests below pin the
eligibility matrix — especially that a COMPLETE hour is never rebuilt, which is
what stops us re-shipping hours the dashboard already ingested.

F-COL-20 — the old flush re-tried every pending bundle every tick, serially, with
no backoff/cap/give-up. The tests pin each bound.

Pure unit tests: no DB, no network, no clock. Every db.* call the uploader made a
module-level import of is monkeypatched on `uploader`, `now` is injected, and the
transport is a fake `upload_file`.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from collector import uploader


def _local(year: int, month: int, day: int, hour: int, minute: int = 0, second: int = 0) -> datetime:
    """Tz-aware datetime in the MACHINE's local zone.

    The uploader buckets scans into hours in collector-LOCAL time (bundle
    filenames are stamped that way), so building fixtures in local time keeps
    these tests timezone-agnostic: they pass on a UTC CI runner and on a
    US/Pacific dev box alike. Mid-July dates dodge every DST transition.
    """
    return datetime(year, month, day, hour, minute, second).astimezone()


def _settings(tmp_path, **over):
    base = dict(
        district_slug="dist", school_slug="school", device_slug="sensor",
        device_name="sensor", bundle_dir=tmp_path,
        bundle_transport="sftp", sftp_enabled=True,
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clear_stop_event():
    """_stop_event is a module global; never leak a set() into another test."""
    uploader._stop_event.clear()
    yield
    uploader._stop_event.clear()


# ---------------------------------------------------------------------------
# _retry_delay
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("retry_count,expect", [
    (0, timedelta(0)),            # a fresh bundle never waits...
    (2, timedelta(0)),            # ...nor does one that's barely stumbled
    (3, timedelta(hours=4)),      # persistent failure -> back off
    (7, timedelta(hours=4)),
    (8, timedelta(hours=12)),     # hopeless -> back off hard
    (60, timedelta(hours=12)),
])
def test_retry_delay_table(retry_count, expect):
    assert uploader._retry_delay(retry_count) == expect


# ---------------------------------------------------------------------------
# _hour_windows_with_scans
# ---------------------------------------------------------------------------

def test_hour_windows_are_newest_first_and_deduped(monkeypatch):
    # Two scans in the 10:00 hour must collapse to ONE window (one bundle).
    times = [
        _local(2026, 7, 16, 10, 5),
        _local(2026, 7, 16, 10, 55),
        _local(2026, 7, 16, 12, 30),
    ]
    monkeypatch.setattr(uploader, "list_completed_scan_times_since", lambda hours: times)
    got = uploader._hour_windows_with_scans(_local(2026, 7, 16, 14, 0, 15))
    assert got == [_local(2026, 7, 16, 13), _local(2026, 7, 16, 11)]


def test_hour_windows_excludes_the_still_open_hour(monkeypatch):
    # A scan at 13:30 belongs to the window ending 14:00. Bundling that before
    # 14:00 would ship a PARTIAL hour under the filename that the complete hour
    # needs -- the boundary is `window_end <= now`, exactly.
    times = [_local(2026, 7, 16, 13, 30)]
    monkeypatch.setattr(uploader, "list_completed_scan_times_since", lambda hours: times)
    assert uploader._hour_windows_with_scans(_local(2026, 7, 16, 13, 59, 59)) == []
    assert uploader._hour_windows_with_scans(_local(2026, 7, 16, 14)) == [_local(2026, 7, 16, 14)]


def test_hour_windows_empty_when_no_scans(monkeypatch):
    monkeypatch.setattr(uploader, "list_completed_scan_times_since", lambda hours: [])
    assert uploader._hour_windows_with_scans(_local(2026, 7, 16, 14)) == []


def test_hour_windows_asks_for_the_catchup_horizon(monkeypatch):
    asked: list[int] = []
    monkeypatch.setattr(uploader, "list_completed_scan_times_since",
                        lambda hours: asked.append(hours) or [])
    uploader._hour_windows_with_scans(_local(2026, 7, 16, 14))
    assert asked == [uploader.CATCHUP_HORIZON_HOURS]


# ---------------------------------------------------------------------------
# _catch_up_missed_hours  (the eligibility matrix)
# ---------------------------------------------------------------------------

def _catchup(monkeypatch, tmp_path, windows, rows):
    """Wire catch-up's dependencies. `rows` is keyed by window_end for
    convenience and re-keyed to real filenames here, so the test exercises the
    same _filename_for the production lookup uses."""
    monkeypatch.setattr(uploader, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(uploader, "_hour_windows_with_scans", lambda now: list(windows))
    by_name = {uploader._filename_for(we): row for we, row in rows.items()}
    monkeypatch.setattr(uploader, "get_bundle_rows", lambda filenames: by_name)
    built: list[datetime] = []

    def _fake_build(window_end):
        built.append(window_end)
        return uploader._filename_for(window_end), 3

    monkeypatch.setattr(uploader, "_build_hour", _fake_build)
    return built


def _row(window_end, *, built_at, gave_up_at=None, uploaded_at=None):
    return {"built_at": built_at, "uploaded_at": uploaded_at, "gave_up_at": gave_up_at}


def test_catchup_builds_hour_with_no_bundle_row(monkeypatch, tmp_path):
    # THE data-loss case: we were down across the boundary, so nothing ever
    # bundled this hour.
    we = _local(2026, 7, 16, 13)
    built = _catchup(monkeypatch, tmp_path, [we], rows={})
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 1
    assert built == [we]


def test_catchup_rebuilds_partial_bundle(monkeypatch, tmp_path):
    # Built mid-hour (by an operator's upload-now), so it's missing the rest of
    # the hour: built_at < window_end -> rebuild to upgrade partial -> complete.
    we = _local(2026, 7, 16, 13)
    rows = {we: _row(we, built_at=we - timedelta(minutes=20))}
    built = _catchup(monkeypatch, tmp_path, [we], rows)
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 1
    assert built == [we]


def test_catchup_skips_complete_bundle(monkeypatch, tmp_path):
    # THE idempotency guarantee: built at-or-after the hour closed means complete
    # (and possibly already ingested by the dashboard) -> never auto-re-ship.
    we = _local(2026, 7, 16, 13)
    rows = {we: _row(we, built_at=we + timedelta(seconds=15))}
    built = _catchup(monkeypatch, tmp_path, [we], rows)
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 0
    assert built == []


def test_catchup_skips_complete_bundle_that_never_uploaded(monkeypatch, tmp_path):
    # Pending-but-complete is still complete: the flush ships it, catch-up must
    # not rebuild it (a rebuild would reset its upload state for nothing).
    we = _local(2026, 7, 16, 13)
    rows = {we: _row(we, built_at=we + timedelta(seconds=15), uploaded_at=None)}
    built = _catchup(monkeypatch, tmp_path, [we], rows)
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 0
    assert built == []


def test_catchup_skips_given_up_hour_even_if_partial(monkeypatch, tmp_path):
    # gave_up_at is terminal for AUTOMATION and outranks the partial-rebuild
    # rule; otherwise catch-up would resurrect what the flush just gave up on and
    # the two would fight forever.
    we = _local(2026, 7, 16, 13)
    rows = {we: _row(we, built_at=we - timedelta(minutes=20),
                     gave_up_at=_local(2026, 7, 16, 13, 59))}
    built = _catchup(monkeypatch, tmp_path, [we], rows)
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 0
    assert built == []


def test_catchup_builds_newest_first_and_honors_the_cap(monkeypatch, tmp_path):
    # A box back from a long outage: cap the per-pass work, but make sure the
    # FRESHEST hours are the ones that ship first.
    windows = [_local(2026, 7, 16, h) for h in range(1, 24)]
    built = _catchup(monkeypatch, tmp_path, windows, rows={})
    n = uploader._catch_up_missed_hours(_local(2026, 7, 17, 0))
    assert n == uploader.CATCHUP_MAX_BUILDS_PER_PASS
    assert built == sorted(windows, reverse=True)[:uploader.CATCHUP_MAX_BUILDS_PER_PASS]


def test_catchup_mixed_matrix_builds_only_what_is_owed(monkeypatch, tmp_path):
    missing = _local(2026, 7, 16, 12)
    partial = _local(2026, 7, 16, 11)
    complete = _local(2026, 7, 16, 10)
    gave_up = _local(2026, 7, 16, 9)
    rows = {
        partial: _row(partial, built_at=partial - timedelta(minutes=5)),
        complete: _row(complete, built_at=complete + timedelta(seconds=15)),
        gave_up: _row(gave_up, built_at=gave_up - timedelta(minutes=5),
                      gave_up_at=_local(2026, 7, 16, 13)),
    }
    built = _catchup(monkeypatch, tmp_path, [missing, partial, complete, gave_up], rows)
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 2
    assert built == [missing, partial]


def test_catchup_one_bad_hour_does_not_block_the_rest(monkeypatch, tmp_path):
    # A single unbuildable hour must not re-introduce the data loss for the others.
    good = _local(2026, 7, 16, 12)
    bad = _local(2026, 7, 16, 13)
    _catchup(monkeypatch, tmp_path, [bad, good], rows={})
    built: list[datetime] = []

    def _explode(window_end):
        if window_end == bad:
            raise RuntimeError("corrupt scan row")
        built.append(window_end)
        return "sensor_x.zip", 1

    monkeypatch.setattr(uploader, "_build_hour", _explode)
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 1
    assert built == [good]


def test_catchup_stops_when_stop_requested(monkeypatch, tmp_path):
    windows = [_local(2026, 7, 16, h) for h in range(1, 12)]
    built = _catchup(monkeypatch, tmp_path, windows, rows={})
    uploader._stop_event.set()
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 0
    assert built == []


def test_catchup_noop_when_no_hours_have_scans(monkeypatch, tmp_path):
    built = _catchup(monkeypatch, tmp_path, [], rows={})
    assert uploader._catch_up_missed_hours(_local(2026, 7, 16, 14)) == 0
    assert built == []


# ---------------------------------------------------------------------------
# _flush_pending  (the bounds)
# ---------------------------------------------------------------------------

def _pending_row(tmp_path, name, *, built_at=None, last_attempt_at=None,
                 retry_count=0, create=True):
    path = tmp_path / name
    if create:
        path.write_bytes(b"PK\x03\x04 pretend zip")
    return {
        "id": abs(hash(name)) % 10_000, "filename": name, "local_path": str(path),
        "built_at": built_at or _local(2026, 7, 16, 13),
        "last_attempt_at": last_attempt_at, "retry_count": retry_count,
        "last_error": None,
    }


def _flush(monkeypatch, tmp_path, pending, *, upload=None, sweep=(), **settings_over):
    monkeypatch.setattr(uploader, "get_settings", lambda: _settings(tmp_path, **settings_over))
    monkeypatch.setattr(uploader, "mark_bundles_gave_up", lambda days, retries: list(sweep))
    monkeypatch.setattr(uploader, "list_pending_bundles", lambda: list(pending))
    calls: dict[str, list] = {"attempts": [], "uploaded": [], "failed": [], "gave_up": []}
    monkeypatch.setattr(uploader, "record_bundle_uploaded",
                        lambda f, r: calls["uploaded"].append(f))
    monkeypatch.setattr(uploader, "record_bundle_upload_failure",
                        lambda f, e: calls["failed"].append((f, e)))
    monkeypatch.setattr(uploader, "mark_bundle_gave_up",
                        lambda f, r: calls["gave_up"].append((f, r)))

    def _fake_upload(path):
        calls["attempts"].append(path.name)
        if upload is not None:
            return upload(path)
        return f"/remote/{path.name}"

    monkeypatch.setattr(uploader, "upload_file", _fake_upload)
    return calls


def test_flush_uploads_everything_pending_when_healthy(monkeypatch, tmp_path):
    pending = [_pending_row(tmp_path, f"sensor_{i}.zip") for i in range(4)]
    calls = _flush(monkeypatch, tmp_path, pending)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.succeeded == 4
    assert counters.failed == 0
    assert counters.breaker_tripped is False
    assert len(calls["attempts"]) == 4


def test_flush_breaker_trips_after_three_consecutive_failures(monkeypatch, tmp_path):
    # A dead depot is not 200 individually-broken bundles. Stop after 3 and let
    # the next tick retry, instead of burning ~30s of SFTP timeout apiece.
    pending = [_pending_row(tmp_path, f"sensor_{i}.zip") for i in range(8)]

    def _boom(path):
        raise RuntimeError("depot unreachable")

    calls = _flush(monkeypatch, tmp_path, pending, upload=_boom)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.attempted == uploader.UPLOAD_BREAKER_CONSECUTIVE_FAILURES == 3
    assert counters.failed == 3
    assert counters.breaker_tripped is True
    assert len(calls["attempts"]) == 3          # the other 5 were never touched
    assert len(calls["failed"]) == 3            # and each failure was recorded


def test_flush_breaker_resets_on_success(monkeypatch, tmp_path):
    # Interleaved failures are NOT an outage -- the breaker must only count
    # CONSECUTIVE ones, or one flaky bundle would stall the whole queue.
    pending = [_pending_row(tmp_path, f"sensor_{i}.zip") for i in range(6)]

    def _flaky(path):
        if path.name in ("sensor_0.zip", "sensor_1.zip", "sensor_3.zip", "sensor_4.zip"):
            raise RuntimeError("transient")
        return f"/remote/{path.name}"

    _flush(monkeypatch, tmp_path, pending, upload=_flaky)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.breaker_tripped is False
    assert counters.attempted == 6
    assert counters.succeeded == 2
    assert counters.failed == 4


def test_flush_skips_bundles_inside_retry_backoff(monkeypatch, tmp_path):
    now = _local(2026, 7, 16, 14)
    pending = [
        # retry_count 5 -> 4h delay, last tried 1h ago -> SKIP
        _pending_row(tmp_path, "cold.zip", retry_count=5,
                     last_attempt_at=now - timedelta(hours=1)),
        # retry_count 5 -> 4h delay, last tried 5h ago -> DUE
        _pending_row(tmp_path, "due.zip", retry_count=5,
                     last_attempt_at=now - timedelta(hours=5)),
        # retry_count 0 -> no delay, even though it was tried a second ago. This
        # is what keeps a freshly-built bundle (and an operator's upload-now)
        # shipping instantly during someone else's backoff.
        _pending_row(tmp_path, "fresh.zip", retry_count=0,
                     last_attempt_at=now - timedelta(seconds=1)),
    ]
    calls = _flush(monkeypatch, tmp_path, pending)
    counters = uploader._flush_pending("sftp", now=now)
    assert calls["attempts"] == ["due.zip", "fresh.zip"]
    assert counters.skipped == 1
    assert counters.succeeded == 2
    assert counters.attempted == 2


def test_flush_gives_up_on_missing_file_without_burning_an_attempt(monkeypatch, tmp_path):
    # Retrying can never conjure the file back, so it must not consume an attempt
    # (or a breaker slot) that a shippable bundle needs.
    pending = [
        _pending_row(tmp_path, "gone.zip", create=False),
        _pending_row(tmp_path, "here.zip"),
    ]
    calls = _flush(monkeypatch, tmp_path, pending)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert calls["gave_up"] == [("gone.zip", "local file missing")]
    assert counters.gave_up == 1
    assert calls["attempts"] == ["here.zip"]
    assert counters.attempted == 1
    assert counters.succeeded == 1
    assert counters.failed == 0


def test_flush_does_not_give_up_when_the_bundle_dir_is_gone(monkeypatch, tmp_path):
    # An unmounted volume makes EVERY file look missing. Giving up on the whole
    # queue because of a sick mount would be exactly the data loss we're fixing.
    pending = [_pending_row(tmp_path, "x.zip", create=False)]
    calls = _flush(monkeypatch, tmp_path, pending, bundle_dir=tmp_path / "unmounted")
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert calls["gave_up"] == []
    assert counters.gave_up == 0
    assert counters.skipped == 1
    assert counters.attempted == 0


def test_flush_stops_at_the_attempt_cap(monkeypatch, tmp_path):
    over = uploader.UPLOAD_MAX_ATTEMPTS_PER_TICK + 5
    pending = [_pending_row(tmp_path, f"sensor_{i:03d}.zip") for i in range(over)]
    calls = _flush(monkeypatch, tmp_path, pending)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.attempted == uploader.UPLOAD_MAX_ATTEMPTS_PER_TICK
    assert counters.succeeded == uploader.UPLOAD_MAX_ATTEMPTS_PER_TICK
    assert len(calls["attempts"]) == uploader.UPLOAD_MAX_ATTEMPTS_PER_TICK


def test_flush_sweep_gives_up_and_unlinks_hopeless_bundles(monkeypatch, tmp_path):
    # The disk-reclaim path: the first tick after deploy sweeps ancient pendings.
    doomed = tmp_path / "ancient.zip"
    doomed.write_bytes(b"PK\x03\x04 old")
    sweep = [{
        "filename": "ancient.zip", "local_path": str(doomed),
        "built_at": _local(2026, 7, 1, 0), "retry_count": 61,
        "last_error": "depot unreachable",
    }]
    _flush(monkeypatch, tmp_path, [], sweep=sweep)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.gave_up == 1
    assert not doomed.exists()


def test_flush_sweep_failure_does_not_block_uploads(monkeypatch, tmp_path):
    pending = [_pending_row(tmp_path, "sensor_0.zip")]
    calls = _flush(monkeypatch, tmp_path, pending)

    def _boom(days, retries):
        raise RuntimeError("db hiccup")

    monkeypatch.setattr(uploader, "mark_bundles_gave_up", _boom)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.succeeded == 1
    assert calls["attempts"] == ["sensor_0.zip"]


def test_flush_reports_remote_path_for_the_current_bundle(monkeypatch, tmp_path):
    # build_and_upload_hour's `remote_path` result key rides on this.
    pending = [_pending_row(tmp_path, "old.zip"), _pending_row(tmp_path, "current.zip")]
    _flush(monkeypatch, tmp_path, pending)
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14),
                                       current_filename="current.zip")
    assert counters.current_remote_path == "/remote/current.zip"


def test_flush_stops_when_stop_requested(monkeypatch, tmp_path):
    # The old flush ignored request_stop() for as long as the queue took.
    pending = [_pending_row(tmp_path, f"sensor_{i}.zip") for i in range(3)]
    calls = _flush(monkeypatch, tmp_path, pending)
    uploader._stop_event.set()
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.attempted == 0
    assert calls["attempts"] == []


def test_flush_noop_when_nothing_pending(monkeypatch, tmp_path):
    calls = _flush(monkeypatch, tmp_path, [])
    counters = uploader._flush_pending("sftp", now=_local(2026, 7, 16, 14))
    assert counters.attempted == 0
    assert counters.succeeded == 0
    assert calls["attempts"] == []


# ---------------------------------------------------------------------------
# build_and_upload_hour  (the manual path's CONSUMED contract)
# ---------------------------------------------------------------------------
# __main__.cmd_upload_now and checkin's "upload-now" command both read these
# result keys and branch on these exact status strings (cmd_upload_now sets its
# EXIT CODE from them). The scheduler no longer calls this function, so these
# tests are what keep the operator-facing contract from drifting.

_SUCCESS_STATUSES = {"uploaded", "saved_only", "skipped"}


def _build_and_upload(monkeypatch, tmp_path, *, built, counters=None, transport="sftp"):
    monkeypatch.setattr(uploader, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(uploader, "_active_transport", lambda s: transport)
    monkeypatch.setattr(uploader, "_build_hour", lambda window_end: built)
    seen: dict = {"pruned": False}

    def _fake_flush(t, now=None, current_filename=None):
        seen["transport"] = t
        seen["current_filename"] = current_filename
        return counters if counters is not None else uploader._FlushCounters()

    monkeypatch.setattr(uploader, "_flush_pending", _fake_flush)
    monkeypatch.setattr(uploader, "_prune_old_uploaded_bundles",
                        lambda: seen.__setitem__("pruned", True))
    return seen


def test_build_and_upload_hour_result_keys_are_unchanged(monkeypatch, tmp_path):
    window_end = _local(2026, 7, 16, 14)
    _build_and_upload(
        monkeypatch, tmp_path, built=("sensor_2026_07_16_13.zip", 5),
        counters=uploader._FlushCounters(attempted=1, succeeded=1,
                                         current_remote_path="/remote/sensor.zip"),
    )
    result = uploader.build_and_upload_hour(window_end)
    assert set(result) == {"local_path", "remote_path", "status", "message",
                           "window_start", "window_end", "scans", "retried"}
    assert result["status"] == "uploaded"
    assert result["scans"] == "5"
    assert result["retried"] == "0"          # the only upload WAS this hour's
    assert result["remote_path"] == "/remote/sensor.zip"
    assert result["local_path"] == str(tmp_path / "sensor_2026_07_16_13.zip")
    assert result["window_end"] == window_end.isoformat()
    assert result["window_start"] == (window_end - timedelta(hours=1)).isoformat()


def test_build_and_upload_hour_saved_only_without_transport(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=("f.zip", 1), transport=None)
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["status"] == "saved_only"
    assert "no upload transport active" in result["message"]
    assert result["status"] in _SUCCESS_STATUSES


def test_build_and_upload_hour_skipped_when_hour_is_empty(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=None)
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["status"] == "skipped"
    assert result["scans"] == "0"
    assert result["local_path"] is None
    assert result["message"] == "nothing pending to upload"
    assert result["status"] in _SUCCESS_STATUSES


def test_build_and_upload_hour_retried_excludes_the_current_bundle(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=("cur.zip", 2),
                      counters=uploader._FlushCounters(attempted=4, succeeded=4))
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["retried"] == "3"
    assert result["status"] == "uploaded"


def test_build_and_upload_hour_retried_counts_all_when_nothing_built(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=None,
                      counters=uploader._FlushCounters(attempted=2, succeeded=2))
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["retried"] == "2"
    assert result["status"] == "uploaded"


def test_build_and_upload_hour_upload_failed(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=("cur.zip", 1),
                      counters=uploader._FlushCounters(attempted=1, failed=1,
                                                       last_error="depot unreachable"))
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["status"] == "upload_failed"
    assert result["message"] == "depot unreachable"
    assert result["status"] not in _SUCCESS_STATUSES     # caller must exit non-zero


def test_build_and_upload_hour_partial(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=("cur.zip", 1),
                      counters=uploader._FlushCounters(attempted=3, succeeded=1, failed=2,
                                                       last_error="boom"))
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["status"] == "partial"
    assert "1 bundle(s) uploaded, 2 failed (last error: boom)" in result["message"]
    assert result["status"] not in _SUCCESS_STATUSES


def test_build_and_upload_hour_reports_backoff_instead_of_lying(monkeypatch, tmp_path):
    # Newly reachable: an empty hour while old bundles sit in backoff. Nothing is
    # wrong (status stays in the success set), but don't claim "nothing pending".
    _build_and_upload(monkeypatch, tmp_path, built=None,
                      counters=uploader._FlushCounters(skipped=2))
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["status"] == "skipped"
    assert result["message"] == "2 pending bundle(s) waiting on retry backoff"
    assert result["status"] in _SUCCESS_STATUSES


def test_build_and_upload_hour_reports_a_give_up_instead_of_nothing_pending(monkeypatch, tmp_path):
    _build_and_upload(monkeypatch, tmp_path, built=None,
                      counters=uploader._FlushCounters(gave_up=1))
    result = uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert result["status"] == "skipped"
    assert result["message"] == "gave up on 1 unshippable bundle(s)"


def test_build_and_upload_hour_flushes_current_bundle_and_prunes(monkeypatch, tmp_path):
    seen = _build_and_upload(monkeypatch, tmp_path, built=("cur.zip", 1),
                             counters=uploader._FlushCounters(attempted=1, succeeded=1))
    uploader.build_and_upload_hour(_local(2026, 7, 16, 14))
    assert seen["current_filename"] == "cur.zip"     # so remote_path can be reported
    assert seen["transport"] == "sftp"
    assert seen["pruned"] is True
