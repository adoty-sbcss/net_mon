"""Customer transactions must survive an offline check-in without false success."""
from types import SimpleNamespace
from unittest.mock import Mock

from collector import checkin, webperf


def test_incomplete_transfer_is_not_success(monkeypatch):
    monkeypatch.setattr(webperf.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout="0.01 0.02 0.03 0.04 10 200 100 10", stderr="transfer timed out", returncode=28,
    ))
    result = webperf.probe_url("https://classroom.google.com")
    assert result["ok"] is False
    assert result["error"] == "transfer failed"


def test_http_429_remains_refusal_evidence(monkeypatch):
    monkeypatch.setattr(webperf.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout="0.01 0.02 0.03 0.04 0.1 429 100 1000", stderr="", returncode=0,
    ))
    result = webperf.probe_url("https://classroom.google.com")
    assert result["ok"] is False
    assert result["http_status"] == 429
    assert result["error"] == "HTTP 429"


def test_cycle_is_batched_offline_and_preserves_measurement_time(monkeypatch):
    spool = Mock()
    post = Mock()
    monkeypatch.setattr(checkin, "_spool_results", spool)
    monkeypatch.setattr(checkin, "_post_result", post)
    ts = "2026-09-04T15:00:00+00:00"
    checkin._report_webperf("https://dash", "tok", [
        {"url": "https://classroom.google.com", "ok": False, "error": "timeout"},
        {"url": "https://login.microsoftonline.com", "ok": False, "error": "timeout"},
    ], "scheduled", started_at=ts, spool_only=True)
    post.assert_not_called()
    spool.assert_called_once()
    endpoint, rows = spool.call_args.args
    assert endpoint == "/api/sensor/webperf-result"
    assert len(rows) == 2
    assert {r["startedAt"] for r in rows} == {ts}


def test_three_minute_cadence_bounded_and_no_duplicate_cycle(monkeypatch, tmp_path):
    import time
    monkeypatch.setattr(checkin, "WEBPERF_LAST_FILE", tmp_path / "last")
    monkeypatch.setattr(checkin, "_load_webperf_urls", lambda: [f"https://host{i}.example" for i in range(20)])
    monkeypatch.setattr(time, "time", lambda: 1800)
    probe = Mock(return_value=[])
    report = Mock()
    monkeypatch.setattr(webperf, "probe_urls", probe)
    monkeypatch.setattr(checkin, "_report_webperf", report)
    settings = SimpleNamespace(webperf_enabled=True, webperf_schedule_sec=180)
    checkin._maybe_webperf("https://dash", "tok", settings, offline=True)
    assert len(probe.call_args.args[0]) == 8
    assert probe.call_args.kwargs["timeout"] == 10
    assert report.call_args.kwargs["spool_only"] is True
    checkin._maybe_webperf("https://dash", "tok", settings, offline=True)
    probe.assert_called_once()
    monkeypatch.setattr(time, "time", lambda: 1980)
    checkin._maybe_webperf("https://dash", "tok", settings)
    assert probe.call_count == 2
    assert report.call_args.kwargs["spool_only"] is False


def test_failed_checkin_runs_website_probe(monkeypatch, tmp_path):
    from test_checkin_offline_latency import _harness
    _harness(monkeypatch, tmp_path, checkin_ok=False)
    probe = Mock()
    monkeypatch.setattr(checkin, "_maybe_webperf", probe)
    assert checkin.run_checkin() == 1
    probe.assert_called_once()
    assert probe.call_args.kwargs["offline"] is True
