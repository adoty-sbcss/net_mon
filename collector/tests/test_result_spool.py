"""Guards Fable audit 01 finding #3: a scheduled perf result (iperf/speedtest/
latency/webperf) whose POST fails must NOT be lost — it is spooled and
redelivered on a later check-in. Before the fix, the scheduler ledger advanced
regardless of delivery, so every dashboard deploy/restart silently dropped that
interval's measurement.

Pure unit tests: no DB, no network — `_post` is the single network chokepoint
and is monkeypatched; the spool dir is redirected to tmp_path.
"""

from __future__ import annotations

import json

from collector import checkin


def _redirect_spool(monkeypatch, tmp_path):
    spool = tmp_path / "result-spool"
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DIR", spool)
    return spool


def test_failed_result_is_spooled(monkeypatch, tmp_path):
    spool = _redirect_spool(monkeypatch, tmp_path)
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: None)  # dashboard unreachable

    ok = checkin._post_result("https://dash", "tok", "/api/sensor/iperf-result", {"throughputMbps": 100})

    assert ok is False
    files = list(spool.glob("*.json"))
    assert len(files) == 1
    doc = json.loads(files[0].read_text())
    assert doc["endpoint"] == "/api/sensor/iperf-result"
    assert doc["payload"]["throughputMbps"] == 100  # original measurement preserved


def test_successful_result_is_not_spooled(monkeypatch, tmp_path):
    spool = _redirect_spool(monkeypatch, tmp_path)
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: {})  # 2xx

    ok = checkin._post_result("https://dash", "tok", "/api/sensor/iperf-result", {"x": 1})

    assert ok is True
    assert not list(spool.glob("*.json"))


def test_drain_redelivers_oldest_first_and_clears(monkeypatch, tmp_path):
    spool = _redirect_spool(monkeypatch, tmp_path)
    # Dashboard down: two results spool (in order).
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: None)
    checkin._post_result("https://dash", "tok", "/api/sensor/latency-result", {"n": 1})
    checkin._post_result("https://dash", "tok", "/api/sensor/webperf-result", {"n": 2})
    assert len(list(spool.glob("*.json"))) == 2

    # Dashboard recovers: drain redelivers both, oldest first, and empties the spool.
    sent: list[tuple[str, dict]] = []
    monkeypatch.setattr(checkin, "_post", lambda u, t, b: (sent.append((u, b)), {})[1])
    checkin._drain_result_spool("https://dash", "tok")

    assert [u for u, _ in sent] == [
        "https://dash/api/sensor/latency-result",
        "https://dash/api/sensor/webperf-result",
    ]
    assert not list(spool.glob("*.json"))


def test_drain_keeps_spool_while_still_down(monkeypatch, tmp_path):
    spool = _redirect_spool(monkeypatch, tmp_path)
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: None)
    checkin._post_result("https://dash", "tok", "/api/sensor/speedtest-result", {"n": 1})

    checkin._drain_result_spool("https://dash", "tok")  # still unreachable → keep it

    assert len(list(spool.glob("*.json"))) == 1


def test_corrupt_spool_file_is_dropped(monkeypatch, tmp_path):
    spool = _redirect_spool(monkeypatch, tmp_path)
    spool.mkdir(parents=True)
    (spool / "0.json").write_text("{not valid json")
    calls: list = []
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: calls.append(a) or {})

    checkin._drain_result_spool("https://dash", "tok")

    assert calls == []  # never tried to POST a corrupt payload
    assert not list(spool.glob("*.json"))  # and it was removed
