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


# --- batching: the cap is on FILES, so a cycle must not cost four of them -----
# One check-in cycle's latency probe is ~4 results. Spooled one-per-file at ~16
# cycles/hour, the 500-file cap filled in ~7h and then evicted the OLDEST — so a
# multi-day outage kept its tail and lost its ONSET, the part an investigator
# actually needs. A batched cycle is one file.


def test_a_batch_is_one_file_and_drains_in_order(monkeypatch, tmp_path):
    spool = _redirect_spool(monkeypatch, tmp_path)

    checkin._spool_results("/api/sensor/latency-result", [{"n": 1}, {"n": 2}, {"n": 3}])

    files = list(spool.glob("*.json"))
    assert len(files) == 1, "a whole cycle costs ONE file against the cap, not three"
    assert json.loads(files[0].read_text())["payloads"] == [{"n": 1}, {"n": 2}, {"n": 3}]

    sent: list[dict] = []
    monkeypatch.setattr(checkin, "_post", lambda u, t, b: (sent.append(b), {})[1])
    checkin._drain_result_spool("https://dash", "tok")

    assert sent == [{"n": 1}, {"n": 2}, {"n": 3}]
    assert not list(spool.glob("*.json"))


def test_single_payload_keeps_the_original_on_disk_shape(monkeypatch, tmp_path):
    """A rollback to an older collector must still be able to drain what it finds,
    so one-payload files keep the pre-batching {"endpoint","payload"} shape."""
    spool = _redirect_spool(monkeypatch, tmp_path)

    checkin._spool_results("/api/sensor/latency-result", [{"n": 1}])

    doc = json.loads(next(iter(spool.glob("*.json"))).read_text())
    assert doc["payload"] == {"n": 1}
    assert "payloads" not in doc


def test_partial_batch_delivery_keeps_only_the_undelivered_remainder(monkeypatch, tmp_path):
    """The dashboard dies halfway through a batch: the delivered payloads must not
    be re-POSTed on the next drain (that would duplicate rows), and the rest must
    survive."""
    spool = _redirect_spool(monkeypatch, tmp_path)
    checkin._spool_results("/api/sensor/latency-result", [{"n": 1}, {"n": 2}, {"n": 3}])
    before = next(iter(spool.glob("*.json"))).name

    sent: list[dict] = []

    def _flaky(u, t, b):
        sent.append(b)
        return None if b["n"] == 2 else {}

    monkeypatch.setattr(checkin, "_post", _flaky)
    checkin._drain_result_spool("https://dash", "tok")

    assert sent == [{"n": 1}, {"n": 2}]
    files = list(spool.glob("*.json"))
    assert len(files) == 1
    assert files[0].name == before, "same filename → its place in the age order is kept"
    assert json.loads(files[0].read_text())["payloads"] == [{"n": 2}, {"n": 3}]

    # Dashboard recovers: only the remainder is delivered — no duplicate of {"n": 1}.
    sent.clear()
    monkeypatch.setattr(checkin, "_post", lambda u, t, b: (sent.append(b), {})[1])
    checkin._drain_result_spool("https://dash", "tok")
    assert sent == [{"n": 2}, {"n": 3}]
    assert not list(spool.glob("*.json"))


def test_drain_payload_budget_bounds_work_and_keeps_the_rest(monkeypatch, tmp_path):
    """A file may now hold several payloads, so the per-run bound has to count
    payloads too — otherwise a recovery drain could fire 50 files x N POSTs."""
    spool = _redirect_spool(monkeypatch, tmp_path)
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DRAIN_PAYLOADS", 2)
    checkin._spool_results("/api/sensor/latency-result", [{"n": 1}, {"n": 2}, {"n": 3}])

    sent: list[dict] = []
    monkeypatch.setattr(checkin, "_post", lambda u, t, b: (sent.append(b), {})[1])
    checkin._drain_result_spool("https://dash", "tok")

    assert sent == [{"n": 1}, {"n": 2}], "stopped at the budget"
    assert json.loads(next(iter(spool.glob("*.json"))).read_text())["payload"] == {"n": 3}
