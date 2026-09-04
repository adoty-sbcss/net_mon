"""A BLOCKED speed test must not be recorded as a successful 0.0 Mbps one.

The Cucamonga firewall incident (2026-08/09): a failing district firewall passed
the 20 tiny `bytes=0` latency GETs but choked every bulk stream. `_download` /
`_upload` swallowed the resulting exceptions (`except Exception: pass`) and
returned bytes-so-far, so `run_cloudflare` reported `ok=true, download_mbps=0.0`
— indistinguishable from a genuine zero-throughput measurement, and invisible to
the dashboard, which filters `ok=true` and takes max() per day. 47% of that
district's speed tests stored 0.0 Mbps and nothing ever flagged it.

The rules under test:
  * a direction that moved ZERO bytes is `ok=false` — it measured nothing. BOTH
    mechanisms count, and the error text says which one it was:
      - one or more streams RAISED (reset / timeout): actively blocked;
      - NOTHING raised and still no bytes: every request's setup outlasted the
        measurement window (a saturated inspection proxy). Keying the failure on
        "an exception was seen" missed this second path entirely, which left the
        original 0.0-Mbps-with-ok=true symptom reachable after the first fix.
  * partial numbers survive — a blocked download still reports the upload figure
    and the latency/jitter sample;
  * some streams failing while others move bytes stays `ok=true` (a degraded but
    real measurement), with the stream-failure counts recorded in `raw`.

Pure unit tests: no network. `urllib.request.urlopen` is the single chokepoint
and is monkeypatched; the exception types are the ones urllib actually raises
through a filtering firewall (connection reset / URLError-wrapped timeout).
"""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request

from collector import speedtest


class _FakeResp:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, chunks: list[bytes] | None = None) -> None:
        self._chunks = list(chunks or [])

    def read(self, _size: int | None = None) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def _install(monkeypatch, *, down, up):
    """Patch urlopen. `down`/`up` are callables returning a response or raising.
    The tiny `bytes=0` latency GETs always succeed — that is the whole point: the
    firewall passed those, which is why the probe looked healthy."""

    def _urlopen(req, timeout=None, context=None, **_kw):  # noqa: ANN001
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "bytes=0" in url:
            return _FakeResp()
        return down() if "__down" in url else up()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)


def _blocked_reset():
    raise ConnectionResetError(104, "Connection reset by peer")


def _blocked_timeout():
    raise urllib.error.URLError(TimeoutError("timed out"))


def _serves_data():
    time.sleep(0.01)  # throttle the fake so the 2s window isn't a hot spin
    return _FakeResp([b"x" * 131072])


def test_blocked_download_is_not_a_successful_zero(monkeypatch):
    """The exact incident shape: bulk downloads reset, uploads fine."""
    _install(monkeypatch, down=_blocked_reset, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=2)

    assert res["ok"] is False, "a blocked download must not be reported as a success"
    assert "download moved 0 bytes" in res["error"]
    assert "ConnectionResetError" in res["error"], "the error must name the cause"
    # Partial numbers are preserved, not discarded.
    assert res["download_mbps"] == 0.0
    assert res["upload_mbps"] > 0
    assert res["latency_ms"] is not None
    assert res["raw"]["download_bytes"] == 0
    assert res["raw"]["download_streams_failed"] == 2


def test_both_directions_blocked_names_both(monkeypatch):
    _install(monkeypatch, down=_blocked_timeout, up=_blocked_timeout)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["ok"] is False
    assert "download moved 0 bytes" in res["error"]
    assert "upload moved 0 bytes" in res["error"]
    assert res["raw"]["upload_bytes"] == 0


def test_zero_bytes_without_an_exception_is_still_a_failure(monkeypatch):
    """Zero bytes and NOTHING raised. Keying the failure on "an exception was
    seen" left this path reporting ok=true / 0.0 Mbps — the incident symptom
    verbatim, reached by a second mechanism. A direction that moved zero bytes
    measured nothing, so it is a failed test however it got there; the error
    text says which mechanism, because they need different fixes."""
    _install(monkeypatch, down=_FakeResp, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["ok"] is False, "a direction that moved zero bytes measured nothing"
    assert "download moved 0 bytes" in res["error"]
    assert "no stream raised" in res["error"], "name the mechanism: setup, not a reset"
    assert res["raw"]["download_streams_failed"] == 0
    assert res["raw"]["download_error"] is None
    # The working direction and the latency sample still survive.
    assert res["upload_mbps"] > 0
    assert res["latency_ms"] is not None


def test_slow_setup_outlasting_the_window_is_a_failure(monkeypatch):
    """The realistic Cucamonga mechanism: an overloaded inspection proxy passes
    the 20 tiny `bytes=0` latency GETs (10s timeout each) but takes longer than
    the entire measurement window just to establish each bulk transfer. The read
    loop never runs, no exception is ever raised, and the exception-keyed rule
    scored it as a perfectly successful 0.0 Mbps measurement."""

    def _setup_outlasts_window():
        time.sleep(2.5)  # longer than the 2s duration below
        return _FakeResp([b"x" * 131072])

    _install(monkeypatch, down=_setup_outlasts_window, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=2)

    assert res["ok"] is False, "0.0 Mbps from a stalled setup is not a success"
    assert res["download_mbps"] == 0.0
    assert "no stream raised" in res["error"]
    assert res["raw"]["download_bytes"] == 0
    assert res["raw"]["download_error"] is None


def test_partly_failing_streams_still_report_a_measurement(monkeypatch):
    """Some streams raise, others move bytes: a degraded but genuine number.
    Flagging it ok=false would erase the only reading we have during a brown-out —
    the failure count goes into `raw` instead."""
    lock = threading.Lock()
    calls = {"n": 0}

    def _first_two_fail():
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n <= 2:
            raise ConnectionResetError(104, "Connection reset by peer")
        return _serves_data()

    _install(monkeypatch, down=_first_two_fail, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=4)

    assert res["ok"] is True, "a partial measurement is still a measurement"
    assert res["download_mbps"] > 0
    assert res["raw"]["download_bytes"] > 0
    assert res["raw"]["download_streams_failed"] == 2
    assert "ConnectionResetError" in res["raw"]["download_error"]
