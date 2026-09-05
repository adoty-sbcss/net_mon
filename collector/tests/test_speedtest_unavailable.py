"""A REFUSING measurement source and a BROKEN LINK must not look the same.

Cucamonga SD, 2026-08/09: three sensors behind ONE shared egress IP showed ~47%
of speed tests returning 0.0 Mbps for over a week. It was diagnosed as a failing
district firewall; the firewall was rebooted over it; the symptom came back.

It was never the firewall. Once the probe recorded WHY a transfer moved nothing
(PR #87), the first labelled failures read:

    failed — download moved 0 bytes (16/16 streams failed):
             HTTPError: HTTP Error 429: Too Many Requests

Cloudflare was rate-limiting OUR OWN PROBE. Single-sensor districts on their own
addresses never showed it and sat at 910-925 Mbps on every run.

The defect is that a speed test had only two endings — measured, or failed —
when it has three. An HTTP status from speed.cloudflare.com means the endpoint
was reached, understood us, and declined: it is not evidence about the
district's link, and filing it as `ok=false` alongside a real outage is what
sent a week of diagnosis at the wrong device.

The rules under test:
  * an UNAMBIGUOUS refusal status (429, and only 429) that leaves a direction
    with no bytes is `unavailable` — a refusal, not a network failure;
  * every OTHER HTTP status stays `failed`. A school's own filtering proxy
    answers 403 on a block page and a middlebox can answer 5xx, so those cannot
    tell "the provider turned us away" from "this district turned us away" — and
    the latter is a real finding that must not be buried under "not measured";
  * a transport error (reset / timeout) with no bytes is still `failed`;
  * MIXED is `failed`, not `unavailable` — if even one stream was reset there is
    real evidence about the link in this run, and suppressing a genuine WAN
    failure is the more expensive mistake;
  * zero bytes with NO exception at all stays `failed` (the stalled-setup path
    from test_speedtest_honesty.py must not drift into the refusal bucket);
  * the tiny latency GETs return early on failure and classify the same way —
    a separate code path with its own way of being wrong;
  * `ok` KEEPS ITS OLD MEANING (`status == "ok"`), so every existing reader stays
    truthful without being touched.

Pure unit tests: no network. `urllib.request.urlopen` is the single chokepoint.
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


def _install(monkeypatch, *, down, up, latency=None):
    """Patch urlopen. The tiny `bytes=0` latency GETs succeed unless `latency`
    says otherwise — a rate limit that only bites the bulk transfers is exactly
    what Cucamonga looked like."""

    def _urlopen(req, timeout=None, context=None, **_kw):  # noqa: ANN001
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "bytes=0" in url:
            return latency() if latency else _FakeResp()
        return down() if "__down" in url else up()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)


def _http_error(code: int, reason: str):
    """The real thing urllib raises on a non-2xx — an HTTPError, which is also a
    URLError and an OSError, so the ordering of except-branches matters."""

    def _raise():
        raise urllib.error.HTTPError(
            "https://speed.cloudflare.com/__down", code, reason, {}, None  # type: ignore[arg-type]
        )

    return _raise


def _rate_limited():
    return _http_error(429, "Too Many Requests")()


def _blocked_reset():
    raise ConnectionResetError(104, "Connection reset by peer")


def _serves_data():
    time.sleep(0.01)  # throttle the fake so the 2s window isn't a hot spin
    return _FakeResp([b"x" * 131072])


# --- the incident itself -----------------------------------------------------


def test_a_429_is_unavailable_not_a_network_failure(monkeypatch):
    """The exact Cucamonga shape: every bulk download stream gets 429."""
    _install(monkeypatch, down=_rate_limited, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=2)

    assert res["status"] == "unavailable", (
        "a provider rate limit says NOTHING about the district's link — filing it "
        "as a network failure is what caused a week of false diagnosis"
    )
    # `ok` keeps its old meaning so existing readers stay truthful untouched.
    assert res["ok"] is False
    assert "refused the probe" in res["error"]
    assert "HTTP 429" in res["error"], "the status code is the whole discriminator"
    assert "moved 0 bytes" not in res["error"], (
        "the message must not read as an accusation against the link"
    )
    assert res["raw"]["download_http_status"] == 429
    assert res["raw"]["download_streams_refused"] == 2
    # The working direction and the latency sample still survive.
    assert res["upload_mbps"] > 0
    assert res["latency_ms"] is not None


def test_a_5xx_from_an_intercepting_middlebox_is_also_a_failure(monkeypatch):
    """A 502/503 can equally come from an intercepting middlebox on the site side."""
    _install(monkeypatch, down=_http_error(503, "Service Unavailable"), up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "failed"
    assert res["raw"]["download_http_status"] == 503


def test_a_403_block_page_is_a_FAILURE_not_a_refusal(monkeypatch):
    """The narrowing that matters, and a deliberate reversal of this file's first
    cut (which called any 4xx/5xx a refusal).

    A school's own filtering proxy answers 403 on a block page, so a 403 cannot
    tell "Cloudflare turned us away" from "this district blocks speed tests" —
    and the second is a real, actionable finding about the site. Filing it under
    "not measured" is the same class of mistake as the incident itself, pointed
    the other way. Only a status with no second possible author counts, and 429
    is the one: no campus firewall rate-limits a client with a 429."""
    _install(monkeypatch, down=_http_error(403, "Forbidden"), up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "failed", (
        "a 403 has a second possible author — this site's own proxy — so it must "
        "not be filed as the provider refusing us"
    )
    # The evidence is fully recorded either way; only the CLASSIFICATION is narrow.
    assert res["raw"]["download_http_status"] == 403
    assert res["raw"]["download_streams_refused"] == 0
    assert "403" in res["error"]


def test_the_latency_early_return_narrows_the_same_way(monkeypatch):
    """The early return is its own code path and had the same over-broad rule."""
    _install(
        monkeypatch, down=_serves_data, up=_serves_data, latency=_http_error(403, "Forbidden")
    )

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "failed"
    assert res["raw"]["latency_http_status"] == 403


def test_both_directions_refused_is_unavailable(monkeypatch):
    _install(monkeypatch, down=_rate_limited, up=_rate_limited)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "unavailable"
    assert res["raw"]["upload_http_status"] == 429


# --- the boundary that protects a REAL outage --------------------------------


def test_a_reset_with_no_bytes_is_still_failed(monkeypatch):
    """A transport error is evidence about the network. It must stay `failed`."""
    _install(monkeypatch, down=_blocked_reset, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=2)

    assert res["status"] == "failed"
    assert res["ok"] is False
    assert "download moved 0 bytes" in res["error"]
    assert res["raw"]["download_http_status"] is None
    assert res["raw"]["download_streams_refused"] == 0


def test_mixed_refusal_and_reset_is_failed_not_unavailable(monkeypatch):
    """Some streams refused, others RESET. There is real evidence about the link
    in this run, so it must not be filed under "the provider wouldn't talk to
    us" — a suppressed WAN failure is the more expensive mistake, and WAN
    degradation on this fleet is already hard enough to see."""
    lock = threading.Lock()
    calls = {"n": 0}

    def _first_is_refused():
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n == 1:
            _rate_limited()
        _blocked_reset()

    _install(monkeypatch, down=_first_is_refused, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=4)

    assert res["status"] == "failed", (
        "refusal must explain ALL of the failure before we call the run unavailable"
    )
    # The 429 is still surfaced — it is the most useful thing in the row — even
    # though it did not decide the verdict.
    assert res["raw"]["download_http_status"] == 429
    assert res["raw"]["download_streams_refused"] == 1
    assert res["raw"]["download_streams_failed"] == 4


def test_one_direction_refused_and_the_other_broken_is_failed(monkeypatch):
    """ACROSS directions, same rule as within one: a refusal has to explain the
    WHOLE run. Download refused, upload reset — the reset is real evidence about
    the link, so the run is `failed`. Without this the cross-direction combiner
    could be `any` instead of `all` and nothing would notice."""
    _install(monkeypatch, down=_rate_limited, up=_blocked_reset)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "failed", (
        "an upload that was RESET is evidence about the network; a refused "
        "download alongside it must not downgrade the run to 'not measured'"
    )
    assert res["raw"]["download_http_status"] == 429
    assert res["raw"]["upload_http_status"] is None


def test_the_message_names_the_transport_error_not_a_lone_refusal(monkeypatch):
    """When the verdict is `failed` because one stream was RESET, the reported
    error must be that reset. Surfacing a lone 429 next to a verdict of "the
    link broke" contradicts itself and sends the reader back to square one."""
    lock = threading.Lock()
    calls = {"n": 0}

    def _first_is_refused():
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n == 1:
            _rate_limited()
        _blocked_reset()

    _install(monkeypatch, down=_first_is_refused, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=4)

    assert res["status"] == "failed"
    assert "ConnectionResetError" in res["error"], (
        "the failure the verdict rests on is the reset, so name the reset"
    )
    assert "429" not in res["error"]
    # ...but the status code is not lost; it stays queryable in `raw`.
    assert res["raw"]["download_http_status"] == 429


def test_zero_bytes_with_no_exception_stays_failed(monkeypatch):
    """The stalled-setup path (test_speedtest_honesty.py): nothing raised, so
    nothing was REFUSED either. Guarding on `refused > 0` is what keeps this out
    of the unavailable bucket."""
    _install(monkeypatch, down=_FakeResp, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "failed"
    assert "no stream raised" in res["error"]
    assert res["raw"]["download_streams_refused"] == 0


def test_a_partial_measurement_is_ok_even_when_a_stream_was_refused(monkeypatch):
    """Bytes moved, so we measured the link. A 429 on one stream does not erase
    a genuine number."""
    lock = threading.Lock()
    calls = {"n": 0}

    def _first_is_refused():
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n == 1:
            _rate_limited()
        return _serves_data()

    _install(monkeypatch, down=_first_is_refused, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=4)

    assert res["status"] == "ok"
    assert res["ok"] is True
    assert res["download_mbps"] > 0


def test_a_clean_run_is_status_ok(monkeypatch):
    _install(monkeypatch, down=_serves_data, up=_serves_data)

    res = speedtest.run_cloudflare(duration=2, streams=2)

    assert res["status"] == "ok"
    assert res["ok"] is True
    assert res.get("error") is None


# --- the other code path that can be wrong -----------------------------------


def test_a_refused_latency_probe_is_unavailable(monkeypatch):
    """The latency GETs run FIRST and return early on failure — a separate path
    with its own chance to mislabel a rate limit as a broken link."""
    _install(monkeypatch, down=_serves_data, up=_serves_data, latency=_rate_limited)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "unavailable"
    assert res["ok"] is False
    assert "refused" in res["error"]
    assert "HTTP 429" in res["error"]


def test_a_broken_latency_probe_is_still_failed(monkeypatch):
    def _dead():
        raise ConnectionResetError(104, "Connection reset by peer")

    _install(monkeypatch, down=_serves_data, up=_serves_data, latency=_dead)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    assert res["status"] == "failed"
    assert "latency probe failed" in res["error"]


# --- stop GENERATING the rate limit -----------------------------------------
#
# The refusal was self-inflicted. Measured on a live 900 Mbps sensor, the old
# fixed 1 MiB upload block made 557 POSTs inside the 5-second window (~110/s)
# against ~12 download GETs. Three sensors doing that behind one egress IP is
# what earned the 429.


def test_upload_grows_its_block_so_a_fast_link_makes_few_requests(monkeypatch):
    """Same bytes, same throughput number, far fewer requests."""
    posts = {"n": 0}
    lock = threading.Lock()

    def _fast_up():
        with lock:
            posts["n"] += 1
        return _FakeResp()

    _install(monkeypatch, down=_serves_data, up=_fast_up)

    res = speedtest.run_cloudflare(duration=2, streams=1)

    sent = res["raw"]["upload_bytes"]
    at_old_size = sent / speedtest._UPLOAD_BLOCK_MIN
    assert sent > 0
    assert posts["n"] * 4 < at_old_size, (
        f"{posts['n']} requests moved {sent} bytes; the old fixed 1 MiB block "
        f"would have needed {at_old_size:.0f} — the request rate is the thing "
        f"that tripped the rate limiter"
    )


def test_a_block_is_never_started_that_cannot_fit_the_remaining_window(monkeypatch):
    """Sizing at one second of the measured rate is not enough on its own: with
    0.2 s of the window left, a full-size block still commits the stream to a
    full second of transfer and the whole run waits for it. On a link that has
    slowed since the estimate was taken that tail is longer still, and the
    check-in behind it is delayed. So the target is the LESSER of one second and
    what is actually left.

    Runs on a VIRTUAL clock that advances only as the fake link moves bytes:
    block size is a pure function of rate and remaining window, so the test is
    too. (An earlier cut used real sleeps and passed alone but failed inside the
    full suite — a timing-flaky test is worse than no test.)
    """
    rate_bps = 8_000_000  # 64 Mbps per stream — fast enough to leave the floor
    dur = 3
    now = {"t": 1000.0}
    # `time` is imported lazily inside run_cloudflare, so it resolves
    # `time.monotonic` off the stdlib module on every use — patch it there.
    # `time.sleep` is untouched, so nothing else in the suite is affected.
    monkeypatch.setattr(time, "monotonic", lambda: now["t"])

    started: list[tuple[float, int]] = []  # (window remaining at start, size)
    up_deadline: list[float] = []

    def _urlopen(req, timeout=None, context=None, **_kw):  # noqa: ANN001
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "bytes=0" in url:
            return _FakeResp()
        if "__down" in url:
            now["t"] += 0.5  # keep the download phase finite on a virtual clock
            return _FakeResp([b"x" * 131072])
        # The upload window opens at the first upload request.
        if not up_deadline:
            up_deadline.append(now["t"] + dur)
        n = len(req.data)
        started.append((max(0.0, up_deadline[0] - now["t"]), n))
        now["t"] += n / rate_bps
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    speedtest.run_cloudflare(duration=dur, streams=1)

    assert len(started) > 2, "need a few requests to see the ramp and the tail"
    for remaining, size in started:
        budget = rate_bps * min(speedtest._UPLOAD_TARGET_SEC, remaining)
        assert size <= max(speedtest._UPLOAD_BLOCK_MIN, budget), (
            f"started a {size}-byte block with {remaining:.2f}s of the window "
            f"left — at {rate_bps} B/s that runs {size / rate_bps:.1f}s, "
            f"{size / rate_bps - remaining:.1f}s past the deadline"
        )
    # And the cap must actually have bitten: some request was shrunk by the
    # window rather than by the one-second target.
    assert any(rem < speedtest._UPLOAD_TARGET_SEC for rem, _ in started)


def test_a_slow_upload_never_grows_past_a_second_of_its_own_rate(monkeypatch):
    """The floor matters as much as the cap: a congested site must never be made
    to push MORE data than it does today just to save requests.

    The fake models a real BANDWIDTH limit — time proportional to bytes — not a
    fixed per-request delay. That distinction is the whole test: a fixed delay
    describes a link with infinite bandwidth, where growing the block IS correct,
    and judging the sizing rule against it proves nothing about a slow site.

    The property that actually bounds the damage: one request is at most ~1
    second of the link's own measured throughput, so the window overshoot and the
    extra bytes are bounded no matter how slow the link is."""
    rate_bps = 2_000_000  # 16 Mbps — a congested school uplink, per stream
    sizes: list[int] = []

    def _urlopen(req, timeout=None, context=None, **_kw):  # noqa: ANN001
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "bytes=0" in url:
            return _FakeResp()
        if "__down" in url:
            return _serves_data()
        n = len(req.data)
        sizes.append(n)
        time.sleep(n / rate_bps)  # a real link: bigger block, proportionally longer
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)

    speedtest.run_cloudflare(duration=2, streams=1)

    assert sizes, "the upload must actually have run"
    assert sizes[0] == speedtest._UPLOAD_BLOCK_MIN, "the first, uncalibrated block is the floor"
    # 2x tolerance for the ramp; the point is that it converges near the rate and
    # does not run away to the 25MB cap on a link that cannot carry it.
    assert max(sizes) <= 2 * rate_bps * speedtest._UPLOAD_TARGET_SEC, (
        f"a {rate_bps} B/s link grew its block to {max(sizes)} bytes — the sizing "
        f"rule must converge to ~1s of the measured rate, not compound to the cap"
    )
