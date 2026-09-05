"""Public internet speed test (PERF-2) — the WAN counterpart to iperf3.

Cloudflare-only: a lightweight, dependency-free probe against
speed.cloudflare.com using the stdlib (urllib) — parallel time-boxed
download/upload streams + a latency/jitter sample.

Practical ceiling: ~1 Gbps. This is a stdlib/urllib + thread-pool probe, so on
multi-Gig links it becomes CPU-bound and under-reports — and it measures to
Cloudflare's shared public edge, not the provisioned line rate. For 1–10 Gbps
validation use iperf3 (the internal-throughput path) against a high-capacity
server, not this WAN reachability/approx-speed check.

The Ookla CLI provider was removed (2026-06-11): its binary couldn't be reliably
installed on field boxes that build their image behind school egress filtering,
and speedtest.net's servers are themselves frequently blocked by school content
filters. Cloudflare's endpoint isn't, so it's the dependable WAN number.

On-demand runs come via the check-in command queue; scheduled runs are driven
from the check-in loop using pushed config (NETMON_SPEEDTEST_*).

A run ends in one of THREE states — ok / failed / unavailable — because the
provider refusing us (HTTP 429) and the district's link being broken are
different facts that looked identical for a week. See STATUS_* below.
"""
from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

# --- the three outcomes of a speed test ------------------------------------
# A probe has THREE possible endings, not two, and collapsing the third is what
# produced a week of false diagnosis at Cucamonga (2026-08/09):
#
#   ok           we measured the link.
#   failed       we tried and the transfer genuinely broke (reset, timeout,
#                stalled setup). This is EVIDENCE ABOUT THE NETWORK.
#   unavailable  the measurement SOURCE REFUSED US — speed.cloudflare.com
#                answered with an HTTP status instead of data (429 above all).
#                This says NOTHING about the district's link.
#
# Cucamonga was diagnosed as a failing firewall for over a week, and a firewall
# was rebooted over it. It was Cloudflare rate-limiting our own probe: three
# sensors behind one shared egress IP, each generating hundreds of requests per
# run. Single-sensor districts on their own address never showed it. With only
# ok/failed to land in, the 429 was indistinguishable from a broken WAN.
#
# This is the DNSBL lesson one level up — a refusing source and a clean result
# both returned NXDOMAIN there; here a refusing source and a broken link both
# returned ok=false. Design the third state; don't special-case 429.
#
# `ok` KEEPS ITS EXACT MEANING ("we measured the link", i.e. no direction moved
# zero bytes) so every existing reader stays truthful without being changed;
# `status` is the new, finer fact. Anything that treats ok=false as a network
# fault must consult `status` before saying so.
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_UNAVAILABLE = "unavailable"

# Cloudflare's speed.cloudflare.com edge now blocks the stdlib's default
# `Python-urllib/<ver>` User-Agent (returns 403/404), which silently broke the
# probe even though the endpoints are reachable. Send a browser-like UA so the
# requests are served. (Confirmed 2026-06-12: Python-urllib UA → 403, browser UA
# → 200 on /__down + /__up.)
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# --- upload request SIZING (why the 429 happened at all) --------------------
# Cloudflare rate-limits per SOURCE IP, and districts routinely put several
# sensors behind one. The UPLOAD loop is what generates the volume: one POST per
# block, so a small block on a fast link means an enormous request rate. Measured
# on a live 900 Mbps sensor at the old fixed 1 MiB: 557 POSTs inside the 5-second
# window (~110/s) against ~12 download GETs. Three sensors doing that on one
# address is enough to earn a 429 — the Cucamonga incident, self-inflicted.
#
# So size each request at roughly ONE SECOND of the stream's own measured rate:
# identical bytes, identical throughput number, ~20x fewer requests on a fast
# link. The floor matters as much as the cap — a congested site keeps sending
# 1 MiB blocks, so we never make a slow link push MORE data than it does today
# (the first block of every stream is always the floor, un-calibrated).
_UPLOAD_BLOCK_MIN = 1 << 20  # 1 MiB
_UPLOAD_BLOCK_MAX = 25_000_000  # /__up serves 100MB; 25MB bounds one request's overshoot
_UPLOAD_TARGET_SEC = 1.0


def _empty(provider: str, error: str, status: str = STATUS_FAILED) -> dict:
    return {
        "ok": False,
        "status": status,
        "provider": provider,
        "error": error[:500],
    }


def _describe(exc: BaseException) -> str:
    """Short, greppable rendering of a transfer exception for the `error` field.
    The class name matters as much as the message: a bare `timed out` and an
    `HTTPError: 403` mean very different things to whoever reads the row."""
    return f"{type(exc).__name__}: {exc}"[:200]


def _http_code(exc: BaseException) -> int | None:
    """The HTTP status if the endpoint ANSWERED us with one, else None.

    This is the whole discriminator between `failed` and `unavailable`: a status
    code means speed.cloudflare.com was reached, understood the request, and
    declined it. A reset or a timeout means the transfer itself broke.

    Note HTTPError subclasses URLError (and OSError), so this must be checked
    BEFORE any generic transport-error branch."""
    import urllib.error

    code = getattr(exc, "code", None)
    return int(code) if isinstance(exc, urllib.error.HTTPError) and code is not None else None


def run_cloudflare(duration: int = 5, streams: int = 16, timeout: int = 60) -> dict:
    """Lightweight Cloudflare probe (stdlib only): latency/jitter + time-boxed
    parallel download/upload throughput against speed.cloudflare.com."""
    import ssl
    import statistics
    import time
    import urllib.error
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    base = "https://speed.cloudflare.com"
    ctx = ssl.create_default_context()
    dur = max(2, min(int(duration or 5), 20))
    # Clamp streams like dur — it's pushed from the dashboard and feeds
    # ThreadPoolExecutor(max_workers=...) directly, so an unbounded value would
    # spawn that many threads (and sockets) on a small field box.
    streams = max(1, min(int(streams or 16), 64))
    # One buffer for the whole run, sliced per request by every upload thread.
    # Allocated here rather than at import so a box that never speed-tests never
    # pays for it, and once rather than per-request so 16 threads growing their
    # block size don't churn 25MB allocations.
    upload_buf = memoryview(b"0" * _UPLOAD_BLOCK_MAX)

    def _get(url: str, timeout_s: int):
        # A real User-Agent is required — Cloudflare blocks Python-urllib's default.
        return urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": _BROWSER_UA}),
            timeout=timeout_s,
            context=ctx,
        )

    # --- latency + jitter: a handful of tiny timed requests ---
    samples: list[float] = []
    try:
        for _ in range(20):
            t0 = time.monotonic()
            with _get(f"{base}/__down?bytes=0", 10) as r:
                r.read()
            samples.append((time.monotonic() - t0) * 1000.0)
    except urllib.error.HTTPError as exc:
        # The endpoint answered — it just refused. Nothing was learned about the
        # link, so this is `unavailable`, not a WAN fault. (A rate limit reaches
        # these tiny GETs too once the IP is over budget.)
        return _empty(
            "cloudflare",
            f"latency probe refused by speed.cloudflare.com "
            f"(HTTP {exc.code}): {_describe(exc)}",
            STATUS_UNAVAILABLE,
        )
    except Exception as exc:  # noqa: BLE001
        return _empty("cloudflare", f"latency probe failed: {exc}")
    latency_ms = round(min(samples), 2) if samples else None
    jitter_ms = round(statistics.pstdev(samples), 2) if len(samples) > 1 else None

    # Each transfer worker returns (bytes_moved, first_exception_or_None). The
    # exception is CAPTURED, not swallowed: a stream that moved nothing because it
    # was reset/timed out is evidence of a blocked path, and the exception CLASS is
    # the most useful thing in the row. (Cucamonga, 2026-08/09: 47% of speed tests
    # stored 0.0 Mbps with ok=true and nothing ever flagged it.)
    # Note the exception is diagnostic, NOT the failure trigger — zero bytes is.
    # Setup can outlast the window without ever raising; see the `blocked` rules.
    def _download(deadline: float) -> tuple[int, str | None, int | None]:
        n = 0
        # Cloudflare 403s very large single /__down requests (100MB is rejected;
        # ≤50MB is served). Request a safe size and RE-REQUEST until the time
        # window closes, so a fast link still saturates the measurement window.
        # 50MB (the served max) + many parallel streams pushes the ceiling toward
        # ~1 Gbps; past that this stdlib/urllib probe is CPU-bound — use iperf3.
        per_req = 50_000_000
        try:
            while time.monotonic() < deadline:
                with _get(f"{base}/__down?bytes={per_req}", timeout) as r:
                    while time.monotonic() < deadline:
                        chunk = r.read(131072)
                        if not chunk:
                            break
                        n += len(chunk)
        except Exception as exc:  # noqa: BLE001
            return n, _describe(exc), _http_code(exc)
        return n, None, None

    def _upload(deadline: float) -> tuple[int, str | None, int | None]:
        sent = 0
        size = _UPLOAD_BLOCK_MIN
        began = time.monotonic()
        try:
            while time.monotonic() < deadline:
                req = urllib.request.Request(
                    f"{base}/__up",
                    # A read-only slice of the shared buffer — no per-request
                    # allocation, and 16 threads can hold slices of the same
                    # immutable bytes safely.
                    data=upload_buf[:size],
                    method="POST",
                    headers={"User-Agent": _BROWSER_UA},
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    r.read()
                sent += size
                # Re-aim each request at ~1 s of THIS stream's own rate, measured
                # CUMULATIVELY rather than from the last request alone. The
                # per-request ratio compounds: where fixed overhead (RTT, TLS)
                # dominates a small block, every step multiplies the size again
                # and it runs away to the cap — worst on exactly the high-latency,
                # low-bandwidth links that can least afford a 25MB request. A
                # running average self-corrects instead: an over-large block
                # takes proportionally longer, which pulls the next one back down.
                rate = sent / max(time.monotonic() - began, 0.001)
                size = max(
                    _UPLOAD_BLOCK_MIN,
                    min(_UPLOAD_BLOCK_MAX, int(rate * _UPLOAD_TARGET_SEC)),
                )
        except Exception as exc:  # noqa: BLE001
            return sent, _describe(exc), _http_code(exc)
        return sent, None, None

    def _measure(fn) -> tuple[float, int, int, int, str | None, int | None]:
        """Run `streams` copies of fn for `dur` seconds.

        Returns (mbps, total_bytes, streams_that_errored, streams_REFUSED,
        first_error, first_http_status). `refused` counts only streams whose
        failure carried an HTTP status — the endpoint answered and declined."""
        start = time.monotonic()
        deadline = start + dur
        with ThreadPoolExecutor(max_workers=streams) as ex:
            outcomes = list(ex.map(lambda _: fn(deadline), range(streams)))
        elapsed = max(0.001, time.monotonic() - start)
        total = sum(n for n, _, _ in outcomes)
        errs = [(e, code) for _, e, code in outcomes if e]
        mbps = round(total * 8 / 1e6 / elapsed, 3)
        first_error, first_code = errs[0] if errs else (None, None)
        # Surface an HTTP status if ANY stream saw one: it is the most useful
        # thing in the row, and streams do not all fail the same way.
        for err, code in errs:
            if code is not None:
                first_error, first_code = err, code
                break
        refused = sum(1 for _, code in errs if code is not None)
        return mbps, total, len(errs), refused, first_error, first_code

    try:
        download_mbps, dl_bytes, dl_failed, dl_refused, dl_error, dl_code = _measure(_download)
        upload_mbps, ul_bytes, ul_failed, ul_refused, ul_error, ul_code = _measure(_upload)
    except Exception as exc:  # noqa: BLE001
        return _empty("cloudflare", f"throughput probe failed: {exc}")

    # A direction that moved ZERO bytes MEASURED NOTHING. It is a failed test, not
    # a 0.0 Mbps reading, and reporting it as a success is the whole Cucamonga bug.
    # TWO different mechanisms produce a zero, and both were reachable there:
    #   * one or more streams RAISED (reset / timed out) → the path is actively
    #     blocked mid-transfer;
    #   * NO stream raised and still nothing moved → every stream's request setup
    #     (TCP + TLS, typically through an overloaded inspection proxy) outlasted
    #     the `dur`-second window, so the read loop never got to run. There is no
    #     exception to catch on this path — which is why keying the failure on
    #     "an exception was seen" was not enough: a firewall that merely makes
    #     setup slow, rather than resetting, still produced ok=true / 0.0 Mbps.
    # The error text names which mechanism it was, because they need different
    # fixes (a block/ACL vs. a saturated proxy).
    #
    # Deliberately NOT a failure: some streams raised but bytes still moved — a
    # degraded yet genuine measurement. Erasing it would remove the only number
    # available during a brown-out; the per-stream failure counts go into `raw`
    # instead, so the degradation is visible without the row leaving the baselines.
    def _blocked_reason(direction: str, failed: int, error: str | None) -> str:
        if error:
            return f"{direction} moved 0 bytes ({failed}/{streams} streams failed): {error}"
        return (
            f"{direction} moved 0 bytes (no stream raised — every request's setup "
            f"outlasted the {dur}s measurement window)"
        )

    # A direction that moved zero bytes is problematic either way, but WHY decides
    # whether the row is evidence about the district's network.
    #
    # `unavailable` requires that refusal explains ALL of it: every stream that
    # failed did so with an HTTP status. If even one stream was reset or timed
    # out, there IS real network evidence in this run and it must not be filed
    # under "the provider wouldn't talk to us" — suppressing a genuine WAN
    # failure is the more expensive mistake, and WAN degradation on this fleet is
    # already hard enough to see.
    def _outcome(failed: int, refused: int) -> str:
        return STATUS_UNAVAILABLE if refused > 0 and refused == failed else STATUS_FAILED

    def _refused_reason(direction: str, refused: int, code: int | None, error: str | None) -> str:
        return (
            f"{direction} not measured — speed.cloudflare.com refused the probe "
            f"(HTTP {code}) on {refused}/{streams} streams: {error}"
        )

    blocked: list[str] = []
    outcomes: list[str] = []
    for direction, moved, failed, refused, error, code in (
        ("download", dl_bytes, dl_failed, dl_refused, dl_error, dl_code),
        ("upload", ul_bytes, ul_failed, ul_refused, ul_error, ul_code),
    ):
        if moved:
            continue
        outcome = _outcome(failed, refused)
        outcomes.append(outcome)
        blocked.append(
            _refused_reason(direction, refused, code, error)
            if outcome == STATUS_UNAVAILABLE
            else _blocked_reason(direction, failed, error)
        )

    if not blocked:
        status = STATUS_OK
    elif all(o == STATUS_UNAVAILABLE for o in outcomes):
        status = STATUS_UNAVAILABLE
    else:
        status = STATUS_FAILED

    result = {
        # Partial numbers are preserved either way: a blocked download with a
        # working upload still reports the upload figure and the latency sample.
        "ok": status == STATUS_OK,  # unchanged meaning: no direction moved zero bytes
        "status": status,
        "provider": "cloudflare",
        "download_mbps": download_mbps,
        "upload_mbps": upload_mbps,
        "latency_ms": latency_ms,
        "jitter_ms": jitter_ms,
        "loss_pct": None,
        "server": "Cloudflare",
        "isp": None,
        "result_url": None,
        "external_ip": None,
        "raw": {
            "streams": streams,
            "duration_sec": dur,
            "latency_samples": len(samples),
            "download_bytes": dl_bytes,
            "upload_bytes": ul_bytes,
            "download_streams_failed": dl_failed,
            "upload_streams_failed": ul_failed,
            "download_error": dl_error,
            "upload_error": ul_error,
            # The status codes are the discriminator; keep them queryable rather
            # than only greppable out of the message text.
            "download_streams_refused": dl_refused,
            "upload_streams_refused": ul_refused,
            "download_http_status": dl_code,
            "upload_http_status": ul_code,
        },
    }
    if blocked:
        result["error"] = "; ".join(blocked)[:500]
        if status == STATUS_UNAVAILABLE:
            # NOT a network fault. Logged at its own level and wording so a box's
            # journal doesn't read like the district's link failed.
            log.warning(
                "speed test unavailable — the provider refused the probe "
                "(rate limit or block); this says nothing about the link",
                error=result["error"],
                latency_ms=latency_ms,
            )
        else:
            log.warning(
                "speed test blocked (zero bytes moved)",
                error=result["error"],
                latency_ms=latency_ms,
            )
    return result


def run_speedtest(provider: str = "cloudflare", **kwargs) -> dict:
    """Run the speed test. Cloudflare is the only provider (Ookla removed), so any
    provider value runs the Cloudflare probe."""
    return run_cloudflare(
        duration=int(kwargs.get("duration") or 5),
        streams=int(kwargs.get("streams") or 16),
    )
