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
"""
from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

# Cloudflare's speed.cloudflare.com edge now blocks the stdlib's default
# `Python-urllib/<ver>` User-Agent (returns 403/404), which silently broke the
# probe even though the endpoints are reachable. Send a browser-like UA so the
# requests are served. (Confirmed 2026-06-12: Python-urllib UA → 403, browser UA
# → 200 on /__down + /__up.)
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _empty(provider: str, error: str) -> dict:
    return {"ok": False, "provider": provider, "error": error[:500]}


def _describe(exc: BaseException) -> str:
    """Short, greppable rendering of a transfer exception for the `error` field.
    The class name matters as much as the message: a bare `timed out` and an
    `HTTPError: 403` mean very different things to whoever reads the row."""
    return f"{type(exc).__name__}: {exc}"[:200]


def run_cloudflare(duration: int = 5, streams: int = 16, timeout: int = 60) -> dict:
    """Lightweight Cloudflare probe (stdlib only): latency/jitter + time-boxed
    parallel download/upload throughput against speed.cloudflare.com."""
    import ssl
    import statistics
    import time
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    base = "https://speed.cloudflare.com"
    ctx = ssl.create_default_context()
    dur = max(2, min(int(duration or 5), 20))
    # Clamp streams like dur — it's pushed from the dashboard and feeds
    # ThreadPoolExecutor(max_workers=...) directly, so an unbounded value would
    # spawn that many threads (and sockets) on a small field box.
    streams = max(1, min(int(streams or 16), 64))

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
    except Exception as exc:  # noqa: BLE001
        return _empty("cloudflare", f"latency probe failed: {exc}")
    latency_ms = round(min(samples), 2) if samples else None
    jitter_ms = round(statistics.pstdev(samples), 2) if len(samples) > 1 else None

    # Each transfer worker returns (bytes_moved, first_exception_or_None). The
    # exception is CAPTURED, not swallowed: a stream that moved nothing because it
    # was reset/timed out is evidence of a blocked path, and without it a firewall
    # that passes the tiny latency GETs but chokes every bulk stream is recorded as
    # a perfectly successful 0.0 Mbps measurement. (Cucamonga, 2026-08/09: 47% of
    # speed tests stored 0.0 Mbps with ok=true and nothing ever flagged it.)
    def _download(deadline: float) -> tuple[int, str | None]:
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
            return n, _describe(exc)
        return n, None

    def _upload(deadline: float) -> tuple[int, str | None]:
        sent = 0
        block = b"0" * (1 << 20)  # 1 MiB
        try:
            while time.monotonic() < deadline:
                req = urllib.request.Request(
                    f"{base}/__up",
                    data=block,
                    method="POST",
                    headers={"User-Agent": _BROWSER_UA},
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    r.read()
                sent += len(block)
        except Exception as exc:  # noqa: BLE001
            return sent, _describe(exc)
        return sent, None

    def _measure(fn) -> tuple[float, int, int, str | None]:
        """Run `streams` copies of fn for `dur` seconds.
        Returns (mbps, total_bytes, streams_that_errored, first_error)."""
        start = time.monotonic()
        deadline = start + dur
        with ThreadPoolExecutor(max_workers=streams) as ex:
            outcomes = list(ex.map(lambda _: fn(deadline), range(streams)))
        elapsed = max(0.001, time.monotonic() - start)
        total = sum(n for n, _ in outcomes)
        errs = [e for _, e in outcomes if e]
        mbps = round(total * 8 / 1e6 / elapsed, 3)
        return mbps, total, len(errs), (errs[0] if errs else None)

    try:
        download_mbps, dl_bytes, dl_failed, dl_error = _measure(_download)
        upload_mbps, ul_bytes, ul_failed, ul_error = _measure(_upload)
    except Exception as exc:  # noqa: BLE001
        return _empty("cloudflare", f"throughput probe failed: {exc}")

    # A direction is BLOCKED — not merely slow — when it moved zero bytes AND at
    # least one stream raised. Two cases are deliberately NOT failures:
    #   * zero bytes with no exception   → the edge served nothing but nothing broke;
    #                                      a genuine (if odd) zero-throughput reading.
    #   * some streams raised, some moved bytes → a real, if degraded, measurement.
    #     Reporting it as a failure would erase the only number we have during a
    #     brown-out. The per-direction stream-error counts go into `raw` instead, so
    #     the degradation is visible without the row being dropped from baselines.
    blocked: list[str] = []
    if dl_bytes == 0 and dl_error:
        blocked.append(
            f"download moved 0 bytes ({dl_failed}/{streams} streams failed): {dl_error}"
        )
    if ul_bytes == 0 and ul_error:
        blocked.append(
            f"upload moved 0 bytes ({ul_failed}/{streams} streams failed): {ul_error}"
        )

    result = {
        # Partial numbers are preserved either way: a blocked download with a
        # working upload still reports the upload figure and the latency sample.
        "ok": not blocked,
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
        },
    }
    if blocked:
        result["error"] = "; ".join(blocked)[:500]
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
