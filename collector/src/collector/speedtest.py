"""Public internet speed test (PERF-2) — the WAN counterpart to iperf3.

Cloudflare-only: a lightweight, dependency-free probe against
speed.cloudflare.com using the stdlib (urllib) — parallel time-boxed
download/upload streams + a latency/jitter sample.

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


def _empty(provider: str, error: str) -> dict:
    return {"ok": False, "provider": provider, "error": error[:500]}


def run_cloudflare(duration: int = 5, streams: int = 8, timeout: int = 60) -> dict:
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

    # --- latency + jitter: a handful of tiny timed requests ---
    samples: list[float] = []
    try:
        for _ in range(20):
            t0 = time.monotonic()
            with urllib.request.urlopen(f"{base}/__down?bytes=0", timeout=10, context=ctx) as r:
                r.read()
            samples.append((time.monotonic() - t0) * 1000.0)
    except Exception as exc:  # noqa: BLE001
        return _empty("cloudflare", f"latency probe failed: {exc}")
    latency_ms = round(min(samples), 2) if samples else None
    jitter_ms = round(statistics.pstdev(samples), 2) if len(samples) > 1 else None

    def _download(deadline: float) -> int:
        n = 0
        try:
            with urllib.request.urlopen(
                f"{base}/__down?bytes=100000000", timeout=timeout, context=ctx
            ) as r:
                while time.monotonic() < deadline:
                    chunk = r.read(131072)
                    if not chunk:
                        break
                    n += len(chunk)
        except Exception:  # noqa: BLE001
            pass
        return n

    def _upload(deadline: float) -> int:
        sent = 0
        block = b"0" * (1 << 20)  # 1 MiB
        try:
            while time.monotonic() < deadline:
                req = urllib.request.Request(f"{base}/__up", data=block, method="POST")
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    r.read()
                sent += len(block)
        except Exception:  # noqa: BLE001
            pass
        return sent

    def _measure(fn) -> float:
        start = time.monotonic()
        deadline = start + dur
        with ThreadPoolExecutor(max_workers=streams) as ex:
            totals = list(ex.map(lambda _: fn(deadline), range(streams)))
        elapsed = max(0.001, time.monotonic() - start)
        return round(sum(totals) * 8 / 1e6 / elapsed, 3)

    try:
        download_mbps = _measure(_download)
        upload_mbps = _measure(_upload)
    except Exception as exc:  # noqa: BLE001
        return _empty("cloudflare", f"throughput probe failed: {exc}")

    return {
        "ok": True,
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
        "raw": {"streams": streams, "duration_sec": dur, "latency_samples": len(samples)},
    }


def run_speedtest(provider: str = "cloudflare", **kwargs) -> dict:
    """Run the speed test. Cloudflare is the only provider (Ookla removed), so any
    provider value runs the Cloudflare probe."""
    return run_cloudflare(
        duration=int(kwargs.get("duration") or 5),
        streams=int(kwargs.get("streams") or 8),
    )
