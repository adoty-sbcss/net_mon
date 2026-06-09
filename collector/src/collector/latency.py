"""Latency / jitter / loss probes (PERF-4).

Cheap, continuous `ping` measurements to a few fixed targets — the internet
(1.1.1.1 / 8.8.8.8), the default gateway, and the DNS resolver — so the dashboard
can trend round-trip latency, jitter (mdev), and packet loss over time. Uses the
`ping` binary already in the image; runs each check-in when enabled.
"""
from __future__ import annotations

import re
import subprocess

import structlog

log = structlog.get_logger(__name__)

_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s*packet loss")
_RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")


def _ping(host: str, count: int = 10, deadline: int = 12) -> dict:
    """Run `ping -c <count>` and parse loss% + rtt min/avg/max/mdev."""
    try:
        proc = subprocess.run(
            # -i 0.3: 10 probes in ~3s (collector runs as root); -w bounds it.
            ["ping", "-n", "-c", str(count), "-i", "0.3", "-w", str(deadline), host],
            capture_output=True,
            text=True,
            timeout=deadline + 5,
        )
    except FileNotFoundError:
        return {"host": host, "ok": False, "error": "ping not installed"}
    except subprocess.TimeoutExpired:
        return {"host": host, "ok": False, "error": "ping timed out", "loss_pct": 100.0}

    out = proc.stdout or ""
    loss_m = _LOSS_RE.search(out)
    loss = float(loss_m.group(1)) if loss_m else None
    rtt_m = _RTT_RE.search(out)
    if rtt_m:
        return {
            "host": host,
            "ok": loss is None or loss < 100.0,
            "latency_ms": round(float(rtt_m.group(2)), 3),  # avg
            "jitter_ms": round(float(rtt_m.group(4)), 3),  # mdev
            "loss_pct": loss,
        }
    # No RTT line → total loss / unreachable.
    return {
        "host": host,
        "ok": False,
        "latency_ms": None,
        "jitter_ms": None,
        "loss_pct": loss if loss is not None else 100.0,
        "error": (proc.stderr or "host unreachable").strip()[:200] or "host unreachable",
    }


def default_gateway() -> str | None:
    """Best-effort default-gateway IP via `ip route`."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
        ).stdout
        m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:  # noqa: BLE001
        return None


def probe_latency(targets: list[tuple[str, str]], count: int = 10) -> list[dict]:
    """Ping each (label, host) target. Returns one result dict per target with
    the label + kind attached."""
    results: list[dict] = []
    seen: set[str] = set()
    for label, host in targets:
        if not host or host in seen:
            continue
        seen.add(host)
        r = _ping(host, count=count)
        r["label"] = label
        results.append(r)
    return results
