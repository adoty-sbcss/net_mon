"""Latency / jitter / loss probes (PERF-4).

Cheap, continuous `ping` measurements to a few fixed targets — the internet
(1.1.1.1 / 8.8.8.8), the default gateway, and the DNS resolver — so the dashboard
can trend round-trip latency, jitter (mdev), and packet loss over time. Uses the
`ping` binary already in the image; runs each check-in when enabled.

⚠️ `loss_pct` IS A MEASUREMENT, NEVER A FABRICATION.
A missing `loss_pct` means "we sent no packets and counted none", and readers
depend on that: the dashboard's `latencyRowUnavailable` (lib/rules/wan-edge-core.ts)
treats `ok = false` with a NULL loss as UNMEASURED rather than as a degraded WAN
link, precisely so a broken instrument cannot be read as a broken circuit.

This module used to report 100.0 whenever `ping` produced no packet-loss line —
which is every case where the instrument failed rather than the path: no
CAP_NET_RAW after a container restart (`socket: Operation not permitted`), no
route (`connect: Network is unreachable`), a name that would not resolve, or a
`ping` process that hung past its own deadline. Each of those was reported as
total packet loss, i.e. as a WAN fault, and correlated across a fleet on the same
image it is exactly the shape `rule:wan-edge` reports as a shared edge failure.

A genuine outage is unaffected: an unreachable host still prints
"10 packets transmitted, 0 received, 100% packet loss", so the figure is parsed
and reported as the real 100.0 it is. The distinction is whether `ping` COUNTED,
not whether it succeeded.
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
        # No binary, so no packets. No `loss_pct` key at all — see the header.
        return {"host": host, "ok": False, "error": "ping not installed"}
    except subprocess.TimeoutExpired:
        # `-w <deadline>` makes ping terminate itself and PRINT a summary, so
        # reaching the subprocess timeout (deadline + 5) means the process hung
        # rather than that the network was slow. Nothing was counted, so there is
        # no loss figure to report.
        return {"host": host, "ok": False, "error": "ping timed out"}

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

    # No RTT line. Two very different cases, and conflating them is the bug this
    # module carried: ping COUNTED and lost everything (a real unreachable host
    # still prints its statistics block), versus ping never got to count at all.
    result = {
        "host": host,
        "ok": False,
        "latency_ms": None,
        "jitter_ms": None,
        "error": (proc.stderr or "host unreachable").strip()[:200] or "host unreachable",
    }
    if loss is not None:
        # A parsed figure is a real measurement — usually the genuine 100.0.
        result["loss_pct"] = loss
    else:
        # No statistics block: the instrument failed, not the path. Omit the key
        # so the row reaches the dashboard with a NULL loss and is read as
        # UNMEASURED. `error` still carries the diagnosis for whoever looks.
        log.warning(
            "ping produced no packet-loss line — reporting loss as unmeasured",
            host=host,
            returncode=proc.returncode,
            error=result["error"],
        )
    return result


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
