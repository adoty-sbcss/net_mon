"""iperf3 throughput test (#10).

Runs `iperf3 -c <server>` against the district target and parses the JSON
summary into a compact result the dashboard stores. On-demand runs come via the
check-in command queue; scheduled runs are driven from the check-in loop using
pushed config (NETMON_IPERF_*). Requires the `iperf3` binary in the image.
"""
from __future__ import annotations

import json
import subprocess

import structlog

log = structlog.get_logger(__name__)


def run_iperf(
    server: str,
    port: int = 5201,
    protocol: str = "tcp",
    direction: str = "down",
    duration: int = 10,
) -> dict:
    """Run one iperf3 test. Returns a result dict (ok / throughput_mbps / …)."""
    if not server:
        return {"ok": False, "error": "no iperf server configured"}
    proto = "udp" if protocol == "udp" else "tcp"
    dur = max(1, min(int(duration or 10), 60))
    cmd = ["iperf3", "-c", server, "-p", str(int(port or 5201)), "-t", str(dur), "-J"]
    if direction == "down":
        cmd.append("-R")  # reverse: server sends → measures download at the sensor
    if proto == "udp":
        cmd += ["-u", "-b", "0"]  # push max so jitter/loss are meaningful

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=dur + 20)
    except FileNotFoundError:
        return {"ok": False, "error": "iperf3 not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "iperf3 timed out"}

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"ok": False, "error": (proc.stderr or "iperf3 produced no JSON")[:500]}

    if data.get("error"):
        return {"ok": False, "error": str(data["error"])[:500]}

    end = data.get("end", {})
    result: dict = {
        "ok": True,
        "server": server,
        "port": int(port or 5201),
        "protocol": proto,
        "direction": direction,
        "duration": dur,
    }
    if proto == "udp":
        s = end.get("sum", {})
        result["throughput_mbps"] = round((s.get("bits_per_second") or 0) / 1e6, 3)
        result["jitter_ms"] = s.get("jitter_ms")
        result["loss_pct"] = s.get("lost_percent")
        result["raw"] = {"sum": s}
    else:
        recv = end.get("sum_received", {})
        sent = end.get("sum_sent", {})
        bps = (recv if direction == "down" else sent).get("bits_per_second") or 0
        result["throughput_mbps"] = round(bps / 1e6, 3)
        result["retransmits"] = sent.get("retransmits")
        result["raw"] = {"sum_sent": sent, "sum_received": recv}
    return result
