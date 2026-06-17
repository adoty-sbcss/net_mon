"""Network-device reachability probing (ping + traceroute + SNMP-response).

Answers the operator question "which switches are out there, and which ones
answer SNMP vs. only respond to ping?" — useful when most access switches are
reachable at L3 but silently drop SNMP (ACL not permitting the sensor, or SNMP
disabled). For each infrastructure candidate (gateway + LLDP mgmt IPs +
network-vendor OUIs — the same set SNMP polling uses) we record:

  * ICMP ping: alive, average RTT, packet-loss %.
  * SNMP: whether it answered the poll/credential trial (passed in by caller).
  * traceroute: the L3 path (hop list) and hop count, so even devices that
    refuse SNMP show up with their network path.

All bounded and best-effort: short per-probe timeouts, a target cap, and a
graceful skip if `traceroute` isn't installed (ping still runs).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_LOSS = re.compile(r"(\d+(?:\.\d+)?)%\s*packet loss")
_RTT_AVG = re.compile(r"=\s*[\d.]+/([\d.]+)/")
_FLOAT_MS = re.compile(r"([\d.]+)\s*ms")
_HOP = re.compile(r"^(\d+)\s+(.*)$")  # traceroute hop line: "<n>  <rest>"


def probe(
    targets: list[dict[str, Any]],
    *,
    traceroute: bool = True,
    max_hops: int = 10,
    ping_count: int = 2,
    ping_timeout: int = 1,
    tr_wait: int = 1,
    limit: int = 256,
) -> list[dict[str, Any]]:
    """Ping (and optionally traceroute) each target; return enriched records.

    Each input target is a dict with at least ``ip`` and may carry
    ``hostname``/``vendor``/``source``/``snmp_responded``/``snmp_version``
    which are passed through onto the output record.
    """
    have_tr = traceroute and shutil.which("traceroute") is not None
    if traceroute and not have_tr:
        log.info("traceroute not installed; reachability will ping only")

    out: list[dict[str, Any]] = []
    for i, t in enumerate(targets):
        ip = t.get("ip")
        if not ip:
            continue
        if i >= limit:
            log.info("reachability capped", limit=limit)
            break

        alive, rtt_ms, loss_pct = _ping(ip, count=ping_count, timeout=ping_timeout)
        path: list[dict[str, Any]] = []
        hops: int | None = None
        if have_tr:
            path, hops = _traceroute(ip, max_hops=max_hops, wait=tr_wait)

        out.append({
            "ip": ip,
            "hostname": t.get("hostname"),
            "vendor": t.get("vendor"),
            "source": t.get("source"),
            "ping_alive": alive,
            "ping_rtt_ms": rtt_ms,
            "ping_loss_pct": loss_pct,
            "snmp_responded": t.get("snmp_responded"),
            "snmp_version": t.get("snmp_version"),
            "traceroute_hops": hops,
            "traceroute_path": path,
        })
    return out


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------


def _ping(ip: str, *, count: int, timeout: int) -> tuple[bool, float | None, int | None]:
    """Return (alive, avg_rtt_ms, loss_pct). Best-effort; never raises."""
    cmd = ["ping", "-n", "-c", str(count), "-W", str(timeout), ip]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=count * timeout + 5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False, None, None
    text = res.stdout + res.stderr

    loss: int | None = None
    m = _LOSS.search(text)
    if m:
        try:
            loss = int(round(float(m.group(1))))
        except ValueError:
            loss = None

    rtt: float | None = None
    m = _RTT_AVG.search(text)
    if m:
        try:
            rtt = float(m.group(1))
        except ValueError:
            rtt = None

    # Alive if the OS reported at least one received reply (rc==0 is reliable
    # for ping, but we also accept a parsed <100% loss as a fallback).
    alive = res.returncode == 0 or (loss is not None and loss < 100)
    return alive, rtt, loss


# ---------------------------------------------------------------------------
# traceroute
# ---------------------------------------------------------------------------


def _traceroute(ip: str, *, max_hops: int, wait: int) -> tuple[list[dict[str, Any]], int | None]:
    """Return (path, hop_count_to_destination). path is a list of
    {hop, ip, rtt_ms} (ip None for a timed-out hop). hop_count is the hop at
    which the destination IP first appears, else None (never reached)."""
    cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(wait), "-q", "1", ip]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max_hops * wait + 10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return [], None

    path: list[dict[str, Any]] = []
    reached_at: int | None = None
    for line in res.stdout.splitlines():
        line = line.strip()
        m = _HOP.match(line)
        if not m:
            continue  # the "traceroute to ..." header
        hop_num = int(m.group(1))
        rest = m.group(2)
        hop_ip: str | None = None
        rtt_ms: float | None = None
        ipm = _IPV4.search(rest)
        if ipm:
            hop_ip = ipm.group(1)
        msm = _FLOAT_MS.search(rest)
        if msm:
            try:
                rtt_ms = float(msm.group(1))
            except ValueError:
                rtt_ms = None
        path.append({"hop": hop_num, "ip": hop_ip, "rtt_ms": rtt_ms})
        if hop_ip == ip and reached_at is None:
            reached_at = hop_num
    return path, reached_at
