"""Explicit reverse-DNS (PTR) enrichment.

nmap resolves PTR via the container's resolver, which on a sensor is frequently
public DNS (no internal records). This pass instead queries the LOCAL site
resolvers (DHCP-assigned DNS servers + the gateway) with `dig -x`, so internal
device hostnames that nmap couldn't see get filled. Bounded and best-effort.
"""
from __future__ import annotations

import re
import subprocess

import structlog

log = structlog.get_logger(__name__)

_BAD_PREFIXES = (";", "-", "communications error", "connection timed out")


def _dig_ptr(ip: str, resolver: str | None, timeout: int) -> str | None:
    cmd = ["dig", "-x", ip, "+short", f"+time={int(timeout)}", "+tries=1"]
    if resolver:
        cmd.insert(1, f"@{resolver}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if any(low.startswith(p) for p in _BAD_PREFIXES):
            continue
        # A PTR answer is a hostname ending in a dot, e.g. "switch1.lan."
        if re.match(r"^[A-Za-z0-9_.-]+\.?$", line):
            return line.rstrip(".")
    return None


def resolve_ptr(
    ips: list[str],
    resolvers: list[str],
    *,
    timeout: int = 2,
    limit: int = 512,
) -> dict[str, str]:
    """Return {ip: hostname} for the IPs that resolve. Tries each resolver in
    order per IP (then the system resolver as a last resort)."""
    res_list: list[str | None] = [r for r in resolvers if r]
    res_list.append(None)  # system resolver fallback
    out: dict[str, str] = {}
    for i, ip in enumerate(ips):
        if i >= limit:
            log.info("rdns capped", limit=limit)
            break
        for r in res_list:
            name = _dig_ptr(ip, r, timeout)
            if name:
                out[ip] = name
                break
    if out:
        log.info("rdns resolved", count=len(out), of=min(len(ips), limit))
    return out
