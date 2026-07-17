"""Explicit reverse-DNS (PTR) enrichment.

nmap resolves PTR via the container's resolver, which on a sensor is frequently
public DNS (no internal records). This pass instead queries the LOCAL site
resolvers (DHCP-assigned DNS servers + the gateway) with `dig -x`, so internal
device hostnames that nmap couldn't see get filled. Bounded and best-effort.
"""
from __future__ import annotations

import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

import structlog

log = structlog.get_logger(__name__)

_BAD_PREFIXES = (";", "-", "communications error", "connection timed out")

# Bounded fan-out. Every lookup is a `dig` subprocess blocked on the network, so
# threads are the right tool; the cap is about not spawning `limit` (512)
# processes at once on a small sensor box. Serially this pass cost MANY MINUTES
# per scan on a /22 with a few hundred unnamed hosts.
_MAX_WORKERS = 16

# A resolver that fails to REPLY this many times in a row is treated as dead for
# the rest of this batch and skipped. This matters because scan.py appends the
# GATEWAY as a resolver and it usually does not serve DNS at all, so without the
# gate every unresolvable IP burns a full `+time=N` timeout on it.
#
# CRITICAL: only a *non-reply* is a strike. A resolver that answers NXDOMAIN /
# "no PTR record" is ALIVE and healthy — that is the normal case for client
# subnets (most DHCP/IoT hosts have no PTR), and counting it would bench every
# working resolver almost immediately. Any reply resets the counter.
_DEAD_STRIKES = 8

# dig exit status 9 = "no reply from server". Everything that got an answer —
# including NXDOMAIN — exits 0.
_DIG_NO_REPLY = 9
# Belt-and-suspenders alongside the exit code: the stderr text dig prints when a
# resolver never answered, in case a dig build reports the status differently.
_NO_REPLY_MARKERS = (
    "communications error",
    "no servers could be reached",
    "connection timed out",
)


def _dig_ptr(ip: str, resolver: str | None, timeout: int) -> tuple[str | None, bool]:
    """Look up one PTR. Returns (hostname_or_None, resolver_replied).

    `resolver_replied` distinguishes "this resolver is alive but has no PTR for
    that IP" (True — keep using it) from "this resolver never answered" (False —
    a strike toward benching it). See `_DEAD_STRIKES`.
    """
    cmd = ["dig", "-x", ip, "+short", f"+time={int(timeout)}", "+tries=1"]
    if resolver:
        cmd.insert(1, f"@{resolver}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # A hard timeout is a non-reply. dig being missing / unspawnable is not
        # the resolver's fault, but nothing can ever resolve in that state either,
        # so reporting "no reply" makes the whole pass bail out fast — the useful
        # outcome, and identical to the old behavior's (None) result.
        return None, False

    err = (res.stderr or "").lower()
    if res.returncode == _DIG_NO_REPLY or any(m in err for m in _NO_REPLY_MARKERS):
        return None, False

    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if any(low.startswith(p) for p in _BAD_PREFIXES):
            continue
        # A PTR answer is a hostname ending in a dot, e.g. "switch1.lan."
        if re.match(r"^[A-Za-z0-9_.-]+\.?$", line):
            return line.rstrip("."), True
    # The resolver answered, it just had no PTR for this IP (the common case).
    return None, True


def resolve_ptr(
    ips: list[str],
    resolvers: list[str],
    *,
    timeout: int = 2,
    limit: int = 512,
) -> dict[str, str]:
    """Return {ip: hostname} for the IPs that resolve. Tries each resolver in
    order per IP (then the system resolver as a last resort).

    Hosts are resolved on a small thread pool (`_MAX_WORKERS`) rather than one at
    a time, and a resolver that stops replying is dropped for the rest of the
    batch (`_DEAD_STRIKES`) instead of costing every remaining host a timeout.
    """
    res_list: list[str | None] = [r for r in resolvers if r]
    res_list.append(None)  # system resolver fallback
    targets = ips[:limit]
    if len(ips) > limit:
        log.info("rdns capped", limit=limit)
    if not targets:
        return {}

    # Consecutive non-replies per resolver. Shared across the pool, so guarded.
    strikes: dict[str | None, int] = dict.fromkeys(res_list, 0)
    lock = threading.Lock()

    def _is_dead(resolver: str | None) -> bool:
        with lock:
            return strikes[resolver] >= _DEAD_STRIKES

    def _record(resolver: str | None, replied: bool) -> None:
        with lock:
            strikes[resolver] = 0 if replied else strikes[resolver] + 1

    def _one(ip: str) -> tuple[str, str | None]:
        for resolver in res_list:
            if _is_dead(resolver):
                continue
            name, replied = _dig_ptr(ip, resolver, timeout)
            _record(resolver, replied)
            if name:
                return ip, name
        return ip, None

    out: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(targets))) as pool:
        for ip, name in pool.map(_one, targets):
            if name:
                out[ip] = name

    dead = [r for r in res_list if strikes[r] >= _DEAD_STRIKES]
    if dead:
        # Usually the gateway, which is rarely a DNS server — worth surfacing so
        # an operator can see why a resolver contributed nothing.
        log.info("rdns: resolver(s) not replying, skipped for the rest of this pass",
                 resolvers=[r or "system" for r in dead])
    if out:
        log.info("rdns resolved", count=len(out), of=len(targets))
    return out
