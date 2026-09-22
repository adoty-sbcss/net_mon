"""Egress (public) IP self-report — PUB-21.

The dashboard wants to know which public address each school reaches the
internet from: a WAN failover to the backup circuit shows up as an address
change, and the address is what the external-exposure lookup (Shodan
InternetDB, run dashboard-side) is keyed on. Until this module the fleet had no
producer at all — `speedtest_results.external_ip` is hard-coded None on the
Cloudflare path.

How it measures: a GET of Cloudflare's `/cdn-cgi/trace` on the resolver's
anycast IP LITERALS. The response carries an `ip=` line — the address the
request arrived from. Using literals rather than a hostname pins the address
family (a request to 1.1.1.1 can only leave over IPv4), needs no DNS, and the
certificate on those addresses carries IP SANs, so TLS still verifies.

Honesty rules, the same shape as speedtest.py's:

* Every candidate is VALIDATED, not just the last one. A captive portal or a
  filtering proxy can answer 200 with a page of its own; an `ip=` that is not a
  global address of the requested family is rejected and the next source is
  tried. A guard that ran only on the final fallback would prefer a bad early
  answer over a good late one.
* Three endings per family, never collapsed into "no IP":
    ok       — a validated global address.
    refused  — a source answered, but with a non-200 status, a body with no
               usable `ip=` (a block page, a portal, a rate limit), or a TLS
               certificate that isn't Cloudflare's (a decrypting middlebox). We
               learned nothing about the address, and nothing about the link.
    failed   — no source could be reached at all (timeout, reset, no route).
  IPv6 additionally has `none`: the box has no IPv6 route, which is normal and
  must not read as a fault.
* The status is decided by the FAMILY-PINNED literals only. The hostname
  fallback resolves to whichever family the box prefers, so its answer can make
  a family `ok` (when it answered in that family) but its failures say nothing
  about either family — they are appended to the error text as `hostname: …`
  and never change the status.
* Measured at most every REFRESH_SEC (RETRY_SEC after an unsuccessful IPv4
  attempt — IPv6 trouble alone does not shorten the cache) and cached on disk, so a three-minute check-in does not become a three-minute
  poll of someone else's endpoint. The cached `observedAt` travels with the
  value, so the dashboard knows how old the reading is.

The dashboard ALSO records the address a check-in arrives from; this report is
the one that works regardless of the proxy topology in front of the dashboard
and the only one that sees IPv6.
"""
from __future__ import annotations

import errno
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from . import __version__

log = structlog.get_logger(__name__)

EGRESS_CACHE_FILE = Path("/var/lib/netmon/egress.json")
REFRESH_SEC = 15 * 60
RETRY_SEC = 5 * 60
TIMEOUT_SEC = 3.0
SOURCE = "cloudflare-trace"

# The IP literals come first (family-pinned, no DNS). Many K-12 firewalls block
# 1.1.1.1 / 1.0.0.1 outright as a DoH-bypass control, so the last candidate is
# the same trace endpoint on an ordinary Cloudflare hostname. It is NOT
# family-pinned — the resolver picks — but parse_trace rejects an answer of the
# wrong family, so it can only ever fill the family it actually used.
_HOSTNAME_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
V4_SOURCES: tuple[str, ...] = (
    "https://1.1.1.1/cdn-cgi/trace",
    "https://1.0.0.1/cdn-cgi/trace",
    _HOSTNAME_TRACE,
)
V6_SOURCES: tuple[str, ...] = (
    "https://[2606:4700:4700::1111]/cdn-cgi/trace",
    "https://[2606:4700:4700::1001]/cdn-cgi/trace",
    _HOSTNAME_TRACE,
)

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_FAILED = "failed"
STATUS_NONE = "none"  # IPv6 only: no route — normal, not a fault

# errno values that mean "this host has no path for that family at all".
_NO_ROUTE_ERRNOS = frozenset(
    e for e in (
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "EADDRNOTAVAIL", None),
        getattr(errno, "EAFNOSUPPORT", None),
    ) if e is not None
)

Fetcher = Callable[[str], tuple[int, str]]


def parse_trace(body: str, family: int) -> str | None:
    """The validated `ip=` address from a trace body, or None.

    Only a GLOBAL address of the requested family counts: RFC 1918, CGNAT
    (100.64/10), loopback, link-local, documentation and reserved space are all
    rejected, because none of them can be a public egress and every one of them
    is what a misbehaving middlebox might echo.
    """
    for line in body.splitlines():
        if not line.startswith("ip="):
            continue
        raw = line[3:].strip()
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return None
        if ip.version != family or not ip.is_global:
            return None
        return str(ip)
    return None


def _default_fetch(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": f"netmon-collector/{__version__}"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:  # noqa: S310 — fixed https literals
        return int(resp.status), resp.read(4096).decode("utf-8", "replace")


def _is_no_route(exc: BaseException) -> bool:
    reason: Any = getattr(exc, "reason", exc)
    if isinstance(reason, OSError) and reason.errno in _NO_ROUTE_ERRNOS:
        return True
    if isinstance(reason, socket.gaierror):
        return True
    return False


def measure_family(family: int, sources: tuple[str, ...], fetch: Fetcher) -> dict[str, Any]:
    """Try every source for one family; first VALIDATED answer wins.

    Evidence from family-pinned sources decides the status; the unpinned
    hostname can only contribute an `ok` (see the module doc).
    """
    refused: list[str] = []
    failed: list[str] = []
    hostname_notes: list[str] = []
    no_route = 0
    literals = [u for u in sources if u != _HOSTNAME_TRACE]
    for url in sources:
        pinned = url != _HOSTNAME_TRACE
        if not pinned and family == 6 and literals and no_route >= len(literals):
            # Every pinned v6 literal said "no route": the hostname would connect
            # over IPv4 and could never yield IPv6 evidence. Skip the request.
            break
        refusals = refused if pinned else hostname_notes
        failures = failed if pinned else hostname_notes
        try:
            status, body = fetch(url)
        except urllib.error.HTTPError as exc:
            refusals.append(f"HTTP {exc.code}")
            continue
        except Exception as exc:  # noqa: BLE001 — every transport failure is data here
            reason: Any = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError) and not isinstance(
                reason, (ssl.SSLEOFError, ssl.SSLZeroReturnError)
            ):
                # Something spoke TLS back with a certificate (or protocol) that
                # isn't the source's — a decrypting filter or a portal. A refusal,
                # not a dead link. A peer that merely CLOSED mid-handshake proves
                # nothing answered, so it stays `failed`, like a reset.
                refusals.append(f"TLS: {type(reason).__name__}")
                continue
            if pinned and _is_no_route(exc):
                no_route += 1
            failures.append(type(reason).__name__)
            continue
        if status != 200:
            refusals.append(f"HTTP {status}")
            continue
        ip = parse_trace(body, family)
        if ip is None:
            if not pinned and parse_trace(body, 10 - family) is not None:
                # The hostname resolved to the OTHER family: no evidence either
                # way about this one.
                continue
            refusals.append("no usable ip= in response")
            continue
        return {"ip": ip, "status": STATUS_OK}
    notes = f"; hostname: {', '.join(hostname_notes)}" if hostname_notes else ""
    if family == 6 and literals and no_route >= len(literals):
        return {"ip": None, "status": STATUS_NONE}
    if refused:
        return {"ip": None, "status": STATUS_REFUSED, "error": ("; ".join(refused) + notes)[:200]}
    return {"ip": None, "status": STATUS_FAILED, "error": ("; ".join(failed) + notes)[:200]}


def _read_cache(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_cache(path: Path, data: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / (path.name + ".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(str(tmp), str(path))
    except OSError as exc:
        # Best-effort: an unwritable cache only costs a re-measure next time.
        log.warning("could not write egress cache", error=str(exc))


def _fresh(cached: dict[str, Any], now: float) -> bool:
    at = cached.get("measuredAtEpoch")
    if not isinstance(at, (int, float)):
        return False
    age = now - float(at)
    if age < 0:
        return False  # clock stepped backwards — re-measure
    v4 = cached.get("v4")
    if not isinstance(v4, dict):
        return False  # a malformed entry is a cache miss, not a reading
    ttl = REFRESH_SEC if v4.get("status") == STATUS_OK else RETRY_SEC
    return age < ttl


def observe(
    *,
    fetch: Fetcher | None = None,
    cache_path: Path | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """The egress report for the check-in payload (cached; see module doc)."""
    path = cache_path or EGRESS_CACHE_FILE
    t = time.time() if now is None else now
    cached = _read_cache(path)
    if cached is not None and _fresh(cached, t):
        return _payload(cached)
    f = fetch or _default_fetch
    v4 = measure_family(4, V4_SOURCES, f)
    v6 = measure_family(6, V6_SOURCES, f)
    result: dict[str, Any] = {"measuredAtEpoch": t, "v4": v4, "v6": v6}
    _write_cache(path, result)
    # Log transitions only — including recovery — not every retry: a site that
    # filters Cloudflare would otherwise write the same line every five minutes.
    prev_v4 = (cached or {}).get("v4")
    prev_status = prev_v4.get("status") if isinstance(prev_v4, dict) else None
    if v4["status"] != prev_status:
        log.info("egress ipv4 status", status=v4["status"], previous=prev_status, error=v4.get("error"))
    return _payload(result)


def _payload(r: dict[str, Any]) -> dict[str, Any]:
    raw4 = r.get("v4")
    raw6 = r.get("v6")
    v4: dict[str, Any] = raw4 if isinstance(raw4, dict) else {}
    v6: dict[str, Any] = raw6 if isinstance(raw6, dict) else {}
    at = r.get("measuredAtEpoch")
    observed = (
        datetime.fromtimestamp(float(at), tz=UTC).isoformat()
        if isinstance(at, (int, float)) else None
    )
    out: dict[str, Any] = {
        "source": SOURCE,
        "observedAt": observed,
        "ipv4": v4.get("ip"),
        "ipv4Status": v4.get("status"),
        "ipv6": v6.get("ip"),
        "ipv6Status": v6.get("status"),
    }
    errors = {k: d["error"] for k, d in (("ipv4", v4), ("ipv6", v6)) if d.get("error")}
    if errors:
        out["errors"] = errors
    return out
