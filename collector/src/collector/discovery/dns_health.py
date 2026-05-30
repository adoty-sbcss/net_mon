"""DNS health probes — measure resolver latency, status, and correctness.

Every scan, we query a small set of test names against two sets of resolvers:

  * **Public** — operator-configured list (NETMON_DNS_PUBLIC_RESOLVERS),
    defaults to 1.1.1.1 / 8.8.8.8 / 9.9.9.9. Measures the box's path to
    public DNS, which is the baseline most end-users care about.

  * **DHCP-assigned / static** — auto-discovered from the host's
    `/etc/resolv.conf` (mounted read-only into the container). Captures
    whatever the device actually uses, including the systemd-resolved stub
    on Ubuntu, which is the resolver applications hit by default.

For each (resolver, test_name) pair we record:
  - status:        NOERROR / NXDOMAIN / SERVFAIL / TIMEOUT / ERROR
  - query_time_ms: latency
  - answer_count:  how many RRs came back
  - answers_text:  first ~3 RR values (helpful for spotting hijacked DNS)

We also send a **unique-per-scan NXDOMAIN probe** with `expected_status =
'NXDOMAIN'` so we can tell when a resolver silently rewrites bogus names
to an ad page or filter portal — a real problem on some ISP DNS.

Tool: `dig` (already present via `dnsutils` in the Dockerfile). Roughly
5 resolvers × 4 names = 20 quick UDP queries per scan ≈ 1 second of work.
"""
from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import structlog

from ..config import get_settings

log = structlog.get_logger(__name__)


# The compose file mounts the host's resolv.conf at these paths. Order
# matters: the systemd-resolved file lists the real upstreams; the plain
# /etc/resolv.conf often just points at 127.0.0.53.
_HOST_RESOLV_CONF_PATHS = [
    Path("/etc/host-systemd-resolv.conf"),   # /run/systemd/resolve/resolv.conf
    Path("/etc/host-resolv.conf"),           # /etc/resolv.conf
    Path("/etc/resolv.conf"),                # container's own — best-effort
]


@dataclass
class DnsProbeResult:
    resolver_ip: str
    resolver_source: str
    query_name: str
    query_type: str
    expected_status: str | None     # 'NXDOMAIN' for the negative probe, else None
    status: str
    query_time_ms: int | None
    answer_count: int
    answers_text: str | None
    error: str | None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def probe_all() -> list[DnsProbeResult]:
    """Run all configured DNS probes. Returns a flat list of result rows."""
    settings = get_settings()
    if not settings.dns_enabled:
        return []
    if shutil.which("dig") is None:
        log.warning("dig not available; skipping DNS health probes "
                    "(ensure the `dnsutils` apt package is installed)")
        return []

    resolvers = _discover_resolvers()
    if not resolvers:
        log.warning("no DNS resolvers discovered; skipping probes")
        return []

    test_names = [n.strip() for n in settings.dns_test_names.split(",") if n.strip()]
    if not test_names:
        log.info("no DNS test names configured; skipping probes")
        return []

    timeout_sec = max(1, int(settings.dns_timeout_sec))
    results: list[DnsProbeResult] = []

    # Positive probes for each (resolver, name).
    for resolver_ip, source in resolvers:
        for name in test_names:
            results.append(_probe_one(resolver_ip, source, name, "A",
                                      expected_status=None,
                                      timeout_sec=timeout_sec))

    # Unique-per-scan NXDOMAIN probe. The random suffix busts both
    # resolver caches and any ad-rewrite "saw this last week" memory.
    if settings.dns_include_nxdomain_probe:
        nx_name = (f"netmon-nx-{int(time.time())}"
                   f"-{secrets.token_hex(3)}.invalid")
        for resolver_ip, source in resolvers:
            results.append(_probe_one(resolver_ip, source, nx_name, "A",
                                      expected_status="NXDOMAIN",
                                      timeout_sec=timeout_sec))

    log.info("dns probes complete",
             resolvers=len(resolvers),
             names=len(test_names),
             rows=len(results),
             include_nxdomain=settings.dns_include_nxdomain_probe)
    return results


# ---------------------------------------------------------------------------
# Resolver discovery
# ---------------------------------------------------------------------------


def _discover_resolvers() -> list[tuple[str, str]]:
    """Return (ip, source) tuples for every resolver we plan to probe.

    De-duped by IP; the first source we see wins.
    """
    settings = get_settings()
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    # 1. Public list (env-configured).
    for ip in settings.dns_public_resolvers.split(","):
        ip = ip.strip()
        if ip and ip not in seen:
            out.append((ip, "public"))
            seen.add(ip)

    # 2. DHCP/static from host's resolv.conf. Tag 127.0.0.x as 'system-stub'
    # so the dashboard can distinguish "resolver app actually hits" from
    # "real upstream the OS forwards to."
    for path in _HOST_RESOLV_CONF_PATHS:
        try:
            text = path.read_text()
        except (OSError, FileNotFoundError):
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            m = re.match(r"^nameserver\s+([0-9a-fA-F:.]+)\s*$", line)
            if not m:
                continue
            ip = m.group(1)
            if ip in seen:
                continue
            source = "system-stub" if ip.startswith("127.") else "dhcp"
            out.append((ip, source))
            seen.add(ip)

    return out


# ---------------------------------------------------------------------------
# Single probe
# ---------------------------------------------------------------------------


_STATUS_RE        = re.compile(r"status:\s*([A-Z_]+)")
_QUERY_TIME_RE    = re.compile(r"Query time:\s*(\d+)\s*msec")
_ANSWER_COUNT_RE  = re.compile(r"ANSWER:\s*(\d+)")
_ANSWER_LINE_RE   = re.compile(
    r"^\S+\.\s+\d+\s+IN\s+(A|AAAA|CNAME|TXT|MX|NS)\s+(\S.+)$"
)


def _probe_one(
    resolver_ip: str,
    resolver_source: str,
    name: str,
    qtype: str,
    *,
    expected_status: str | None,
    timeout_sec: int,
) -> DnsProbeResult:
    cmd = [
        "dig",
        f"@{resolver_ip}",
        name,
        qtype,
        f"+time={timeout_sec}",
        "+tries=1",
        "+noall",
        "+answer",
        "+comments",
        "+stats",
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 2,
            check=False,
        )
    except FileNotFoundError:
        return DnsProbeResult(
            resolver_ip=resolver_ip, resolver_source=resolver_source,
            query_name=name, query_type=qtype,
            expected_status=expected_status,
            status="TOOL_MISSING", query_time_ms=None, answer_count=0,
            answers_text=None, error="dig not installed",
        )
    except subprocess.TimeoutExpired:
        return DnsProbeResult(
            resolver_ip=resolver_ip, resolver_source=resolver_source,
            query_name=name, query_type=qtype,
            expected_status=expected_status,
            status="TIMEOUT", query_time_ms=int((time.monotonic() - started) * 1000),
            answer_count=0, answers_text=None,
            error="subprocess timeout",
        )

    text = (proc.stdout or "") + (proc.stderr or "")

    m = _STATUS_RE.search(text)
    status = m.group(1) if m else "ERROR"

    m = _QUERY_TIME_RE.search(text)
    qtime_ms = int(m.group(1)) if m else int((time.monotonic() - started) * 1000)

    answer_count = 0
    m = _ANSWER_COUNT_RE.search(text)
    if m:
        answer_count = int(m.group(1))

    # Pluck the first few RR data values to surface in the bundle. Useful
    # for spotting hijacked / rewritten DNS without dumping every answer.
    answers: list[str] = []
    for line in text.splitlines():
        m = _ANSWER_LINE_RE.match(line.strip())
        if m:
            answers.append(f"{m.group(1)}={m.group(2)}")
            if len(answers) >= 3:
                break

    # Surface dig's own error text on hard failures only — NXDOMAIN and
    # NOERROR are valid responses, not errors.
    error: str | None = None
    if status not in ("NOERROR", "NXDOMAIN") and proc.stderr:
        error = proc.stderr.strip()[:200] or None

    return DnsProbeResult(
        resolver_ip=resolver_ip,
        resolver_source=resolver_source,
        query_name=name,
        query_type=qtype,
        expected_status=expected_status,
        status=status,
        query_time_ms=qtime_ms,
        answer_count=answer_count,
        answers_text=";".join(answers) if answers else None,
        error=error,
    )
