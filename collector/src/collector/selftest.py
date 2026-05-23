"""Startup self-test and ad-hoc healthcheck.

Runs at collector startup (logged for operator visibility) and on demand via
`python -m collector healthcheck` (exits non-zero if anything is broken — used
by Docker's HEALTHCHECK directive in the Dockerfile).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import psycopg
import structlog

from .config import get_settings

log = structlog.get_logger(__name__)


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def run_all() -> list[CheckResult]:
    checks: list[Callable[[], CheckResult]] = [
        _check_db,
        _check_tool_versions,
        _check_disk_space,
        _check_log_dir,
        _check_bundle_dir,
        _check_interfaces,
        _check_capabilities,
    ]
    out: list[CheckResult] = []
    for fn in checks:
        try:
            out.append(fn())
        except Exception as exc:
            out.append(CheckResult(
                name=fn.__name__.lstrip("_"),
                ok=False,
                detail=f"check raised: {exc}",
            ))
    return out


def log_results(results: list[CheckResult]) -> None:
    for r in results:
        if r.ok:
            log.info("selftest", check=r.name, ok=True, detail=r.detail)
        else:
            log.warning("selftest", check=r.name, ok=False, detail=r.detail)
    bad = [r for r in results if not r.ok]
    if bad:
        log.warning("selftest summary", failures=len(bad), total=len(results),
                    failed=[r.name for r in bad])
    else:
        log.info("selftest summary", ok=True, total=len(results))


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_db() -> CheckResult:
    settings = get_settings()
    try:
        with psycopg.connect(settings.dsn, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return CheckResult("db", True, f"reachable at {settings.postgres_host}:{settings.postgres_port}")
    except Exception as exc:
        return CheckResult("db", False, f"connect failed: {exc}")


def _check_tool_versions() -> CheckResult:
    """Verify each external tool we shell out to is on PATH and runs."""
    tools = {
        "tshark":    ["tshark", "--version"],
        "nmap":      ["nmap", "--version"],
        "arp-scan":  ["arp-scan", "--version"],
        "lldpcli":   ["lldpcli", "-v"],
        "ip":        ["ip", "-V"],
    }
    missing: list[str] = []
    versions: list[str] = []
    for name, cmd in tools.items():
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            first_line = (out.stdout or out.stderr).splitlines()[0] if (out.stdout or out.stderr) else ""
            versions.append(f"{name}: {first_line.strip()[:80]}")
        except (FileNotFoundError, subprocess.SubprocessError):
            missing.append(name)
    if missing:
        return CheckResult("tool_versions", False, f"missing: {', '.join(missing)}")
    return CheckResult("tool_versions", True, " | ".join(versions))


def _check_disk_space() -> CheckResult:
    """Bail loudly if either the bundle dir or log dir is nearly full."""
    settings = get_settings()
    thresholds_pct = 95  # warn above this
    paths = [settings.bundle_dir, Path("/var/log/appmon")]
    summaries: list[str] = []
    ok = True
    for p in paths:
        if not p.exists():
            continue
        usage = shutil.disk_usage(str(p))
        used_pct = (usage.used / usage.total) * 100 if usage.total else 0
        summaries.append(f"{p}: {used_pct:.0f}% used "
                         f"({usage.free / (1024**3):.1f} GB free)")
        if used_pct >= thresholds_pct:
            ok = False
    return CheckResult("disk_space", ok, " | ".join(summaries) or "no paths checked")


def _check_log_dir() -> CheckResult:
    p = Path(os.environ.get("APPMON_LOG_DIR", "/var/log/appmon"))
    if not p.exists():
        try:
            p.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return CheckResult("log_dir", False, f"cannot create {p}: {exc}")
    if not os.access(p, os.W_OK):
        return CheckResult("log_dir", False, f"{p} not writable")
    return CheckResult("log_dir", True, f"{p} writable")


def _check_bundle_dir() -> CheckResult:
    settings = get_settings()
    p = settings.bundle_dir
    if not p.exists():
        try:
            p.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return CheckResult("bundle_dir", False, f"cannot create {p}: {exc}")
    if not os.access(p, os.W_OK):
        return CheckResult("bundle_dir", False, f"{p} not writable")
    return CheckResult("bundle_dir", True, f"{p} writable")


def _check_interfaces() -> CheckResult:
    """At least one non-excluded interface with carrier should be present."""
    base = Path("/sys/class/net")
    if not base.is_dir():
        return CheckResult("interfaces", False, "/sys/class/net not mounted (need host net?)")
    settings = get_settings()
    excludes = settings.exclude_prefixes
    seen_up = []
    for iface in base.iterdir():
        name = iface.name
        if any(name == p or name.startswith(p) for p in excludes):
            continue
        carrier_file = iface / "carrier"
        try:
            carrier = carrier_file.read_text().strip()
        except (OSError, FileNotFoundError):
            continue
        if carrier == "1":
            seen_up.append(name)
    if seen_up:
        return CheckResult("interfaces", True, f"with carrier: {', '.join(seen_up)}")
    return CheckResult("interfaces", False, "no non-excluded interface has carrier yet")


def _check_capabilities() -> CheckResult:
    """We need NET_RAW (for arp-scan, tshark) and NET_ADMIN (for ip neigh).
    Crude check: try opening a raw socket. Inside a container with the right
    cap_add list this succeeds; without it, PermissionError."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return CheckResult("capabilities", True, "raw sockets allowed")
    except PermissionError:
        return CheckResult("capabilities", False,
                           "raw sockets denied — collector container needs NET_RAW")
    except Exception as exc:
        return CheckResult("capabilities", False, f"socket test error: {exc}")
