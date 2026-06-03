"""Sensor self-health metrics — the box's OWN vitals (CPU / RAM / disk / OS /
uptime), distinct from the network it monitors. Reported to the dashboard on
each check-in so the sensor page can show box health at a glance and threshold
to green/yellow/red.

Pure-stdlib reads of /proc + os; no dependency. Runs from inside the collector
container, where (with host networking + the bind mounts) these read through as
HOST values:
  - CPU       /proc/stat   — host CPU (not namespaced)
  - RAM       /proc/meminfo — host memory (not namespaced)
  - uptime    /proc/uptime — host uptime
  - kernel    os.uname()   — shared host kernel
  - disk      os.statvfs(/var/lib/netmon) — the host data filesystem (bind mount)
  - temp      /sys/class/thermal — host sensors (Pi); usually absent on x86
The one exception is the DISTRO string: /etc/os-release inside the container is
the image's (Debian), so docker-compose mounts the host's at /etc/host-os-release
and we prefer that. Everything is best-effort — a failed read yields None, never
an exception that could disrupt the check-in.
"""
from __future__ import annotations

import glob
import os
from typing import Any

import structlog

log = structlog.get_logger(__name__)

HOST_OS_RELEASE = "/etc/host-os-release"   # host's, bind-mounted (preferred)
OS_RELEASE = "/etc/os-release"             # container's (fallback)
DISK_PATH = "/var/lib/netmon"              # bind-mounted host data dir


# ---------------------------------------------------------------------------
# Pure parsers (unit-testable without /proc)
# ---------------------------------------------------------------------------


def _parse_cpu_stat(text: str) -> tuple[int, int] | None:
    """From /proc/stat content, return (idle_jiffies, total_jiffies) for the
    aggregate `cpu` line. idle includes iowait."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            parts = [int(x) for x in line.split()[1:]]
            if len(parts) < 4:
                return None
            idle = parts[3] + (parts[4] if len(parts) > 4 else 0)  # idle + iowait
            return idle, sum(parts)
    return None


def _parse_meminfo(text: str) -> dict[str, Any]:
    """From /proc/meminfo content, return total/used/available MB + used %."""
    info: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields:
            try:
                info[key.strip()] = int(fields[0])  # kB
            except ValueError:
                continue
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(0, total - avail)
    return {
        "total_mb": round(total / 1024),
        "used_mb": round(used / 1024),
        "available_mb": round(avail / 1024),
        "used_pct": round(100 * used / total, 1) if total else None,
    }


def _parse_os_release(text: str) -> dict[str, str | None]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            data[key.strip()] = val.strip().strip('"')
    return {
        "name": data.get("PRETTY_NAME") or data.get("NAME"),
        "version": data.get("VERSION_ID"),
    }


def _parse_uptime(text: str) -> int | None:
    try:
        return int(float(text.split()[0]))
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Readers (thin /proc + os wrappers around the parsers)
# ---------------------------------------------------------------------------


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _cpu() -> dict[str, Any]:
    import time
    cores = os.cpu_count() or 1
    load1 = load5 = load15 = None
    try:
        load1, load5, load15 = (round(x, 2) for x in os.getloadavg())
    except (OSError, AttributeError):
        pass
    util: float | None = None
    first = _read("/proc/stat")
    a = _parse_cpu_stat(first) if first else None
    if a:
        time.sleep(0.2)
        second = _read("/proc/stat")
        b = _parse_cpu_stat(second) if second else None
        if b:
            idle_d, total_d = b[0] - a[0], b[1] - a[1]
            if total_d > 0:
                util = round(100 * (1 - idle_d / total_d), 1)
    return {"util_pct": util, "load1": load1, "load5": load5,
            "load15": load15, "cores": cores}


def _mem() -> dict[str, Any]:
    text = _read("/proc/meminfo")
    return _parse_meminfo(text) if text else {}


def _disk() -> dict[str, Any]:
    path = DISK_PATH
    try:
        st = os.statvfs(path)
    except (OSError, AttributeError):  # AttributeError: no statvfs on Windows dev
        path = "/"
        try:
            st = os.statvfs(path)
        except (OSError, AttributeError):
            return {}
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize          # available to non-root
    used = total - st.f_bfree * st.f_frsize   # actually used (df semantics)
    return {
        "path": path,
        "total_gb": round(total / 1024**3, 1),
        "used_gb": round(used / 1024**3, 1),
        "free_gb": round(free / 1024**3, 1),
        "used_pct": round(100 * used / total, 1) if total else None,
    }


def _os_info() -> dict[str, Any]:
    osr: dict[str, str | None] = {"name": None, "version": None}
    for p in (HOST_OS_RELEASE, OS_RELEASE):
        text = _read(p)
        if text:
            parsed = _parse_os_release(text)
            if parsed.get("name"):
                osr = parsed
                break
    kernel = None
    try:
        kernel = os.uname().release
    except (AttributeError, OSError):  # os.uname absent on Windows
        pass
    return {"name": osr["name"], "version": osr["version"], "kernel": kernel}


def _uptime() -> int | None:
    text = _read("/proc/uptime")
    return _parse_uptime(text) if text else None


def _temp_c() -> float | None:
    """Hottest thermal zone in °C (Raspberry Pi etc.); None on most x86."""
    best: float | None = None
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        text = _read(p)
        if not text:
            continue
        try:
            c = int(text.strip()) / 1000.0
        except ValueError:
            continue
        if best is None or c > best:
            best = round(c, 1)
    return best


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def collect() -> dict[str, Any]:
    """The box's self-health snapshot for the check-in payload. Resilient
    per-field: a failure in one reader yields that field None/empty but never
    drops the rest, and never raises (the check-in must not break)."""
    out: dict[str, Any] = {}
    readers: tuple[tuple[str, Any], ...] = (
        ("cpu", _cpu), ("mem", _mem), ("disk", _disk),
        ("os", _os_info), ("uptimeSec", _uptime), ("tempC", _temp_c),
    )
    for key, fn in readers:
        try:
            out[key] = fn()
        except Exception as exc:  # pragma: no cover — defensive
            log.warning("host metric reader failed", metric=key, error=str(exc))
            out[key] = None
    return out
