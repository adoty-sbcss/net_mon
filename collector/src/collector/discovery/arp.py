from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def _oui_lookup():
    try:
        from manuf import manuf
        return manuf.MacParser()
    except Exception as exc:  # pragma: no cover — manuf is optional at runtime
        log.warning("OUI lookup unavailable", error=str(exc))
        return None


_LINE_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F:]{17})\s+(?P<vendor>.*)$"
)


def run(interface: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Run `arp-scan --localnet` on the given interface and parse the table."""
    cmd = ["arp-scan", "--localnet", "--interface", interface, "--retry=2"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        log.warning("arp-scan not found")
        return []
    except subprocess.TimeoutExpired:
        log.warning("arp-scan timed out", interface=interface)
        return []
    if out.returncode != 0:
        log.warning("arp-scan failed", stderr=out.stderr.strip())
        # Don't return — partial stdout may still be useful.

    results: list[dict[str, Any]] = []
    parser = _oui_lookup()
    for line in out.stdout.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        ip = m.group("ip")
        mac = m.group("mac").lower()
        vendor = m.group("vendor").strip() or None
        # arp-scan often reports "(Unknown)" — replace with OUI lookup if available.
        if (not vendor or "unknown" in vendor.lower()) and parser is not None:
            try:
                v = parser.get_manuf_long(mac)
                if v:
                    vendor = v
            except Exception:
                pass
        results.append({"ip": ip, "mac": mac, "vendor": vendor})
    return results
