from __future__ import annotations

import os
import re
import subprocess
from functools import lru_cache
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# A current Wireshark OUI table fetched at image-build time (see Dockerfile).
# The `manuf` PyPI package bundles a years-old table, which leaves ~a third of
# real (globally-unique) OUIs unresolved on a typical fleet. We prefer this
# freshly-baked copy when present and fall back to the bundled one if the
# build-time download was skipped/unavailable. Runtime stays air-gapped — the
# file ships inside the image, nothing is fetched on the box.
_FRESH_OUI_DB = "/usr/share/netmon/manuf"


@lru_cache(maxsize=1)
def _oui_lookup():
    try:
        from manuf import manuf
    except Exception as exc:  # pragma: no cover — manuf is optional at runtime
        log.warning("OUI lookup unavailable", error=str(exc))
        return None

    # Prefer the freshly-baked table; if it's missing or the (older) parser
    # chokes on its format, fall back to manuf's bundled table so we never
    # lose vendor lookup entirely.
    if os.path.exists(_FRESH_OUI_DB) and os.path.getsize(_FRESH_OUI_DB) > 0:
        try:
            parser = manuf.MacParser(manuf_name=_FRESH_OUI_DB)
            log.info("OUI lookup using fresh manuf db", path=_FRESH_OUI_DB)
            return parser
        except Exception as exc:
            log.warning("fresh OUI db unusable, falling back to bundled",
                        error=str(exc))
    try:
        return manuf.MacParser()
    except Exception as exc:  # pragma: no cover
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
        raise RuntimeError("arp-scan executable not found") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"arp-scan timed out on {interface}") from None
    if out.returncode != 0:
        raise RuntimeError(
            f"arp-scan failed on {interface} (rc={out.returncode}): "
            f"{(out.stderr or '').strip()[:500]}"
        )

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
