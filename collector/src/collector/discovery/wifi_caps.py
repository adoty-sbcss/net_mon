"""Per-radio Wi-Fi capability probe (WIFI-1) — what each sensor radio can do.

Reported at check-in on every wireless entry of the interface list, so the dashboard
can say which bands and channels a radio can use, whether it supports monitor mode
(the gate for WIFI-4 passive sniffing), and which regulatory domain it runs under. A
radio left on the world domain ("00") is restricted on 5 GHz: most channels are
passive-scan only and DFS channels need radar detection, which a client-only radio
skips — a real cause of "the sensor never sees half the 5 GHz APs".

Runs `iw` inside the collector container (host network namespace, so nl80211 sees
the host's radios). Read-only: `iw phy <phy> info` and `iw reg get` change nothing.
Best-effort: None when iw is missing (an image older than this change) or fails.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

_FREQ_RE = re.compile(r"^\*\s+(\d+)(?:\.\d+)?\s+MHz\s+\[(\d+)\](.*)$")
_COUNTRY_RE = re.compile(r"^country\s+([0-9A-Z]{2}):")
_PHY_RE = re.compile(r"^phy#(\d+)")


def _band(freq: int) -> str | None:
    if 2400 <= freq < 2500:
        return "2.4GHz"
    if 4900 <= freq < 5925:
        return "5GHz"
    if 5925 <= freq <= 7125:
        return "6GHz"
    return None  # 60 GHz (802.11ad) and anything else: not a band we report


def parse_phy_info(text: str) -> dict[str, Any]:
    """Parse `iw phy <phy> info`. Pure. Channels marked "disabled" by the regulatory
    domain are counted, not listed; "radar detection" marks a DFS channel; "no IR"
    (no initiating radiation) means the radio may only scan passively there."""
    bands: dict[str, dict[str, Any]] = {}
    modes: list[str] = []
    max_scan: int | None = None
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        indent = len(raw) - len(raw.lstrip("\t"))
        if indent == 1:
            low = line.lower()
            if low.startswith("supported interface modes") or low.startswith("software interface modes"):
                section = "modes"
            elif low.startswith("band "):
                section = "band"
            elif low.startswith("max # scan ssids:"):
                section = ""
                tail = line.split(":", 1)[1].strip()
                max_scan = int(tail) if tail.isdigit() else None
            else:
                section = ""
            continue
        if section == "modes" and line.startswith("*"):
            mode = line.lstrip("*").strip()
            if mode and mode not in modes:
                modes.append(mode)
            continue
        if section == "band":
            m = _FREQ_RE.match(line)
            if not m:
                continue
            freq, chan, flags = int(m.group(1)), int(m.group(2)), m.group(3).lower()
            name = _band(freq)
            if name is None:
                continue
            b = bands.setdefault(name, {"channels": [], "disabled": 0, "dfs": 0, "no_ir": 0})
            if "disabled" in flags:
                b["disabled"] += 1
                continue
            b["channels"].append(chan)
            if "radar detection" in flags:
                b["dfs"] += 1
            if "no ir" in flags or "passive scan" in flags or "no ibss" in flags:
                b["no_ir"] += 1
    order = ["2.4GHz", "5GHz", "6GHz"]
    return {
        "bands": {k: bands[k] for k in order if k in bands},
        "modes": modes,
        "monitor": "monitor" in modes,
        "ap": "AP" in modes,
        "max_scan_ssids": max_scan,
    }


def parse_reg(text: str, phy_index: int | None) -> str | None:
    """Country code that governs this phy from `iw reg get`: its own self-managed
    domain when the driver keeps one (`phy#N (self-managed)`), else the global one."""
    current: str = "global"
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line == "global":
            current = "global"
            continue
        pm = _PHY_RE.match(line)
        if pm:
            current = f"phy{pm.group(1)}"
            continue
        cm = _COUNTRY_RE.match(line)
        if cm and current not in found:
            found[current] = cm.group(1)
    if phy_index is not None and f"phy{phy_index}" in found:
        return found[f"phy{phy_index}"]
    return found.get("global")


def _iw(*args: str) -> str | None:
    try:
        out = subprocess.run(["iw", *args], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def probe(iface: str) -> dict[str, Any] | None:
    """Capabilities of the radio behind `iface`, or None if they can't be read."""
    if shutil.which("iw") is None:
        return None
    phy_dir = Path(f"/sys/class/net/{iface}/phy80211")
    try:
        phy = (phy_dir / "name").read_text().strip()
    except OSError:
        return None
    try:
        phy_index: int | None = int((phy_dir / "index").read_text().strip())
    except (OSError, ValueError):
        phy_index = None
    info = _iw("phy", phy, "info")
    if not info:
        return None
    caps = parse_phy_info(info)
    reg = _iw("reg", "get")
    caps["phy"] = phy
    caps["regdom"] = parse_reg(reg, phy_index) if reg else None
    return caps
