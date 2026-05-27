"""Wi-Fi discovery via `iw dev <iface> scan` and `iw dev <iface> survey dump`.

Phase 1 uses `iw scan` (which works on any Linux Wi-Fi adapter, no monitor
mode required) to enumerate visible APs and their RF properties. Phase 2 will
add a monitor-mode path (airodump-ng + tshark) for stations / deauths /
probe-request analysis — that needs a known-good adapter and disconnects the
NIC from any associated network, so we ship it as opt-in later.

What `iw scan` gives us per BSS:
    BSSID, frequency, SSID, channel, signal (dBm), capability flags, RSN/WPA
    info (encryption), supported rates, beacon-interval, vendor IEs.

What `iw survey dump` gives us per channel:
    frequency, noise (dBm), channel-active-time, channel-busy-time.
    (Some drivers expose less; we treat missing fields as None.)

We don't need root to scan (CAP_NET_ADMIN is enough on a modern Linux box,
and the collector container already has it). Some distros prevent scans
while NetworkManager is busy on the same NIC — in that case `iw scan`
returns "Device or resource busy" and we surface that as a scan error.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


@dataclass
class WifiScanResult:
    interface: str
    aps: list[dict[str, Any]] = field(default_factory=list)
    channel_stats: list[dict[str, Any]] = field(default_factory=list)
    raw_scan_text: str = ""
    raw_survey_text: str = ""
    raw_iw_list_text: str = ""
    error: str | None = None


def run_wifi_scan(interface: str, *, scan_timeout: int = 30) -> WifiScanResult:
    """Run `iw scan` + `iw survey dump` + `iw list` and parse outputs.

    Returns a WifiScanResult even on failure — caller can inspect .error.
    """
    result = WifiScanResult(interface=interface)

    # iw list — adapter capabilities (channels supported, band info, modes).
    list_text, list_err = _run_iw(["iw", "list"], timeout=10)
    result.raw_iw_list_text = list_text or list_err

    # Bring the interface up (no harm if it already is).
    _run_iw(["ip", "link", "set", interface, "up"], timeout=5)

    # iw dev <iface> scan — the main event.
    scan_text, scan_err = _run_iw(["iw", "dev", interface, "scan"], timeout=scan_timeout)
    result.raw_scan_text = scan_text
    if scan_err:
        result.error = scan_err.strip()
        log.warning("iw scan failed", interface=interface, error=result.error)
        return result

    result.aps = _parse_iw_scan(scan_text)

    # iw dev <iface> survey dump — channel utilization where available.
    survey_text, _ = _run_iw(["iw", "dev", interface, "survey", "dump"], timeout=5)
    result.raw_survey_text = survey_text
    survey = _parse_iw_survey(survey_text)

    # Merge survey rows with AP counts per channel for a richer channel view.
    ap_counts_by_channel: dict[int, int] = {}
    for ap in result.aps:
        ch = ap.get("channel")
        if isinstance(ch, int):
            ap_counts_by_channel[ch] = ap_counts_by_channel.get(ch, 0) + 1

    channels: list[dict[str, Any]] = []
    seen_channels: set[int] = set()
    for row in survey:
        ch = row.get("channel")
        row["ap_count"] = ap_counts_by_channel.get(ch, 0) if ch else 0
        channels.append(row)
        if ch is not None:
            seen_channels.add(ch)
    # Any channel we saw APs on but the survey didn't mention.
    for ch, count in ap_counts_by_channel.items():
        if ch in seen_channels:
            continue
        channels.append({
            "channel": ch,
            "frequency_mhz": None,
            "band": _band_for_frequency(_channel_to_freq(ch)),
            "ap_count": count,
            "noise_dbm": None,
            "active_ms": None,
            "busy_ms": None,
            "busy_pct": None,
        })
    result.channel_stats = channels

    return result


# ---------------------------------------------------------------------------
# `iw scan` parser
# ---------------------------------------------------------------------------

_BSS_HEADER_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})", re.MULTILINE)


def _parse_iw_scan(text: str) -> list[dict[str, Any]]:
    """Parse `iw dev <iface> scan` output into a list of AP dicts."""
    if not text:
        return []

    # Split into per-BSS blocks. We capture the header line + everything
    # before the next "BSS xx:xx:..." marker.
    blocks: list[tuple[str, str]] = []
    matches = list(_BSS_HEADER_RE.finditer(text))
    for i, m in enumerate(matches):
        bssid = m.group(1).lower()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        blocks.append((bssid, text[start:end]))

    results: list[dict[str, Any]] = []
    for bssid, body in blocks:
        ap = _parse_bss_block(bssid, body)
        results.append(ap)
    return results


def _parse_bss_block(bssid: str, body: str) -> dict[str, Any]:
    """One AP's-worth of `iw scan` output -> a flat dict."""
    ap: dict[str, Any] = {
        "bssid": bssid,
        "essid": None,
        "channel": None,
        "frequency_mhz": None,
        "band": None,
        "signal_dbm": None,
        "beacon_count": None,
        "privacy": None,        # 'OPEN' / 'WEP' / 'WPA' / 'WPA2' / 'WPA3' / mixed
        "cipher": None,
        "auth": None,
        "hidden": False,
        "extra": {},
    }

    # Single-line scalar fields.
    if (m := re.search(r"^\s*freq:\s+(\d+)", body, re.MULTILINE)):
        freq = int(m.group(1))
        ap["frequency_mhz"] = freq
        ap["band"] = _band_for_frequency(freq)
    if (m := re.search(r"^\s*signal:\s+(-?\d+(?:\.\d+)?)\s+dBm", body, re.MULTILINE)):
        ap["signal_dbm"] = int(float(m.group(1)))
    if (m := re.search(r"^\s*beacon interval:\s+(\d+)", body, re.MULTILINE)):
        ap["extra"]["beacon_interval"] = int(m.group(1))
    if (m := re.search(r"^\s*DS Parameter set:\s+channel\s+(\d+)", body, re.MULTILINE)):
        ap["channel"] = int(m.group(1))
    elif ap["frequency_mhz"]:
        ap["channel"] = _freq_to_channel(ap["frequency_mhz"])

    # SSID: appears as `SSID: foo`; empty value = hidden network.
    if (m := re.search(r"^\s*SSID:\s*(.*)$", body, re.MULTILINE)):
        raw_ssid = m.group(1).strip()
        if not raw_ssid:
            ap["hidden"] = True
            ap["essid"] = None
        else:
            ap["essid"] = raw_ssid

    # Capability — gives us a quick OPEN/WEP hint.
    has_privacy = bool(re.search(r"^\s*capability:.*Privacy", body, re.MULTILINE))

    # RSN / WPA presence + ciphers.
    rsn_present = "RSN:" in body
    wpa_present = "WPA:" in body
    if not has_privacy and not rsn_present and not wpa_present:
        ap["privacy"] = "OPEN"
    elif rsn_present and wpa_present:
        ap["privacy"] = "WPA-WPA2"
    elif rsn_present:
        # Check for WPA3 (SAE auth suite) vs WPA2.
        if "SAE" in body or "OWE" in body:
            ap["privacy"] = "WPA3" if "SAE" in body else "OWE"
            if "PSK" in body and "SAE" in body:
                ap["privacy"] = "WPA2-WPA3"
        else:
            ap["privacy"] = "WPA2"
    elif wpa_present:
        ap["privacy"] = "WPA"
    elif has_privacy:
        # Privacy bit set but no RSN/WPA blocks => WEP.
        ap["privacy"] = "WEP"
    else:
        ap["privacy"] = "OPEN"

    # Ciphers and auth — pick the first we find in RSN (preferred) or WPA.
    cipher_match = re.search(
        r"^\s*(?:Group cipher|Pairwise ciphers):\s+(.+)$", body, re.MULTILINE,
    )
    if cipher_match:
        ap["cipher"] = cipher_match.group(1).strip()
    auth_match = re.search(r"^\s*Authentication suites:\s+(.+)$", body, re.MULTILINE)
    if auth_match:
        ap["auth"] = auth_match.group(1).strip()

    # Vendor IEs occasionally hint at vendor; OUI lookup happens in the
    # caller, not here.
    return ap


# ---------------------------------------------------------------------------
# `iw survey dump` parser
# ---------------------------------------------------------------------------

_SURVEY_BLOCK_RE = re.compile(
    r"Survey data from .*?\n((?:\s+[^\n]+\n?)+)", re.MULTILINE,
)


def _parse_iw_survey(text: str) -> list[dict[str, Any]]:
    """Parse `iw dev X survey dump` into per-channel busy-time rows."""
    if not text:
        return []
    out: list[dict[str, Any]] = []
    for block in _SURVEY_BLOCK_RE.finditer(text):
        body = block.group(1)
        row: dict[str, Any] = {
            "channel": None,
            "frequency_mhz": None,
            "band": None,
            "noise_dbm": None,
            "active_ms": None,
            "busy_ms": None,
            "busy_pct": None,
        }
        if (m := re.search(r"^\s*frequency:\s+(\d+)\s+MHz", body, re.MULTILINE)):
            freq = int(m.group(1))
            row["frequency_mhz"] = freq
            row["channel"] = _freq_to_channel(freq)
            row["band"] = _band_for_frequency(freq)
        if (m := re.search(r"^\s*noise:\s+(-?\d+)\s+dBm", body, re.MULTILINE)):
            row["noise_dbm"] = int(m.group(1))
        if (m := re.search(r"^\s*channel active time:\s+(\d+)\s+ms", body, re.MULTILINE)):
            row["active_ms"] = int(m.group(1))
        if (m := re.search(r"^\s*channel busy time:\s+(\d+)\s+ms", body, re.MULTILINE)):
            row["busy_ms"] = int(m.group(1))
        if row["active_ms"] and row["busy_ms"] is not None:
            row["busy_pct"] = round(100 * row["busy_ms"] / row["active_ms"], 2)
        if row["channel"] is not None:
            out.append(row)
    return out


# ---------------------------------------------------------------------------
# Channel ↔ frequency helpers
# ---------------------------------------------------------------------------


def _freq_to_channel(freq: int | None) -> int | None:
    if freq is None:
        return None
    # 2.4 GHz: ch 1 = 2412, ch 13 = 2472, ch 14 = 2484 (Japan only).
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    # 5 GHz: ch = (freq - 5000) / 5. Covers 36..165.
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    # 6 GHz: ch = (freq - 5950) / 5 + 1, covers ch 1..233.
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def _channel_to_freq(channel: int | None) -> int | None:
    if channel is None:
        return None
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel == 14:
        return 2484
    if 36 <= channel <= 165:
        return 5000 + channel * 5
    return None


def _band_for_frequency(freq: int | None) -> str | None:
    if freq is None:
        return None
    if 2400 <= freq < 2500:
        return "2.4GHz"
    if 5000 <= freq < 5900:
        return "5GHz"
    if 5925 <= freq < 7125:
        return "6GHz"
    return None


# ---------------------------------------------------------------------------
# subprocess helper
# ---------------------------------------------------------------------------


def _run_iw(cmd: list[str], *, timeout: int) -> tuple[str, str]:
    """Run cmd, return (stdout, stderr_or_friendly_error_message).

    We tolerate non-zero exit codes — `iw scan` legitimately returns 240
    (EBUSY) when NetworkManager is bouncing the radio. Caller decides what
    to do with stderr.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError:
        return "", f"{cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return "", f"{' '.join(cmd)} timed out after {timeout}s"
    if proc.returncode != 0 and not proc.stdout:
        return "", proc.stderr.strip() or f"{' '.join(cmd)} exit {proc.returncode}"
    return proc.stdout, ""
