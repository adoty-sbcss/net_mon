"""Wi-Fi RF / AP survey (WIFI-2) — normalize the host-side survey envelope.

The actual scan runs on the HOST (`scripts/netmon-wifi-survey.sh`): the collector
container ships neither `iw` nor `nmcli`, and on a NetworkManager-managed box NM
owns the radio, so surveying in-container would contend with it. That script drops
a small base64-wrapped envelope at /var/lib/netmon/wifi_survey.json (the shared
state dir, bind-mounted into the container exactly like host_metrics' disk path).
Here we read it, decode the raw tool output, and normalize every BSS into a flat
record the bundle (and later the dashboard) can consume.

Passive data only — neighbor SSIDs / BSSIDs / channels / signal / encryption.
No association, no payloads, no secrets.

Two source tools, picked host-side by network backend (mirrors lib/trunk.sh):
  * nmcli  — NetworkManager boxes. Terse output; SIGNAL is a 0-100 quality.
             FULLY parsed + validated on a live NM box (Monitor1).
  * iw     — systemd-networkd boxes. SIGNAL is dBm; richer (PMF, width, BSS load).
             Best-effort parser — NOT yet hardware-validated (no networkd Wi-Fi
             box on hand). See _parse_iw.
"""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

SURVEY_PATH = Path("/var/lib/netmon/wifi_survey.json")

# Field order MUST match scripts/netmon-wifi-survey.sh NMCLI_FIELDS.
_NMCLI_FIELDS = (
    "in_use", "ssid", "bssid", "chan", "freq", "rate",
    "signal", "security", "wpa_flags", "rsn_flags", "mode",
)


@dataclass
class WifiBss:
    interface: str
    tool: str                 # "nmcli" | "iw"
    ssid: str | None          # None = hidden / not advertised
    bssid: str | None
    band: str | None          # "2.4GHz" | "5GHz" | "6GHz"
    channel: int | None
    freq_mhz: int | None
    rate_mbps: int | None
    signal: int | None        # value; interpret via signal_unit
    signal_unit: str          # "quality" (nmcli 0-100) | "dbm" (iw)
    security: str | None      # human summary, e.g. "WPA2 802.1X"
    auth: str                 # open | wep | psk | sae | psk+sae | 802.1x | unknown
    cipher: str | None        # ccmp | tkip | ccmp+tkip | none
    pmf: bool | None          # protected management frames, if known (nmcli: None)
    mode: str | None
    in_use: bool
    is_district_ssid: bool | None   # vs NETMON_WIFI_DISTRICT_SSIDS; None if unset


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def survey() -> dict[str, Any]:
    """Read + normalize the host survey envelope. Returns a dict ready to stash
    in the scan's raw_outputs and ship in the bundle. Never raises — a missing or
    malformed file yields ``{"available": False, ...}``."""
    # Lazy import so the pure parsers below stay loadable/standalone-testable.
    from ..config import get_settings

    settings = get_settings()
    if not settings.wifi_survey_enabled:
        return {"available": False, "reason": "disabled"}

    district = _district_set(getattr(settings, "wifi_district_ssids", ""))
    max_age = max(0, int(getattr(settings, "wifi_survey_max_age", 1800)))

    try:
        env = json.loads(SURVEY_PATH.read_text())
    except FileNotFoundError:
        log.info("wifi survey enabled but no envelope yet "
                 "(host timer netmon-wifi-survey hasn't run, or no Wi-Fi NIC)",
                 path=str(SURVEY_PATH))
        return {"available": False, "reason": "no-envelope"}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("wifi survey envelope unreadable", error=str(exc))
        return {"available": False, "reason": "unreadable"}

    age_sec = _age_seconds(env.get("generated_at"))
    stale = age_sec is not None and max_age > 0 and age_sec > max_age

    bss: list[WifiBss] = []
    errors: list[dict[str, Any]] = []
    for iface in env.get("interfaces", []) or []:
        name = iface.get("name") or "?"
        if iface.get("error"):
            errors.append({"interface": name, "error": iface["error"]})
        raw_b64 = iface.get("raw_b64") or ""
        if not raw_b64:
            continue
        try:
            raw = base64.b64decode(raw_b64).decode("utf-8", "replace")
        except (ValueError, TypeError) as exc:
            errors.append({"interface": name, "error": f"b64 decode: {exc}"})
            continue
        tool = iface.get("tool")
        try:
            if tool == "nmcli":
                bss.extend(_parse_nmcli(raw, name, district))
            elif tool == "iw":
                bss.extend(_parse_iw(raw, name, district))
        except Exception as exc:  # pragma: no cover — never let one iface break the scan
            log.warning("wifi survey parse failed", interface=name, tool=tool, error=str(exc))
            errors.append({"interface": name, "error": f"parse: {exc}"})

    if stale:
        log.info("wifi survey is stale", age_sec=age_sec, max_age=max_age)
    log.info("wifi survey normalized", networks=len(bss),
             backend=env.get("backend"), regdom=env.get("regdom"), stale=stale)

    return {
        "available": True,
        "generated_at": env.get("generated_at"),
        "age_sec": age_sec,
        "stale": stale,
        "backend": env.get("backend"),
        "regdom": env.get("regdom"),
        "host": env.get("host"),
        "errors": errors,
        "bss": [asdict(b) for b in bss],
    }


# ---------------------------------------------------------------------------
# nmcli terse parser (NetworkManager boxes) — validated on Monitor1
# ---------------------------------------------------------------------------


def _parse_nmcli(raw: str, interface: str, district: set[str]) -> list[WifiBss]:
    out: list[WifiBss] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = _split_terse(line)
        if len(parts) < len(_NMCLI_FIELDS):
            continue
        f = dict(zip(_NMCLI_FIELDS, parts, strict=False))
        ssid = f["ssid"] or None
        security = f["security"] or None
        auth, cipher, pmf = _auth_cipher_pmf(f["security"], f["wpa_flags"], f["rsn_flags"])
        freq = _int(re.sub(r"[^0-9]", "", f["freq"]))
        out.append(WifiBss(
            interface=interface,
            tool="nmcli",
            ssid=ssid,
            bssid=_norm_bssid(f["bssid"]),
            band=_band_from_freq(freq),
            channel=_int(f["chan"]),
            freq_mhz=freq,
            rate_mbps=_int(re.sub(r"[^0-9]", "", f["rate"])),
            signal=_int(f["signal"]),
            signal_unit="quality",
            security=security,
            auth=auth,
            cipher=cipher,
            pmf=pmf,
            mode=f["mode"] or None,
            in_use=f["in_use"].strip() == "*",
            is_district_ssid=_is_district(ssid, district),
        ))
    return out


def _split_terse(line: str) -> list[str]:
    r"""Split an `nmcli -t` line on unescaped ':' and unescape '\:' / '\\'.

    nmcli terse mode escapes ':' and '\' inside field values, so a BSSID comes
    through as `98\:8F\:...`. Split only on separators not preceded by a
    backslash, then unescape each field.
    """
    fields = re.split(r"(?<!\\):", line)
    return [re.sub(r"\\(.)", r"\1", x) for x in fields]


# ---------------------------------------------------------------------------
# iw scan parser (systemd-networkd boxes) — best-effort, NOT hw-validated yet
# ---------------------------------------------------------------------------


def _parse_iw(raw: str, interface: str, district: set[str]) -> list[WifiBss]:
    """Parse `iw dev <x> scan` output. One `BSS <mac>(...)` block per network.

    Best-effort: covers bssid / freq / signal(dBm) / ssid / channel / auth /
    cipher / PMF. Channel width + BSS-load utilization are left for a follow-up.
    Unvalidated on hardware (no networkd Wi-Fi box on hand) — guarded so a format
    surprise degrades to fewer fields, never an exception.
    """
    out: list[WifiBss] = []
    blocks = re.split(r"(?m)^BSS\s+", raw)
    for blk in blocks:
        blk = blk.strip()
        if not blk:
            continue
        m = re.match(r"([0-9a-fA-F:]{17})", blk)
        if not m:
            continue
        bssid = m.group(1).lower()
        ssid_m = re.search(r"(?m)^\s*SSID:\s*(.*)$", blk)
        ssid = ssid_m.group(1).strip() if ssid_m else ""
        ssid = ssid or None
        freq = _int(_search1(r"(?m)^\s*freq:\s*(\d+)", blk))
        sig = _search1(r"(?m)^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", blk)
        signal = int(round(float(sig))) if sig is not None else None
        chan = _int(_search1(r"(?m)\*\s*primary channel:\s*(\d+)", blk)) \
            or _int(_search1(r"(?m)DS Parameter set:\s*channel\s*(\d+)", blk)) \
            or _channel_from_freq(freq)

        has_rsn = "RSN:" in blk           # WPA2/WPA3
        has_wpa = re.search(r"(?m)^\s*WPA:", blk) is not None  # WPA1
        low = blk.lower()
        has_sae = "sae" in low and "authentication suites" in low
        has_8021x = "ieee 802.1x" in low
        has_psk = re.search(r"authentication suites:.*\bpsk\b", low) is not None
        if has_8021x:
            auth = "802.1x"
        elif has_sae and has_psk:
            auth = "psk+sae"
        elif has_sae:
            auth = "sae"
        elif has_psk:
            auth = "psk"
        elif has_rsn or has_wpa:
            auth = "unknown"
        elif re.search(r"(?m)Privacy", blk):
            auth = "wep"
        else:
            auth = "open"
        has_ccmp = "ccmp" in low
        has_tkip = "tkip" in low
        cipher = ("ccmp+tkip" if has_ccmp and has_tkip
                  else "ccmp" if has_ccmp
                  else "tkip" if has_tkip
                  else "none" if auth == "open" else None)
        # RSN capabilities MFP bits (PMF). Present only when iw printed them.
        pmf: bool | None = None
        if "mfp-required" in low:
            pmf = True
        elif "mfp-capable" in low:
            pmf = True
        elif has_rsn:
            pmf = False

        out.append(WifiBss(
            interface=interface, tool="iw", ssid=ssid, bssid=bssid,
            band=_band_from_freq(freq), channel=chan, freq_mhz=freq,
            rate_mbps=None, signal=signal, signal_unit="dbm",
            security=None, auth=auth, cipher=cipher, pmf=pmf,
            mode="Infra", in_use=False, is_district_ssid=_is_district(ssid, district),
        ))
    return out


# ---------------------------------------------------------------------------
# Shared derivations
# ---------------------------------------------------------------------------


def _auth_cipher_pmf(security: str, wpa_flags: str, rsn_flags: str
                     ) -> tuple[str, str | None, bool | None]:
    """Derive (auth, cipher, pmf) from nmcli's SECURITY + WPA/RSN flag strings."""
    flags = f"{wpa_flags} {rsn_flags}".lower()
    sec = (security or "").lower()
    has_8021x = "802.1x" in flags or "802.1x" in sec
    has_sae = "sae" in flags
    has_psk = "psk" in flags
    if has_8021x:
        auth = "802.1x"
    elif has_sae and has_psk:
        auth = "psk+sae"
    elif has_sae:
        auth = "sae"
    elif has_psk:
        auth = "psk"
    elif "wep" in sec:
        auth = "wep"
    elif not security and "ccmp" not in flags and "tkip" not in flags:
        auth = "open"
    else:
        auth = "unknown"

    has_ccmp = "ccmp" in flags
    has_tkip = "tkip" in flags
    if has_ccmp and has_tkip:
        cipher: str | None = "ccmp+tkip"
    elif has_ccmp:
        cipher = "ccmp"
    elif has_tkip:
        cipher = "tkip"
    elif auth == "open":
        cipher = "none"
    else:
        cipher = None

    # nmcli's terse flags expose "mfp" only on some versions; absent => unknown.
    pmf: bool | None = True if "mfp" in flags else None
    return auth, cipher, pmf


def _band_from_freq(mhz: int | None) -> str | None:
    if mhz is None:
        return None
    if 2400 <= mhz < 2500:
        return "2.4GHz"
    if 4900 <= mhz < 5900:
        return "5GHz"
    if 5925 <= mhz <= 7125:
        return "6GHz"
    return None


def _channel_from_freq(mhz: int | None) -> int | None:
    if mhz is None:
        return None
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if 5000 <= mhz <= 5895:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:
        return (mhz - 5950) // 5
    return None


def _norm_bssid(v: str) -> str | None:
    v = (v or "").strip().lower()
    return v or None


def _district_set(csv: str) -> set[str]:
    return {s.strip().lower() for s in (csv or "").split(",") if s.strip()}


def _is_district(ssid: str | None, district: set[str]) -> bool | None:
    if not district:
        return None
    if not ssid:
        return False
    return ssid.lower() in district


def _age_seconds(generated_at: str | None) -> int | None:
    """Seconds since the envelope was generated. `generated_at` is UTC (`…Z`, from
    the host script's `date -u`), so parse it as UTC and diff against epoch —
    DST-safe (the old `time.timezone` math was an hour off during DST and mixed
    naive-local with UTC)."""
    if not generated_at:
        return None
    try:
        gen = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        return max(0, int(time.time() - gen.timestamp()))
    except (ValueError, TypeError):
        return None


def _search1(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def _int(v: str | None) -> int | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None
