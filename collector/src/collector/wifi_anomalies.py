"""Phase 1 Wi-Fi anomaly detection rules.

Lightweight pattern-match rules that produce findings for the bundle. The
Claude-side analysis goes deeper using the raw data; these rules just catch
the obvious stuff so it's flagged even before AI review.

Rule set:
    weak_security      — open / WEP / WPA1-only networks
    duplicate_ssid     — same SSID broadcast by multiple BSSIDs (info: could
                         be a legit enterprise WLAN OR an evil-twin attempt;
                         we let Claude judge)
    channel_saturation — channel busy_pct above THRESHOLD_BUSY_PCT
    hidden_ssid        — SSIDs that are broadcasting but with empty name
                         (informational — common in some deployments)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

THRESHOLD_BUSY_PCT = 70.0


def detect(aps: list[dict[str, Any]],
           channel_stats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run every Phase-1 rule, return a flat list of finding dicts."""
    out: list[dict[str, Any]] = []
    out.extend(_weak_security(aps))
    out.extend(_duplicate_ssids(aps))
    out.extend(_channel_saturation(channel_stats))
    out.extend(_hidden_ssids(aps))
    return out


def _weak_security(aps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ap in aps:
        privacy = (ap.get("privacy") or "").upper()
        bssid = ap.get("bssid") or ""
        essid = ap.get("essid") or "(hidden)"
        ch = ap.get("channel")
        if privacy == "OPEN":
            out.append({
                "kind": "weak_security",
                "severity": "high",
                "title": f"Open Wi-Fi network: {essid!r} on ch {ch}",
                "detail": f"BSSID {bssid} has no encryption. "
                          "Acceptable only for intentional guest / captive-portal networks.",
                "evidence": {"bssid": bssid, "essid": essid, "channel": ch,
                             "privacy": privacy},
            })
        elif privacy == "WEP":
            out.append({
                "kind": "weak_security",
                "severity": "high",
                "title": f"WEP-encrypted Wi-Fi: {essid!r} on ch {ch}",
                "detail": f"BSSID {bssid} uses WEP, which is trivially broken. "
                          "Should be replaced immediately.",
                "evidence": {"bssid": bssid, "essid": essid, "channel": ch,
                             "privacy": privacy},
            })
        elif privacy == "WPA":
            out.append({
                "kind": "weak_security",
                "severity": "medium",
                "title": f"WPA1-only Wi-Fi: {essid!r} on ch {ch}",
                "detail": f"BSSID {bssid} advertises WPA1 without WPA2 fallback. "
                          "WPA1 is deprecated; upgrade to WPA2/WPA3.",
                "evidence": {"bssid": bssid, "essid": essid, "channel": ch,
                             "privacy": privacy},
            })
    return out


def _duplicate_ssids(aps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ssid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ap in aps:
        essid = ap.get("essid")
        if not essid:
            continue
        by_ssid[essid].append(ap)

    out: list[dict[str, Any]] = []
    for essid, group in by_ssid.items():
        if len(group) < 2:
            continue
        bssids = [g.get("bssid") for g in group]
        channels = sorted({g.get("channel") for g in group if g.get("channel") is not None})
        # Privacy mix is suspicious: if one BSSID claims WPA2 and another OPEN for
        # the same SSID, that's a much stronger evil-twin signal.
        privacies = {(g.get("privacy") or "").upper() for g in group}
        severity = "medium" if len(privacies) > 1 else "info"
        title = f"SSID {essid!r} broadcast by {len(group)} BSSIDs"
        detail_extra = ""
        if len(privacies) > 1:
            detail_extra = (" Different encryption settings across BSSIDs — "
                            "could indicate an evil-twin attempt.")
        out.append({
            "kind": "duplicate_ssid",
            "severity": severity,
            "title": title,
            "detail": (f"BSSIDs: {', '.join(bssids)}; channels: {channels}; "
                       f"privacy values: {sorted(privacies)}.{detail_extra} "
                       "Normal for enterprise WLANs; suspect if not deployed by you."),
            "evidence": {"essid": essid, "bssids": bssids,
                         "channels": channels, "privacies": sorted(privacies)},
        })
    return out


def _channel_saturation(channel_stats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in channel_stats:
        busy = row.get("busy_pct")
        if busy is None or busy < THRESHOLD_BUSY_PCT:
            continue
        ch = row.get("channel")
        band = row.get("band") or "?"
        ap_count = row.get("ap_count")
        out.append({
            "kind": "channel_saturation",
            "severity": "medium",
            "title": f"Channel {ch} ({band}) is {busy:.0f}% busy",
            "detail": (f"Sustained channel activity above {THRESHOLD_BUSY_PCT:.0f}% "
                       f"will cause association and throughput problems. "
                       f"APs visible on this channel: {ap_count}."),
            "evidence": {"channel": ch, "band": band, "busy_pct": busy,
                         "ap_count": ap_count},
        })
    return out


def _hidden_ssids(aps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hidden = [a for a in aps if a.get("hidden")]
    if not hidden:
        return []
    return [{
        "kind": "hidden_ssid",
        "severity": "info",
        "title": f"{len(hidden)} hidden SSID(s) observed",
        "detail": ("Beacons present without SSID. Not necessarily a problem — "
                   "some operators intentionally hide guest networks. Worth a "
                   "look if your environment shouldn't have any."),
        "evidence": {"bssids": [a.get("bssid") for a in hidden]},
    }]
