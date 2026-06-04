"""802.1Q VLAN detection on a trunk's parent NIC.

Sniffs tagged frames on `interface` for a few seconds and reports which VLAN IDs
are present. libpcap sees the 802.1Q tag in promiscuous mode even when the parent
has no VLAN sub-interfaces yet — so this is the trunk wizard's "what VLANs are on
this port?" detect step, run BEFORE any sub-interface is created.

Pure-stdlib + tshark (already a dependency). The parser is unit-testable; the
capture is best-effort and time-bounded.
"""
from __future__ import annotations

import subprocess

import structlog

log = structlog.get_logger(__name__)


def _parse_vlan_ids(output: str) -> list[int]:
    """From tshark `-e vlan.id` output (one frame per line; a line can carry
    several comma/space-separated ids for stacked/QinQ tags) return the sorted
    unique set of valid VLAN IDs (1..4094)."""
    ids: set[int] = set()
    for line in output.splitlines():
        for tok in line.replace(",", " ").split():
            try:
                v = int(tok)
            except ValueError:
                continue
            if 1 <= v <= 4094:
                ids.add(v)
    return sorted(ids)


def detect_vlans(interface: str, seconds: int = 8) -> list[int]:
    """Capture on `interface` for `seconds` and return the 802.1Q VLAN IDs seen.
    Empty list if none are seen (a quiet trunk or a plain access port), or on any
    error — callers treat empty as "no tags detected, maybe not a trunk."""
    cmd = [
        "tshark", "-i", interface,
        "-a", f"duration:{seconds}",
        "-f", "vlan",                       # BPF: only 802.1Q-tagged frames
        "-T", "fields", "-e", "vlan.id",
        "-n", "-l",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=seconds + 30, check=False)
    except FileNotFoundError:
        log.warning("tshark not found for vlan detect")
        return []
    except subprocess.TimeoutExpired:
        log.warning("vlan detect hard-timeout", seconds=seconds)
        return []
    if proc.returncode not in (0, 1):  # 1 = captured nothing matching
        log.warning("vlan detect tshark failed", returncode=proc.returncode,
                    stderr=proc.stderr[:300])
    vlans = _parse_vlan_ids(proc.stdout)
    log.info("vlan detect", interface=interface, seconds=seconds, vlans=vlans)
    return vlans
