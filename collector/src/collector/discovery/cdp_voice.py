"""Voice VLAN the switch advertises to the sensor's own port, over CDP.

A Cisco switch sends CDP every 60 s; on a port with `switchport voice vlan`
configured the frame carries the "VoIP VLAN Reply" TLV (0x000e) — the VLAN a
phone plugged into that port would be told to use. lldpd hears the frame but
does not keep that TLV, while the passive tshark capture does (tshark.py,
`CaptureResult.cdp`). This joins the two: each CDP neighbor lldpd reports gets
`extra.cdp_voice = {"frames", "voice_vlan", "native_vlan"}`.

Three states, and the dashboard must keep them apart:

* `frames == 0`  — no matching frame was captured THIS scan (the 60 s window
  missed the once-a-minute frame, or the scan ran on a VLAN sub-interface that
  never sees the untagged CDP). UNKNOWN — not "no voice VLAN".
* `frames >= 1`, `voice_vlan` None — the switch spoke and advertised no voice
  VLAN on this port.
* `voice_vlan` an int — advertised. 0 means 802.1p priority-tagged (`dot1p`),
  4095 untagged; see tshark._cdp_vlan.

LLDP neighbors are left untouched: no `cdp_voice` key means "not a CDP
neighbor", which is different from any of the three.
"""
from __future__ import annotations

from typing import Any


def _norm(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _at_least_as_recent(current: dict[str, Any], candidate: dict[str, Any]) -> bool:
    """Whether `candidate` is at least as recent as `current`. Frames arrive in
    capture order, so a tie or an incomparable timestamp keeps the later one."""
    a, b = current.get("seen_at"), candidate.get("seen_at")
    if a is None or b is None:
        return True
    try:
        return bool(b >= a)
    except TypeError:
        return True


def annotate_neighbors(neighbors: list[dict[str, Any]], cdp_frames: list[dict[str, Any]]) -> None:
    """Set `extra.cdp_voice` on every CDP neighbor, in place.

    Matching assumes lldpd's CDP decode (its cdp.c): the Device ID TLV becomes
    BOTH the chassis id (subtype "local") and the system name, and the Port ID
    TLV becomes the port id (subtype "ifname"). So a frame belongs to a neighbor
    when its Device ID equals that neighbor's system name or chassis id AND its
    Port ID equals the neighbor's port id — exact strings, after strip.

    Both halves are required. Device alone would merge two ports of the same
    switch (a sensor with two NICs, or a CDP neighbor seen via an unmanaged
    switch that floods CDP). Port alone would match any switch's
    "GigabitEthernet1/0/5". And the capture also records the sensor's OWN CDP
    frames (entrypoint runs `lldpd -c`, which starts sending CDP once it hears a
    CDP peer): those carry the sensor's hostname and interface name, so they
    never match the switch's neighbor record.
    """
    for n in neighbors:
        if not str(n.get("protocol") or "").strip().lower().startswith("cdp"):
            continue
        names = {x for x in (_norm(n.get("system_name")), _norm(n.get("chassis_id"))) if x}
        port = _norm(n.get("port_id"))
        frames = 0
        latest: dict[str, Any] | None = None
        if names and port is not None:
            for f in cdp_frames:
                if _norm(f.get("port_id")) != port or _norm(f.get("device_id")) not in names:
                    continue
                frames += 1
                if latest is None or _at_least_as_recent(latest, f):
                    latest = f
        extra = n.get("extra")
        n["extra"] = {
            **(extra if isinstance(extra, dict) else {}),
            "cdp_voice": {
                "frames": frames,
                "voice_vlan": latest.get("voice_vlan") if latest is not None else None,
                "native_vlan": latest.get("native_vlan") if latest is not None else None,
            },
        }
