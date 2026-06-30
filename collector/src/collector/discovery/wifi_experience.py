"""WIFI-3: read the host-side client-experience battery artifact for the bundle.

The battery runs HOST-side (scripts/netmon-wifi-experience.sh): it controls the
analysis radio (join/leave) and does source-routed probes the container can't, and
drops /var/lib/netmon/wifi_experience.json. Here we read it, decode the base64'd
captive-portal redirect, and hand it to the bundle. Gated by NETMON_WIFI_JOIN_ENABLED
(the same flag that enables the join). Never raises — a missing/bad artifact yields
``{"available": False}``.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

EXPERIENCE_PATH = Path("/var/lib/netmon/wifi_experience.json")


def load() -> dict[str, Any]:
    """Return the normalized experience artifact for the bundle, or unavailable."""
    from ..config import get_settings

    if not get_settings().wifi_join_enabled:
        return {"available": False, "reason": "disabled"}
    try:
        env = json.loads(EXPERIENCE_PATH.read_text())
    except FileNotFoundError:
        return {"available": False, "reason": "no-artifact"}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("wifi experience artifact unreadable", error=str(exc))
        return {"available": False, "reason": "unreadable"}

    for r in env.get("results", []) or []:
        cp = r.get("captive_portal")
        if isinstance(cp, dict):
            raw = cp.pop("redirect_b64", "") or ""
            if raw:
                try:
                    cp["redirect"] = base64.b64decode(raw).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    cp["redirect"] = None
    env["available"] = True
    log.info("wifi experience normalized", results=len(env.get("results", []) or []))
    return env
