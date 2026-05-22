from __future__ import annotations

import hashlib
import signal
import time

import structlog

from .config import get_settings
from .db import recent_network_scan
from .discovery import interfaces as iface_mod
from .scan import run_scan

log = structlog.get_logger(__name__)

_stop = False


def _handle_signal(signum, frame):  # noqa: ANN001
    global _stop
    log.info("signal received, stopping", signum=signum)
    _stop = True


def _network_id(gateway_mac: str | None, cidr: str | None) -> str | None:
    if not cidr:
        return None
    key = f"{gateway_mac or 'no-gw'}|{cidr}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def run_poller() -> None:
    settings = get_settings()
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Per-interface last-seen network id, so we know what was up last tick.
    previous: dict[str, str | None] = {}

    while not _stop:
        try:
            tick(previous)
        except Exception as exc:  # pragma: no cover — keep loop alive
            log.exception("poller tick failed", error=str(exc))
        # Sleep in small slices so SIGTERM is handled quickly.
        for _ in range(settings.poll_interval):
            if _stop:
                break
            time.sleep(1)


def tick(previous: dict[str, str | None]) -> None:
    settings = get_settings()
    states = iface_mod.snapshot(exclude_prefixes=settings.exclude_prefixes)

    seen_now: dict[str, str | None] = {}
    for st in states:
        if not st.has_usable_ip:
            seen_now[st.name] = None
            continue

        net_id = _network_id(st.gateway_mac, st.primary_cidr)
        seen_now[st.name] = net_id
        prev = previous.get(st.name)

        if prev == net_id:
            # Same interface, same network as last tick — nothing new.
            continue

        # Either a new interface, new network on this interface, or recovered from down.
        # In field mode, respect cooldown to avoid hammering the same network.
        if settings.mode == "field" and net_id is not None:
            recent = recent_network_scan(net_id, settings.cooldown_seconds)
            if recent:
                log.info("skipping scan, network within cooldown",
                         interface=st.name, network_id=net_id, last_scan=recent["id"])
                continue

        log.info("triggering scan",
                 interface=st.name, cidr=st.primary_cidr,
                 gateway=st.gateway_ip, reason="link_up_or_network_change")
        run_scan(interface=st.name, trigger_reason="link_up", force=False)

    previous.clear()
    previous.update(seen_now)
