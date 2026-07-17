"""Poller cadence: between full re-scans, a LIGHT capture-only pass fires on the
capture_interval so sporadic DHCP/STP is sampled far more often than the hourly
full scan, without paying for the full discovery each time.

Pure unit tests: the interface snapshot, the DB "recent scan" lookup, and
run_scan are all monkeypatched, so there is no DB and no network. Asserts the
exact run_scan call the tick() rule produces for each freshness state.
"""

from __future__ import annotations

from collector import poller


class _State:
    """Minimal stand-in for an interface snapshot entry used by tick()."""

    def __init__(self) -> None:
        self.name = "eno1"
        self.primary_cidr = "10.0.0.5/24"
        self.gateway_mac = "aa:bb:cc:dd:ee:ff"
        self.gateway_ip = "10.0.0.1"
        self.has_usable_ip = True


def _setup(monkeypatch, *, recent_within):
    """Wire up tick()'s dependencies. `recent_within(window_sec) -> bool` decides
    whether a prior scan exists inside the queried window. Returns the list that
    captures each run_scan(**kwargs) call."""
    calls: list[dict] = []
    monkeypatch.setattr(poller.iface_mod, "snapshot", lambda **k: [_State()])
    monkeypatch.setattr(poller.iface_mod, "primary_interface", lambda: "eno1")
    monkeypatch.setattr(poller, "_maybe_purge", lambda s: None)
    monkeypatch.setattr(
        poller, "recent_network_scan",
        lambda net_id, window: {"id": 1} if recent_within(window) else None,
    )
    monkeypatch.setattr(poller, "run_scan", lambda **kw: calls.append(kw) or 1)
    return calls


def test_full_scan_when_nothing_recent(monkeypatch):
    # No prior scan in any window -> a FULL periodic scan (not light).
    calls = _setup(monkeypatch, recent_within=lambda w: False)
    poller.tick()
    assert len(calls) == 1
    assert calls[0]["trigger_reason"] == "periodic"
    assert calls[0].get("light", False) is False


def test_light_capture_between_full_scans(monkeypatch):
    # A scan exists inside the rescan window (full NOT due) but not inside the
    # smaller capture window -> a LIGHT capture-only pass.
    settings = poller.get_settings()
    assert settings.capture_interval > 0, "light pass requires capture_interval > 0"
    assert settings.capture_interval < settings.rescan_interval
    calls = _setup(monkeypatch, recent_within=lambda w: w >= settings.rescan_interval)
    poller.tick()
    assert len(calls) == 1
    assert calls[0]["trigger_reason"] == "capture"
    assert calls[0]["light"] is True


def test_idle_when_captured_recently(monkeypatch):
    # A scan exists inside even the small capture window -> nothing due at all.
    calls = _setup(monkeypatch, recent_within=lambda w: True)
    poller.tick()
    assert calls == []
