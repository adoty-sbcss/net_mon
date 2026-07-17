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


def _setup(monkeypatch, *, rows):
    """Wire up tick()'s dependencies with a fake scan_runs history.

    `rows` is a list of {"age": <seconds since started_at>, "reason": <trigger_reason>}.
    The fake recent_network_scan honors BOTH the query window and exclude_capture,
    exactly like the real SQL — so these tests exercise the real freshness rule,
    including that a light 'capture' row must NOT satisfy the full-scan gate.
    Returns the list that captures each run_scan(**kwargs) call."""
    calls: list[dict] = []
    monkeypatch.setattr(poller.iface_mod, "snapshot", lambda **k: [_State()])
    monkeypatch.setattr(poller.iface_mod, "primary_interface", lambda: "eno1")
    monkeypatch.setattr(poller, "_maybe_purge", lambda s: None)

    def _recent(net_id, window, exclude_capture=False):
        best = None
        for r in rows:
            if r["age"] > window:
                continue
            if exclude_capture and r.get("reason") == "capture":
                continue
            if best is None or r["age"] < best["age"]:
                best = r
        return {"id": 1} if best is not None else None

    monkeypatch.setattr(poller, "recent_network_scan", _recent)
    monkeypatch.setattr(poller, "run_scan", lambda **kw: calls.append(kw) or 1)
    return calls


def test_full_scan_when_nothing_recent(monkeypatch):
    # No prior scan at all -> a FULL periodic scan (not light).
    calls = _setup(monkeypatch, rows=[])
    poller.tick()
    assert len(calls) == 1
    assert calls[0]["trigger_reason"] == "periodic"
    assert calls[0].get("light", False) is False


def test_light_capture_between_full_scans(monkeypatch):
    # A full scan exists inside the rescan window (full NOT due) but nothing
    # inside the smaller capture window -> a LIGHT capture-only pass.
    s = poller.get_settings()
    assert s.capture_interval > 0, "light pass requires capture_interval > 0"
    assert s.capture_interval < s.rescan_interval
    mid = (s.capture_interval + s.rescan_interval) // 2  # inside rescan, outside capture
    calls = _setup(monkeypatch, rows=[{"age": mid, "reason": "periodic"}])
    poller.tick()
    assert len(calls) == 1
    assert calls[0]["trigger_reason"] == "capture"
    assert calls[0]["light"] is True


def test_idle_when_fully_scanned_recently(monkeypatch):
    # A full scan inside even the small capture window -> nothing due at all.
    calls = _setup(monkeypatch, rows=[{"age": 1, "reason": "periodic"}])
    poller.tick()
    assert calls == []


def test_periodic_not_starved_by_light_capture(monkeypatch):
    # REGRESSION (F-COL-1): the last FULL scan is older than the rescan interval,
    # but recent light 'capture' passes exist inside it. The full periodic scan
    # MUST still fire — a capture row must not satisfy the full-scan gate.
    # Against the pre-fix code (no exclude_capture) the fresh capture row keeps
    # the gate "recent" and this network is never re-scanned; this asserts it is.
    s = poller.get_settings()
    calls = _setup(monkeypatch, rows=[
        {"age": s.rescan_interval + 400, "reason": "periodic"},  # stale full scan
        {"age": 100, "reason": "capture"},                       # fresh light pass
    ])
    poller.tick()
    assert len(calls) == 1, "a stale-full-scan network with fresh capture rows must re-scan"
    assert calls[0]["trigger_reason"] == "periodic"
    assert calls[0].get("light", False) is False
