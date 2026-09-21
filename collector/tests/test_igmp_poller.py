"""PERF-9: the poller starts every full scan's IGMP listener together.

Each listener needs ~150 s. Started inside each scan, a trunk with eight VLANs
paid that eight times over, one after another, under the scan lock. The poller
now plans the tick first, starts one listener per FULL scan up front, hands each
to its scan, and stops them all afterwards (a scan skipped by the cooldown never
collects its own). Light passes get none.

Pure unit test: interfaces, the DB gate, run_scan and the listener are stubbed.
"""

from __future__ import annotations

from types import SimpleNamespace

from collector import poller


class _FakeListener:
    made: list[_FakeListener] = []

    def __init__(self, interface, window):
        self.interface = interface
        self.started = False
        self.stopped = False
        _FakeListener.made.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def _state(name):
    return SimpleNamespace(name=name, has_usable_ip=True, gateway_mac="aa:bb:cc:dd:ee:ff",
                           primary_cidr=f"10.0.{name[-2:]}.5/24", gateway_ip="10.0.0.1")


def test_full_scans_share_one_concurrent_listening_window(monkeypatch):
    _FakeListener.made = []
    settings = SimpleNamespace(
        local_retention_days=0, snmp_bulk_retention_days=0, exclude_prefixes=(),
        exclude_vlan_set=set(), capture_interval=900, capture_seconds=60,
        rescan_interval=3600, igmp_enabled=True, igmp_listen_seconds=150,
    )
    monkeypatch.setattr(poller, "get_settings", lambda: settings)
    monkeypatch.setattr(poller.dhcp_server, "collect_and_store", lambda s: None)
    monkeypatch.setattr(poller.device_config, "collect_and_store", lambda s: None)
    states = [_state("eth0.20"), _state("eth0.30"), _state("eth0.40")]
    monkeypatch.setattr(poller.iface_mod, "snapshot", lambda exclude_prefixes: states)
    monkeypatch.setattr(poller.iface_mod, "primary_interface", lambda: "eth0.20")

    # eth0.20 and eth0.30 are due a FULL scan; eth0.40 only a light pass.
    def recent(net_id, window, exclude_capture=False, require_success=True):
        full_due = {poller._network_id(s.gateway_mac, s.primary_cidr)
                    for s in states[:2]}
        if exclude_capture:
            return None if net_id in full_due else {"id": 1}
        return None
    monkeypatch.setattr(poller, "recent_network_scan", recent)
    monkeypatch.setattr(poller.igmp_mod, "IgmpListener", _FakeListener)

    calls = []

    def fake_run_scan(**kw):
        # Every listener must already be running when the FIRST scan starts.
        calls.append((kw["interface"], kw["light"], kw["igmp_listener"],
                      [lst.started for lst in _FakeListener.made]))
    monkeypatch.setattr(poller, "run_scan", fake_run_scan)

    poller.tick()

    assert [c[0] for c in calls] == ["eth0.20", "eth0.30", "eth0.40"]
    assert len(_FakeListener.made) == 2, "one listener per FULL scan, none for light"
    assert calls[0][3] == [True, True], "all listeners started before the first scan"
    assert calls[0][2].interface == "eth0.20" and calls[1][2].interface == "eth0.30"
    assert calls[2][1] is True and calls[2][2] is None, "a light pass gets no listener"
    assert all(lst.stopped for lst in _FakeListener.made), "every listener is stopped"


def test_igmp_off_starts_nothing(monkeypatch):
    _FakeListener.made = []
    settings = SimpleNamespace(
        local_retention_days=0, snmp_bulk_retention_days=0, exclude_prefixes=(),
        exclude_vlan_set=set(), capture_interval=900, capture_seconds=60,
        rescan_interval=3600, igmp_enabled=False, igmp_listen_seconds=150,
    )
    monkeypatch.setattr(poller, "get_settings", lambda: settings)
    monkeypatch.setattr(poller.dhcp_server, "collect_and_store", lambda s: None)
    monkeypatch.setattr(poller.device_config, "collect_and_store", lambda s: None)
    monkeypatch.setattr(poller.iface_mod, "snapshot", lambda exclude_prefixes: [_state("eth0.20")])
    monkeypatch.setattr(poller.iface_mod, "primary_interface", lambda: "eth0.20")
    monkeypatch.setattr(poller, "recent_network_scan", lambda *a, **k: None)
    monkeypatch.setattr(poller.igmp_mod, "IgmpListener", _FakeListener)
    seen = []
    monkeypatch.setattr(poller, "run_scan", lambda **kw: seen.append(kw["igmp_listener"]))
    poller.tick()
    assert seen == [None] and _FakeListener.made == []
