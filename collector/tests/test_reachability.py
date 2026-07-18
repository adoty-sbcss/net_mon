"""Network-device reachability probing: the parallel probe + its traceroute gate.

Pure unit tests: `_ping` / `_traceroute` / `shutil.which` are the boundaries and
are faked, so nothing is spawned and no packet is sent. These pin the two things
the parallelization must not break — the output record shape/ORDER the bundle and
dashboard read positionally, and the rule that only ping-alive targets are traced
(an offline candidate otherwise walked out to the full hop limit, ~10-20s each,
to learn nothing).
"""
from __future__ import annotations

from typing import Any

from collector.discovery import reachability


def _targets(*ips: str) -> list[dict[str, Any]]:
    return [{"ip": ip, "hostname": f"h-{ip}", "vendor": "Cisco",
             "source": "oui", "snmp_responded": False, "snmp_version": None}
            for ip in ips]


def _install(monkeypatch, *, alive: set[str], have_tr: bool = True):
    """Fake the probe boundaries. Returns the list of IPs traceroute was run on."""
    traced: list[str] = []

    monkeypatch.setattr(reachability.shutil, "which",
                        lambda _n: "/usr/bin/traceroute" if have_tr else None)

    def _fake_ping(ip, *, count, timeout):
        if ip in alive:
            return True, 1.5, 0
        return False, None, 100

    def _fake_traceroute(ip, *, max_hops, wait):
        traced.append(ip)
        return [{"hop": 1, "ip": ip, "rtt_ms": 1.5}], 1

    monkeypatch.setattr(reachability, "_ping", _fake_ping)
    monkeypatch.setattr(reachability, "_traceroute", _fake_traceroute)
    return traced


def test_traceroute_only_runs_for_ping_alive_targets(monkeypatch):
    traced = _install(monkeypatch, alive={"10.0.0.1", "10.0.0.3"})

    out = reachability.probe(_targets("10.0.0.1", "10.0.0.2", "10.0.0.3"))

    assert sorted(traced) == ["10.0.0.1", "10.0.0.3"], "dead targets must not be traced"
    by_ip = {r["ip"]: r for r in out}
    assert by_ip["10.0.0.1"]["traceroute_hops"] == 1
    assert by_ip["10.0.0.1"]["traceroute_path"] == [{"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.5}]
    # An unreachable candidate reports no path rather than a list of timed-out hops.
    assert by_ip["10.0.0.2"]["ping_alive"] is False
    assert by_ip["10.0.0.2"]["traceroute_hops"] is None
    assert by_ip["10.0.0.2"]["traceroute_path"] == []


def test_output_order_follows_input_order(monkeypatch):
    """The pool must not reorder results — callers and the bundle read these as a
    plain list."""
    ips = [f"10.0.0.{i}" for i in range(1, 41)]
    _install(monkeypatch, alive=set(ips))

    out = reachability.probe(_targets(*ips))
    assert [r["ip"] for r in out] == ips


def test_record_shape_is_preserved(monkeypatch):
    _install(monkeypatch, alive={"10.0.0.1"})

    out = reachability.probe([{
        "ip": "10.0.0.1", "hostname": "sw1", "vendor": "Aruba", "source": "lldp",
        "snmp_responded": True, "snmp_version": "2c",
    }])

    assert out == [{
        "ip": "10.0.0.1",
        "hostname": "sw1",
        "vendor": "Aruba",
        "source": "lldp",
        "ping_alive": True,
        "ping_rtt_ms": 1.5,
        "ping_loss_pct": 0,
        "snmp_responded": True,
        "snmp_version": "2c",
        "traceroute_hops": 1,
        "traceroute_path": [{"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.5}],
    }]


def test_targets_without_an_ip_are_skipped(monkeypatch):
    _install(monkeypatch, alive={"10.0.0.1"})

    out = reachability.probe([{"ip": None}, {"hostname": "no-ip"}, {"ip": "10.0.0.1"}])
    assert [r["ip"] for r in out] == ["10.0.0.1"]


def test_respects_the_target_cap(monkeypatch):
    _install(monkeypatch, alive=set())

    out = reachability.probe(_targets(*[f"10.0.1.{i}" for i in range(1, 51)]), limit=5)
    assert len(out) == 5


def test_missing_traceroute_binary_still_pings(monkeypatch):
    traced = _install(monkeypatch, alive={"10.0.0.1"}, have_tr=False)

    out = reachability.probe(_targets("10.0.0.1"))
    assert traced == []
    assert out[0]["ping_alive"] is True
    assert out[0]["traceroute_path"] == []


def test_traceroute_disabled_by_caller(monkeypatch):
    traced = _install(monkeypatch, alive={"10.0.0.1"})

    out = reachability.probe(_targets("10.0.0.1"), traceroute=False)
    assert traced == []
    assert out[0]["ping_alive"] is True
