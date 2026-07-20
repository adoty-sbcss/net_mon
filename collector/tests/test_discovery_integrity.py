"""Tests that collection failures and observation times remain distinguishable."""

import inspect
import json
import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from collector.discovery import arp, interfaces, mdns_ssdp, nmap, snmp, tshark


def test_secondary_interface_does_not_borrow_another_gateway(monkeypatch) -> None:
    monkeypatch.setattr(
        interfaces,
        "_run_ip_json",
        lambda command: [{"dev": "eth0", "gateway": "192.0.2.1"}],
    )
    monkeypatch.setattr(
        interfaces,
        "_arp_lookup",
        lambda ip, iface: pytest.fail("foreign gateway must not be resolved"),
    )

    assert interfaces._default_route_via("eth1") == (None, None)


def test_tshark_missing_is_a_scan_failure(monkeypatch) -> None:
    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(tshark.subprocess, "run", missing)

    with pytest.raises(RuntimeError, match="tshark executable not found"):
        tshark.run_capture(interface="eth0", seconds=1)


def test_arp_timeout_is_a_scan_failure(monkeypatch) -> None:
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(["arp-scan"], 1)

    monkeypatch.setattr(arp.subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="arp-scan timed out"):
        arp.run("eth0", timeout=1)


def test_nmap_nonzero_exit_is_a_scan_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        nmap.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="bad target"
        ),
    )

    with pytest.raises(RuntimeError, match="nmap failed scanning"):
        nmap.host_discovery("192.0.2.0/24")


def test_packet_capture_time_is_stored_on_dhcp_and_stp(monkeypatch) -> None:
    epoch = 1_700_000_000.25
    packet = {
        "timestamp": str(epoch),
        "layers": {
            "eth": {
                "eth_eth_dst": "ff:ff:ff:ff:ff:ff",
                "eth_eth_src": "00:11:22:33:44:55",
            },
            "dhcp": {
                "dhcp_dhcp_option_dhcp": "1",
                "dhcp_dhcp_hw_mac_addr": "00:11:22:33:44:55",
            },
            "stp": {"stp_stp_type": "0"},
        },
    }
    monkeypatch.setattr(
        tshark.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(packet), stderr=""
        ),
    )

    result = tshark.run_capture(interface="eth0", seconds=1)
    expected = datetime.fromtimestamp(epoch, UTC)

    assert result.dhcp[0]["seen_at"] == expected
    assert result.stp[0]["seen_at"] == expected


def test_snmp_candidate_cap_reports_truncation(monkeypatch) -> None:
    settings = SimpleNamespace(
        snmp_enabled=True,
        snmp_community_list=("public",),
        snmp_poll_max_candidates=2,
        snmp_poll_time_budget=120,
    )
    monkeypatch.setattr(snmp, "get_settings", lambda: settings)
    monkeypatch.setattr(snmp.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(
        snmp,
        "_select_community",
        lambda ip, communities, deadline=float("inf"): "public",
    )
    monkeypatch.setattr(
        snmp,
        "_poll_oids",
        lambda ip, community, include_bulk=True, deadline=float("inf"): [],
    )
    status = {}

    snmp.poll(["192.0.2.1", "192.0.2.2", "192.0.2.3"], status=status)

    assert status["attempted"] == 2
    assert status["completed"] == 2
    assert status["truncated"] is True


def test_multicast_discovery_selects_the_scanned_interface() -> None:
    source = inspect.getsource(mdns_ssdp)

    assert source.count("socket.IP_MULTICAST_IF") >= 2
    assert "sock.bind((bind_ip, 0))" in source
