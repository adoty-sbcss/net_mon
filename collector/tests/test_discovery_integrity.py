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


def test_nmap_nonzero_exit_raises(monkeypatch) -> None:
    # nmap still surfaces failures loudly at the tool layer; the scan layer
    # catches this and records it as a degraded section rather than failing the
    # whole scan (see test_nmap_failure_does_not_fail_the_scan in test_scan_integrity).
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
    # Real tshark -T ek output carries BOTH a top-level `timestamp` in epoch
    # MILLISECONDS (Elasticsearch epoch_millis) and layers.frame.frame_time_epoch
    # in epoch SECONDS. The seconds field is authoritative and must be used — the
    # millis value parsed as seconds overflows and would silently fall back to the
    # scan-start time.
    epoch_s = 1_700_000_000.25
    packet = {
        "timestamp": str(int(epoch_s * 1000)),  # 13-digit epoch millis, as real EK emits
        "layers": {
            "eth": {
                "eth_eth_dst": "ff:ff:ff:ff:ff:ff",
                "eth_eth_src": "00:11:22:33:44:55",
            },
            "frame": {"frame_frame_time_epoch": str(epoch_s)},
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
    expected = datetime.fromtimestamp(epoch_s, UTC)

    assert result.dhcp[0]["seen_at"] == expected
    assert result.stp[0]["seen_at"] == expected


def test_packet_time_falls_back_to_millisecond_envelope(monkeypatch) -> None:
    # When only the EK top-level `timestamp` (epoch millis) is present, it must be
    # divided by 1000 — parsing 13-digit millis as seconds raises and would
    # otherwise silently fall back to the scan-start time.
    epoch_s = 1_700_000_000.0
    packet = {
        "timestamp": str(int(epoch_s * 1000)),
        "layers": {
            "eth": {
                "eth_eth_dst": "ff:ff:ff:ff:ff:ff",
                "eth_eth_src": "00:11:22:33:44:55",
            },
            "dhcp": {
                "dhcp_dhcp_option_dhcp": "1",
                "dhcp_dhcp_hw_mac_addr": "00:11:22:33:44:55",
            },
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

    assert result.dhcp[0]["seen_at"] == datetime.fromtimestamp(epoch_s, UTC)


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
