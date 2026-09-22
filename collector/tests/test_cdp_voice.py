"""Voice VLAN advertised to the sensor's own port over CDP.

The two CDP layer dicts in fixtures/cdp_tshark_ek.json are COPIED verbatim from
the sensor's tshark 4.4.18 dissector (a crafted frame, the real dissector), so
the field names below are pinned against real output. Variations built from
them in this file (a phone's Query TLV, dot1p VLAN 0, junk values) are TYPED and
say so.

The rule under test is the three honest states the dashboard renders:
frames == 0 is UNKNOWN (not captured this scan), frames >= 1 with no voice VLAN
is "the switch advertises none", and an int is "advertised".
"""

from __future__ import annotations

import copy
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from collector import scan
from collector.discovery import cdp_voice, tshark
from collector.discovery.tshark import CaptureResult
from collector.models import ScanContext

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "cdp_tshark_ek.json").read_text(encoding="utf-8"))
WITH_VOICE = FIXTURE["with_voice_vlan"]
WITHOUT_VOICE = FIXTURE["without_voice_vlan"]

SWITCH_MAC = "AA:BB:CC:00:00:01"
T0 = datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)  # 1700000000000 ms


def _ek_line(cdp_layer: dict, *, ts_ms: int = 1700000000000, src: str = SWITCH_MAC) -> str:
    return json.dumps({
        "timestamp": str(ts_ms),
        "layers": {
            "eth": {"eth_eth_dst": "01:00:0c:cc:cc:cc", "eth_eth_src": src},
            "cdp": cdp_layer,
        },
    })


def _capture(monkeypatch, lines: list[str]) -> CaptureResult:
    stdout = "\n".join(lines) + "\n"
    monkeypatch.setattr(tshark.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout=stdout, stderr=""))
    return tshark.run_capture(interface="eth0", seconds=1)


# --- tshark parse -------------------------------------------------------------


def test_tshark_keeps_both_real_cdp_frames(monkeypatch):
    res = _capture(monkeypatch, [
        '{"index":{"_index":"packets-2023-11-14","_type":"doc"}}',
        _ek_line(WITH_VOICE),
        '{"index":{"_index":"packets-2023-11-14","_type":"doc"}}',
        _ek_line(WITHOUT_VOICE, ts_ms=1700000060000),
    ])
    assert res.cdp == [
        {"device_id": "SW1", "port_id": "GigabitEthernet1/0/5", "native_vlan": 10,
         "voice_vlan": 100, "src_mac": "aa:bb:cc:00:00:01", "seen_at": T0},
        {"device_id": "SW1", "port_id": "GigabitEthernet1/0/5", "native_vlan": 10,
         "voice_vlan": None, "src_mac": "aa:bb:cc:00:00:01", "seen_at": T0 + timedelta(seconds=60)},
    ]
    assert res.total_packets == 2 and res.multicast_packets == 2


def test_cdp_is_not_bounded_by_the_raw_evidence_cap(monkeypatch):
    # A busy VLAN fills `raw` long before the once-a-minute CDP frame arrives.
    monkeypatch.setattr(tshark, "RAW_FRAME_CAP", 1)
    arp = json.dumps({"timestamp": "1699999999000", "layers": {
        "eth": {"eth_eth_dst": "ff:ff:ff:ff:ff:ff", "eth_eth_src": "aa:bb:cc:00:00:09"},
        "arp": {"arp_arp_opcode": "1"}}})
    res = _capture(monkeypatch, [arp, _ek_line(WITH_VOICE)])
    assert len(res.raw) == 1 and "arp" in res.raw[0]["summary"]
    assert [f["voice_vlan"] for f in res.cdp] == [100]


def test_voice_vlan_from_a_phones_query_tlv_is_not_an_advertisement():
    # TYPED: a phone's frame carries the VoIP VLAN QUERY (0x000f), not the reply.
    body = copy.deepcopy(WITH_VOICE)
    body["cdp_cdp_tlv_type"] = ["0x0001", "0x0003", "0x0004", "0x000f"]
    assert tshark._parse_cdp(body, {})["voice_vlan"] is None


def test_reply_and_query_in_one_frame_takes_the_reply():
    # TYPED: both TLVs, values in TLV order; the reply's value is the one kept.
    body = copy.deepcopy(WITH_VOICE)
    body["cdp_cdp_tlv_type"] = ["0x0001", "0x000f", "0x000e"]
    body["cdp_cdp_voice_vlan"] = ["200", "100"]
    assert tshark._parse_cdp(body, {})["voice_vlan"] == 100


def test_dot1p_voice_vlan_zero_is_an_advertisement_not_absence():
    # TYPED: `switchport voice vlan dot1p` advertises VLAN 0. It is a voice-VLAN
    # configuration; reading it as None would report "the switch advertises none".
    body = copy.deepcopy(WITH_VOICE)
    body["cdp_cdp_voice_vlan"] = "0"
    assert tshark._parse_cdp(body, {})["voice_vlan"] == 0


def test_junk_vlan_values_parse_to_none():
    # TYPED junk: never a crash, never a made-up number.
    for junk in ("", "abc", "70000", "-1", "10.5", True, None):
        body = copy.deepcopy(WITH_VOICE)
        body["cdp_cdp_voice_vlan"] = junk
        body["cdp_cdp_native_vlan"] = junk
        parsed = tshark._parse_cdp(body, {})
        assert parsed["voice_vlan"] is None and parsed["native_vlan"] is None, junk
    # ek lists (a repeated TLV) and hex are still read.
    body = copy.deepcopy(WITH_VOICE)
    body["cdp_cdp_native_vlan"] = ["0x000a"]
    assert tshark._parse_cdp(body, {})["native_vlan"] == 10


def test_missing_ids_parse_to_none_without_raising():
    parsed = tshark._parse_cdp({}, {})
    assert parsed == {"device_id": None, "port_id": None, "native_vlan": None,
                      "voice_vlan": None, "src_mac": None}


# --- annotate_neighbors -------------------------------------------------------


def _frame(voice_vlan, *, device="SW1", port="GigabitEthernet1/0/5", at=T0, native=10):
    return {"device_id": device, "port_id": port, "native_vlan": native,
            "voice_vlan": voice_vlan, "src_mac": "aa:bb:cc:00:00:01", "seen_at": at}


def _cdp_neighbor(**over):
    # The shape lldp._flatten emits for a CDP neighbor, per lldpd's CDP decode:
    # Device ID -> chassis id AND system name, Port ID -> port id.
    n = {"local_port": "eth0", "protocol": "cdpv2", "chassis_id": "SW1",
         "port_id": "GigabitEthernet1/0/5", "system_name": "SW1",
         "system_description": None, "port_description": "GigabitEthernet1/0/5",
         "vlan_id": None, "mgmt_ip": None, "capabilities": ["Bridge"]}
    n.update(over)
    return n


def _lldp_neighbor():
    return {"local_port": "eth0", "protocol": "lldp", "chassis_id": "aa:bb:cc:00:00:02",
            "port_id": "GigabitEthernet1/0/5", "system_name": "SW1",
            "system_description": None, "port_description": None, "vlan_id": 10,
            "mgmt_ip": None, "capabilities": ["Bridge"]}


def test_three_states():
    advertised, none_advertised, not_captured = _cdp_neighbor(), _cdp_neighbor(), _cdp_neighbor()
    cdp_voice.annotate_neighbors([advertised], [_frame(100)])
    cdp_voice.annotate_neighbors([none_advertised], [_frame(None)])
    cdp_voice.annotate_neighbors([not_captured], [])
    assert advertised["extra"]["cdp_voice"] == {"frames": 1, "voice_vlan": 100, "native_vlan": 10}
    assert none_advertised["extra"]["cdp_voice"] == {"frames": 1, "voice_vlan": None, "native_vlan": 10}
    # UNKNOWN, not "no voice VLAN": the frame was simply not captured this scan.
    assert not_captured["extra"]["cdp_voice"] == {"frames": 0, "voice_vlan": None, "native_vlan": None}


def test_real_frames_end_to_end_through_the_parser(monkeypatch):
    res = _capture(monkeypatch, [_ek_line(WITHOUT_VOICE), _ek_line(WITH_VOICE, ts_ms=1700000060000)])
    n = _cdp_neighbor()
    cdp_voice.annotate_neighbors([n], res.cdp)
    assert n["extra"]["cdp_voice"] == {"frames": 2, "voice_vlan": 100, "native_vlan": 10}


def test_most_recent_frame_wins_by_capture_time_not_list_position():
    n = _cdp_neighbor()
    later_without = _frame(None, at=T0 + timedelta(seconds=60))
    earlier_with = _frame(100, at=T0)
    cdp_voice.annotate_neighbors([n], [later_without, earlier_with])
    assert n["extra"]["cdp_voice"] == {"frames": 2, "voice_vlan": None, "native_vlan": 10}


def test_the_sensors_own_frames_and_other_ports_do_not_match():
    n = _cdp_neighbor()
    frames = [
        # The sensor's own CDP (lldpd -c answers a CDP peer): its hostname + NIC.
        _frame(None, device="netmon-sensor", port="eth0"),
        # Same switch, a different port (a CDP frame flooded by a dumb switch).
        _frame(200, port="GigabitEthernet1/0/6"),
        # Another switch, same port name.
        _frame(300, device="SW2"),
    ]
    cdp_voice.annotate_neighbors([n], frames)
    assert n["extra"]["cdp_voice"] == {"frames": 0, "voice_vlan": None, "native_vlan": None}
    # Positive control: the matching frame, added to the same noise, is found.
    cdp_voice.annotate_neighbors([n], [*frames, _frame(100)])
    assert n["extra"]["cdp_voice"] == {"frames": 1, "voice_vlan": 100, "native_vlan": 10}


def test_match_on_chassis_id_when_system_name_differs_and_strip_whitespace():
    n = _cdp_neighbor(system_name=None, chassis_id="SW1")
    cdp_voice.annotate_neighbors([n], [_frame(100, device=" SW1 ", port="GigabitEthernet1/0/5 ")])
    assert n["extra"]["cdp_voice"]["frames"] == 1


def test_lldp_neighbor_is_untouched_and_existing_extra_is_kept():
    lldp = _lldp_neighbor()
    cdp = _cdp_neighbor(extra={"kept": True})
    before = copy.deepcopy(lldp)
    cdp_voice.annotate_neighbors([lldp, cdp], [_frame(100)])
    assert lldp == before and "extra" not in lldp
    assert cdp["extra"] == {"kept": True,
                            "cdp_voice": {"frames": 1, "voice_vlan": 100, "native_vlan": 10}}


# --- scan wiring --------------------------------------------------------------


@contextmanager
def _ctx(value):
    yield value


def _run_scan(monkeypatch, *, neighbors, cdp_frames):
    now = datetime.now(UTC)
    state = SimpleNamespace(
        name="eth0", has_usable_ip=True, is_up=True, has_carrier=True,
        ipv4_addrs=["192.0.2.5/24"], primary_cidr=None,
        gateway_ip=None, gateway_mac="aa:bb:cc:dd:ee:ff",
    )
    monkeypatch.setattr(scan.iface_mod, "get_one", lambda iface: state)
    monkeypatch.setattr(scan.iface_mod, "read_counters", lambda iface: {})
    monkeypatch.setattr(scan.tshark_mod, "run_capture",
                        lambda **kw: CaptureResult(started_at=now, completed_at=now, cdp=cdp_frames))
    monkeypatch.setattr(scan.lldp_mod, "fetch_neighbors", lambda: neighbors)
    monkeypatch.setattr(scan.arp_mod, "run", lambda iface: [])
    monkeypatch.setattr(scan, "_snmp_candidates", lambda *a, **k: [])
    monkeypatch.setattr(scan, "insert_scan_run", lambda **kw: 7)
    monkeypatch.setattr(scan, "audit", lambda *a, **k: None)
    persisted: dict = {}
    monkeypatch.setattr(scan, "_persist", lambda ctx, **kw: persisted.update(kw))
    monkeypatch.setattr(scan, "connect", lambda: _ctx(object()))
    completed: dict = {}

    def record_complete(scan_id, *, duration_sec, error, notes):
        completed.update(error=error, notes=notes)

    monkeypatch.setattr(scan, "complete_scan_run", record_complete)
    monkeypatch.setattr(scan, "get_settings", lambda: SimpleNamespace(
        capture_seconds=1, snmp_enabled=False, snmp_poll_all_hosts=False,
        snmp_topology_enabled=False, dns_enabled=False, reachability_enabled=False,
        mdns_enabled=False, dhcp_probe_enabled=False, igmp_enabled=False))
    result = scan._run_scan_locked(interface="eth0", trigger_reason="periodic", force=True)
    return result, persisted, completed


def test_scan_annotates_cdp_neighbors_before_persisting(monkeypatch):
    result, persisted, completed = _run_scan(
        monkeypatch, neighbors=[_cdp_neighbor(), _lldp_neighbor()], cdp_frames=[_frame(100)])
    assert result == 7 and completed["error"] is None
    cdp, lldp = persisted["lldp_neighbors"]
    assert cdp["extra"]["cdp_voice"] == {"frames": 1, "voice_vlan": 100, "native_vlan": 10}
    assert "extra" not in lldp


def test_annotation_failure_degrades_the_scan_never_fails_it(monkeypatch):
    def boom(neighbors, frames):
        raise ValueError("unexpected CDP shape")

    monkeypatch.setattr(cdp_voice, "annotate_neighbors", boom)
    result, persisted, completed = _run_scan(
        monkeypatch, neighbors=[_cdp_neighbor()], cdp_frames=[_frame(100)])
    assert result == 7 and completed["error"] is None
    assert "cdp_voice" in str(completed["notes"])
    assert len(persisted["lldp_neighbors"]) == 1  # the neighbors still persist


def test_neighbors_insert_serializes_extra_and_nothing_else_leaks(monkeypatch):
    rows_by_table: dict[str, list[dict]] = {}

    def record_insert(table, rows, *, connection=None):
        rows_by_table.setdefault(table, []).extend(rows)

    monkeypatch.setattr(scan, "insert_many", record_insert)
    monkeypatch.setattr(scan, "get_settings",
                        lambda: SimpleNamespace(rdns_enabled=False, inventory_enabled=False))
    cdp = _cdp_neighbor(stray_key="must not become a column")
    cdp_voice.annotate_neighbors([cdp], [_frame(100)])
    lldp = _lldp_neighbor()
    now = datetime.now(UTC)
    scan._persist(
        ScanContext(1, "eth0", "192.0.2.2/24", None, None, "network", 0.0),
        connection=object(),
        pre_counters={}, post_counters={},
        cap_results=CaptureResult(started_at=now, completed_at=now),
        lldp_neighbors=[cdp, lldp], arp_results=[], nmap_results=[], snmp_results=[],
    )
    rows = rows_by_table["neighbors"]
    columns = {"local_port", "protocol", "chassis_id", "port_id", "system_name",
               "system_description", "port_description", "vlan_id", "mgmt_ip",
               "capabilities", "scan_run_id", "extra"}
    # insert_many takes its column list from the FIRST row: every row must agree.
    assert all(set(r) == columns for r in rows)
    assert json.loads(rows[0]["extra"]) == {
        "cdp_voice": {"frames": 1, "voice_vlan": 100, "native_vlan": 10}}
    assert json.loads(rows[1]["extra"]) == {}
    assert rows[0]["system_name"] == "SW1" and rows[0]["scan_run_id"] == 1
    assert rows[0]["capabilities"] == ["Bridge"]
