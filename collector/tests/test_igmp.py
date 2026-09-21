"""PERF-9 IGMP listener: parsing, and the rule that silence is only reported as
`none_heard` after the positive control passed and a full query interval elapsed.

A listener that hears nothing — a wrong kernel filter, a socket bound to the wrong
place — would otherwise report "no querier" on every VLAN of the fleet, which is
exactly the false finding this product keeps having to walk back.
"""

from __future__ import annotations

import socket
import struct

from collector.discovery import igmp

SRC_MAC = bytes.fromhex("aabbccddeeff")


def _frame(src: str, dst: str, payload: bytes) -> bytes:
    # IGMP rides with the Router Alert IP option (IHL 6) on real networks.
    ip = struct.pack("!BBHHHBBH4s4s", 0x46, 0xC0, 24 + len(payload), 1, 0, 1, 2, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + b"\x94\x04\x00\x00"
    return b"\x01\x00\x5e\x00\x00\x01" + SRC_MAC + b"\x08\x00" + ip + payload


def _v2_query(max_resp=100, group="0.0.0.0"):
    return struct.pack("!BBH4s", 0x11, max_resp, 0, socket.inet_aton(group))


def _v3_query(max_resp=100, qqic=125, qrv=2):
    return struct.pack("!BBH4sBBH", 0x11, max_resp, 0, b"\x00" * 4, qrv, qqic, 0)


def test_time_code_decoding():
    assert igmp._decode_time_code(100) == 100
    assert igmp._decode_time_code(0x8C) == (12 | 0x10) << 3


def test_parse_v2_general_query():
    p = igmp.parse_igmp(_frame("10.0.9.1", "224.0.0.1", _v2_query()))
    assert p is not None
    assert p["kind"] == "query" and p["general"] and p["version"] == 2
    assert p["src_ip"] == "10.0.9.1" and p["src_mac"] == "aa:bb:cc:dd:ee:ff"
    assert p["max_resp_ms"] == 10_000


def test_parse_v1_query_has_zero_max_resp():
    p = igmp.parse_igmp(_frame("10.0.9.1", "224.0.0.1", _v2_query(max_resp=0)))
    assert p["version"] == 1


def test_parse_v3_query_reads_the_querier_interval():
    p = igmp.parse_igmp(_frame("10.0.9.1", "224.0.0.1", _v3_query(qqic=60)))
    assert p["version"] == 3 and p["qqi_sec"] == 60 and p["robustness"] == 2


def test_parse_group_specific_query():
    p = igmp.parse_igmp(_frame("10.0.9.1", "239.1.1.1", _v2_query(group="239.1.1.1")))
    assert p["general"] is False and p["group"] == "239.1.1.1"


def test_parse_v2_report_and_leave():
    rep = igmp.parse_igmp(_frame("10.0.9.50", "239.1.1.1",
                                 struct.pack("!BBH4s", 0x16, 0, 0, socket.inet_aton("239.1.1.1"))))
    assert rep["kind"] == "report" and rep["groups"] == ["239.1.1.1"]
    leave = igmp.parse_igmp(_frame("10.0.9.50", "224.0.0.2",
                                   struct.pack("!BBH4s", 0x17, 0, 0, socket.inet_aton("239.1.1.1"))))
    assert leave["kind"] == "leave"


def test_parse_v3_report_with_several_records():
    rec1 = struct.pack("!BBH4s", 4, 0, 0, socket.inet_aton("239.10.0.1"))
    rec2 = struct.pack("!BBH4s", 4, 0, 1, socket.inet_aton("239.10.0.2")) + socket.inet_aton("10.0.0.9")
    payload = struct.pack("!BBHHH", 0x22, 0, 0, 0, 2) + rec1 + rec2
    p = igmp.parse_igmp(_frame("10.0.9.50", "224.0.0.22", payload))
    assert p["version"] == 3 and p["groups"] == ["239.10.0.1", "239.10.0.2"]


def test_non_igmp_is_ignored():
    frame = bytearray(_frame("10.0.9.1", "224.0.0.1", _v2_query()))
    frame[14 + 9] = 17
    assert igmp.parse_igmp(bytes(frame)) is None
    assert igmp.parse_igmp(b"\x00" * 20) is None


# --- the outcome rules --------------------------------------------------------


def _listener(**state):
    lst = igmp.IgmpListener("eth0.20", window_sec=150)
    lst._self_test_group = "239.255.7.7"
    for k, v in state.items():
        setattr(lst, k, v)
    return lst


INCOMING = ("eth0.20", 0x0800, 2, 1, SRC_MAC)
OUTGOING = ("eth0.20", 0x0800, igmp.PACKET_OUTGOING, 1, SRC_MAC)


def test_a_heard_query_is_querier_seen():
    lst = _listener(_listened_sec=150.0, _self_test_seen=True)
    lst._handle(_frame("10.0.20.1", "224.0.0.1", _v2_query()), INCOMING)
    s = lst.summary()
    assert s["status"] == "querier_seen"
    assert s["queriers"][0]["ip"] == "10.0.20.1" and s["queriers"][0]["general_queries"] == 1


def test_silence_with_control_and_full_window_is_none_heard():
    s = _listener(_listened_sec=150.0, _self_test_seen=True).summary()
    assert s["status"] == "none_heard" and s["reason"] is None


def test_silence_without_the_positive_control_is_unavailable():
    s = _listener(_listened_sec=150.0, _self_test_seen=False).summary()
    assert s["status"] == "unavailable"
    assert "positive control" in s["reason"]


def test_silence_over_a_short_window_is_unavailable():
    s = _listener(_listened_sec=60.0, _self_test_seen=True).summary()
    assert s["status"] == "unavailable"
    assert "shorter than one default query interval" in s["reason"]


def test_a_listener_error_is_unavailable():
    s = _listener(_listened_sec=150.0, _self_test_seen=True, _error="listener failed: x").summary()
    assert s["status"] == "unavailable"


def test_own_report_proves_the_listener_and_is_not_counted_as_a_group():
    lst = _listener(_listened_sec=150.0)
    own = struct.pack("!BBH4s", 0x16, 0, 0, socket.inet_aton("239.255.7.7"))
    lst._handle(_frame("10.0.20.9", "239.255.7.7", own), OUTGOING)
    s = lst.summary()
    assert s["self_test_seen"] is True
    assert s["groups"] == [] and s["reports_seen"] == 0
    assert s["status"] == "none_heard"


def test_other_hosts_reports_become_groups():
    lst = _listener(_listened_sec=150.0, _self_test_seen=True)
    rep = struct.pack("!BBH4s", 0x16, 0, 0, socket.inet_aton("239.1.1.1"))
    lst._handle(_frame("10.0.20.50", "239.1.1.1", rep), INCOMING)
    lst._handle(_frame("10.0.20.51", "239.1.1.1", rep), INCOMING)
    s = lst.summary()
    assert s["groups"] == [{"group": "239.1.1.1", "versions": [2], "reporters": 2}]
    assert s["reports_seen"] == 2
