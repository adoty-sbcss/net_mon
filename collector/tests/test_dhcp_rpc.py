"""Unit tests for the MS-DHCPM RPC fallback parser (DHCP-9).

Pure tests of the response-decoding helpers against dict structures shaped like
impacket's NDR responses — no impacket, no network. (The live RPC path was
validated end-to-end against a real hardened DHCP server: 485 scopes, options,
names, state — all DHCP-Users-only.)
"""
from __future__ import annotations

from collector.discovery import dhcp_rpc as r


def test_num_handles_int_and_ndr_element():
    assert r._num(42) == 42
    # bare NDR array elements (the subnet list) arrive wrapped in ['Data']
    assert r._num({"Data": 167772160}) == 167772160


def test_ip_and_wstr():
    assert r._ip(167772160) == "10.0.0.0"
    assert r._ip({"Data": 4294967040}) == "255.255.255.0"
    assert r._wstr("SBCSS.ORG\x00") == "SBCSS.ORG"
    assert r._wstr(None) == ""
    assert r._wstr("NULL") == ""


def test_opt_value_strings_decodes_each_type():
    data = {"Elements": [
        {"OptionType": 4, "Element": {"IpAddressOption": 167772414}},   # 10.0.0.254
        {"OptionType": 5, "Element": {"StringDataOption": "SBCSS.ORG\x00"}},
        {"OptionType": 2, "Element": {"DWordOption": 28800}},
        {"OptionType": 0, "Element": {"ByteOption": 1}},
        {"OptionType": 1, "Element": {"WordOption": 1500}},
    ]}
    assert r._opt_value_strings(data) == ["10.0.0.254", "SBCSS.ORG", "28800", "1", "1500"]


def test_options_from_enum_flattens_values():
    resp = {"OptionValues": {"Values": [
        {"OptionID": 6, "Value": {"Elements": [
            {"OptionType": 4, "Element": {"IpAddressOption": 134744072}},   # 8.8.8.8
            {"OptionType": 4, "Element": {"IpAddressOption": 134743044}},   # 8.8.4.4
        ]}},
        {"OptionID": 51, "Value": {"Elements": [
            {"OptionType": 2, "Element": {"DWordOption": 28800}},
        ]}},
    ]}}
    assert r._options_from_enum(resp) == [
        {"id": 6, "name": "", "value": ["8.8.8.8", "8.8.4.4"]},
        {"id": 51, "name": "", "value": ["28800"]},
    ]


def test_options_from_enum_tolerates_empty():
    assert r._options_from_enum({"OptionValues": None}) == []
    assert r._options_from_enum({}) == []


def test_extract_elements_ranges_and_excludes():
    # EnumSubnetElementsV5 shape: tag == element type; 0/5/6/7 are IP ranges, 3 = exclude.
    resp = {"EnumElementInfo": {"NumElements": 3, "Elements": [
        {"Element": {"tag": 0, "IpRange": {"StartAddress": 167772161, "EndAddress": 167772413}}},   # .1-.253
        {"Element": {"tag": 6, "IpRange": {"StartAddress": 167772416, "EndAddress": 167772430}}},   # bootp subtype
        {"Element": {"tag": 3, "ExcludeIpRange": {"StartAddress": 167772417, "EndAddress": 167772417}}},
    ]}}
    els = r._extract_elements(resp)
    assert els == [
        {"kind": "range", "start": 167772161, "end": 167772413},
        {"kind": "range", "start": 167772416, "end": 167772430},
        {"kind": "exclude", "start": 167772417, "end": 167772417},
    ]


def test_extract_elements_reservation_emits_full_uid():
    resp = {"EnumElementInfo": {"NumElements": 1, "Elements": [
        {"Element": {"tag": 2, "ReservedIp": {
            "ReservedIpAddress": 167772171,  # 10.0.0.11
            "ReservedForClient": {"DataLength": 6,
                                  "Data_": [b"\xaa", b"\xbb", b"\xcc", b"\xdd", b"\xee", b"\xff"]},
        }}},
    ]}}
    assert r._extract_elements(resp) == [
        {"kind": "reservation", "ip": 167772171, "uid": "aabbccddeeff"},
    ]


def test_extract_elements_reservation_11byte_uid_full():
    # Windows reservation UIDs are often 11 bytes (client-id prefix + 6-byte MAC).
    uid = [b"\x00", b"\x01", b"\x01", b"\x0a", b"\x01",
           b"\x28", b"\x29", b"\x86", b"\x09", b"\xc1", b"\x78"]
    resp = {"EnumElementInfo": {"NumElements": 1, "Elements": [
        {"Element": {"tag": 2, "ReservedIp": {
            "ReservedIpAddress": 167838053,  # 10.1.1.101
            "ReservedForClient": {"DataLength": 11, "Data_": uid},
        }}},
    ]}}
    assert r._extract_elements(resp) == [
        {"kind": "reservation", "ip": 167838053, "uid": "0001010a0128298609c178"},
    ]


def test_fmt_mac_takes_trailing_six_and_colon_lowercases():
    assert r._fmt_mac(bytes.fromhex("28298609c178")) == "28:29:86:09:c1:78"
    # 11-byte UID -> trailing 6
    assert r._fmt_mac(bytes.fromhex("000101 0a01 28298609c178".replace(" ", ""))) == "28:29:86:09:c1:78"
    # short blob used as-is
    assert r._fmt_mac(b"\x01\x02\x03") == "01:02:03"


def test_hw_mac_keeps_real_suppresses_ip_synthetic():
    ip = 167841499  # 10.1.14.219  (little-endian bytes db 0e 01 0a)
    real = bytes.fromhex("000e010a0128298609c178")   # 11-byte hardware UID (ends in MAC)
    synth = bytes.fromhex("000e010a01db0e010a")       # 9-byte, ends in the reserved IP
    assert r._hw_mac(real, ip) == "28:29:86:09:c1:78"
    assert r._hw_mac(synth, ip) == ""                 # server-synthesized -> no MAC
    assert r._hw_mac(b"\x01\x02", ip) == ""           # too short -> no MAC


def test_filetime_iso_converts_and_treats_infinite_as_none():
    # 2020-08-26T16:32:03Z as a FILETIME (100ns ticks since 1601)
    ft = int((1598459523 + 11644473600) * 1e7)
    iso = r._filetime_iso(ft & 0xFFFFFFFF, ft >> 32)
    assert iso is not None and iso.startswith("2020-08-26T16:32:03")
    assert r._filetime_iso(0, 0) is None                       # infinite / unset lease
    assert r._filetime_iso(0xFFFFFFFF, 0x7FFFFFFF) is None      # max


def test_scope_reservations_joins_leases(monkeypatch):
    # reserved .101 has a live lease (active, same MAC); .200 has none (never used)
    monkeypatch.setattr(r, "_enum_elements", lambda *_a: [
        {"kind": "reservation", "ip": 167838053, "uid": "0001010a0128298609c178"},  # 10.1.1.101
        {"kind": "reservation", "ip": 167838152, "uid": "aabbccddeeff"},            # 10.1.1.200
    ])
    leases = {167838053: {"mac": "28:29:86:09:c1:78", "name": "pdu02", "expiry": None}}
    out = r._scope_reservations(object(), 0, leases)
    assert out == [
        {"ip": "10.1.1.101", "mac": "28:29:86:09:c1:78", "name": "pdu02", "active": True,
         "client_mac": "28:29:86:09:c1:78", "lease_expiry": None, "bad_address": False},
        {"ip": "10.1.1.200", "mac": "aa:bb:cc:dd:ee:ff", "name": "", "active": False,
         "client_mac": "", "lease_expiry": None, "bad_address": False},
    ]


def test_scope_reservations_flags_bad_address_and_suppresses_synthetic(monkeypatch):
    # a bad-address reservation: synthetic UID (ends in the reserved IP) + BAD_ADDRESS lease
    monkeypatch.setattr(r, "_enum_elements", lambda *_a: [
        {"kind": "reservation", "ip": 167841499, "uid": "000e010a01db0e010a"},  # 10.1.14.219
    ])
    leases = {167841499: {"mac": "", "name": "BAD_ADDRESS", "expiry": None}}
    out = r._scope_reservations(object(), 0, leases)
    assert out == [
        {"ip": "10.1.14.219", "mac": "", "name": "BAD_ADDRESS", "active": True,
         "client_mac": "", "lease_expiry": None, "bad_address": True},
    ]


def test_extract_elements_tolerates_empty_and_null():
    assert r._extract_elements({"EnumElementInfo": None}) == []
    assert r._extract_elements({}) == []
    assert r._extract_elements({"EnumElementInfo": {"NumElements": 0, "Elements": None}}) == []


def test_scope_range_sums_ranges():
    # two ranges → overall start/end span + total = sum of per-range sizes
    def fake_enum(_dce2, _sid, _et):
        return [
            {"kind": "range", "start": 167772161, "end": 167772165},   # 10.0.0.1-.5  (5)
            {"kind": "range", "start": 167772171, "end": 167772172},   # 10.0.0.11-.12 (2)
        ]
    orig = r._enum_elements
    r._enum_elements = fake_enum
    try:
        start, end, total = r._scope_range(object(), 167772160)
    finally:
        r._enum_elements = orig
    assert start == "10.0.0.1"
    assert end == "10.0.0.12"
    assert total == 7


def test_scope_range_no_ranges_is_zero():
    orig = r._enum_elements
    r._enum_elements = lambda *_a: []
    try:
        assert r._scope_range(object(), 1) == ("", "", 0)
    finally:
        r._enum_elements = orig
