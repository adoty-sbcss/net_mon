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
