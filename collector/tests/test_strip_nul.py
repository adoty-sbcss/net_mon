"""Regression: a device advertising an embedded NUL (0x00) must not fail the
whole scan persist.

Cucamonga Middle 2026-07-25: an Android TV's mDNS/SSDP record carried a NUL, and
the service_discovery batch insert died with psycopg
`UntranslatableCharacter: \\u0000 cannot be converted to text` -- failing the
ENTIRE scan and leaving the sensor with zero data on the dashboard. db._strip_nul
sanitizes at the one batch-insert chokepoint (insert_many).
"""

from collector.db import _strip_nul


def test_strips_nul_from_plain_string():
    assert _strip_nul("am=AndroidTV3.1\x00trailing") == "am=AndroidTV3.1trailing"


def test_clean_string_returned_unchanged():
    clean = "normal-value"
    assert _strip_nul(clean) is clean  # no needless copy when there's nothing to strip


def test_recurses_into_dict_and_list_jsonb_payloads():
    payload = {"name": "tv\x00", "services": ["_airplay._tcp\x00", "ok"], "port": 7000}
    assert _strip_nul(payload) == {
        "name": "tv",
        "services": ["_airplay._tcp", "ok"],
        "port": 7000,
    }


def test_non_string_scalars_pass_through():
    assert _strip_nul(42) == 42
    assert _strip_nul(None) is None
    assert _strip_nul(True) is True
