"""Parsing of net-snmp `-Oqn` output, where the value may span MULTIPLE lines.

Cisco IOS/IOS-XE, Junos and ArubaOS all return a multi-line sysDescr, and the
same text reaches us out of a WALK as lldpRemSysDesc / cdpCacheVersion. The
old parser treated every line as a new varbind, which failed twice over:

  * the value was truncated at line 1, keeping the stray opening quote net-snmp
    adds around multi-line strings and LOSING the trailing `Compiled <date>`
    stamp (a free "this image is N years old" signal for firmware currency); and
  * continuation lines that happened to contain a space split cleanly into two
    parts, so "Technical Support: http://..." was stored as a varbind with an
    `oid` of "Technical".

`snmp._poll_oids` and `snmp_topology._snmp_walk` now share one parser, so the
GET path and the WALK path cannot drift apart again.
"""
from __future__ import annotations

from collector.discovery import snmp, snmp_topology

# Verbatim shape of a C3560-CX sysDescr under `snmpget -Oqn` — net-snmp wraps a
# multi-line string in double quotes, opening on line 1 and closing on the last.
CISCO_SYSDESCR = (
    '.1.3.6.1.2.1.1.1.0 "Cisco IOS Software, C3560CX Software '
    "(C3560CX-UNIVERSALK9-M), Version 15.2(7)E5, RELEASE SOFTWARE (fc3)\n"
    "Technical Support: http://www.cisco.com/techsupport\n"
    "Copyright (c) 1986-2019 by Cisco Systems, Inc.\n"
    'Compiled Tue 20-Aug-19 12:00 by prod_rel_team"\n'
)


def test_multiline_value_is_folded_into_one_varbind() -> None:
    rows = snmp.parse_oqn_output(CISCO_SYSDESCR)
    assert len(rows) == 1, f"continuation lines leaked as varbinds: {rows}"
    oid, value = rows[0]
    assert oid == ".1.3.6.1.2.1.1.1.0"
    # Surrounding quotes gone, all four lines present, Compiled date retained.
    assert not value.startswith('"')
    assert not value.endswith('"')
    assert value.startswith("Cisco IOS Software, C3560CX Software")
    assert "Technical Support: http://www.cisco.com/techsupport" in value
    assert value.endswith("Compiled Tue 20-Aug-19 12:00 by prod_rel_team")
    assert value.count("\n") == 3


def test_continuation_lines_do_not_become_bogus_oids() -> None:
    """The specific regression: `oid` of "Technical" / "Compiled"."""
    oids = [oid for oid, _ in snmp.parse_oqn_output(CISCO_SYSDESCR)]
    assert oids == [".1.3.6.1.2.1.1.1.0"]
    assert not any(not o.startswith(".") for o in oids)


def test_single_line_walk_rows_are_unchanged() -> None:
    """The common case must parse exactly as before — one row per line."""
    out = (
        ".1.3.6.1.2.1.31.1.1.1.1.1 Gi1/0/1\n"
        ".1.3.6.1.2.1.31.1.1.1.1.2 Gi1/0/2\n"
        ".1.3.6.1.2.1.31.1.1.1.1.3 Vlan 100 uplink\n"
    )
    assert snmp.parse_oqn_output(out) == [
        (".1.3.6.1.2.1.31.1.1.1.1.1", "Gi1/0/1"),
        (".1.3.6.1.2.1.31.1.1.1.1.2", "Gi1/0/2"),
        # a value containing spaces still keeps them
        (".1.3.6.1.2.1.31.1.1.1.1.3", "Vlan 100 uplink"),
    ]


def test_multiline_row_does_not_swallow_the_next_varbind() -> None:
    """A walk mixing a multi-line row with normal rows keeps them separate."""
    out = (
        ".1.0.8802.1.1.2.1.4.1.1.9.0.5.1 core-sw1\n"
        '.1.0.8802.1.1.2.1.4.1.1.10.0.5.1 "Cisco IOS Software, Version 15.2\n'
        'Compiled Tue 20-Aug-19 12:00 by prod_rel_team"\n'
        ".1.0.8802.1.1.2.1.4.1.1.12.0.5.1 20\n"
    )
    rows = snmp.parse_oqn_output(out)
    assert len(rows) == 3
    assert rows[0] == (".1.0.8802.1.1.2.1.4.1.1.9.0.5.1", "core-sw1")
    assert rows[1][1] == (
        "Cisco IOS Software, Version 15.2\n"
        "Compiled Tue 20-Aug-19 12:00 by prod_rel_team"
    )
    assert rows[2] == (".1.0.8802.1.1.2.1.4.1.1.12.0.5.1", "20")


def test_absent_object_varbinds_are_skipped() -> None:
    out = (
        ".1.3.6.1.2.1.43.5.1.1.16 No Such Object available at this OID\n"
        ".1.3.6.1.2.1.1.5.0 core-sw1\n"
    )
    assert snmp.parse_oqn_output(out) == [(".1.3.6.1.2.1.1.5.0", "core-sw1")]


def test_trailing_timeout_is_not_glued_onto_the_last_value() -> None:
    """_run_snmp concatenates stderr after stdout; that text has no leading OID
    and must not be folded into the preceding varbind as a continuation."""
    out = (
        ".1.3.6.1.2.1.1.5.0 core-sw1\n"
        "Timeout: No Response from 10.8.2.100\n"
    )
    assert snmp.parse_oqn_output(out) == [(".1.3.6.1.2.1.1.5.0", "core-sw1")]


def test_valueless_and_empty_lines_produce_no_rows() -> None:
    assert snmp.parse_oqn_output("") == []
    assert snmp.parse_oqn_output("\n\n  \n") == []
    assert snmp.parse_oqn_output(".1.3.6.1.2.1.1.6.0\n") == []
    assert snmp.parse_oqn_output('.1.3.6.1.2.1.1.6.0 ""\n') == []


def test_quotes_only_stripped_when_they_wrap_the_whole_value() -> None:
    # An unpaired quote is left alone rather than mangled further.
    assert snmp._strip_wrapping_quotes('"half open') == '"half open'
    assert snmp._strip_wrapping_quotes('"both"') == "both"
    assert snmp._strip_wrapping_quotes("plain") == "plain"
    # An interior quote pair is preserved.
    assert snmp._strip_wrapping_quotes('say "hi" now') == 'say "hi" now'


def test_poll_oids_stores_the_whole_multiline_sysdescr(monkeypatch) -> None:
    """End-to-end through _poll_oids: one sysDescr row, Compiled date intact."""
    def fake_run(cmd: list[str]) -> tuple[int, str]:
        oid = cmd[-1]
        if oid == snmp.SYSDESCR_OID:
            return 0, CISCO_SYSDESCR
        return 0, ""

    monkeypatch.setattr(snmp, "_run_snmp", fake_run)
    rows = snmp._poll_oids("10.8.2.1", "public", include_bulk=False)

    assert len(rows) == 1
    row = rows[0]
    assert row["oid_name"] == "sysDescr"
    assert row["oid"] == ".1.3.6.1.2.1.1.1.0"
    assert row["device_ip"] == "10.8.2.1"
    assert "Compiled Tue 20-Aug-19 12:00 by prod_rel_team" in row["value"]
    assert not row["value"].startswith('"')


def test_get_and_walk_paths_agree_on_the_same_value(monkeypatch) -> None:
    """snmp_topology._snmp_get (-Oqv) and the walk parser must yield the same
    string for the same sysDescr — the two paths are not allowed to drift."""
    value_only = CISCO_SYSDESCR.split(" ", 1)[1]  # what -Oqv prints (no OID)

    monkeypatch.setattr(snmp_topology._snmp, "_run_snmp",
                        lambda cmd: (0, value_only))
    via_get = snmp_topology._strip_quotes(
        snmp_topology._snmp_get("10.8.2.1", "public", snmp_topology.SYS_DESCR))

    via_walk = snmp.parse_oqn_output(CISCO_SYSDESCR)[0][1]
    assert via_get == via_walk
