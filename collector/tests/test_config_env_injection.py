"""Env-file injection defenses for dashboard-pushed sensor configuration.

`/etc/netmon/netmon.env` is written one `KEY=VALUE` line per mapping entry and is
the `env_file:` for BOTH the collector and the postgres service. A pushed string
carrying a newline therefore appends attacker-chosen lines that set any NETMON_* or
POSTGRES_* variable in both services. These tests pin the two layers that stop it:
`_validate_desired_config` hard-rejects the push (so it is audited, not half-applied),
and `_update_env_file` refuses the write even if a future caller forgets to validate.
"""

import re
import subprocess
from pathlib import Path

import pytest

from collector import checkin


def _apply(data: dict, monkeypatch) -> list[tuple[Path, dict]]:
    """Run _apply_config with the env write recorded instead of performed."""
    writes: list[tuple[Path, dict]] = []
    monkeypatch.setattr(
        checkin, "_update_env_file", lambda path, mapping: writes.append((path, mapping))
    )
    checkin._apply_config(data)
    return writes


# --- layer 1: the push is hard-rejected -------------------------------------


# Every character Python's str.splitlines() treats as a line break, derived at
# runtime rather than hard-coded. _update_env_file re-reads the file with
# splitlines() and re-joins with "\n", so ANY of these — not just "\n" — promotes
# the tail of a value to a real env line on the NEXT push. Deriving the list means
# this test cannot drift from CPython's definition (an earlier version of this fix
# blocklisted only \n \r \x00 and was bypassable with \x0b).
LINE_BREAKS = [c for c in map(chr, range(0x110000)) if len(("a" + c + "b").splitlines()) > 1]


def test_the_derived_line_break_set_is_what_we_think_it_is() -> None:
    # Guard the guard: if this ever changes, the parametrization above changed too.
    assert {ord(c) for c in LINE_BREAKS} == {
        0x0A, 0x0B, 0x0C, 0x0D, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029,
    }


@pytest.mark.parametrize("sep", LINE_BREAKS, ids=lambda c: f"U+{ord(c):04X}")
def test_every_line_break_character_is_refused(sep, monkeypatch) -> None:
    with pytest.raises(ValueError, match="must not contain the control character"):
        _apply({"snmp_communities": f"public{sep}POSTGRES_PASSWORD=owned"}, monkeypatch)


def test_two_push_split_injection_is_closed(tmp_path, monkeypatch) -> None:
    """The full attack, end to end, against the real writer.

    Push #1 stores a value whose separator compose itself ignores; push #2 (any key)
    makes OUR reader split it and re-emit the tail as a genuine env line. Both pushes
    must be refused, and the file must be byte-identical afterwards.
    """
    env = tmp_path / "netmon.env"
    original = "NETMON_SNMP_COMMUNITIES=public\nKEEP=x\n"
    env.write_text(original)
    monkeypatch.setattr(checkin, "ENV_FILE", env)

    for sep in LINE_BREAKS:
        with pytest.raises(ValueError):
            checkin._apply_config(
                {"snmp_communities": f"public{sep}POSTGRES_PASSWORD=owned"}
            )
        # And the writer refuses independently, even handed the value directly.
        with pytest.raises(ValueError, match="refusing to write"):
            checkin._update_env_file(
                env, {"NETMON_SNMP_COMMUNITIES": f"public{sep}POSTGRES_PASSWORD=owned"}
            )

    assert env.read_text() == original
    # A benign follow-up push must still not resurrect an injected line.
    checkin._update_env_file(env, {"NETMON_SNMP_ENABLED": "true"})
    assert "POSTGRES_PASSWORD" not in env.read_text()


@pytest.mark.parametrize(
    "payload",
    [
        "1.1.1.1\nNETMON_DASHBOARD_URL=http://evil.example",
        "1.1.1.1\rPOSTGRES_PASSWORD=owned",
        "1.1.1.1\x00POSTGRES_USER=postgres",
        "1.1.1.1\x0bPOSTGRES_PASSWORD=owned",
        "1.1.1.1\u2028POSTGRES_PASSWORD=owned",  # NEL/LS/PS: not ASCII, still a split
        "1.1.1.1\tPOSTGRES_PASSWORD=owned",
    ],
)
def test_newline_injection_in_a_pushed_string_is_refused(payload, monkeypatch) -> None:
    with pytest.raises(ValueError, match="must not contain"):
        _apply({"latency_targets": payload}, monkeypatch)


@pytest.mark.parametrize("quote", ['"', "'"])
def test_leading_quote_is_refused(quote, monkeypatch) -> None:
    # compose reads a leading quote as opening a multi-line quoted value; an
    # unterminated one is a parse error that fails `docker compose up` for every
    # service on the box — including the rollback recreate. Refuse, don't brick.
    with pytest.raises(ValueError, match="must not begin with a quote"):
        _apply({"snmp_communities": quote}, monkeypatch)


def test_injection_is_refused_before_any_env_write(monkeypatch) -> None:
    # The whole generation must be refused, not partially applied: a valid key in
    # the same push must not reach the env file either.
    writes: list[tuple[Path, dict]] = []
    monkeypatch.setattr(
        checkin, "_update_env_file", lambda path, mapping: writes.append((path, mapping))
    )

    with pytest.raises(ValueError):
        checkin._apply_config(
            {"snmp_enabled": True, "latency_targets": "1.1.1.1\nPOSTGRES_PASSWORD=owned"}
        )

    assert writes == []


@pytest.mark.parametrize(
    "key",
    sorted(checkin._CONFIG_STR_KEYS),
)
def test_every_pushed_string_rejects_a_newline(key, monkeypatch) -> None:
    # Not just latency_targets: EVERY key copied verbatim into netmon.env.
    with pytest.raises(ValueError, match="must not contain the control character"):
        _apply({key: "ok\nNETMON_BUNDLE_TRANSPORT=sftp"}, monkeypatch)


@pytest.mark.parametrize(
    "value",
    [
        "-f",                    # `ping -c 10 ... -f` → root flood ping
        "1.1.1.1,-w0",
        "--logfile=/etc/passwd",
    ],
)
def test_leading_dash_host_is_refused(value, monkeypatch) -> None:
    with pytest.raises(ValueError, match="must not begin with '-'"):
        _apply({"latency_targets": value}, monkeypatch)


@pytest.mark.parametrize("key", sorted(checkin._CONFIG_HOST_KEYS))
def test_leading_dash_host_scalar_is_refused(key, monkeypatch) -> None:
    # These reach a subprocess argv (`iperf3 -c <server>`, `git rev-parse <ref>`,
    # nmcli/netplan). They are option ARGUMENTS today, so a leading dash is not
    # exploitable as written; the rule is held so that stays true if an argv is
    # reordered to put the value last, which is the shape latency_targets has.
    with pytest.raises(ValueError, match="must not begin with '-'"):
        _apply({key: "-J"}, monkeypatch)
    with pytest.raises(ValueError, match="must not contain whitespace"):
        _apply({key: "host --extra"}, monkeypatch)


@pytest.mark.parametrize(
    "value",
    [
        "1.1.1.1;rm -rf /",
        "1.1.1.1 8.8.8.8",         # space would split one ping operand into two
        "$(id)",
        "999.1.1.1",
        "-leading.example.com",
        "trailing-.example.com",
        "1.1.1.1,,8.8.8.8",        # empty token
    ],
)
def test_non_host_tokens_are_refused(value, monkeypatch) -> None:
    with pytest.raises(ValueError):
        _apply({"latency_targets": value}, monkeypatch)


def test_host_list_token_count_is_capped(monkeypatch) -> None:
    cap = checkin._CONFIG_HOST_LIST_CAPS["latency_targets"]
    at_cap = ",".join(f"10.0.0.{i}" for i in range(1, cap + 1))
    over_cap = ",".join(f"10.0.0.{i}" for i in range(1, cap + 2))

    assert _apply({"latency_targets": at_cap}, monkeypatch)[0][1][
        "NETMON_LATENCY_TARGETS"
    ] == at_cap
    with pytest.raises(ValueError, match=f"at most {cap} hosts"):
        _apply({"latency_targets": over_cap}, monkeypatch)


@pytest.mark.parametrize(
    "value",
    [
        "1.1.1.1,8.8.8.8",
        "1.1.1.1, 8.8.8.8",              # whitespace around a separator is fine
        "one.one.one.one,dns.google",
        "sensor-gw.district.k12.ca.us",
        "example.com.",                  # fully-qualified trailing dot
        "",                              # clearing the field falls back to the default
    ],
)
def test_valid_host_lists_are_accepted(value, monkeypatch) -> None:
    writes = _apply({"latency_targets": value}, monkeypatch)

    expected = value or "1.1.1.1,8.8.8.8"
    assert writes[0][1]["NETMON_LATENCY_TARGETS"] == expected


def test_ordinary_config_still_applies(monkeypatch) -> None:
    # Positive control: the validator must not reject a normal push. Values that
    # legitimately hold non-host characters (SNMP communities, an SSID with a
    # space, a PSK) are only screened for control characters.
    writes = _apply(
        {
            "snmp_communities": "public,private",
            "snmp_credential_overrides": "10.0.0.1=secret,10.0.0.2=other",
            "wifi_join_ssid": "District Guest WiFi",
            "wifi_join_secret": "p@ss word!#$",
            "iperf_server": "iperf.district.k12.ca.us",
            "latency_targets": "1.1.1.1,8.8.8.8",
        },
        monkeypatch,
    )

    mapping = writes[0][1]
    assert mapping["NETMON_SNMP_COMMUNITIES"] == "public,private"
    assert mapping["NETMON_WIFI_JOIN_SSID"] == "District Guest WiFi"
    assert mapping["NETMON_WIFI_JOIN_SECRET"] == "p@ss word!#$"


# --- layer 2: the writer itself refuses -------------------------------------


@pytest.mark.parametrize("bad", ["\n", "\r", "\x00"])
def test_update_env_file_never_writes_a_multi_line_value(bad, tmp_path, monkeypatch) -> None:
    env = tmp_path / "netmon.env"
    env.write_text("NETMON_A=1\nKEEP=x\n")
    wrote: list[str] = []
    monkeypatch.setattr(
        checkin, "_write_file_atomic", lambda p, payload, mode=0o600: wrote.append(payload)
    )

    with pytest.raises(ValueError, match="refusing to write NETMON_A"):
        checkin._update_env_file(env, {"NETMON_A": f"2{bad}POSTGRES_PASSWORD=owned"})

    assert wrote == []                       # nothing reached the writer at all
    assert env.read_text() == "NETMON_A=1\nKEEP=x\n"   # file untouched on disk


def test_update_env_file_emits_exactly_one_line_per_key(tmp_path, monkeypatch) -> None:
    env = tmp_path / "netmon.env"
    env.write_text("NETMON_A=1\nKEEP=x\n")
    wrote: list[str] = []
    monkeypatch.setattr(
        checkin, "_write_file_atomic", lambda p, payload, mode=0o600: wrote.append(payload)
    )

    checkin._update_env_file(env, {"NETMON_A": "2", "NETMON_B": "3"})

    payload = wrote[0]
    assert payload == "NETMON_A=2\nKEEP=x\nNETMON_B=3\n"
    # One key per line, and no key appears twice (an injected line would do both).
    keys = [
        m.group(1)
        for m in (re.match(r"([A-Z0-9_]+)=", line) for line in payload.splitlines())
        if m
    ]
    assert keys == ["NETMON_A", "KEEP", "NETMON_B"]
    assert len(keys) == len(set(keys))


# --- drift guard -------------------------------------------------------------


def test_every_pushed_string_in_apply_config_is_validated() -> None:
    """A new dashboard-pushed string must be added to _CONFIG_STR_KEYS.

    Without this, the next `mapping[...] = str(data.get("new_field"))` reopens the
    injection quietly — every other test here would still pass.
    """
    source = Path(checkin.__file__).read_text(encoding="utf-8")
    body = source[source.index("def _apply_config") : source.index("def _local_net")]
    pushed = {
        m.group(1) or m.group(2)
        for m in re.finditer(
            r'str\(\s*data\.get\("([a-z0-9_]+)"\)|str\(\s*data\["([a-z0-9_]+)"\]', body
        )
    }
    # Safe by construction: normalized to a fixed set, or stripped to a character
    # class, before reaching the mapping — neither can carry a control character.
    normalized = {
        "bundle_transport",
        "snmp_topology_scope",
        "update_channel",
        "wifi_join_auth",
        "trunk_vlans",
        "wifi_join_quiet",
    }

    assert not (pushed - normalized - set(checkin._CONFIG_STR_KEYS))
    # And nothing stale: every declared key is still pushed by _apply_config.
    assert not (set(checkin._CONFIG_STR_KEYS) - pushed)


# --- command-queue argv / record guards --------------------------------------


def test_iperf_server_option_injection_is_refused(monkeypatch) -> None:
    """The command queue's `args.server` had no validation at all.

    `run_iperf` is the choke point: both the pushed NETMON_IPERF_SERVER and the
    on-demand command reach it, so the guard lives there rather than at one caller.
    """
    from collector import iperf

    ran: list[list[str]] = []
    monkeypatch.setattr(
        iperf.subprocess, "run", lambda cmd, **kw: ran.append(cmd) or pytest.fail("ran")
    )

    for bad in ("--logfile=/etc/passwd", "-J", "host with space", "a\tb"):
        res = iperf.run_iperf(server=bad)
        assert res == {"ok": False, "error": "invalid iperf server"}
    assert ran == []


def test_console_sid_record_injection_is_refused(tmp_path, monkeypatch) -> None:
    """A sid carrying the record separators would arm extra HOST-ROOT shells.

    Full-shell mode appends "<sid>\t<nonce>\n" for netmon-console-poll.sh, which
    turns each line into a root `systemd-run` PTY server. An injected line would
    carry a nonce the PUSHER chose rather than the one this box generated.
    """
    req = tmp_path / "host-console-request"
    monkeypatch.setattr(checkin, "HOST_CONSOLE_REQUEST_FILE", req)
    spawned: list = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawned.append(a))

    for bad_sid in (
        "good\tDEADBEEF\nevil",     # a whole extra record, attacker-chosen nonce
        "good\nevil",
        "../../etc/passwd",
        "a/b",
        "x" * 129,
        "sid with space",
        "",
    ):
        status, result = checkin._spawn_console_session(
            {"broker": "wss://b.example/ws", "token": "t", "sid": bad_sid, "mode": "full"}
        )
        assert status == "failed", bad_sid
        assert result["error"] in ("invalid sid", "missing broker/token/sid")

    assert not req.exists()   # nothing was ever appended
    assert spawned == []      # and no session process was started


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("broker", "http://b.example"),      # not a websocket scheme
        ("broker", "wss://b.example/ws#x"),  # fragment truncates the query
        ("broker", "wss://b.example/ w"),
        ("token", "t&role=admin"),           # forges a following query parameter
        ("token", "t#x"),
        ("token", "t v"),
    ],
)
def test_console_broker_and_token_are_validated(field, value, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(checkin, "HOST_CONSOLE_REQUEST_FILE", tmp_path / "req")
    spawned: list = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawned.append(a))

    args = {"broker": "wss://b.example/ws", "token": "t", "sid": "abc123", "mode": "full"}
    args[field] = value

    status, result = checkin._spawn_console_session(args)

    assert status == "failed"
    assert result["error"] == f"invalid {field}"
    assert spawned == []


def test_console_session_still_starts_for_a_normal_request(tmp_path, monkeypatch) -> None:
    # Positive control: the guards must not break the real console feature.
    req = tmp_path / "host-console-request"
    monkeypatch.setattr(checkin, "HOST_CONSOLE_REQUEST_FILE", req)
    seen: dict = {}

    def fake_popen(cmd, **kw):
        seen["cmd"] = cmd
        seen["env"] = kw.get("env") or {}
        return object()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    for sid in ("3f9a1c2e-7b4d-4a11-9f00-1a2b3c4d5e6f", "AbC_-.09", "deadbeef" * 4):
        status, result = checkin._spawn_console_session(
            {"broker": "wss://b.example/ws", "token": "tok.en-1", "sid": sid, "mode": "full"}
        )
        assert (status, result["started"]) == ("done", True)
        assert "--sid" in seen["cmd"] and sid in seen["cmd"]
        assert seen["env"]["NETMON_CONSOLE_TOKEN"] == "tok.en-1"

    # Exactly one record per session, each a single line ending in a real newline.
    lines = req.read_text().splitlines()
    assert len(lines) == 3
    assert all(len(line.split("\t")) == 2 for line in lines)
