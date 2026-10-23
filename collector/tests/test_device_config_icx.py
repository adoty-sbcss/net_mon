"""Ruckus / Brocade ICX (FastIron) config backup: fetch path + on-box redaction.

The failure that matters is a secret leaving the LAN. ICX makes that easy to get
wrong in two ways the other vendors don't:

* It prints secrets as `<type-digit> <value>` — `8 $1$salt$hash` for local and
  super-user passwords, `2 $<base64>` for SNMP communities and RADIUS/TACACS/OSPF
  keys. Type 2 is a REVERSIBLE encoding (public decoders exist) with no second `$`,
  so the cross-vendor `$n$` hash catch-all never sees it, and Cisco-shaped patterns
  mask the DIGIT and leave the value.
* `show running-config` only exists in privileged EXEC, so the driver has to enter
  enable mode — and the stock netmiko driver retries a rejected enable three times
  per switch, invisibly to the auth breaker.

⚠️ FIXTURE PROVENANCE. The configs below are written to the FastIron 08.0.x
documented grammar and to the line shapes published in Ruckus's command reference;
they are NOT captures from a production device (no district has an ICX enrolled as
of 2026-10-21). Every secret VALUE is fabricated — this repo is public. Re-check
against a real `show running-config` the first time an ICX is enrolled.

The leak assertions deliberately do not rely only on the list of secrets the
fixture author knew about (a test written from the same blocklist as the patterns
shares its blind spot): every test also asserts that NO `$`-encoded blob of any
shape survives outside a redaction token.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from collector.discovery import device_config
from collector.discovery.device_config import (
    _PLATFORM_CMDS,
    _redact_config,
    _strip_icx_preamble,
)

_KEY = b"deterministic-test-key-not-a-real-box-key"

# Fabricated secret values, as the ICX would print them.
_SUPER_HASH = "$1$eqT..$H9yzfaxfzdBi0WLYbMSP3/"
_ADMIN_HASH = "$1$Gx/..$dfcQ6uEBsx1aZcADuxUcp1"
_NETMON_HASH = "$1$Aa1..$Bb2Cc3Dd4Ee5Ff6Gg7Hh8I."
_RO_PW_HASH = "$1$Zz9..$Yy8Xx7Ww6Vv5Uu4Tt3Ss2R/"
_COMM_RO = "$U2kyXj1kOSE="
_COMM_RW = "$Uj0oPSI9ZmtQ"
_TRAP_COMM = "$MlVzZCFAbmc="
_TACACS_KEY = "$Z1I/WEJvRSFm"
_RADIUS_KEY = "$MlVzZCFAbg=="
_RADIUS_HOST_KEY = "$bmVvLnJhZDE="
_OSPF_KEY = "$b3NwZmtleTE="
_OSPF_MD5 = "$bWQ1a2V5Mjc="
_VRRP_KEY = "$dnJycGtleTk="
_NTP_KEY = "$bnRwa2V5MDE="
_SNMPV3_AUTH = "4f6e9a1b2c3d4e5f60718293a4b5c6d7"
_SNMPV3_PRIV = "9a8b7c6d5e4f30211203f4e5d6c7b8a9"
_MAC_OVERRIDE = "Summer24"

ICX_RUNNING = f"""Current configuration:
!
ver 08.0.95dT213
!
stack unit 1
  module 1 icx7150-48p-poe-port-management-module
  module 2 icx7150-2-copper-port-2g-module
  module 3 icx7150-4-sfp-plus-port-40g-module
!
global-stp
!
vlan 1 name DEFAULT-VLAN by port
!
vlan 10 name Data by port
 tagged ethe 1/3/1
 untagged ethe 1/1/1 to 1/1/46
 spanning-tree 802-1w
!
vlan 99 name Mgmt by port
 tagged ethe 1/3/1
 router-interface ve 99
!
aaa authentication enable default local
aaa authentication login default tacacs+ local
aaa authentication login privilege-mode
aaa authorization exec default tacacs+ none
enable super-user-password 8 {_SUPER_HASH}
enable read-only-password 8 {_RO_PW_HASH}
enable aaa console
enable password-display
hostname ICX7150-IDF1
ip dhcp-client disable
ip dns server-address 10.0.0.10
ip route 0.0.0.0/0 10.0.99.1
!
username admin password 8 {_ADMIN_HASH}
username netmon privilege 5 password 8 {_NETMON_HASH}
!
tacacs-server host 10.0.0.20
tacacs-server key 2 {_TACACS_KEY}
radius-server host 10.0.0.21 auth-port 1812 acct-port 1813 default key 2 {_RADIUS_HOST_KEY} dot1x mac-auth
radius-server key 2 {_RADIUS_KEY}
!
snmp-server community 2 {_COMM_RO} ro
snmp-server community 2 {_COMM_RW} rw
snmp-server host 10.0.0.30 version v2c 2 {_TRAP_COMM} port 162
snmp-server group v3group v3 priv read all
snmp-server user netmonv3 v3group v3 encrypted auth sha {_SNMPV3_AUTH} priv encrypted aes {_SNMPV3_PRIV}
snmp-server location IDF1
!
clock timezone us Pacific
!
ntp
 authenticate
 authentication-key key-id 1 sha1 2 {_NTP_KEY}
 server 10.0.0.40 key 1
!
web-management https
!
manager registrar
!
mac-authentication password-format xxxx.xxxx.xxxx upper-case
mac-authentication password-override {_MAC_OVERRIDE}
!
ip ssh  authentication-retries 2
!
interface ethernet 1/1/1
 dual-mode 10
 inline power
!
interface ve 99
 ip address 10.0.99.2 255.255.255.0
 ip ospf area 0
 ip ospf authentication-key 2 {_OSPF_KEY}
 ip ospf md5-authentication key-id 1 key 2 {_OSPF_MD5}
 ip vrrp-extended vrid 1
  backup priority 100
  ip-address 10.0.99.1
  ip vrrp-extended auth-type md5-auth 2 {_VRRP_KEY}
  activate
!
router ospf
 area 0
!
end
"""

ICX_STARTUP = "!\nStartup-config data location is flash memory\n!\nStartup configuration:\n" + ICX_RUNNING.split(
    "Current configuration:\n", 1
)[1]

# The same switch with `no service password-encryption`: secrets in the clear.
ICX_PLAINTEXT = """ver 08.0.95dT213
enable super-user-password Sup3rUs3rPw!
enable port-config-password P0rtCfgPw
enable telnet password T3lnetPw9
username netmon privilege 5 password 0 N3tm0nR0
snmp-server community 0 Pl4inC0mm ro
snmp-server community Bare5Comm rw
snmp-server host 10.0.0.30 version v1 TrapC0mm
radius-server key 0 Rad1usKey
tacacs-server key TacKey77
end
"""
_PLAIN_SECRETS = [
    "Sup3rUs3rPw!", "P0rtCfgPw", "T3lnetPw9", "N3tm0nR0", "Pl4inC0mm",
    "Bare5Comm", "TrapC0mm", "Rad1usKey", "TacKey77",
]

_ENCODED_SECRETS = [
    _SUPER_HASH, _ADMIN_HASH, _NETMON_HASH, _RO_PW_HASH, _COMM_RO, _COMM_RW, _TRAP_COMM,
    _TACACS_KEY, _RADIUS_KEY, _RADIUS_HOST_KEY, _OSPF_KEY, _OSPF_MD5, _VRRP_KEY, _NTP_KEY,
    _SNMPV3_AUTH, _SNMPV3_PRIV, _MAC_OVERRIDE,
]

_TOKEN_RE = re.compile(r"<REDACTED:[^>\s]*>")
#: Blocklist-independent oracle: ANY `$`-led blob is a hash or an ICX type-2 value.
_ANY_DOLLAR_BLOB = re.compile(r"\$[A-Za-z0-9+/=.$]{3,}")


def _redact(text: str, platform: str | None = "ruckus_fastiron") -> tuple[str, int]:
    out, suspects = _redact_config(text, _KEY, platform)
    assert out is not None
    return out, suspects


def _assert_no_dollar_blob(out: str) -> None:
    leftover = _ANY_DOLLAR_BLOB.findall(_TOKEN_RE.sub(" ", out))
    assert not leftover, f"a $-encoded value survived redaction: {leftover}"


# --------------------------------------------------------------------------------------
# Redaction — encoded (default) display form
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("secret", _ENCODED_SECRETS)
def test_icx_encoded_secret_never_leaves_the_lan(secret: str) -> None:
    out, _ = _redact(ICX_RUNNING)
    assert secret not in out, f"ICX secret leaked: {secret}"


def test_icx_running_config_has_no_dollar_blob_and_no_backstop_reliance() -> None:
    out, suspects = _redact(ICX_RUNNING)
    _assert_no_dollar_blob(out)
    # Every secret is claimed by a NAMED pattern, not left to the backstop: a suspect
    # here means a grammar gap that only the safety net is covering.
    assert suspects == 0, f"backstop had to catch {suspects} ICX secret(s): {out}"


def test_icx_startup_config_is_redacted_too() -> None:
    out, _ = _redact(ICX_STARTUP)
    _assert_no_dollar_blob(out)
    for secret in _ENCODED_SECRETS:
        assert secret not in out


@pytest.mark.parametrize(
    "line, secret",
    [
        # Each ICX shape alone, so a regression names the exact command.
        (f"enable super-user-password 8 {_SUPER_HASH}", _SUPER_HASH),
        (f"enable read-only-password 8 {_RO_PW_HASH}", _RO_PW_HASH),
        (f"username netmon privilege 5 password 8 {_NETMON_HASH}", _NETMON_HASH),
        (f"snmp-server community 2 {_COMM_RO} ro", _COMM_RO),
        (f"snmp-server host 10.0.0.30 version v2c 2 {_TRAP_COMM} port 162", _TRAP_COMM),
        (f"tacacs-server key 2 {_TACACS_KEY}", _TACACS_KEY),
        (f"radius-server host 10.0.0.21 auth-port 1812 default key 2 {_RADIUS_HOST_KEY} dot1x", _RADIUS_HOST_KEY),
        (f" ip ospf authentication-key 2 {_OSPF_KEY}", _OSPF_KEY),
        (f" ip ospf md5-authentication key-id 1 key 2 {_OSPF_MD5}", _OSPF_MD5),
        (f"  ip vrrp-extended auth-type md5-auth 2 {_VRRP_KEY}", _VRRP_KEY),
        (f" authentication-key key-id 1 sha1 2 {_NTP_KEY}", _NTP_KEY),
        (f"snmp-server user u1 g1 v3 encrypted auth md5 {_SNMPV3_AUTH} priv encrypted des {_SNMPV3_PRIV}", _SNMPV3_PRIV),
        (f"snmp-server user u1 g1 v3 encrypted auth md5 {_SNMPV3_AUTH} priv encrypted des {_SNMPV3_PRIV}", _SNMPV3_AUTH),
        (f"mac-authentication password-override {_MAC_OVERRIDE}", _MAC_OVERRIDE),
        # Short plaintext forms the backstop cannot catch (not credential-shaped).
        (" ip ospf authentication plain-text mystring", "mystring"),
        (" area 1 virtual-link 20.1.1.1 authentication plain-text vlpw1", "vlpw1"),
        (" vsrp-aware vrid 3 simple-text-auth pri-key", "pri-key"),
        ("  ip vrrp auth-type simple-text-auth vrrp1", "vrrp1"),
        (" auth-mode passcode static 1234", "1234"),
        ("radius-client coa host 10.0.0.5 key CoaPlain99", "CoaPlain99"),
        (" ip ospf authentication md5 key-id 10 key mykey1", "mykey1"),
        (" ipv6 ospf authentication hmac-sha-256 key-id 10 key mykey2", "mykey2"),
        (" area 1 virtual-link 192.0.2.1 authentication hmac-sha-1 key-id 10 key mykey3", "mykey3"),
        ("  password kcpw4", "kcpw4"),
        ("radius-client coa host 10.0.0.5 key 2 $Y29ha2V5MQ==", "$Y29ha2V5MQ=="),
        # Unencrypted SNMPv3 display form: `priv des <pw>` used to mask `des`.
        ("snmp-server user u1 g1 v3 auth md5 Auth1Pass9 priv des Priv1Pass9", "Priv1Pass9"),
        ("snmp-server user u1 g1 v3 auth md5 Auth1Pass9 priv des Priv1Pass9", "Auth1Pass9"),
        # A command this file has never heard of, in the type-2 form: the
        # `<digit> $blob` catch-all must still claim it.
        ("some-future-command secret-thing 2 $ZnV0dXJla2V5", "$ZnV0dXJla2V5"),
    ],
)
def test_icx_secret_shape_is_masked(line: str, secret: str) -> None:
    out, _ = _redact(line)
    assert secret not in out, f"leaked: {out}"
    _assert_no_dollar_blob(out)


@pytest.mark.parametrize("secret", _PLAIN_SECRETS)
def test_icx_plaintext_secrets_never_leave_the_lan(secret: str) -> None:
    out, _ = _redact(ICX_PLAINTEXT)
    assert secret not in out, f"plaintext ICX secret leaked: {secret}"


@pytest.mark.parametrize(
    "line",
    [
        "password resets go through IT",
        "\npassword resets go through IT",
        " port-name authentication md5 key-id 10 key example",
        " port-name ospf authentication plain-text note",
    ],
)
def test_icx_free_text_that_looks_like_auth_grammar_is_kept(line: str) -> None:
    out, _ = _redact(line)
    assert out == line


def test_icx_dot_masked_display_is_harmless() -> None:
    # Older FastIron prints `.....` instead of the value; masking it is fine, and the
    # command must survive.
    out, _ = _redact("snmp-server community ..... ro\nusername admin password .....")
    assert out.startswith("snmp-server community ")
    assert "username admin password " in out


@pytest.mark.parametrize(
    "line",
    [
        "enable password-display",
        "enable aaa console",
        "aaa authentication login privilege-mode",
        "aaa authentication enable default local",
        "mac-authentication password-format xxxx.xxxx.xxxx upper-case",
        "hostname ICX7150-IDF1",
        "ver 08.0.95dT213",
        "vlan 10 name Data by port",
        " untagged ethe 1/1/1 to 1/1/46",
        " server 10.0.0.40 key 1",
        "ip route 0.0.0.0/0 10.0.99.1",
        "snmp-server group v3group v3 priv read all",
    ],
)
def test_icx_non_secret_lines_pass_through_unchanged(line: str) -> None:
    out, suspects = _redact(line)
    assert out == line
    assert suspects == 0


def test_icx_view_name_over_mask_stays_visible() -> None:
    # The same deliberate trade as test_known_over_mask_of_mixed_case_trailing_identifiers
    # in test_redact_secrets.py: a digit-bearing view name is shaped like a community,
    # so it is masked as a SUSPECT (loud), never silently kept or silently dropped.
    out, suspects = _redact(f"snmp-server community 2 {_COMM_RO} ro view v1default")
    assert _COMM_RO not in out
    assert out.endswith(" ro view <REDACTED:suspect>"), out
    assert suspects == 1


def test_icx_trap_host_and_ntp_keep_their_keywords() -> None:
    out, _ = _redact(f"snmp-server host 10.0.0.30 version v2c 2 {_TRAP_COMM} port 162")
    # The type digit is masked too (the Cisco host pattern takes it as the community):
    # harmless over-mask. What matters is the keyword and the port survive.
    assert out.startswith("snmp-server host 10.0.0.30 version v2c <REDACTED:"), out
    assert out.endswith(" port 162") and _TRAP_COMM not in out, out
    out, _ = _redact(f" authentication-key key-id 1 sha1 2 {_NTP_KEY}")
    assert out.startswith(" authentication-key key-id 1 sha1 2 <REDACTED:"), out


# --------------------------------------------------------------------------------------
# The ICX patterns must not reach other vendors (a changed redaction = a phantom config
# change on every existing device's next backup).
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "Room 5 $100",
        " description Room 2 $5 per hour kiosk",
        "snmp-server location Bldg 2 $Annex",
        " ip ospf authentication plain-text-mode-note",
        "logging host 10.0.0.1 transport udp port 2 $foo",
    ],
)
@pytest.mark.parametrize("platform", [None, "cisco_ios", "aruba_aoscx", "juniper_junos", "extreme_exos"])
def test_icx_only_patterns_do_not_touch_other_platforms(line: str, platform: str | None) -> None:
    out, _ = _redact(line, platform)
    assert out == line


def test_platform_argument_defaults_to_the_pre_icx_behaviour() -> None:
    text = "snmp-server community 0 ro\nRoom 5 $100\nhostname x"
    assert _redact_config(text, _KEY) == _redact_config(text, _KEY, "cisco_ios")
    assert "Room 5 $100" in (_redact_config(text, _KEY)[0] or "")


def test_icx_keeps_the_access_mode_and_trap_port() -> None:
    out, _ = _redact(f"snmp-server community 2 {_COMM_RW} rw\nsnmp-server host 10.0.0.30 version v2c 2 {_TRAP_COMM} port 162")
    lines = out.split("\n")
    assert lines[0].endswith(" rw"), lines[0]
    assert lines[1].endswith(" port 162"), lines[1]


# --------------------------------------------------------------------------------------
# Platform table + preamble
# --------------------------------------------------------------------------------------


def test_icx_platform_commands() -> None:
    assert _PLATFORM_CMDS["ruckus_fastiron"] == {
        "running": "show running-config",
        "startup": "show configuration",
    }


def test_icx_preamble_strip_makes_an_in_sync_switch_read_in_sync() -> None:
    run = _strip_icx_preamble(ICX_RUNNING)
    start = _strip_icx_preamble(ICX_STARTUP)
    assert run is not None and run.startswith("ver 08.0.95dT213")
    assert run == start


def test_icx_preamble_strip_leaves_unrecognised_output_alone() -> None:
    odd = "Some unexpected header\nhostname x\nend\n"
    assert _strip_icx_preamble(odd) == odd
    assert _strip_icx_preamble(None) is None
    # A `ver` line deep in the text is not a preamble boundary.
    deep = "\n".join(f"line {i}" for i in range(30)) + "\nver 08.0.95\n"
    assert _strip_icx_preamble(deep) == deep


# --------------------------------------------------------------------------------------
# Enable: exactly ONE attempt, and a rejection is counted as auth
# --------------------------------------------------------------------------------------


class _FakeChannel:
    """A scripted FastIron transcript for the ICX enable() override — no socket.

    `script` maps what the override WRITES to the chunks the switch then sends, one
    chunk per read_channel_timing() call (an Exception chunk is raised). Writing
    anything the script does not expect fails the test, as does the RETURN that
    check_enable_mode() would send once `enable` is in flight.
    """

    def __init__(
        self,
        script: dict[str, list[str | Exception | None]],
        *,
        start_enabled: bool = False,
        base_prompt: str = "SSH@ICX7150-IDF1",
    ) -> None:
        self.script = {k: list(v) for k, v in script.items()}
        self.writes: list[str] = []
        self.pending: list[str | Exception | None] = []
        self.enabled = start_enabled
        self.base_prompt = base_prompt
        self.silent_until = 0.0

    def install(self, obj: Any) -> None:
        obj.username = "netmon"
        obj.secret = "the-ssh-password"
        obj.base_prompt = self.base_prompt
        obj.write_channel = self._write
        obj.normalize_cmd = lambda cmd: cmd + "\n"
        obj.read_until_prompt_or_pattern = lambda **kw: pytest.fail("stream-matched")
        obj.read_until_prompt = lambda **kw: pytest.fail("waited on the prompt alone")
        obj.read_channel = self._read_channel
        obj.read_channel_timing = lambda **kw: pytest.fail(
            "read_channel_timing() raises on a silent channel; it cannot detect a waiting prompt")
        obj.check_enable_mode = self._check

    def _write(self, data: str) -> None:
        if data not in self.script:
            pytest.fail(f"unexpected write {data!r} (after {self.writes})")
        self.writes.append(data)
        self.pending = self.script.pop(data)

    def _read_channel(self) -> str:
        # Real channel semantics: "" when no bytes are waiting. A None chunk is a
        # pause longer than the quiet window (the switch goes silent mid-output).
        if _CLOCK.monotonic() < self.silent_until:
            return ""
        if not self.pending:
            return ""
        nxt = self.pending.pop(0)
        if nxt is None:
            self.silent_until = _CLOCK.monotonic() + 3 * device_config._ICX_QUIET_SEC
            return ""
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def _check(self, *a: Any, **kw: Any) -> bool:
        if self.writes:
            pytest.fail("check_enable_mode() after `enable` sends a RETURN")
        return self.enabled


def _icx_instance(chan: _FakeChannel) -> Any:
    cls = device_config._icx_connection_class()
    obj = object.__new__(cls)
    chan.install(obj)
    return obj


class _VirtualClock:
    """Deterministic time for the enable exchange: sleep() advances monotonic().

    Real sleeps made the pause cases nondeterministic (Windows sleep granularity is
    ~15 ms, so a "pause" could fall anywhere) — a timing test that can pass for the
    wrong reason proves nothing.
    """

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, dt: float) -> None:
        self.now += dt


_CLOCK = _VirtualClock()


@pytest.fixture(autouse=True)
def _virtual_icx_time(monkeypatch: pytest.MonkeyPatch) -> None:
    import types

    monkeypatch.setattr(device_config, "time", types.SimpleNamespace(
        monotonic=_CLOCK.monotonic, sleep=_CLOCK.sleep))


_PRIV = "SSH@ICX7150-IDF1#"
_UNPRIV = "SSH@ICX7150-IDF1>"
_EN, _USER, _PW = "enable\n", "netmon\n", "the-ssh-password\n"
_BAD = "Error - Incorrect username or password.\n"


def test_icx_a_waiting_password_prompt_is_answered_on_a_silent_channel() -> None:
    # Codex N12: the switch prints "Password:" and then sends NOTHING while it waits.
    # That silence must read as "waiting", and get exactly one answer.
    chan = _FakeChannel({_EN: ["Pass", "word:"], _PW: [_PRIV]})
    _icx_instance(chan).enable()
    assert chan.writes == [_EN, _PW]


def test_icx_a_long_pause_on_a_credential_word_after_the_secret_is_a_refusal() -> None:
    # Indistinguishable from a real re-prompt, so it must take the SAFE branch:
    # refuse (counted), never answer a second time.
    chan = _FakeChannel({_EN: ["Password:"], _PW: ["Login:", None, " use your district account\n", _PRIV]})
    with pytest.raises(device_config.IcxEnableRejected):
        _icx_instance(chan).enable()
    assert chan.writes == [_EN, _PW]


def test_icx_enable_skipped_when_already_privileged() -> None:
    chan = _FakeChannel({}, start_enabled=True)
    _icx_instance(chan).enable()
    assert chan.writes == [], "privilege-mode login must send nothing"


def test_icx_enable_answers_username_then_password_once() -> None:
    chan = _FakeChannel({_EN: ["User Name:"], _USER: ["Password:"], _PW: [_PRIV]})
    obj = _icx_instance(chan)
    obj.enable()
    assert chan.writes == [_EN, _USER, _PW]
    assert obj._icx_unresolved is False


def test_icx_enable_password_only() -> None:
    chan = _FakeChannel({_EN: ["Password:"], _PW: [_PRIV]})
    _icx_instance(chan).enable()
    assert chan.writes == [_EN, _PW]


@pytest.mark.parametrize(
    "after_pw",
    [
        [_BAD + _UNPRIV],
        [_BAD + "Password:"],
        ["SSH@ICX7150-IDF1: Error - RADIUS authentication failed\nPassword:"],
        ["User Name:"],
        ["SSH@ICX7150-IDF1: Error - RADIUS rejected\nPolicy #17 denies SSH@ICX7150-IDF1 access\n" + _UNPRIV],
        [None, _BAD + _UNPRIV],  # slow AAA
        ["Access denied for SSH@ICX7150-IDF1#", None, "\nPassword:"],
        ["Access denied for SSH@ICX7150-IDF1#\nPassword:"],
        [TimeoutError("read timeout")],
    ],
)
def test_icx_enable_failures_are_one_credential_then_rejected(after_pw: list[str | Exception]) -> None:
    chan = _FakeChannel({_EN: ["User Name:"], _USER: ["Password:"], _PW: after_pw})
    obj = _icx_instance(chan)
    with pytest.raises(device_config.IcxEnableRejected):
        obj.enable()
    assert chan.writes == [_EN, _USER, _PW], "exactly one credential, nothing after it"
    if obj._icx_unresolved:  # still at a credential prompt: cleanup must stay silent
        obj.cleanup()  # an unexpected write fails the test
    else:
        assert after_pw[-1] == _BAD + _UNPRIV or str(after_pw[-1]).endswith('>')
    assert chan.writes == [_EN, _USER, _PW]


@pytest.mark.parametrize(
    "after_pw, prompt",
    [
        (["Authorized login only.\n" + _PRIV], "SSH@ICX7150-IDF1"),
        (["Report errors to IT.\n" + _PRIV], "SSH@ICX7150-IDF1"),
        (["Login: use your district account\n" + _PRIV], "SSH@ICX7150-IDF1"),
        (["Notice: Login: use your district account\nPassword: never share it\n" + _PRIV], "SSH@ICX7150-IDF1"),
        (["Help with incorrect password: call IT\n" + _PRIV], "SSH@ICX7150-IDF1"),
        (["Login:", " use your district account\n", _PRIV], "SSH@ICX7150-IDF1"),
        ([None, _PRIV], "SSH@ICX7150-IDF1"),  # slow AAA: silence, then the prompt
        (["SSH@error-switch#"], "SSH@error-switch"),
        (["SSH@login-switch#"], "SSH@login-switch"),
        (["SSH@ICX7150-IDF1#\x1b[K"], "SSH@ICX7150-IDF1"),
        (["SSH@ICX7150-IDF1#\x1b[", None, "K"], "SSH@ICX7150-IDF1"),
        (["\r\nSSH@ICX7150-IDF1# \r"], "SSH@ICX7150-IDF1"),
        (["\x1b[?25hSSH@sw#"], "\x1b[?25hSSH@sw"),
    ],
)
def test_icx_enable_success_is_decided_by_the_final_prompt(after_pw: list[str | Exception], prompt: str) -> None:
    chan = _FakeChannel({_EN: ["Password:"], _PW: after_pw}, base_prompt=prompt)
    obj = _icx_instance(chan)
    obj.enable()
    assert chan.writes == [_EN, _PW]
    assert obj._icx_unresolved is False


@pytest.mark.parametrize(
    "after_enable, prompt",
    [
        # Immediate success, hostname containing "login" (AAA method `none`).
        (["SSH@login-switch#"], "SSH@login-switch"),
        # No super-user password: warning, then privileged.
        (["No password has been assigned yet...\nSSH@ICX7150-IDF1#"], "SSH@ICX7150-IDF1"),
        (["\x1b[?25hSSH@sw#"], "\x1b[?25hSSH@sw"),
    ],
)
def test_icx_enable_granted_without_any_credential(after_enable: list[str | Exception], prompt: str) -> None:
    chan = _FakeChannel({_EN: after_enable}, base_prompt=prompt)
    _icx_instance(chan).enable()
    assert chan.writes == [_EN], "nothing may be typed when no credential was asked for"


def test_icx_text_containing_the_prompt_above_a_password_prompt_is_not_a_prompt() -> None:
    # Codex N9: "Notice: SSH@sw" above "Password:" disarmed the guard and sent RETURN.
    chan = _FakeChannel({_EN: ["Notice: SSH@sw\nPassword:"], _PW: ["SSH@sw#"]}, base_prompt="SSH@sw")
    _icx_instance(chan).enable()
    assert chan.writes == [_EN, _PW]


@pytest.mark.parametrize(
    "after_enable",
    [
        ["No password has been assigned"],  # nothing more: never settles
        ["No password has been assigned yet...\n" + _UNPRIV],
        [_UNPRIV],
    ],
)
def test_icx_enable_with_no_path_is_no_access_without_a_credential(
    after_enable: list[str | Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(device_config, "_ICX_ENABLE_SETTLE_SEC", 0.05)
    chan = _FakeChannel({_EN: after_enable})
    with pytest.raises((device_config.IcxNoEnableAccess, device_config.IcxEnableRejected)) as ei:
        _icx_instance(chan).enable()
    if after_enable[-1].endswith(">"):
        assert isinstance(ei.value, device_config.IcxNoEnableAccess)
    assert chan.writes == [_EN]


def test_icx_cleanup_writes_nothing_if_the_first_enable_read_fails() -> None:
    chan = _FakeChannel({_EN: [TimeoutError("prompt arrived after the read deadline")]})
    obj = _icx_instance(chan)
    with pytest.raises(device_config.IcxEnableRejected):
        obj.enable()
    assert obj._icx_unresolved is True
    obj.cleanup()
    assert chan.writes == [_EN]


def test_icx_enable_uppercase_prompts_are_recognised() -> None:
    chan = _FakeChannel({_EN: ["USER NAME:"], _USER: ["PASSWORD:"], _PW: [_PRIV]})
    _icx_instance(chan).enable()
    assert chan.writes == [_EN, _USER, _PW]


def test_icx_enable_that_never_settles_is_a_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(device_config, "_ICX_ENABLE_SETTLE_SEC", 0.05)
    chan = _FakeChannel({_EN: ["Password:"], _PW: ["banner text\n"] * 1000})
    with pytest.raises(device_config.IcxEnableRejected):
        _icx_instance(chan).enable()


def test_netmiko_channel_logging_is_kept_above_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    import logging

    class _Stub:
        def __init__(self, **kw: Any) -> None:
            pass

    monkeypatch.setattr(device_config, "_icx_connection_class", lambda: _Stub)
    logging.getLogger("netmiko").setLevel(logging.NOTSET)
    device_config._connect("ruckus_fastiron", host="h", password="p")
    assert not logging.getLogger("netmiko").isEnabledFor(logging.DEBUG)


# --------------------------------------------------------------------------------------
# _fetch_one with the connection stubbed
# --------------------------------------------------------------------------------------


class _FakeConn:
    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        self.sent: list[str] = []

    def send_command(self, cmd: str, read_timeout: int = 0) -> str:
        self.sent.append(cmd)
        return self.outputs[cmd]

    def disconnect(self) -> None:
        pass


_TARGET = {"target_id": 7, "host": "10.0.99.2", "label": "IDF1", "platform": "ruckus_fastiron",
           "ssh_user": "netmon", "ssh_password": "the-ssh-password"}


def test_fetch_one_icx_backs_up_redacted_and_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConn({"show running-config": ICX_RUNNING, "show configuration": ICX_STARTUP})
    seen: dict[str, Any] = {}

    def fake_connect(platform: str, **kw: Any) -> _FakeConn:
        seen["platform"] = platform
        seen.update(kw)
        return conn

    monkeypatch.setattr(device_config, "_connect", fake_connect)
    res = device_config._fetch_one(_TARGET, key=_KEY, ssh_timeout=5)
    assert res["status"] == "ok", res
    assert seen["platform"] == "ruckus_fastiron"
    assert conn.sent == ["show running-config", "show configuration"]
    for text in (res["running_config"], res["startup_config"]):
        assert text.startswith("ver 08.0.95dT213")
        _assert_no_dollar_blob(text)
        for secret in _ENCODED_SECRETS:
            assert secret not in text
    assert res["running_config"] == res["startup_config"], "in-sync ICX must not read as drifted"
    assert res["redaction_suspects"] == 0


def test_fetch_one_reports_suspects_per_config(monkeypatch: pytest.MonkeyPatch) -> None:
    # The dashboard stored the running + startup total on BOTH snapshots, so every
    # device page claimed twice the masked lines. Per-kind counts fix that; the total
    # stays for dashboards that predate them. (Lives here for _FakeConn; not ICX.)
    running = "hostname sw1\nauthentication abcdefghijklmnop\n"
    startup = "hostname sw1\n"
    conn = _FakeConn({"show running-config": running, "show startup-config": startup})
    monkeypatch.setattr(device_config, "_connect", lambda platform, **kw: conn)
    res = device_config._fetch_one({**_TARGET, "platform": "cisco_ios"}, key=_KEY, ssh_timeout=5)
    assert res["status"] == "ok", res
    assert res["redaction_suspects_running"] == 1
    assert res["redaction_suspects_startup"] == 0
    assert res["redaction_suspects"] == 1


def test_fetch_one_icx_enable_rejection_is_auth_and_trips_the_breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def fake_connect(platform: str, **kw: Any) -> None:
        attempts.append(kw["host"])
        raise device_config.IcxEnableRejected("enable refused")

    monkeypatch.setattr(device_config, "_connect", fake_connect)
    monkeypatch.setattr(device_config.ssh_diag, "tcp_ping", lambda *a, **kw: pytest.fail("no ping after sign-in"))
    monkeypatch.setattr(device_config, "_redact_key", lambda: _KEY)
    res = device_config._fetch_one(_TARGET, key=_KEY, ssh_timeout=5)
    assert (res["stage"], res["code"]) == ("auth", "auth.enable_rejected")

    targets = [{**_TARGET, "target_id": i, "host": f"10.0.99.{i}"} for i in range(1, 11)]
    out = device_config.fetch_all(targets)
    assert len(attempts) == 1 + 3, f"breaker let {len(attempts) - 1} enable rejections through"
    assert out["stats"]["stopped_early"] is True


def test_fetch_one_icx_no_enable_path_is_authz(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_connect(platform: str, **kw: Any) -> None:
        raise device_config.IcxNoEnableAccess("no enable path")

    monkeypatch.setattr(device_config, "_connect", fake_connect)
    res = device_config._fetch_one(_TARGET, key=_KEY, ssh_timeout=5)
    assert (res["stage"], res["code"]) == ("authz", "authz.no_read_access")


def test_icx_code_is_in_the_shared_taxonomy() -> None:
    assert "auth.enable_rejected" in device_config.ssh_diag.CODES
