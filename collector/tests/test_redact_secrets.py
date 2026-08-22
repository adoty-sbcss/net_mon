"""Secret redaction — the two functions that stand between a live credential and the
cloud. `_redact_secrets` (collector.checkin) scrubs credential VALUES out of any text
that leaves the box; `_redact_config` (discovery.device_config) masks secrets in the
DEVICE configs NCM-1 backs up. The second block of this file covers the latter.

`_redact_secrets` scrubs credential VALUES out of any text that
leaves the box (collect-logs tails, restricted-diag output, and the live-op streaming
path in remote_console — all route through this ONE function + its persistent broker
transcript).

Why this is worth pinning tightly: it is security-sensitive SHARED code where BOTH
failure directions are bugs. Under-masking leaks a live credential into an operator
console / persisted transcript; over-masking corrupts legitimate console output so an
operator can't diagnose the box. So every case below asserts the SECRET is gone AND
(where it matters) that the surrounding context is preserved, and a matching block of
NON-secret lines asserts they pass through byte-for-byte.

This file specifically covers the two shapes the keyword `KEY=value` matcher used to
miss (Azure blob SAS `?sig=`, and `scheme://user:pass@host` URL userinfo) alongside a
regression guard on the pre-existing KEY=secret / Bearer behavior.
"""
from __future__ import annotations

import pytest

from collector.checkin import _redact_secrets
from collector.discovery.device_config import _backstop_line, _redact_config

# A realistic Azure blob SAS URL as it appears in an `upload-now`
# blob error: metadata params (sv/se/sr/sp) precede the `sig` HMAC. The sig value uses
# percent-encoded base64 (%2B %2F %3D) exactly as Azure emits it.
_BLOB_SAS = (
    "https://acct.blob.core.windows.net/depot/box.tgz"
    "?sv=2021-06-08&se=2026-07-17T00%3A00%3A00Z&sr=b&sp=rw"
    "&sig=aBcD3f%2Bgh4Ij%2FkLmN5oPq%3D"
)
_SAS_SECRET = "aBcD3f%2Bgh4Ij%2FkLmN5oPq%3D"


# --------------------------------------------------------------------------------------
# SECRETS — must be masked (value gone), context kept.
# --------------------------------------------------------------------------------------

def test_blob_sas_sig_value_is_masked() -> None:
    out = _redact_secrets(f"upload-now failed: PUT {_BLOB_SAS} -> 403")
    assert _SAS_SECRET not in out, "SAS signature (the credential) leaked"
    assert "sig=***" in out, "param name should be kept, value masked"


def test_blob_sas_keeps_nonsecret_metadata_for_diagnosis() -> None:
    # sv/se/sr/sp are version/expiry/resource/permissions — NOT secret and useful when
    # debugging a 403 (e.g. an expired `se`). They must survive.
    out = _redact_secrets(_BLOB_SAS)
    for keep in ("sv=2021-06-08", "se=2026-07-17T", "sr=b", "sp=rw", "acct.blob.core.windows.net"):
        assert keep in out, f"non-secret SAS context {keep!r} was eaten"


def test_blob_sas_sig_as_first_param_is_masked() -> None:
    # `?sig=` (leading `?`, not `&`) must match too.
    out = _redact_secrets("https://h/c/b?sig=SECRETHMACvalue123")
    assert "SECRETHMACvalue123" not in out
    assert "?sig=***" in out


def test_sftp_url_password_is_masked() -> None:
    out = _redact_secrets("upload failed: sftp://netmon:s3cretpw@depot.example.com/in/x")
    assert "s3cretpw" not in out, "SFTP password leaked"
    assert "sftp://netmon:***@depot.example.com" in out, "scheme/user/host must survive"
    assert "/in/x" in out, "path after host must survive"


def test_url_userinfo_password_with_special_chars_is_masked() -> None:
    # A password can contain ':' (everything from the first ':' to the '@' is the
    # password). A raw '@' inside a password is not RFC-valid (must be %40), so the
    # first '@' is correctly treated as the userinfo/host boundary.
    out = _redact_secrets("postgres://svc:p:ss1+w@db.local:5432/netmon")
    assert "p:ss1+w" not in out
    # user + host:port + db path all kept; only the password blanked.
    assert out == "postgres://svc:***@db.local:5432/netmon"


@pytest.mark.parametrize(
    "text, secret",
    [
        ("NETMON_SFTP_PASSWORD=hunter2 loaded from env", "hunter2"),
        ('{"api_key": "sk-live-abc123"}', "sk-live-abc123"),
        ("got token=abc.def-123 back", "abc.def-123"),
        ("NETMON_SNMP_COMMUNITIES=public,private,secret3", "private"),
        ("Authorization: Bearer eyJhbGciOi.Jfoo_bar-9", "eyJhbGciOi.Jfoo_bar-9"),
    ],
)
def test_existing_keyword_and_bearer_secrets_still_masked(text: str, secret: str) -> None:
    # Regression guard: adding the two URL patterns must not weaken the original
    # KEY=value / Bearer masking.
    out = _redact_secrets(text)
    assert secret not in out, f"pre-existing masking regressed for {text!r}"
    assert "***" in out


# --------------------------------------------------------------------------------------
# NON-SECRETS — must pass through byte-for-byte (over-masking corrupts operator output).
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        # A plain URL with NO userinfo — nothing to mask.
        "fetched https://depot.example.com/bundles/box.tgz (200 OK)",
        # A blob URL with NO sig param.
        "listing https://acct.blob.core.windows.net/depot?comp=list&restype=container",
        # host:port with no '@' — the ':443' must NOT be read as a password.
        "connected to https://acct.blob.core.windows.net:443/depot",
        # Bare `user@host` (ssh target) — no scheme, no ':pass', not a credential.
        "ssh adaministrator@10.8.2.100 to verify the box",
        # An email address — the '@' must not trip userinfo masking.
        "notified admin a.user@sbcss.net about the scan",
        # scp-like git remote `git@host:path` — no '://', not a password.
        "git clone git@github.com:adoty-sbcss/net_mon.git",
        # Ordinary key=value log fields must stay readable.
        "scan complete: count=5 devices=42 elapsed=3.1s",
        # Prose containing 'password' as a substring must be untouched (assignment-only).
        "sshd config: passwordauthentication no",
        # A 'sig' substring that is NOT a query param (e.g. inside a word) is left alone.
        "redesign=true applied to the layout",
    ],
)
def test_non_secrets_pass_through_unchanged(text: str) -> None:
    assert _redact_secrets(text) == text


def test_mixed_line_masks_only_the_secret() -> None:
    # A single line carrying a secret AND diagnostic context: mask the one, keep the rest.
    line = (
        "op=upload-now host=depot.example.com attempt=2 "
        "url=sftp://netmon:s3cretpw@depot.example.com/in status=auth-failed"
    )
    out = _redact_secrets(line)
    assert "s3cretpw" not in out
    assert "op=upload-now" in out
    assert "host=depot.example.com" in out
    assert "attempt=2" in out
    assert "status=auth-failed" in out
    assert "sftp://netmon:***@depot.example.com/in" in out


# ======================================================================================
# DEVICE CONFIG redaction — `_redact_config` (discovery/device_config.py)
# ======================================================================================
# NCM-1's core security premise: on-box redaction exists precisely so the real device
# secret never leaves the district LAN. These pin the FASTPATH SNMP leak (three forms
# that shipped the real community in cleartext) and, more importantly, the SHAPE bug
# underneath it — a fail-closed backstop that skipped any line already carrying a
# token, i.e. skipped exactly the partially-handled lines where a pattern gap hides.
#
# ⚠️ FIXTURE PROVENANCE. These config lines are written to the vendors' documented
# grammars and to the exact line shapes `_redact_config` was RUN against when the leak
# was found — they are NOT byte-for-byte captures from a production device, and must
# not be described as such. Every secret VALUE is fabricated: this repo is public, so a
# real community must never appear here. What matters for these tests is the STRUCTURE
# (which token sits in which position), and that is faithful.

_KEY = b"deterministic-test-key-not-a-real-box-key"
#: Fabricated. Digit-bearing + mixed case, like a real strong community.
_COMMUNITY = "S3cretC0mmun1ty"


def _redact(text: str) -> tuple[str, int]:
    out, suspects = _redact_config(text, _KEY)
    assert out is not None
    return out, suspects


# --------------------------------------------------------------------------------------
# THE LEAK — FASTPATH (Ubiquiti EdgeSwitch / Netgear ProSafe) SNMP community forms.
# --------------------------------------------------------------------------------------
# FASTPATH puts a SUBCOMMAND KEYWORD where Cisco puts the secret, so the Cisco-shaped
# pattern masked `ipaddr`/`ipmask`/`mode` and the real community — sitting later on the
# line — was claimed by no pattern at all and shipped in the clear.

@pytest.mark.parametrize(
    "line",
    [
        f"snmp-server community ipaddr 10.1.1.1 {_COMMUNITY}",
        f"snmp-server community ipmask 255.255.255.0 {_COMMUNITY}",
        f"snmp-server community mode {_COMMUNITY}",
        # The forms that already worked — regression guards, not new coverage.
        f"snmp-server community {_COMMUNITY}",
        f"snmp-server community ro {_COMMUNITY}",
        f"snmp-server community rw {_COMMUNITY}",
    ],
)
def test_fastpath_snmp_community_never_leaves_the_lan(line: str) -> None:
    out, _ = _redact(line)
    assert _COMMUNITY not in out, f"SNMP community leaked in cleartext: {out}"
    assert out.startswith("snmp-server community "), "the command itself must survive"


@pytest.mark.parametrize(
    "line, keep",
    [
        (f"snmp-server community ipaddr 10.1.1.1 {_COMMUNITY}", "10.1.1.1"),
        (f"snmp-server community ipmask 255.255.255.0 {_COMMUNITY}", "255.255.255.0"),
    ],
)
def test_fastpath_snmp_acl_address_is_kept(line: str, keep: str) -> None:
    # The ACL address / mask says WHO may poll SNMP — config the operator owns, and an
    # over-broad SNMP ACL is itself a finding. Masking it would also fire
    # `redaction_suspects` on every healthy FASTPATH box, turning a review signal into
    # noise, so over-masking here is a bug in its own right.
    out, suspects = _redact(line)
    assert keep in out, f"the SNMP ACL address was eaten: {out}"
    assert suspects == 0, "a healthy FASTPATH line must not be flagged for review"


@pytest.mark.parametrize("mode", ["ro", "rw"])
def test_fastpath_access_mode_token_is_preserved_as_evidence(mode: str) -> None:
    # ⚠️ DO NOT "CLEAN THIS UP". FASTPATH writes the access mode before the community,
    # so the Cisco-shaped pattern masks it as `<REDACTED:DEFAULT-ro|rw>`. That token is
    # the ONLY thing that reveals FASTPATH access mode, the dashboard reads exactly this
    # shape (src/lib/rules/config-parse.ts, platform-scoped so it is not mistaken for a
    # weak community), and historical snapshots carry it forever. Narrowing it on the
    # sensor would need a fleet rollout AND would silently invalidate that cloud parse.
    out, _ = _redact(f"snmp-server community {mode} {_COMMUNITY}")
    assert f"<REDACTED:DEFAULT-{mode}>" in out, f"access-mode evidence token lost: {out}"
    assert _COMMUNITY not in out


# --------------------------------------------------------------------------------------
# THE SHAPE BUG — a partially-redacted line is exactly where a pattern gap hides.
# --------------------------------------------------------------------------------------

def test_backstop_inspects_lines_that_already_carry_a_token() -> None:
    # The generalizable defect: the backstop read `if "<REDACTED:" not in line`, so the
    # token step 3 had just inserted for the MIS-CAPTURED keyword switched off the one
    # mechanism designed to catch the resulting gap. suspects was 0 and nothing was
    # flagged. This pins the new shape directly on the primitive: an unmasked secret
    # AFTER an existing token must still be caught.
    line = f"pretend-vendor community <REDACTED:abc1234567> mode {_COMMUNITY}"
    out, n = _backstop_line(line)
    assert _COMMUNITY not in out, f"backstop skipped a partially-redacted line: {out}"
    assert n == 1
    assert "<REDACTED:abc1234567>" in out, "the pre-existing token must survive intact"


def test_backstop_never_remasks_an_existing_token_as_its_own_suspect() -> None:
    # Tokens are blanked before scanning; a fully-handled line must come back untouched
    # and uncounted, or every healthy config would report suspects.
    line = "snmp-server community <REDACTED:DEFAULT-rw> <REDACTED:3b495887fc>"
    out, n = _backstop_line(line)
    assert out == line
    assert n == 0


def test_exos_snmpv3_community_is_still_caught_by_the_backstop() -> None:
    # ⚠️ EXOS `configure snmpv3 add community <secret> user ...` has NO named pattern —
    # the backstop is the only thing standing between it and the cloud. Any future
    # change to the backstop must keep this working.
    out, suspects = _redact(f"configure snmpv3 add community {_COMMUNITY} user netmon")
    assert _COMMUNITY not in out, f"EXOS snmpv3 community leaked: {out}"
    assert "<REDACTED:suspect>" in out
    assert suspects == 1, "the fail-closed catch must remain VISIBLE as a review signal"


@pytest.mark.parametrize(
    "line, secrets",
    [
        (
            "configure snmpv3 add user netmon authentication md5 Aut4P4sswordXyz"
            " privacy des Pr1vP4sswordXyz",
            ("Aut4P4sswordXyz", "Pr1vP4sswordXyz"),
        ),
        (
            'configure snmpv3 add user "netmon" authentication sha encrypted'
            ' "Auth3ncrypted12" privacy aes encrypted "Priv3ncrypted12"',
            ("Auth3ncrypted12", "Priv3ncrypted12"),
        ),
        (
            "configure snmpv3 add user netmon authentication md5 hex a1b2c3d4e5f60718"
            " privacy hex 0918273645abcdef",
            ("a1b2c3d4e5f60718", "0918273645abcdef"),
        ),
    ],
)
def test_exos_snmpv3_user_passwords_never_leave_the_lan(
    line: str, secrets: tuple[str, ...]
) -> None:
    # A SECOND leak of the same class, found while fixing the FASTPATH one. EXOS spells
    # these `authentication md5 <pw>` / `privacy des <pw>`, not the hyphenated
    # `auth-md5` FASTPATH form — and `_SECRET_KEYWORD_RE` contains neither
    # `authentication ` nor `privacy `, so the fail-closed backstop never fired either.
    # Both SNMPv3 passwords shipped in cleartext.
    out, _ = _redact(line)
    for secret in secrets:
        assert secret not in out, f"EXOS SNMPv3 password leaked: {out}"


def test_cisco_standby_key_string_keyword_is_not_masked_as_a_secret() -> None:
    # ⚠️ Guards the EXOS `authentication (md5|sha)` pattern against over-reaching onto
    # Cisco. `standby N authentication md5 key-string <secret>` puts the literal keyword
    # `key-string` where EXOS puts a password. cisco_ios is one of only two platforms
    # actually in production, and changing its redacted output would fire a false
    # "config changed" event on every device (the snapshot is content-addressed).
    line = "standby 10 authentication md5 key-string 7 060506324F41"
    out, _ = _redact(line)
    assert "key-string" in out, f"a Cisco grammar keyword was masked: {out}"
    assert "060506324F41" not in out, "the actual standby key must still be masked"


def test_backstop_keeps_a_grammar_keyword_after_a_masked_value() -> None:
    # Junos: `authorization` is 13 alphabetic chars, so it trips the base64/hex-blob
    # alternative once the community before it has been masked. Masking it would corrupt
    # the line on every Junos device that has an SNMP community.
    out, suspects = _redact(f"set snmp community {_COMMUNITY} authorization read-only")
    assert _COMMUNITY not in out
    assert out.endswith(" authorization read-only"), f"grammar keyword eaten: {out}"
    assert suspects == 0


# --------------------------------------------------------------------------------------
# Cross-vendor regression guard — the ~60 named patterns must keep working.
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "line, secret",
    [
        ("snmp-server community R0Str0ngC0mm RO 99", "R0Str0ngC0mm"),
        ("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0"),
        ("username netops privilege 15 password 7 104D000A0618", "104D000A0618"),
        ("radius-server key encrypted R4diusK3yValue", "R4diusK3yValue"),
        ("snmpv3 user netmon auth sha ciphertext AQBapAuthCipher01", "AQBapAuthCipher01"),
        ('configure snmp add community readonly "R0Community12345"', "R0Community12345"),
        ("set snmp community JunosC0mmun1ty authorization read-only", "JunosC0mmun1ty"),
        ("radius server key auth 1 encrypted 3d4f6a8b9c0d1e2f", "3d4f6a8b9c0d1e2f"),
        ("wireless security wpa-passphrase Wp4P4ssphrase123", "Wp4P4ssphrase123"),
    ],
)
def test_other_vendor_secrets_still_redacted(line: str, secret: str) -> None:
    out, _ = _redact(line)
    assert secret not in out, f"a pre-existing pattern regressed: {out}"


def test_private_key_block_body_is_dropped_and_fences_kept() -> None:
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAx3Fk3PRIVATEKEYBODYxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out, _ = _redact(text)
    assert "PRIVATEKEYBODY" not in out
    assert "<REDACTED:key-block>" in out
    assert out.startswith("-----BEGIN RSA PRIVATE KEY-----")


# --------------------------------------------------------------------------------------
# NON-SECRET config must survive byte-for-byte (over-masking blinds the operator).
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "line",
    [
        "hostname rch-idf-n-3560cx-1",
        "ip access-list standard SNMP-ACL",
        " permit 10.20.30.0 0.0.0.255",
        "interface GigabitEthernet1/0/24",
        " description UPLINK-TO-CORE-1",
        " ip address 10.20.100.1 255.255.255.0",
        "spanning-tree mode rapid-pvst",
        "ntp server 10.20.30.49 prefer",
        "snmp-server location RCH-IDF-NORTH",
        "snmp-server contact netops@example.org",
        "vlan 100",
        " name STAFF-DATA",
    ],
)
def test_non_secret_config_passes_through_unchanged(line: str) -> None:
    out, suspects = _redact(line)
    assert out == line, "legitimate config was altered by redaction"
    assert suspects == 0


def test_empty_and_none_configs_are_handled() -> None:
    assert _redact_config(None, _KEY) == (None, 0)
    assert _redact_config("", _KEY) == ("", 0)
