"""Secret redaction: `_redact_secrets` scrubs credential VALUES out of any text that
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

# A realistic Azure blob SAS URL as it appears in a `config-backup` / `upload-now`
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
    out = _redact_secrets(f"config-backup failed: PUT {_BLOB_SAS} -> 403")
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
