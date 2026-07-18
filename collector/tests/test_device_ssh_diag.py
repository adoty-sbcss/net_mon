"""Tests for the device SSH failure taxonomy.

The strings below are REAL netmiko / paramiko / socket failure messages. The whole
value of this module is that an operator gets sent to the right place, so the tests
that matter most are the ones separating failures that look identical to a naive
implementation but have different fixes and different owners.
"""

from __future__ import annotations

import pytest

from collector.discovery.device_ssh_diag import (
    classify_exception,
    looks_like_authz_denial,
    result_for,
    stage_ladder,
)


class FakeAuthError(Exception):
    """Stands in for netmiko's NetmikoAuthenticationException (name-matched)."""


class NetmikoAuthenticationException(Exception):
    pass


class NetmikoTimeoutException(Exception):
    pass


# --- The reach split: same symptom, different building ----------------------


def test_timeout_with_ping_is_ssh_filtered_not_host_down():
    stage, code = classify_exception(
        NetmikoTimeoutException("Connection to device timed-out: cisco_ios 10.8.2.11:22"),
        ping_ok=True,
    )
    assert (stage, code) == ("reach", "reach.ssh_timeout")


def test_timeout_without_ping_is_host_silent():
    """Identical exception, opposite conclusion — this is why we probe."""
    stage, code = classify_exception(
        NetmikoTimeoutException("Connection to device timed-out: cisco_ios 10.8.2.11:22"),
        ping_ok=False,
    )
    assert (stage, code) == ("reach", "reach.host_silent")


def test_refused_is_not_a_timeout():
    """Refused means something IS there saying no — turn SSH on, not check cabling."""
    stage, code = classify_exception(ConnectionRefusedError("[Errno 111] Connection refused"))
    assert (stage, code) == ("reach", "reach.refused")


def test_no_route_is_a_routing_problem():
    stage, code = classify_exception(OSError("[Errno 113] No route to host"))
    assert (stage, code) == ("reach", "reach.no_route")


# --- auth vs authz vs AAA: the expensive misdiagnoses ------------------------


def test_authentication_failure_is_auth_rejected():
    stage, code = classify_exception(
        NetmikoAuthenticationException("Authentication to device failed. Common causes: ...")
    )
    assert (stage, code) == ("auth", "auth.rejected")


def test_aaa_timeout_is_not_a_bad_password():
    """A RADIUS outage looks like an auth failure; rotating the password won't fix it."""
    stage, code = classify_exception(
        NetmikoAuthenticationException("TACACS+ server unreachable, authentication timeout")
    )
    assert (stage, code) == ("auth", "auth.aaa_timeout")


def test_lockout_is_distinguished_from_a_plain_rejection():
    """Retrying a lockout makes it worse — the copy has to say 'verify first'."""
    stage, code = classify_exception(
        NetmikoAuthenticationException("Account locked out due to too many failed attempts")
    )
    assert (stage, code) == ("auth", "auth.lockout_suspected")


@pytest.mark.parametrize(
    "output",
    [
        "% Invalid input detected at '^' marker.",
        "% Permission denied for command",
        "Command authorization failed.",
        "% Authorization failed",
    ],
)
def test_privilege_denial_detected_from_device_output(output):
    """Password is RIGHT; the read-only role was never applied to this box.

    Misfiling this as a credentials problem is the most common onboarding
    misdiagnosis — it sends the operator to rotate a working password.
    """
    assert looks_like_authz_denial(output)


def test_a_normal_config_is_not_a_privilege_denial():
    assert not looks_like_authz_denial("Building configuration...\n\nversion 15.2\nhostname SW1")


def test_empty_output_is_not_a_privilege_denial():
    assert not looks_like_authz_denial(None)
    assert not looks_like_authz_denial("")


# --- SSH negotiation: neither reachability nor credentials -------------------


def test_host_key_change_is_its_own_stage():
    """Not an error to retry past — a decision a human must make."""
    stage, code = classify_exception(
        Exception("Host key for server 10.8.2.11 does not match: known_hosts mismatch")
    )
    assert (stage, code) == ("ssh", "ssh.identity_changed")


def test_legacy_crypto_is_not_an_auth_failure():
    """Old school gear offers only diffie-hellman-group1-sha1; the password is fine."""
    stage, code = classify_exception(
        Exception("Incompatible ssh peer (no acceptable kex algorithm) - no matching key exchange")
    )
    assert (stage, code) == ("ssh", "ssh.legacy_crypto")


def test_banner_timeout_is_not_a_connect_timeout():
    stage, code = classify_exception(Exception("Error reading SSH protocol banner"), ping_ok=True)
    assert (stage, code) == ("ssh", "ssh.banner_timeout")


# --- Post-auth failures can never be credential problems --------------------


def test_read_timeout_after_auth_is_not_an_auth_failure():
    stage, code = classify_exception(
        Exception("Search pattern never detected in send_command: read timeout"),
        authenticated=True,
    )
    assert stage == "read"
    assert code == "read.timeout"


def test_permission_denied_text_after_auth_does_not_become_auth_rejected():
    """Guard against the obvious regression: once signed in, stop blaming the password."""
    stage, _ = classify_exception(Exception("permission denied"), authenticated=True)
    assert stage != "auth"


# --- Unknowns stay honest ----------------------------------------------------


def test_unrecognized_failure_is_labelled_unclassified_not_guessed():
    stage, code = classify_exception(Exception("something nobody has seen before"))
    assert (stage, code) == ("error", "error.unclassified")


# --- The ladder --------------------------------------------------------------


def test_ladder_marks_later_stages_skipped_not_failed():
    """We never tried them; calling them failed sends the operator chasing ghosts."""
    ladder = stage_ladder("auth")
    assert ladder["reach"] == "passed"
    assert ladder["ssh"] == "passed"
    assert ladder["auth"] == "failed"
    assert ladder["authz"] == "skipped"
    assert ladder["read"] == "skipped"


def test_ladder_all_passed_on_success():
    assert set(stage_ladder(None).values()) == {"passed"}


# --- The security contract ---------------------------------------------------


def test_result_payload_never_carries_exception_text():
    """A result may contain codes and numbers only.

    Raw library strings routinely embed the username and connection detail; this
    payload crosses the network to the dashboard and is rendered in a browser.
    """
    res = result_for(stage="auth", code="auth.rejected", elapsed_ms=1200, ping_ok=True)
    blob = repr(res).lower()
    for leak in ("password", "traceback", "exception", "netmiko", "username", "secret"):
        assert leak not in blob, f"result payload leaked {leak!r}"
    assert res["code"] == "auth.rejected"
    assert res["ok"] is False


def test_successful_result_has_no_stage_or_code():
    res = result_for(stage=None, code=None, elapsed_ms=800, bytes_read=48_000)
    assert res["ok"] is True
    assert res["stage"] is None and res["code"] is None
    assert res["bytes_read"] == 48_000
