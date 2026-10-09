"""A failed DHCP-server collection must not carry the account name off the box.

dhcp_intel.json ships in the hourly bundle. A failed target used to carry the
exception text with only the password scrubbed, and that text is written by
kinit / pywinrm / impacket / the Windows server — it routinely names the
account. These tests drive every failure path with text that names the account
in each of the three ways it can be spelled, and assert on the WHOLE serialized
entry, so a new field that copies the text through fails too.

They deliberately do not test a redaction list: there isn't one. The entry is
built from a code and that code's fixed sentence, so the assertion is that
nothing variable reaches it at all.
"""
from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

import pytest

from collector.discovery import dhcp_server as dh

USER_UPN = "svc-dhcp@corp.example.org"
PASSWORD = "Tr0ub4dor&3"
# Everything about the credential that failure text has been seen to contain.
NEEDLES = ("svc-dhcp", "corp.example.org", "CORP.EXAMPLE.ORG", "CORP\\svc-dhcp", PASSWORD)
LEAKY = (
    "kinit: Client 'svc-dhcp@CORP.EXAMPLE.ORG' not found in Kerberos database; "
    f"logon as CORP\\svc-dhcp (svc-dhcp@corp.example.org) with {PASSWORD} did not work"
)
TARGET = {
    "server_ip": "10.0.0.10", "label": "Core DHCP", "server_type": "windows",
    "winrm_user": USER_UPN, "winrm_password": PASSWORD,
}
ALLOWED_KEYS = {"server_ip", "label", "server_type", "status", "code", "error", "transport"}


class _Result:
    def __init__(self, std_out: bytes = b"", std_err: bytes = b"", status_code: int = 0):
        self.std_out, self.std_err, self.status_code = std_out, std_err, status_code


def _fake_winrm(monkeypatch, *, result=None, raises=None) -> None:
    mod = types.ModuleType("winrm")

    class Session:
        def __init__(self, endpoint, auth=None, **kwargs):
            if raises is not None:
                raise raises

        def run_ps(self, script):
            return result

    mod.Session = Session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "winrm", mod)


def _fake_rpc(monkeypatch, exc: Exception) -> None:
    fake = types.ModuleType("collector.discovery.dhcp_rpc")

    def collect(*_a, **_k):
        raise exc

    fake.collect = collect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "collector.discovery.dhcp_rpc", fake)
    # `from . import dhcp_rpc` reads the PACKAGE ATTRIBUTE when another test has
    # already imported the real module, and only falls back to sys.modules when
    # it has not. Patch both, or this silently dials a real server.
    import collector.discovery as discovery_pkg

    monkeypatch.setattr(discovery_pkg, "dhcp_rpc", fake, raising=False)
    monkeypatch.setattr(dh, "_cleanup_ccache", lambda c: None)


def _raiser(exc: Exception):
    def _f(*_a, **_k):
        raise exc
    return _f


def _winrm_exception(monkeypatch):
    monkeypatch.setattr(dh, "_detect_transport", lambda e, t: "ntlm")
    monkeypatch.setattr(dh, "_rpc_fallback", lambda *a, **k: None)
    _fake_winrm(monkeypatch, raises=OSError(LEAKY))
    return TARGET


def _winrm_stderr(monkeypatch):
    monkeypatch.setattr(dh, "_detect_transport", lambda e, t: "ntlm")
    _fake_winrm(monkeypatch, result=_Result(std_err=LEAKY.encode(), status_code=1))
    return TARGET


def _ps_reported(monkeypatch):
    monkeypatch.setattr(dh, "_detect_transport", lambda e, t: "ntlm")
    _fake_winrm(monkeypatch, result=_Result(std_out=json.dumps({"ok": False, "error": LEAKY}).encode()))
    return TARGET


def _ps_unparseable(monkeypatch):
    monkeypatch.setattr(dh, "_detect_transport", lambda e, t: "ntlm")
    _fake_winrm(monkeypatch, result=_Result(std_out=("{" + LEAKY).encode()))
    return TARGET


def _kinit_non_auth(monkeypatch):
    monkeypatch.setattr(dh, "_detect_transport", lambda e, t: "kerberos")
    monkeypatch.setattr(dh, "_rpc_fallback", lambda *a, **k: None)
    monkeypatch.setattr(dh, "_kinit", _raiser(RuntimeError(LEAKY)))
    _fake_winrm(monkeypatch, result=_Result())
    return TARGET


def _kinit_auth(monkeypatch):
    monkeypatch.setattr(dh, "_detect_transport", lambda e, t: "kerberos")
    monkeypatch.setattr(dh, "_kinit", _raiser(RuntimeError(f"Password incorrect: {LEAKY}")))
    _fake_winrm(monkeypatch, result=_Result())
    return TARGET


def _rpc_kinit_auth(monkeypatch):
    monkeypatch.setattr(dh, "_kinit", _raiser(RuntimeError(f"Preauthentication failed: {LEAKY}")))
    _fake_rpc(monkeypatch, RuntimeError("unused"))
    return {**TARGET, "transport": "rpc"}


def _rpc_exception(monkeypatch):
    monkeypatch.setattr(dh, "_kinit", lambda u, p, ip: "/tmp/cc")
    _fake_rpc(monkeypatch, RuntimeError(f"STATUS_LOGON_FAILURE {LEAKY}"))
    return {**TARGET, "transport": "rpc"}


def _rpc_exception_other(monkeypatch):
    monkeypatch.setattr(dh, "_kinit", lambda u, p, ip: "/tmp/cc")
    _fake_rpc(monkeypatch, RuntimeError(f"rpc_s_access_denied {LEAKY}"))
    return {**TARGET, "transport": "rpc"}


FAILURE_PATHS = {
    "winrm exception": (_winrm_exception, "collect_failed"),
    "winrm stderr": (_winrm_stderr, "probe_failed"),
    "ps-reported error": (_ps_reported, "probe_failed"),
    "ps unparseable": (_ps_unparseable, "response_unparseable"),
    "kinit, not a credential rejection": (_kinit_non_auth, "kerberos_failed"),
    "kinit, credential rejected": (_kinit_auth, "auth_failed"),
    "rpc kinit, credential rejected": (_rpc_kinit_auth, "auth_failed"),
    "rpc exception, credential rejected": (_rpc_exception, "auth_failed"),
    "rpc exception, other": (_rpc_exception_other, "access_denied"),
}


@pytest.mark.parametrize("name", list(FAILURE_PATHS))
def test_no_failure_path_carries_the_account_into_the_artifact(name, monkeypatch) -> None:
    arrange, expected_code = FAILURE_PATHS[name]
    target = arrange(monkeypatch)

    out = dh._collect_one(target, winrm_timeout=30)

    assert out["status"] == "error"
    assert out["code"] == expected_code
    assert out["error"] == dh._ERROR_TEXT[expected_code]
    assert set(out) <= ALLOWED_KEYS, set(out) - ALLOWED_KEYS
    blob = json.dumps(out)
    for needle in NEEDLES:
        assert needle not in blob, (name, needle)
        assert needle.lower() not in blob.lower(), (name, needle)


def test_the_stored_artifact_is_clean_end_to_end(monkeypatch, tmp_path) -> None:
    # What actually ships: collect_all -> _store -> the file bundle.py zips.
    _winrm_exception(monkeypatch)
    intel_file = tmp_path / "dhcp_intel.json"
    monkeypatch.setattr(dh, "INTEL_FILE", intel_file)

    dh._store(dh.collect_all([TARGET]))

    text = intel_file.read_text(encoding="utf-8")
    assert json.loads(text)["servers"][0]["code"] == "collect_failed"
    for needle in NEEDLES:
        assert needle.lower() not in text.lower(), needle


def test_positive_control_the_leaky_text_really_reaches_the_collector(monkeypatch) -> None:
    # The tests above pass trivially if the fakes never deliver LEAKY. Prove the
    # text arrives, by reading it where it is allowed to go: the local log.
    seen: list[dict] = []
    monkeypatch.setattr(dh.log, "warning", lambda event, **kw: seen.append({"event": event, **kw}))
    _winrm_exception(monkeypatch)

    dh._collect_one(TARGET, winrm_timeout=30)

    details = [e["detail"] for e in seen if e["event"] == "dhcp intel failure detail"]
    assert len(details) == 1
    assert "svc-dhcp" in details[0]          # the detail is kept, for the operator
    assert PASSWORD not in details[0]        # ...with the password still scrubbed


def test_every_error_entry_is_built_by_fail() -> None:
    # A new failure branch that hand-builds {"status": "error", "error": f"...{exc}"}
    # would reintroduce the leak without touching any path tested above.
    src = Path(dh.__file__).read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    code = code[code.index("log = structlog.get_logger") :]  # past the module docstring
    assert len(re.findall(r'"status":\s*"error"', code)) == 1


@pytest.mark.parametrize(
    ("detail", "default", "code"),
    [
        ("InvalidCredentialsError: the specified credentials were rejected", "collect_failed", "auth_failed"),
        ("Cannot connect to CIM server. Access denied", "probe_failed", "wmi_denied"),
        ("Access is denied.", "probe_failed", "access_denied"),
        ("OSError: no route to host", "collect_failed", "unreachable"),
        ("ConnectionResetError: connection reset by peer", "collect_failed", "unreachable"),
        ("ReadTimeout: HTTPConnectionPool(host='h', port=5985): Read timed out.", "collect_failed", "timeout"),
        ("SSLError: certificate verify failed", "collect_failed", "tls_failed"),
        ("kinit: Clock skew too great while getting initial credentials", "kerberos_failed", "kerberos_failed"),
        ("something nobody anticipated", "collect_failed", "collect_failed"),
        ("", "probe_failed", "probe_failed"),
    ],
)
def test_classification(detail, default, code) -> None:
    assert dh._classify(detail, default) == code
    assert code in dh._ERROR_TEXT


def test_credential_rejection_code_agrees_with_the_fail_fast_decision() -> None:
    # The code must never say something other than what _is_auth_failure decided,
    # because that decision is what stops the RPC fallback (AD lockout protection).
    for sign in dh._AUTH_FAILURE_SIGNS:
        assert dh._classify(f"x {sign} y timed out access denied", "collect_failed") == "auth_failed"
