"""Unit tests for the authoritative DHCP server intelligence collector (DHCP-2).

Pure unit tests: no WinRM, no network. `winrm.Session` is the single network
chokepoint and is faked via sys.modules, so we exercise the whole
build-script -> run -> parse -> merge path against captured `ConvertTo-Json`
output shaped the way a real Windows DHCP server returns it.
"""
from __future__ import annotations

import base64
import json
import sys
import types
from datetime import UTC, datetime

import pytest

from collector.discovery import dhcp_server as dh


@pytest.fixture(autouse=True)
def _no_network_probe(monkeypatch):
    """Transport now defaults to 'auto', so _collect_one probes WWW-Authenticate
    via requests.post. Make that probe fail fast in unit tests (→ falls back to
    ntlm) so nothing hits the network; detection-specific tests override it. If
    requests isn't installed locally, _detect_transport already returns None (its
    own import fails inside the try), so there's nothing to stub."""
    try:
        import requests
    except Exception:
        return

    def _fail(*_a, **_k):
        raise OSError("no network in unit tests")

    monkeypatch.setattr(requests, "post", _fail)

# A realistic single-server ConvertTo-Json payload: one hot (90%) active scope
# and one empty inactive scope, server + scope options, one failover relationship.
_SAMPLE = {
    "ok": True,
    "hostname": "DC01",
    "is_authorized": True,
    "is_domain_joined": True,
    "server_stats": {
        "total_scopes": 2, "total_addresses": 500.0, "addresses_in_use": 420.0,
        "addresses_available": 80.0, "percentage_in_use": 84.0,
    },
    "failover": [{
        "name": "dc01-dc02", "partner": "10.0.0.11", "mode": "LoadBalance",
        "state": "Normal", "enabled": True, "scope_ids": ["10.1.0.0"],
    }],
    "server_options": [{"id": 6, "name": "DNS Servers", "value": ["10.0.0.10", "10.0.0.11"]}],
    "scopes": [
        {"scope_id": "10.1.0.0", "name": "Staff", "state": "Active",
         "start_range": "10.1.0.10", "end_range": "10.1.3.254",
         "subnet_mask": "255.255.252.0", "lease_duration_sec": 691200,
         "description": "", "addresses_in_use": 900, "addresses_free": 100,
         "percentage_in_use": 90.0, "reserved": 5,
         "options": [{"id": 3, "name": "Router", "value": ["10.1.3.254"]}]},
        {"scope_id": "10.2.0.0", "name": "Old", "state": "Inactive",
         "start_range": "10.2.0.10", "end_range": "10.2.0.254",
         "subnet_mask": "255.255.255.0", "lease_duration_sec": 86400,
         "description": "", "addresses_in_use": 0, "addresses_free": 244,
         "percentage_in_use": 0.0, "reserved": 0, "options": []},
    ],
}


class _FakeResult:
    def __init__(self, std_out: bytes = b"", std_err: bytes = b"", status_code: int = 0):
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class _OperationTimeout(Exception):
    """Stands in for winrm.exceptions.WinRMOperationTimeoutError."""


class _FakeProtocol:
    """The slice of winrm.protocol.Protocol the collector drives: one shell, one
    command, its stdin, then Receive until done. Records what was sent."""

    def __init__(self, result, capture, receives):
        self.result, self.capture, self.receives = result, capture, receives
        self.calls: list[str] = []

    def open_shell(self):
        self.calls.append("open_shell")
        return "shell-1"

    def run_command(self, shell_id, command, arguments=(), console_mode_stdin=True, skip_cmd_shell=False):
        self.calls.append("run_command")
        if self.capture is not None:
            self.capture["command"] = command
            self.capture["arguments"] = list(arguments)
            self.capture["console_mode_stdin"] = console_mode_stdin
        return "cmd-1"

    def send_command_input(self, shell_id, command_id, stdin_input, end=False):
        self.calls.append("send_command_input")
        if self.capture is not None:
            self.capture["stdin"] = stdin_input
            self.capture["stdin_end"] = end
            self.capture["script"] = base64.b64decode(stdin_input).decode("utf-8")

    def get_command_output_raw(self, shell_id, command_id):
        self.calls.append("receive")
        if self.receives is not None:
            return self.receives(self)
        r = self.result
        return r.std_out, r.std_err, r.status_code, True

    def cleanup_command(self, shell_id, command_id):
        self.calls.append("cleanup_command")

    def close_shell(self, shell_id):
        self.calls.append("close_shell")


def _install_fake_winrm(monkeypatch, *, result=None, raises=None, capture=None, receives=None):
    """Register a fake `winrm` module so `import winrm` inside the collector
    resolves to it. Optionally capture the Session ctor args, the command line and
    the script sent on stdin. `receives(protocol)` overrides each Receive."""
    mod = types.ModuleType("winrm")
    exc_mod = types.ModuleType("winrm.exceptions")
    exc_mod.WinRMOperationTimeoutError = _OperationTimeout  # type: ignore[attr-defined]

    class Session:
        def __init__(self, endpoint, auth=None, **kwargs):
            if capture is not None:
                capture["endpoint"] = endpoint
                capture["auth"] = auth
                capture["kwargs"] = kwargs
            if raises is not None:
                raise raises
            self.protocol = _FakeProtocol(result, capture, receives)
            if capture is not None:
                capture["protocol"] = self.protocol

        def run_ps(self, script):  # pragma: no cover — must never be used again
            raise AssertionError("run_ps puts the whole probe on one command line")

    mod.Session = Session  # type: ignore[attr-defined]
    mod.exceptions = exc_mod  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "winrm", mod)
    monkeypatch.setitem(sys.modules, "winrm.exceptions", exc_mod)


def test_unsupported_server_type():
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "kea"}, winrm_timeout=30)
    assert out["status"] == "unsupported"


def test_missing_ip():
    out = dh._collect_one({"server_type": "windows"}, winrm_timeout=30)
    assert out["status"] == "error"


def test_parse_ok_and_merge(monkeypatch):
    cap: dict = {}
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "label": "Core", "server_type": "windows",
         "winrm_user": "DOM\\svc", "winrm_password": "s3cret", "use_https": False},
        winrm_timeout=30,
    )
    assert out["status"] == "ok"
    assert out["server_ip"] == "10.0.0.10"
    assert out["label"] == "Core"
    assert out["hostname"] == "DC01"
    # PS control fields are stripped from the merged result.
    assert "ok" not in out and "error" not in out
    assert len(out["scopes"]) == 2
    assert out["scopes"][0]["percentage_in_use"] == 90.0
    assert out["server_options"][0]["id"] == 6
    # Endpoint built for plain HTTP/5985 with the requested transport.
    assert cap["endpoint"] == "http://10.0.0.10:5985/wsman"
    assert cap["kwargs"]["transport"] == "ntlm"
    assert cap["auth"] == ("DOM\\svc", "s3cret")


def test_https_endpoint(monkeypatch):
    cap: dict = {}
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap)
    dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows", "use_https": True}, winrm_timeout=30)
    assert cap["endpoint"] == "https://10.0.0.10:5986/wsman"


def test_fqdn_used_as_winrm_host(monkeypatch):
    # When a target carries an FQDN, WinRM must connect BY NAME (so Kerberos gets a
    # resolvable SPN) while the target IDENTITY still reports the IP.
    cap: dict = {}
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "fqdn": "dc01.example.org", "server_type": "windows",
         "winrm_user": "svc@EXAMPLE.ORG", "winrm_password": "pw"},
        winrm_timeout=30,
    )
    assert out["status"] == "ok"
    assert cap["endpoint"] == "http://dc01.example.org:5985/wsman"
    # Identity is unchanged — server_ip anchors the record, not the FQDN.
    assert out["server_ip"] == "10.0.0.10"


def test_empty_fqdn_falls_back_to_ip(monkeypatch):
    # An explicitly empty FQDN behaves exactly like the key being absent (back-compat).
    cap: dict = {}
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap)
    dh._collect_one(
        {"server_ip": "10.0.0.10", "fqdn": "", "server_type": "windows"},
        winrm_timeout=30,
    )
    assert cap["endpoint"] == "http://10.0.0.10:5985/wsman"


def test_fqdn_endpoint_on_kerberos_path(monkeypatch):
    # The motivating case: on the Kerberos transport the SPN is derived from the
    # endpoint host, so it MUST be the FQDN, not the by-IP endpoint that fails
    # "Server not found in Kerberos database".
    cap: dict = {}
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap)
    monkeypatch.setattr(dh, "_detect_transport", lambda endpoint, timeout: "kerberos")
    monkeypatch.setattr(dh, "_kinit", lambda user, password, ip: "/tmp/netmon_ccache")
    monkeypatch.setattr(dh, "_cleanup_ccache", lambda c: None)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "fqdn": "dc01.example.org", "server_type": "windows",
         "winrm_user": "svc@EXAMPLE.ORG", "winrm_password": "pw"},
        winrm_timeout=30,
    )
    assert out["status"] == "ok"
    assert out["transport"] == "kerberos"
    assert cap["endpoint"] == "http://dc01.example.org:5985/wsman"


def test_ps_reported_error(monkeypatch):
    monkeypatch.setattr(dh, "_rpc_fallback", lambda *a, **k: None)  # no real RPC attempt
    _install_fake_winrm(
        monkeypatch,
        result=_FakeResult(std_out=json.dumps({"ok": False, "error": (
            "The specified module 'DhcpServer' was not loaded because no valid module "
            "file was found in any module directory."
        )}).encode()),
    )
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert out["status"] == "error"
    assert out["code"] == "module_missing"
    assert out["error"] == dh._ERROR_TEXT["module_missing"]


def test_nonzero_status_scrubs_password(monkeypatch):
    monkeypatch.setattr(dh, "_rpc_fallback", lambda *a, **k: None)  # no real RPC attempt
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_err=b"auth failed for p@ss", status_code=1))
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows", "winrm_password": "p@ss"},
        winrm_timeout=30,
    )
    assert out["status"] == "error"
    # Not scrubbed-and-forwarded any more: none of the server's text is forwarded.
    assert "p@ss" not in json.dumps(out)
    assert out["error"] == dh._ERROR_TEXT[out["code"]]


def test_connection_error(monkeypatch):
    monkeypatch.setattr(dh, "_rpc_fallback", lambda *a, **k: None)  # no real RPC attempt
    _install_fake_winrm(monkeypatch, raises=OSError("no route to host"))
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert out["status"] == "error"
    assert out["code"] == "unreachable"


def test_collect_all_shape(monkeypatch):
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()))
    intel = dh.collect_all([{"server_ip": "10.0.0.10", "server_type": "windows"}],
                           winrm_timeout=30, time_budget=120)
    assert intel["stats"] == {**intel["stats"], "targets": 1, "ok": 1, "errors": 0}
    assert intel["collected_at"]
    assert intel["servers"][0]["status"] == "ok"


def test_collect_all_budget_exhausted(monkeypatch):
    # A negative budget forces the very first target over budget deterministically.
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()))
    intel = dh.collect_all([{"server_ip": "10.0.0.10", "server_type": "windows"}],
                           winrm_timeout=30, time_budget=-1)
    assert intel["stats"]["budget_exhausted"] is True
    assert intel["servers"][0]["status"] == "skipped"


def test_store_load_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(dh, "INTEL_FILE", tmp_path / "dhcp_intel.json")
    dh._store({"collected_at": "2026-07-10T00:00:00+00:00", "servers": [], "stats": {}})
    got = dh.load()
    assert got is not None
    assert got["collected_at"] == "2026-07-10T00:00:00+00:00"


def test_load_targets_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(dh, "TARGETS_FILE", tmp_path / "nope.json")
    assert dh.load_targets() == []


def test_age_sec():
    now_iso = datetime.now(UTC).isoformat()
    age = dh._age_sec(now_iso)
    assert age is not None and age < 5
    assert dh._age_sec(None) is None
    assert dh._age_sec("garbage") is None


# ---- DHCP-8: transport auto-detection + Kerberos ----


class _Resp:
    def __init__(self, www: str):
        self.headers = {"www-authenticate": www}


def test_detect_transport(monkeypatch):
    requests = pytest.importorskip("requests")

    # Server offering only Negotiate/Kerberos (NTLM disabled) → kerberos.
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp("Negotiate, Kerberos"))
    assert dh._detect_transport("http://x:5985/wsman", 5) == "kerberos"
    # Server offering NTLM → ntlm.
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp("Negotiate, NTLM"))
    assert dh._detect_transport("http://x:5985/wsman", 5) == "ntlm"
    # Unreachable/undetermined → None (caller falls back to ntlm).
    monkeypatch.setattr(requests, "post", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert dh._detect_transport("http://x:5985/wsman", 5) is None


def test_realm_from_server(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("dc01.example.org", [], [ip]))
    assert dh._realm_from_server("10.0.0.10") == "EXAMPLE.ORG"
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError())
    )
    assert dh._realm_from_server("10.0.0.10") is None


def test_auto_selects_kerberos_and_kinits(monkeypatch):
    cap: dict = {}
    _install_fake_winrm(
        monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap
    )
    monkeypatch.setattr(dh, "_detect_transport", lambda endpoint, timeout: "kerberos")
    kinited: dict = {}

    def _fake_kinit(user, password, ip):
        kinited["user"] = user
        return "/tmp/netmon_ccache"

    monkeypatch.setattr(dh, "_kinit", _fake_kinit)
    monkeypatch.setattr(dh, "_cleanup_ccache", lambda c: None)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows",
         "winrm_user": "DHCP_User@EXAMPLE.ORG", "winrm_password": "pw"},
        winrm_timeout=30,
    )
    assert out["status"] == "ok"
    assert out["transport"] == "kerberos"
    assert cap["kwargs"]["transport"] == "kerberos"
    assert kinited["user"] == "DHCP_User@EXAMPLE.ORG"


def test_kerberos_kinit_failure_is_clean(monkeypatch):
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()))
    monkeypatch.setattr(dh, "_detect_transport", lambda endpoint, timeout: "kerberos")

    def _bad_kinit(user, password, ip):
        raise RuntimeError("Password incorrect")

    monkeypatch.setattr(dh, "_kinit", _bad_kinit)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows",
         "winrm_user": "DHCP_User@EXAMPLE.ORG", "winrm_password": "pw"},
        winrm_timeout=30,
    )
    assert out["status"] == "error"
    assert out["transport"] == "kerberos"
    assert out["code"] == "auth_failed"  # "Password incorrect" is a credential rejection


# ---- F-COL-9: fail fast on an auth failure (avoid AD lockout) ----


def test_is_auth_failure_positive():
    # Credential-rejection signatures across kinit / WinRM (401) / impacket.
    for msg in [
        "InvalidCredentialsError: the specified credentials were rejected by the server",
        "requests.exceptions.HTTPError: 401 Client Error for url",
        "kinit: Preauthentication failed while getting initial credentials",
        "Kerberos sign-in failed: Password incorrect",
        "SMB SessionError: STATUS_LOGON_FAILURE(0xC000006D)",
        "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_PASSWORD_EXPIRED",
    ]:
        assert dh._is_auth_failure(msg), msg


def test_is_auth_failure_negative():
    # Transport / connectivity / authorization errors must NOT fail fast — these are
    # exactly the cases the RPC fallback is designed to recover, so they keep falling
    # back. Access-denied is a VALID credential lacking rights (no lockout risk).
    for msg in [
        "OSError: no route to host",
        "ConnectionResetError: connection reset by peer",
        "Cannot connect to CIM server. Access denied",     # WMI/DCOM gate → RPC
        "Server not found in Kerberos database",           # SPN-by-IP → RPC
        "kinit: Clock skew too great while getting initial credentials",
        "rpc_s_access_denied",
        "",
    ]:
        assert not dh._is_auth_failure(msg), msg


def _fallback_spy():
    """A stand-in for _rpc_fallback that records whether it was called (each real
    call is another AD logon we're trying to avoid)."""
    state = {"calls": 0}

    def _fb(*_a, **_k):
        state["calls"] += 1
        return {"status": "ok", "transport": "rpc", "scopes": []}

    return state, _fb


def test_winrm_auth_failure_skips_rpc_fallback(monkeypatch):
    # A 401-style WinRM error must NOT trigger the RPC fallback (which would kinit +
    # NTLM = two more failed logons). Fail fast instead.
    class InvalidCredentialsError(Exception):
        pass

    _install_fake_winrm(
        monkeypatch,
        raises=InvalidCredentialsError("the specified credentials were rejected by the server"),
    )
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows",
         "winrm_user": "DOM\\svc", "winrm_password": "bad"},
        winrm_timeout=30,
    )
    assert out["status"] == "error"
    assert state["calls"] == 0  # no fallback → no extra AD logon


def test_winrm_transport_failure_still_falls_back(monkeypatch):
    # A genuine transport error (connection reset) SHOULD still fall back to RPC.
    _install_fake_winrm(monkeypatch, raises=OSError("connection reset by peer"))
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows",
         "winrm_user": "DOM\\svc", "winrm_password": "pw"},
        winrm_timeout=30,
    )
    assert state["calls"] == 1
    assert out["status"] == "ok"
    assert out["transport"] == "rpc"


def test_kinit_auth_failure_skips_rpc_fallback(monkeypatch):
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()))
    monkeypatch.setattr(dh, "_detect_transport", lambda endpoint, timeout: "kerberos")
    monkeypatch.setattr(
        dh, "_kinit", lambda u, p, ip: (_ for _ in ()).throw(RuntimeError("Preauthentication failed"))
    )
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows",
         "winrm_user": "DHCP_User@EXAMPLE.ORG", "winrm_password": "bad"},
        winrm_timeout=30,
    )
    assert out["status"] == "error"
    assert out["transport"] == "kerberos"
    assert state["calls"] == 0


def test_rpc_kinit_auth_failure_skips_ntlm(monkeypatch):
    # Pinned RPC transport: a bad-password kinit must NOT then try NTLM (another logon).
    monkeypatch.setattr(
        dh, "_kinit", lambda u, p, ip: (_ for _ in ()).throw(RuntimeError("Password incorrect"))
    )
    monkeypatch.setattr(dh, "_cleanup_ccache", lambda c: None)
    fake = types.ModuleType("collector.discovery.dhcp_rpc")
    called = {"n": 0}

    def _collect(*_a, **_k):
        called["n"] += 1
        return {"scopes": []}

    fake.collect = _collect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "collector.discovery.dhcp_rpc", fake)
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows", "transport": "rpc",
         "winrm_user": "u@DOM", "winrm_password": "bad"},
        winrm_timeout=30,
    )
    assert out["status"] == "error"
    assert out["transport"] == "rpc"
    assert out["code"] == "auth_failed"
    assert called["n"] == 0  # NTLM attempt skipped


# ---------------------------------------------------------------------------
# The probe rides stdin, not the command line (DHCP02: "The command line is too
# long." — cmd.exe's 8191-character limit, which the encoded probe passed).
# ---------------------------------------------------------------------------

_CMD_EXE_LIMIT = 8191
_WINDOWS_ONLY = {"server_ip": "10.0.0.10", "server_type": "windows", "transport": "ntlm"}


def test_probe_is_sent_on_stdin_and_command_line_stays_short(monkeypatch):
    cap: dict = {}
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(_SAMPLE).encode()), capture=cap)
    out = dh._collect_one(dict(_WINDOWS_ONLY), winrm_timeout=30)
    assert out["status"] == "ok"
    command_line = " ".join([cap["command"], *cap["arguments"]])
    assert len(command_line) < 2000 < _CMD_EXE_LIMIT
    # The bootstrap is what runs, and the probe arrives whole on stdin, which is closed.
    encoded = cap["arguments"][cap["arguments"].index("-EncodedCommand") + 1]
    assert base64.b64decode(encoded).decode("utf-16-le") == dh._PS_BOOTSTRAP
    assert cap["script"] == dh._PS_PROBE
    assert cap["stdin_end"] is True
    assert cap["console_mode_stdin"] is False
    # ASCII on the wire, so the server's console code page cannot alter it.
    assert isinstance(cap["stdin"], bytes) and cap["stdin"].isascii()
    assert cap["protocol"].calls[-2:] == ["cleanup_command", "close_shell"]


def test_the_old_one_line_form_would_not_fit():
    # Guards the premise: if the probe ever shrank back under the limit this test
    # says so, but the stdin path stays correct either way.
    one_line = "powershell -encodedcommand " + base64.b64encode(dh._PS_PROBE.encode("utf-16-le")).decode()
    assert len(one_line) > _CMD_EXE_LIMIT


def test_probe_waits_through_operation_timeouts(monkeypatch):
    cap: dict = {}
    seen = {"n": 0}

    def receives(proto):
        seen["n"] += 1
        if seen["n"] < 3:
            raise _OperationTimeout()
        return json.dumps(_SAMPLE).encode(), b"", 0, True

    _install_fake_winrm(monkeypatch, result=None, capture=cap, receives=receives)
    out = dh._collect_one(dict(_WINDOWS_ONLY), winrm_timeout=30)
    assert out["status"] == "ok"
    assert seen["n"] == 3


def test_probe_output_arriving_in_chunks_is_joined(monkeypatch):
    body = json.dumps(_SAMPLE).encode()
    parts = [body[: len(body) // 2], body[len(body) // 2:]]

    def receives(proto):
        chunk = parts.pop(0)
        return chunk, b"", (0 if not parts else -1), not parts

    _install_fake_winrm(monkeypatch, result=None, receives=receives)
    out = dh._collect_one(dict(_WINDOWS_ONLY), winrm_timeout=30)
    assert out["status"] == "ok"
    assert len(out["scopes"]) == 2


def test_probe_stops_at_the_deadline_and_terminates_the_command(monkeypatch):
    cap: dict = {}

    def receives(proto):
        raise _OperationTimeout()  # the server never finishes

    _install_fake_winrm(monkeypatch, result=None, capture=cap, receives=receives)
    clock = {"t": 1000.0}

    def fake_monotonic():
        clock["t"] += 10.0
        return clock["t"]

    monkeypatch.setattr(dh.time, "monotonic", fake_monotonic)
    out = dh._collect_one(dict(_WINDOWS_ONLY), winrm_timeout=30, deadline=1050.0)
    assert out["status"] == "error"
    assert out["code"] == "timeout"
    assert cap["protocol"].calls[-2:] == ["cleanup_command", "close_shell"]


def test_probe_output_over_the_cap_is_too_large(monkeypatch):
    monkeypatch.setattr(dh, "_MAX_OUTPUT_BYTES", 100)

    def receives(proto):
        return b"x" * 80, b"", -1, False  # never done; grows past the cap

    _install_fake_winrm(monkeypatch, result=None, receives=receives)
    out = dh._collect_one(dict(_WINDOWS_ONLY), winrm_timeout=30)
    assert out["status"] == "error"
    assert out["code"] == "response_too_large"


def test_auto_falls_back_to_rpc_when_the_probe_exits_non_zero(monkeypatch):
    # The DHCP02 shape: WinRM signed in, the shell refused to run the probe.
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_err=b"The command line is too long.", status_code=1))
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert state["calls"] == 1
    assert out["status"] == "ok" and out["transport"] == "rpc"


def test_pinned_transport_keeps_the_probe_failure(monkeypatch):
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_err=b"The command line is too long.", status_code=1))
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one(dict(_WINDOWS_ONLY), winrm_timeout=30)
    assert state["calls"] == 0
    assert out["code"] == "probe_failed"


def test_auto_falls_back_when_the_probe_reports_access_denied(monkeypatch):
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_out=json.dumps(
        {"ok": False, "error": "Failed to get statistics for server. Access is denied."}).encode()))
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert state["calls"] == 1
    assert out["transport"] == "rpc"


def test_probe_credential_rejection_does_not_fall_back(monkeypatch):
    # Text that reads as a rejected credential never buys another AD logon (SEC-8).
    _install_fake_winrm(monkeypatch, result=_FakeResult(
        std_err=b"The user name or password is incorrect. 0xC000006D", status_code=1))
    state, fb = _fallback_spy()
    monkeypatch.setattr(dh, "_rpc_fallback", fb)
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert state["calls"] == 0
    assert out["code"] == "auth_failed"
