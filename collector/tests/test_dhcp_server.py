"""Unit tests for the authoritative DHCP server intelligence collector (DHCP-2).

Pure unit tests: no WinRM, no network. `winrm.Session` is the single network
chokepoint and is faked via sys.modules, so we exercise the whole
build-script -> run -> parse -> merge path against captured `ConvertTo-Json`
output shaped the way a real Windows DHCP server returns it.
"""
from __future__ import annotations

import json
import sys
import types
from datetime import UTC, datetime

from collector.discovery import dhcp_server as dh

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


def _install_fake_winrm(monkeypatch, *, result=None, raises=None, capture=None):
    """Register a fake `winrm` module so `import winrm` inside the collector
    resolves to it. Optionally capture the Session ctor args / run_ps script."""
    mod = types.ModuleType("winrm")

    class Session:
        def __init__(self, endpoint, auth=None, **kwargs):
            if capture is not None:
                capture["endpoint"] = endpoint
                capture["auth"] = auth
                capture["kwargs"] = kwargs
            if raises is not None:
                raise raises

        def run_ps(self, script):
            if capture is not None:
                capture["script"] = script
            return result

    mod.Session = Session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "winrm", mod)


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


def test_ps_reported_error(monkeypatch):
    _install_fake_winrm(
        monkeypatch,
        result=_FakeResult(std_out=json.dumps({"ok": False, "error": "module missing"}).encode()),
    )
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert out["status"] == "error"
    assert "module missing" in out["error"]


def test_nonzero_status_scrubs_password(monkeypatch):
    _install_fake_winrm(monkeypatch, result=_FakeResult(std_err=b"auth failed for p@ss", status_code=1))
    out = dh._collect_one(
        {"server_ip": "10.0.0.10", "server_type": "windows", "winrm_password": "p@ss"},
        winrm_timeout=30,
    )
    assert out["status"] == "error"
    assert "p@ss" not in out["error"]
    assert "***" in out["error"]


def test_connection_error(monkeypatch):
    _install_fake_winrm(monkeypatch, raises=OSError("no route to host"))
    out = dh._collect_one({"server_ip": "10.0.0.10", "server_type": "windows"}, winrm_timeout=30)
    assert out["status"] == "error"
    assert "no route" in out["error"]


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
