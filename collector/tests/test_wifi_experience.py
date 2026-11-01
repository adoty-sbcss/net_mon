"""WIFI-3: normalizing the host-side client-experience battery artifact.

The battery runs HOST-side and drops a JSON file the container only ever READS, so
this normalizer is the one place a malformed, stale, or half-written artifact can
turn into a bad bundle. Two properties matter more than the happy path:

  * **It must never raise.** The artifact is written by a separate root-owned bash
    script on its own schedule; the collector can and does read it mid-rewrite, or
    not at all. Any exception here would take down the bundle for every OTHER
    subsystem too, so every failure has to come back as an ``available: False``
    reason string instead.
  * **"unavailable" and "measured, and it was fine" must stay distinguishable.**
    A missing artifact, a disabled feature, and a real battery run that found
    nothing wrong are three different states. Collapsing them is how a dead sensor
    comes to look healthy.

The base64 hop for the captive-portal redirect exists because the redirect is an
attacker-influenced URL from an untrusted AP — it rides as opaque base64 through
the bash artifact so no quoting bug in the printf'd JSON can break the file, and is
decoded exactly here.
"""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from collector.discovery import wifi_experience


class _Settings:
    def __init__(self, enabled: bool) -> None:
        self.wifi_join_enabled = enabled


def _enable(monkeypatch, enabled: bool = True) -> None:
    from collector import config

    monkeypatch.setattr(config, "get_settings", lambda: _Settings(enabled))


def _artifact(monkeypatch, tmp_path, payload: str):
    p = tmp_path / "wifi_experience.json"
    p.write_text(payload)
    monkeypatch.setattr(wifi_experience, "EXPERIENCE_PATH", p)
    return p


# --- the three "no data" states, which must not look alike ----------------------


def test_disabled_reports_disabled_not_missing(monkeypatch, tmp_path) -> None:
    # The feature being off is a CONFIG fact. If it came back as "no-artifact" an
    # operator would go hunting for a broken script that was never meant to run.
    _enable(monkeypatch, False)
    _artifact(monkeypatch, tmp_path, '{"results":[]}')
    assert wifi_experience.load() == {"available": False, "reason": "disabled"}


def test_missing_artifact_reports_no_artifact(monkeypatch, tmp_path) -> None:
    _enable(monkeypatch)
    monkeypatch.setattr(wifi_experience, "EXPERIENCE_PATH", tmp_path / "nope.json")
    assert wifi_experience.load() == {"available": False, "reason": "no-artifact"}


def test_unreadable_artifact_reports_unreadable_and_does_not_raise(monkeypatch, tmp_path) -> None:
    # Half-written file: the bash side installs atomically, but a truncated or
    # corrupt file must still degrade to a reason string rather than an exception
    # that would fail the whole bundle.
    _enable(monkeypatch)
    _artifact(monkeypatch, tmp_path, '{"results":[{"ssid":"a"')
    assert wifi_experience.load() == {"available": False, "reason": "unreadable"}


def test_empty_results_is_AVAILABLE_not_unavailable(monkeypatch, tmp_path) -> None:
    # A battery that ran and associated to nothing is a MEASUREMENT (and a finding),
    # not an absence of data. This is the line between "we looked and it's broken"
    # and "we never looked" — see the sensor-health lesson about unmeasured health.
    _enable(monkeypatch)
    _artifact(monkeypatch, tmp_path, '{"schema":1,"results":[]}')
    out = wifi_experience.load()
    assert out["available"] is True
    assert out["results"] == []


# --- captive-portal redirect decoding -------------------------------------------


def test_redirect_is_decoded_and_the_b64_field_is_dropped(monkeypatch, tmp_path) -> None:
    url = "https://uswest4.cloudguest.central.arubanetworks.com/portal/capture?cmd=login"
    b64 = base64.b64encode(url.encode()).decode()
    _enable(monkeypatch)
    _artifact(
        monkeypatch,
        tmp_path,
        json.dumps({"results": [{"ssid": "Guest", "captive_portal": {"state": "portal", "redirect_b64": b64}}]}),
    )
    cp = wifi_experience.load()["results"][0]["captive_portal"]
    assert cp["redirect"] == url
    # The raw field is popped so the bundle carries one representation, not two that
    # can disagree once anything downstream starts editing either.
    assert "redirect_b64" not in cp


def test_undecodable_redirect_yields_none_rather_than_raising(monkeypatch, tmp_path) -> None:
    # The redirect originates from an untrusted AP. Garbage in that field must not
    # be able to take out the bundle for every other subsystem.
    _enable(monkeypatch)
    _artifact(
        monkeypatch,
        tmp_path,
        json.dumps({"results": [{"ssid": "Guest", "captive_portal": {"redirect_b64": "!!!not-base64!!!"}}]}),
    )
    cp = wifi_experience.load()["results"][0]["captive_portal"]
    assert cp["redirect"] is None


def test_absent_redirect_leaves_no_redirect_key(monkeypatch, tmp_path) -> None:
    # An OPEN network has no portal and no redirect; it must not acquire a spurious
    # empty-string redirect that would render as a portal in the UI.
    _enable(monkeypatch)
    _artifact(
        monkeypatch,
        tmp_path,
        json.dumps({"results": [{"ssid": "psk", "captive_portal": {"state": "open", "redirect_b64": ""}}]}),
    )
    cp = wifi_experience.load()["results"][0]["captive_portal"]
    assert "redirect" not in cp


# --- multi-profile + forward compatibility --------------------------------------


def test_every_profile_in_an_ssid_hopping_run_survives(monkeypatch, tmp_path) -> None:
    # The battery hops a LIST of networks (WIFI-6) and emits one object per profile.
    # Decoding must apply per-result, not just to the first one — a bug here would
    # silently drop the guest network, which is the one most likely to be broken.
    urls = ["http://portal.example/a", "http://portal.example/b"]
    _enable(monkeypatch)
    _artifact(
        monkeypatch,
        tmp_path,
        json.dumps(
            {
                "results": [
                    {"ssid": s, "captive_portal": {"redirect_b64": base64.b64encode(u.encode()).decode()}}
                    for s, u in zip(("psk-net", "Guest"), urls, strict=True)
                ]
            }
        ),
    )
    results = wifi_experience.load()["results"]
    assert [r["ssid"] for r in results] == ["psk-net", "Guest"]
    assert [r["captive_portal"]["redirect"] for r in results] == urls


def test_unknown_measurement_fields_pass_through_untouched(monkeypatch, tmp_path) -> None:
    # The bash battery gains fields faster than this normalizer does (dns_via,
    # routing_ok, speedtest, targets...). It is a pass-through by design: anything
    # it does not know about must reach the bundle intact rather than being dropped.
    _enable(monkeypatch)
    _artifact(
        monkeypatch,
        tmp_path,
        json.dumps(
            {
                "results": [
                    {
                        "ssid": "psk-net",
                        "dns_ok": True,
                        "dns_via": "dig",
                        "dns_server": "10.6.0.1",
                        "routing_ok": True,
                        "speedtest": {"download_mbps": 187.6, "upload_mbps": 128.2, "jitter_ms": 2.4},
                    }
                ]
            }
        ),
    )
    r = wifi_experience.load()["results"][0]
    assert r["dns_via"] == "dig"
    assert r["dns_server"] == "10.6.0.1"
    assert r["routing_ok"] is True
    assert r["speedtest"]["upload_mbps"] == 128.2


def test_a_result_without_a_captive_portal_block_is_left_alone(monkeypatch, tmp_path) -> None:
    # Defensive: the battery emits captive_portal for every profile today, but a
    # partial write or a future shape change must not KeyError the whole bundle.
    _enable(monkeypatch)
    _artifact(monkeypatch, tmp_path, json.dumps({"results": [{"ssid": "x"}, {"ssid": "y", "captive_portal": None}]}))
    out = wifi_experience.load()
    assert out["available"] is True
    assert len(out["results"]) == 2


# --- portal URLs handed to curl (host script) -------------------------------------

def _run_url_escape(url: str) -> str:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("needs bash")
    script = Path(__file__).resolve().parents[2] / "scripts" / "netmon-wifi-experience.sh"
    m = re.search(r"^_url_escape\(\) \{\n.*?^\}\n", script.read_text(encoding="utf-8"), re.S | re.M)
    assert m, "_url_escape not found in the battery script"
    out = subprocess.run([bash, "-c", m.group(0) + '_url_escape "$1"', "_", url],
                         capture_output=True, check=True)
    return out.stdout.decode()


def test_portal_url_with_spaces_becomes_one_curl_accepts() -> None:
    # Aruba Central's redirect carries the AP group name unencoded. curl rejects a URL
    # with a space outright (exit 3), which is why the Aruba accept never once worked.
    url = ("https://portal.example/capture?cmd=login&vcname=Tech Services Test Group"
           "&url=http%3A%2F%2Fconnectivitycheck.gstatic.com%2Fgenerate_204")
    got = _run_url_escape(url)
    assert " " not in got
    assert "vcname=Tech%20Services%20Test%20Group&url=http%3A%2F%2F" in got


def test_portal_url_escape_drops_control_bytes_and_keeps_clean_urls() -> None:
    assert _run_url_escape("http://a.example/x\ty\r") == "http://a.example/xy"
    clean = "https://a.example/p?a=1&b=%20"
    assert _run_url_escape(clean) == clean


def test_every_portal_url_is_escaped_and_passed_as_url() -> None:
    # The helper alone is not the fix: the dispatcher and the vendor probe must call it,
    # and no portal fetch may hand curl a bare positional URL an AP could start with "-".
    script = (Path(__file__).resolve().parents[2] / "scripts" / "netmon-wifi-experience.sh").read_text(encoding="utf-8")
    body = re.search(r"^_captive_try_accept\(\) \{\n.*?^\}\n", script, re.S | re.M)
    vendor = re.search(r"^_captive_vendor\(\) \{\n.*?^\}\n", script, re.S | re.M)
    assert body and 'url="$(_url_escape "$url")"' in body.group(0)
    assert vendor and 'redir="$(_url_escape "$redir")"' in vendor.group(0)
    section = script[script.index("_captive_vendor() {"):script.index("_webperf_one() {")]
    lines = section.replace("\\\n", " ").splitlines()
    commands = [c for c in lines if "curl " in c and not c.lstrip().startswith("#")]
    portal = [c for c in commands if "-w '%{http_code}'" not in c]  # the generate_204 poll is fixed
    assert len(portal) == 10, portal
    for cmd in portal:
        assert '--url "' in cmd, cmd
