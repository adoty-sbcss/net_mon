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
import os
import re
import shutil
import subprocess
import tempfile
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


_BATTERY = Path(__file__).resolve().parents[2] / "scripts" / "netmon-wifi-experience.sh"


def _shipped_fn(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", _BATTERY.read_text(encoding="utf-8"), re.S | re.M)
    assert m, f"{name} not found in the battery script"
    return m.group(0)


def _run_fn(name: str, stubs: str, call: str, **env: str) -> tuple[str, list[str]]:
    """Run one shipped function under the script's own shell options with stubbed tools.
    Stubs log what they were called with, so the order of side effects can be checked."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("needs bash")
    code = ('set -uo pipefail\nSUDO=""; log() { printf "%s\\n" "$*" >> "$LOG"; }\n'
            + stubs + _shipped_fn(name) + call)
    with tempfile.TemporaryDirectory() as d:
        # a file, not `bash -c`: a whole function can exceed the Windows command-line limit
        log, script = Path(d) / "log", Path(d) / "run.sh"
        script.write_text(code, encoding="utf-8", newline="\n")
        out = subprocess.run([bash, script.as_posix()], capture_output=True, env=dict(os.environ, LOG=str(log), **env), check=True)
        return out.stdout.decode(), (log.read_text().splitlines() if log.exists() else [])


def _run_reassociate(lease: str, routers: str, up_ok: bool = True) -> tuple[str, list[str]]:
    stubs = (
        '_wifi_conname() { printf "netmon-wifi-%s" "$1"; }\n'
        '_routing_teardown() { log teardown; }\n'
        'sleep() { :; }\n'
        'nmcli() { log nmcli "$@"; if [[ "$*" == *"con up"* ]]; then [[ "$UP_OK" == 1 ]]; return; fi;'
        ' if [[ "$*" == *DHCP4.OPTION* ]]; then printf "%s" "$ROUTERS"; fi; }\n'
        'ip() { [[ -n "$LEASE" ]] && printf "3: wlan0 inet %s brd x scope global\\n" "$LEASE"; }\n'
    )
    return _run_fn("_captive_reassociate", stubs + _shipped_fn("_lease_gateway"),
                   '_captive_reassociate wlan0 Guest; echo "rc=$?"',
                   LEASE=lease, ROUTERS=routers, UP_OK="1" if up_ok else "0")


def test_reassociate_rejoins_the_same_profile_and_reports_the_new_lease() -> None:
    out, calls = _run_reassociate("10.6.0.89/22", "requested_routers = 1, routers = 10.6.3.254")
    assert out == "10.6.0.89/22\t10.6.3.254rc=0\n"
    assert calls[0] == "teardown"  # routing comes down before the link drops
    assert calls[1] == "nmcli con down netmon-wifi-Guest"
    assert calls[2] == "nmcli --wait 25 con up netmon-wifi-Guest"


def test_reassociate_fails_cleanly_without_a_lease_or_gateway() -> None:
    assert _run_reassociate("", "routers = 10.6.3.254")[0] == "rc=1\n"
    assert _run_reassociate("10.6.0.89/22", "")[0] == "rc=1\n"
    assert _run_reassociate("10.6.0.89/22", "routers = 10.6.3.254", up_ok=False)[0] == "rc=1\n"


def test_link_info_keeps_fields_in_place_when_signal_is_blank() -> None:
    # An empty first field must not shift BSSID into the signal slot (the IFS-tab trap).
    stubs = (
        'nmcli() { if [[ "$*" == *SIGNAL* ]]; then printf "*::Guest\\n"; '
        'else printf "*:74\\\\:9E\\\\:75\\\\:CB\\\\:50\\\\:66:5180 MHz:540 Mbit/s\\n"; fi; }\n'
    )
    out, _ = _run_fn("_link_info", stubs, '_link_info wlan0')
    assert out.split("\t") == ["", "74:9E:75:CB:50:66", "5GHz", "540", "quality"]


def test_link_info_on_networkd_reads_the_supplicant_in_dbm() -> None:
    stubs = (
        '_wifi_backend() { printf networkd; }\n'
        'wifi_networkd_link() { printf -- "-58\\taa:bb:cc:00:11:22\\t2437\\t72"; }\n'
    )
    out, _ = _run_fn("_link_info", stubs, '_link_info wlan0')
    assert out.split("\t") == ["-58", "aa:bb:cc:00:11:22", "2.4GHz", "72", "dbm"]


def test_networkd_reassociate_and_lease_values_come_from_the_supplicant_and_lease() -> None:
    stubs = (
        '_wifi_backend() { printf networkd; }\n_wifi_conname() { printf "netmon-wifi-%s" "$1"; }\n'
        '_routing_teardown() { log teardown; }\nsleep() { :; }\n'
        'wifi_networkd_reassociate() { log "reassociate $1"; }\n'
        'wifi_networkd_lease() { log "lease $2"; printf 10.9.0.1; }\n'
        'nmcli() { log "nmcli $*"; }\n'
        'ip() { printf "3: wlo1 inet 10.9.0.50/24 brd x scope global\\n"; }\n'
    )
    out, calls = _run_fn("_captive_reassociate", stubs + _shipped_fn("_lease_gateway"),
                         '_captive_reassociate wlo1 Guest')
    assert out == "10.9.0.50/24\t10.9.0.1"
    assert calls == ["teardown", "reassociate wlo1", "lease ROUTER"]  # no nmcli on networkd


# _run_profile with every helper and network tool stubbed. A portal is always up until the
# rejoin; _routing_setup succeeds for the first SETUP_OK calls only; probe tools log
# "PROBE ..." so a probe that ran without verified routing is visible.
_PROFILE_STUBS = (
    'RT_TABLE=51\n_now_ms() { echo 0; }\nsleep() { :; }\nwifi_join() { log "join table=$6"; }\nwifi_leave() { log leave; }\n'
    'current_value() { if [[ "$1" == NETMON_WEBPERF_ENABLED ]]; then printf "%s" "$WEBPERF"; fi; }\n'
    'b64() { cat; }\nWEBPERF_URLS_FILE="$WPFILE"\n'
    'ip() { case "$*" in *"addr show"*) printf "3: wlan0 inet 10.6.0.89/22 brd x scope global\\n";;'
    ' *"route show default"*) printf "default via 10.8.3.254 dev eth0\\n";; esac; }\n'
    'nmcli() { log "nmcli $*"; if [[ "$*" == *DHCP4.OPTION* ]]; then printf "routers = 10.6.3.254"; fi; return 0; }\n'
    '_link_info() { if [[ -f "$OPEN" ]]; then printf "%s" "$LINK2"; else printf "%s" "$LINK"; fi; }\n'
    'SETUPS=0; _routing_setup() { SETUPS=$((SETUPS+1)); log "routing_setup $3"; (( SETUPS <= SETUP_OK )); }\n'
    '_routing_teardown() { log teardown; }\n'
    '_captive_probe() { log probe; if [[ -f "$OPEN" ]]; then printf "open\\t204\\t"; else printf "portal\\t302\\thttps://cg.example/x"; fi; }\n'
    '_captive_vendor() { printf aruba_central; }\n'
    '_captive_try_accept() { log accept; return "$ACCEPT_RC"; }\n'
    '_captive_reassociate() { log rejoin; [[ "$REJOIN_OPENS" == 1 ]] && : > "$OPEN"; printf "10.6.0.90/22\\t10.6.3.254"; }\n'
    '_wifi_conname() { printf "netmon-wifi-%s" "$1"; }\n'
    '_lease_gateway() { printf 10.6.3.254; }\n_lease_dns() { printf 10.6.3.1; }\n'
    'ping() { log "PROBE ping $*"; }\ncurl() { log "PROBE curl $*"; }\ndig() { log "PROBE dig $*"; }\n'
    'resolvectl() { log "PROBE resolvectl $*"; }\n_webperf_one() { log "PROBE webperf"; }\n'
)


def _run_profile(setup_ok: int, accept_rc: int = 1, rejoin_opens: bool = True) -> tuple[dict, list[str]]:
    # Speed test and webperf are on, so every optional probe block is exercised.
    with tempfile.TemporaryDirectory() as d:
        wp = Path(d) / "webperf-urls.json"
        wp.write_text('["https://site.example/"]', encoding="utf-8")
        out, calls = _run_fn("_run_profile", _PROFILE_STUBS, "_run_profile wlan0 Guest open '' '' 1 1",
                             SETUP_OK=str(setup_ok), ACCEPT_RC=str(accept_rc), OPEN=str(Path(d) / "open"),
                             REJOIN_OPENS="1" if rejoin_opens else "0", WEBPERF="true", WPFILE=wp.as_posix(),
                             LINK="61\taa:bb:cc:00:11:22\t\t", LINK2="58\taa:bb:cc:00:11:99\t\t")
    return json.loads(out), calls


def test_aruba_rejoin_opens_the_portal_and_measures_on_the_new_lease() -> None:
    res, calls = _run_profile(setup_ok=9)
    assert calls[0] == "join table=51"  # the joined subnet's route goes to the policy table
    # positive control: with routing verified, the optional blocks do run
    assert "PROBE webperf" in calls and any("speed.cloudflare.com/__up" in c for c in calls)
    assert calls.index("accept") < calls.index("rejoin") < calls.index("routing_setup 10.6.3.254", calls.index("rejoin"))
    cp = res["captive_portal"]
    assert cp["state"] == "open" and cp["auto_accepted"] is True and cp["rejoined"] is True
    assert res["ip"] == "10.6.0.90/22" and res["routing_ok"] is True
    assert res["link"]["bssid"] == "aa:bb:cc:00:11:99" and res["link"]["band"] == ""  # the post-rejoin AP
    assert any(c.startswith("PROBE ") for c in calls)


def test_unverified_routing_after_the_rejoin_measures_nothing() -> None:
    # Even if the disconnect does nothing (the nmcli stub always "succeeds" without
    # removing anything), no probe may run once routing could not be re-verified.
    res, calls = _run_profile(setup_ok=1)
    after = calls[calls.index("rejoin"):]
    assert not [c for c in after if c.startswith("PROBE ") or c == "probe"], after
    # dropped right there (wifi_leave), and again by the normal end-of-profile leave
    assert after.count("leave") == 2
    assert res["routing_ok"] is False and res["captive_portal"]["rejoined"] is True
    assert res["internet"]["ping_ok"] is False and res["throughput"]["download_mbps"] is None


def test_no_rejoin_when_no_accept_was_sent() -> None:
    res, calls = _run_profile(setup_ok=9, accept_rc=2)
    assert "rejoin" not in calls
    assert res["captive_portal"]["rejoined"] is False and res["captive_portal"]["auto_accepted"] is False


def test_aruba_accept_without_a_login_page_says_no_accept_was_sent() -> None:
    assert "return 2; }   # 2 = no accept was sent" in _shipped_fn("_accept_aruba_central")


# --- the one-battery lock ----------------------------------------------------------

def _lock(path: Path, hold: bool = False) -> str:
    """Take the shipped lock on `path`. hold=True takes it first on a separate open of
    the same file (flock(2) treats separate opens independently, even in one process).
    $SUDO is a stub that logs and runs its command, so privileged creation is visible."""
    if shutil.which("flock") is None:
        pytest.skip("needs flock (util-linux)")
    holder = 'exec 8>"$L"; flock 8\n' if hold else ""
    call = holder + '_take_battery_lock "$L"; echo "rc=$?"; echo "stderr-ok" >&2'
    bash = shutil.which("bash")
    assert bash
    sudo = 'fakesudo() { echo "SUDO $*"; "$@"; }; SUDO=fakesudo\n'
    code = "set -uo pipefail\n" + sudo + _shipped_fn("_take_battery_lock") + call
    out = subprocess.run([bash, "-c", code], capture_output=True, env=dict(os.environ, L=str(path)), check=True)
    return out.stdout.decode() + out.stderr.decode()


def test_battery_lock_opens_a_read_only_lock_left_by_root(tmp_path) -> None:
    # The scheduled run (root) leaves the lock 0644; the Test now host action runs as the
    # check-in user and must still be able to take it.
    if shutil.which("flock") is None:
        pytest.skip("needs flock (util-linux)")
    if getattr(os, "geteuid", lambda: 0)() == 0:
        pytest.skip("root can write any file; the bug only shows for a non-root caller")
    lock = tmp_path / ".wifi-experience.lock"
    lock.write_text("")
    lock.chmod(0o444)
    out = _lock(lock)
    assert "rc=0" in out and "stderr-ok" in out


def test_battery_lock_reports_a_held_lock_as_busy(tmp_path) -> None:
    assert "rc=1" in _lock(tmp_path / ".wifi-experience.lock", hold=True)


def test_battery_lock_creates_a_missing_lock_through_sudo(tmp_path) -> None:
    # The state dir may be root-owned, and a Test-now-only box has no root run to
    # create the lock, so the check-in user must create it with privilege.
    lock = tmp_path / ".wifi-experience.lock"
    out = _lock(lock)
    assert f"SUDO install -m 0644 /dev/null {lock}" in out and "rc=0" in out
    assert lock.exists() and (lock.stat().st_mode & 0o777) == 0o644
    assert "SUDO" not in _lock(lock)  # an existing lock needs no privilege


def test_battery_lock_reports_an_unopenable_lock_honestly(tmp_path) -> None:
    out = _lock(tmp_path / "missing-dir" / ".wifi-experience.lock")
    assert "rc=2" in out and "stderr-ok" in out


def test_main_distinguishes_busy_from_unopenable() -> None:
    main = _shipped_fn("main")
    assert '_take_battery_lock "${NETMON_STATE_DIR:-/var/lib/netmon}/.wifi-experience.lock"' in main
    assert "exec 9>" not in main  # the lock is opened only by the helper
    assert 'not running"; exit 1 ;;' in main  # an unopenable lock is a fault, not "ok"


def test_main_clears_leftover_policy_routing_before_the_first_join() -> None:
    main = _shipped_fn("main")
    assert main.index("_take_battery_lock") < main.index('_routing_teardown "$iface"') < main.index("_run_profile")


# --- the joined subnet stays out of the main table -----------------------------------

@pytest.mark.parametrize("cidr,net", [("10.6.0.89/22", "10.6.0.0/22"), ("192.168.71.57/24", "192.168.71.0/24"),
                                      ("10.0.0.5/32", "10.0.0.5/32"), ("010.1.1.1/8", "10.0.0.0/8"),
                                      ("172.16.5.4/12", "172.16.0.0/12"), ("10.6.0.89/08", "10.0.0.0/8")])
def test_ip4_net_masks_the_host_bits(cidr: str, net: str) -> None:
    out, _ = _run_fn("_ip4_net", "", f'_ip4_net "{cidr}"')
    assert out == net


@pytest.mark.parametrize("bad", ["10.6.0.89", "10.6.0.89/33", "10.6.0.89/0", "300.1.1.1/8", "a.b.c.d/8", "", "/24"])
def test_ip4_net_refuses_what_is_not_an_address_with_a_prefix(bad: str) -> None:
    out, _ = _run_fn("_ip4_net", "", f'_ip4_net "{bad}" || echo refused')
    assert out == "refused\n"


# `ip` against a main table that holds MAIN_ROUTE (one line per file line) until a
# delete removes it; DEL_OK=0 makes deletes fail. Every call is logged.
_ROUTE_STUBS = (
    'RT_TABLE=51; RT_RULE_PRIO=5100\n'
    '_wifi_is_uplink() { [[ "$UPLINK" == 1 ]]; }\n'
    'ip() { log "ip $*"; case "$*" in'
    ' "-4 route show table main dev wlan0"*) [[ -f "$MAIN" ]] && cat "$MAIN";;'
    ' "-4 route del "*) [[ "$DEL_OK" == 1 ]] && rm -f "$MAIN"; return;;'
    ' "rule show") printf "5100:\tfrom 10.6.0.89 lookup 51\n";;'
    ' esac; return 0; }\n'
)


def _route_fn(name: str, call: str, main_route: str, uplink: bool = False,
              del_ok: bool = True) -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory() as d:
        main = Path(d) / "main"
        if main_route:
            main.write_text(main_route + "\n", encoding="utf-8", newline="\n")
        stubs = (_ROUTE_STUBS + _shipped_fn("_ip4_net") + _shipped_fn("_main_table_clear")
                 + _shipped_fn("_routing_teardown"))
        return _run_fn(name, stubs, call, MAIN=main.as_posix(), UPLINK="1" if uplink else "0",
                       DEL_OK="1" if del_ok else "0")


_KERNEL_ROUTE = "10.6.0.0/22 proto kernel scope link src 10.6.0.89 metric 600"


def test_routing_setup_moves_the_joined_subnet_out_of_main() -> None:
    out, calls = _route_fn("_routing_setup", '_routing_setup wlan0 10.6.0.89 10.6.3.254 10.6.0.89/22 2>&1; echo "rc=$?"',
                           _KERNEL_ROUTE)
    assert out.endswith("rc=0\n") and "routing: main table has no route via wlan0\n" in out
    deleted = calls.index("ip -4 route del 10.6.0.0/22 dev wlan0 scope link table main")
    prefix = calls.index("ip route replace 10.6.0.0/22 dev wlan0 src 10.6.0.89 scope link table 51")
    default = calls.index("ip route replace default via 10.6.3.254 dev wlan0 onlink table 51")
    flushed = calls.index("ip route flush table 51")
    assert flushed < deleted < prefix < default  # leftovers gone, main cleared, then install
    # nothing is ever added to the main table
    assert not [c for c in calls if ("replace" in c or " add " in c) and "table 51" not in c and "rule" not in c]


def test_routing_setup_with_a_clean_main_table_deletes_nothing() -> None:
    out, calls = _route_fn("_routing_setup", '_routing_setup wlan0 10.6.0.89 10.6.3.254 10.6.0.89/22 2>&1; echo "rc=$?"',
                           "")
    assert out.endswith("rc=0\n") and not [c for c in calls if c.startswith("ip -4 route del")]
    assert "ip route replace 10.6.0.0/22 dev wlan0 src 10.6.0.89 scope link table 51" in calls


def test_main_table_clear_never_touches_an_uplink() -> None:
    out, calls = _route_fn("_main_table_clear", '_main_table_clear wlan0; echo "rc=$?"', _KERNEL_ROUTE, uplink=True)
    assert out == "rc=2\n" and not [c for c in calls if c.startswith("ip ")]


def test_routing_setup_names_the_uplink_guard_instead_of_an_empty_leftover() -> None:
    out, calls = _route_fn("_routing_setup", '_routing_setup wlan0 10.6.0.89 10.6.3.254 10.6.0.89/22 2>&1; echo "rc=$?"',
                           _KERNEL_ROUTE, uplink=True)
    assert "routing: wlan0 carries a default route — main table left alone\n" in out
    assert "still routes" not in out and not [c for c in calls if c.startswith("ip -4 route del")]


def test_main_table_clear_leaves_a_default_alone_and_says_so() -> None:
    out, calls = _route_fn("_main_table_clear", '_main_table_clear wlan0; echo "rc=$?"', "default scope link")
    assert out == "rc=1\n" and not [c for c in calls if " del " in c]


def test_a_route_that_will_not_go_is_reported_and_probing_still_proceeds() -> None:
    # The leftover is the pre-fix behaviour, not a reason to measure nothing: warn, go on.
    out, calls = _route_fn("_routing_setup", '_routing_setup wlan0 10.6.0.89 10.6.3.254 10.6.0.89/22 2>&1; echo "rc=$?"',
                           _KERNEL_ROUTE, del_ok=False)
    assert out.endswith("rc=0\n") and f"routing: main table still routes via wlan0: {_KERNEL_ROUTE};" in out
    assert len([c for c in calls if c.startswith("ip -4 route del")]) == 1  # one attempt, no spinning


def test_every_battery_join_and_routing_setup_uses_the_policy_table() -> None:
    prof = _shipped_fn("_run_profile")
    assert 'wifi_join "$iface" "$ssid" "${auth:-open}" "$identity" "$secret" "$RT_TABLE"' in prof
    setups = re.findall(r"_routing_setup [^\n]*", prof)
    assert len(setups) == 2 and all(s.startswith('_routing_setup "$iface" "$srcip" "$gw" "$ip4"') for s in setups)
