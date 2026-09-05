"""PERF-7 trigger: WHEN the sensor decides to investigate its own path.

The measurement that explains a WAN outage can only be taken during the outage,
and that is exactly when the dashboard cannot queue a command — the command
channel runs over the path being diagnosed. So the sensor decides for itself.
Deciding well is the whole risk:

  * Fire on a real network fault, or the outage is again just a gap in the data.
  * Do NOT fire when the dashboard merely answered badly (a deploy 502, a
    rotated-token 401). Those are application facts about the dashboard, and a
    ladder for each one trains everyone to ignore the signal.
  * Do NOT fire every three-minute check-in through a multi-day outage.

The distinguishing fact is already in `_post_status`'s contract: it returns an
HTTP status whenever the server RESPONDED, and None only when the request never
completed (DNS/TCP/TLS/timeout). That is a network fact, and — because check-in
is an HTTPS POST — it is also a TCP-level control by construction, which is what
the stateful-firewall case needs and what a ping-based trigger would miss.

Pure unit tests: the spawn is monkeypatched, so no process is ever started.
"""

from __future__ import annotations

from types import SimpleNamespace

from collector import checkin
from collector import wan_path


def _settings(**over):
    base = {
        "dashboard_url": "https://dash",
        "enroll_token": "tok",
        "update_channel": "stable",
        "latency_enabled": False,
        "latency_targets": "",
        "snmp_enabled": False,
        "snmp_communities": "",
        "snmp_exclude": "",
        "snmp_topology_enabled": False,
        "snmp_topology_scope": "",
        "snmp_topology_max_depth": 2,
        "snmp_topology_interval": 3600,
        "bundle_transport": "blob",
        "wan_path_enabled": True,
        "wan_path_targets": "1.1.1.1,8.8.8.8",
        "wan_path_min_interval_sec": 900,
        "wan_path_daily_cap": 48,
        "wan_path_baseline_interval_sec": 24 * 3600,
    }
    base.update(over)
    return SimpleNamespace(**base)


def _harness(monkeypatch, tmp_path, *, status, settings=None):
    """Stand run_checkin up with every side effect stubbed but the trigger."""
    monkeypatch.setattr(wan_path, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(wan_path, "BASELINE_FILE", tmp_path / "baseline.json")
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DIR", tmp_path / "spool")
    monkeypatch.setattr(checkin, "get_settings", lambda: settings or _settings())
    monkeypatch.setattr(checkin, "_current_token", lambda _s: "tok")
    monkeypatch.setattr(checkin, "wait_for_db", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_read_applied_version", lambda: 7)
    monkeypatch.setattr(checkin, "_local_net", lambda: ("10.8.2.100", "eth0", None))
    monkeypatch.setattr(checkin, "_current_sha", lambda: "abc123")
    monkeypatch.setattr(checkin, "_last_update", lambda: None)
    monkeypatch.setattr(checkin, "_last_host_action", lambda: None)
    monkeypatch.setattr(checkin, "_interfaces", lambda: [])
    monkeypatch.setattr(checkin, "_note_checkin_auth", lambda *a, **k: None)
    monkeypatch.setattr(checkin.host_metrics_mod, "collect", lambda: {})
    monkeypatch.setattr(checkin, "_maybe_latency", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_maybe_scheduled_iperf", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_maybe_scheduled_speedtest", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_maybe_webperf", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_drain_result_spool", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: {})
    ok = status is not None and 200 <= status < 300
    resp = ({"config": None, "commands": []}, status) if ok else (None, status)
    monkeypatch.setattr(checkin, "_post_status", lambda *a, **k: resp)

    spawned: list[str] = []
    monkeypatch.setattr(
        checkin, "_spawn_wan_path", lambda reason: (spawned.append(reason), True)[1]
    )
    return spawned


def test_a_network_level_failure_triggers_a_capture(monkeypatch, tmp_path):
    """No HTTP status = the request never completed = a fact about the path."""
    spawned = _harness(monkeypatch, tmp_path, status=None)

    rc = checkin.run_checkin()

    assert rc == 1
    assert spawned == ["outage"], (
        "this is the one window in which the evidence can be collected at all"
    )


def test_a_dashboard_deploy_does_not_trigger_a_capture(monkeypatch, tmp_path):
    """502 means the server ANSWERED. The path is fine; the app is restarting."""
    spawned = _harness(monkeypatch, tmp_path, status=502)

    assert checkin.run_checkin() == 1
    assert spawned == [], (
        "every dashboard deploy would otherwise fire a ladder on every sensor"
    )


def test_an_auth_failure_does_not_trigger_a_capture(monkeypatch, tmp_path):
    """401 is a fact about our credential, not about the network."""
    spawned = _harness(monkeypatch, tmp_path, status=401)

    assert checkin.run_checkin() == 1
    assert spawned == []


def test_repeated_outage_checkins_are_rate_limited(monkeypatch, tmp_path):
    """A 3-minute check-in cadence must not mean a ladder every 3 minutes."""
    spawned = _harness(monkeypatch, tmp_path, status=None)

    checkin.run_checkin()
    checkin.run_checkin()
    checkin.run_checkin()

    assert spawned == ["outage"], "the interval floor holds across process runs"
    assert wan_path.load_state()["degraded"] is True


def test_the_daily_cap_stops_a_flapping_circuit(monkeypatch, tmp_path):
    spawned = _harness(
        monkeypatch, tmp_path,
        status=None,
        settings=_settings(wan_path_daily_cap=2, wan_path_min_interval_sec=120),
    )
    import time as _t
    for _ in range(5):
        # Age the ledger past the interval floor each round so ONLY the daily cap
        # is under test.
        st = wan_path.load_state()
        if st:
            st["last_run"] = _t.time() - 9999
            wan_path.save_state(st)
        checkin.run_checkin()

    assert spawned == ["outage", "outage"], "capped, not unbounded"


def test_recovery_is_captured_once_the_path_comes_back(monkeypatch, tmp_path):
    """Both ends of the break belong in the record, including the healed path."""
    spawned = _harness(monkeypatch, tmp_path, status=None)
    checkin.run_checkin()
    assert spawned == ["outage"]

    # Now the check-in succeeds.
    _harness(monkeypatch, tmp_path, status=200)
    spawned2: list[str] = []
    monkeypatch.setattr(
        checkin, "_spawn_wan_path", lambda reason: (spawned2.append(reason), True)[1]
    )
    checkin.run_checkin()

    assert spawned2 == ["recovery"]
    # The flag stays set until the CHILD writes the capture (see
    # test_recovery_does_not_clear_degraded_on_spawn), so a run killed by the
    # watchdog retries instead of being recorded as handled. Simulate the child
    # finishing, which is what the `wan-path --reason recovery` command does.
    st = wan_path.load_state()
    st["degraded"] = False
    wan_path.save_state(st)

    # …and it does not keep re-capturing once recovered.
    spawned2.clear()
    checkin.run_checkin()
    assert spawned2 == ["baseline"], (
        "with no baseline on file the healthy path refreshes it, once"
    )


def test_recovery_does_not_clear_degraded_on_spawn(monkeypatch, tmp_path):
    """The watchdog restarts this container every 15 min during a long outage.

    Clearing `degraded` when the recovery capture is SPAWNED means a killed run
    is recorded as handled and the healed-path snapshot is lost for good. The
    child clears it once the capture is on disk.
    """
    _harness(monkeypatch, tmp_path, status=None)
    checkin.run_checkin()
    assert wan_path.load_state()["degraded"] is True

    spawned = _harness(monkeypatch, tmp_path, status=200)
    checkin.run_checkin()

    assert spawned == ["recovery"]
    assert wan_path.load_state()["degraded"] is True, (
        "still degraded until the child actually writes the capture"
    )


def test_recovery_is_exempt_from_the_daily_cap(monkeypatch, tmp_path):
    """Otherwise an outage that exhausts the cap latches `degraded` all day."""
    settings = _settings(wan_path_daily_cap=1, wan_path_min_interval_sec=120)
    _harness(monkeypatch, tmp_path, status=None, settings=settings)
    checkin.run_checkin()
    st = wan_path.load_state()
    assert st["runs_today"] == 1 and st["degraded"] is True

    spawned = _harness(monkeypatch, tmp_path, status=200, settings=settings)
    checkin.run_checkin()

    assert spawned == ["recovery"], "the healed-path snapshot outranks the cap"


def test_no_valid_targets_does_not_burn_the_daily_cap(monkeypatch, tmp_path):
    """A hostname in the target list must not spend the day's captures.

    `targets_from` keeps only IP literals, so the child would exit before writing
    a baseline; `updated_at` never advances and every healthy check-in respawns
    one — until the cap is gone and a real outage that day gets nothing.
    """
    spawned = _harness(
        monkeypatch, tmp_path, status=200,
        settings=_settings(wan_path_targets="cloudflare.com"),
    )
    for _ in range(4):
        checkin.run_checkin()

    assert spawned == []
    assert wan_path.load_state() == {}, "no ledger churn either"


def test_a_healthy_box_refreshes_a_stale_baseline(monkeypatch, tmp_path):
    """The baseline cannot be collected after the outage — it must exist before."""
    spawned = _harness(monkeypatch, tmp_path, status=200)
    wan_path.save_baseline(
        {"updated_at": "2020-01-01T00:00:00+00:00", "sample_count": 8, "modes": {}}
    )

    checkin.run_checkin()

    assert spawned == ["baseline"]


def test_a_fresh_baseline_is_left_alone(monkeypatch, tmp_path):
    from datetime import UTC, datetime

    spawned = _harness(monkeypatch, tmp_path, status=200)
    wan_path.save_baseline(
        {"updated_at": datetime.now(UTC).isoformat(), "sample_count": 8, "modes": {}}
    )

    checkin.run_checkin()

    assert spawned == [], "one baseline a day, not one per check-in"


def test_the_feature_can_be_turned_off(monkeypatch, tmp_path):
    spawned = _harness(
        monkeypatch, tmp_path, status=None, settings=_settings(wan_path_enabled=False)
    )

    assert checkin.run_checkin() == 1
    assert spawned == []
