"""NOTIF-8 active monitoring: every rule here exists because its absence lies.

* A target never seen up from this sensor is "never", not "down" (positive
  control): a management VLAN we can't route to must not become an outage.
* Down only after 2 consecutive failed cycles; up after 1 success.
* A blind cycle (our gateway dead, or everything failing at once) moves nothing.
* A target the budget didn't reach is skipped, and its state doesn't move.
* The pushed list is untrusted ping argv: IP literals only, no special ranges,
  strict keys, capped — and an invalid list is refused whole, keeping the old one.
* The pending report survives an unreachable dashboard and is cleared only after a
  check-in the dashboard accepted; dropped events are counted, never silent.

Pure unit tests: no network, no ping. Paths are redirected to tmp_path.
"""

from __future__ import annotations

import json

import pytest

from collector import watch

T = [
    {"key": "switch:1", "ip": "10.0.0.2", "label": "IDF-1"},
    {"key": "switch:2", "ip": "10.0.0.3", "label": "IDF-2"},
    {"key": "host:9", "ip": "10.0.0.9", "label": "SRV"},
]


def run(state, results, now, gateway_ok=True, targets=T):
    return watch.step(state, targets, results, now, gateway_ok)


# --- validation ---------------------------------------------------------------------


def test_valid_list_is_accepted_and_deduped():
    out, refused = watch.validate_targets(T + [T[0]])
    assert refused is None
    assert [t["key"] for t in out] == ["switch:1", "switch:2", "host:9"]


@pytest.mark.parametrize(
    "bad",
    [
        {"key": "k", "ip": "example.org"},  # hostname: resolution happens before any deadline
        {"key": "k", "ip": "-c9999"},  # an option in front of ping's host operand
        {"key": "k", "ip": "127.0.0.1"},
        {"key": "k", "ip": "224.0.0.1"},
        {"key": "k", "ip": "0.0.0.0"},
        {"key": "k", "ip": "169.254.1.1"},
        {"key": "bad key!", "ip": "10.0.0.1"},
        {"key": "k" * 65, "ip": "10.0.0.1"},
        "not-an-object",
    ],
)
def test_one_bad_target_refuses_the_whole_list(bad):
    out, refused = watch.validate_targets(T + [bad])
    assert out == [] and refused


def test_public_unicast_is_allowed_districts_run_public_blocks_internally():
    out, refused = watch.validate_targets([{"key": "k", "ip": "8.8.8.8"}])
    assert refused is None and out[0]["ip"] == "8.8.8.8"


def test_list_is_capped_and_labels_truncated():
    too_many = [{"key": f"k{i}", "ip": f"10.1.{i // 250}.{i % 250 + 1}"} for i in range(watch.MAX_TARGETS + 1)]
    assert watch.validate_targets(too_many)[1]
    out, _ = watch.validate_targets([{"key": "k", "ip": "10.0.0.1", "label": "x" * 500}])
    assert len(out[0]["label"]) == watch.MAX_LABEL


# --- the state machine -----------------------------------------------------------------


def test_never_seen_up_is_never_down():
    state = {}
    for n in range(5):
        state, events, summary = run(state, {"switch:1": False, "switch:2": True, "host:9": True}, now=100 + n)
    assert state["targets"]["switch:1"]["state"] == "never"
    assert events == [] and summary["never"] == 1 and summary["down"] == 0


def test_down_after_two_failed_cycles_then_up_after_one_success():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    one_down = {"switch:1": False, "switch:2": True, "host:9": True}
    state, events, _ = run({}, up, now=0)
    assert state["targets"]["switch:1"]["first_up_at"] == 0
    state, events, _ = run(state, one_down, now=180)
    assert events == [] and state["targets"]["switch:1"]["state"] == "up"  # one failure: no edge
    state, events, _ = run(state, one_down, now=360)
    assert [(e["key"], e["edge"]) for e in events] == [("switch:1", "down")]
    assert state["targets"]["switch:1"]["since"] == 360
    state, events, _ = run(state, one_down, now=540)
    assert events == []  # already down: no repeat edge
    state, events, _ = run(state, up, now=720)
    assert [(e["key"], e["edge"], e["down_since"]) for e in events] == [("switch:1", "up", 360)]


def test_a_blind_cycle_moves_nothing_when_our_gateway_is_dead():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    dead = {"switch:1": False, "switch:2": False, "host:9": False}
    for n in (1, 2, 3):
        state, events, summary = run(state, dead, now=n * 180, gateway_ok=False)
        assert summary["blind"]
        # Losing the view is itself news, once; no device edge ever.
        assert [e["edge"] for e in events] == (["blind"] if n == 1 else [])
    assert all(s["state"] == "up" and s["fails"] == 0 for s in state["targets"].values())


def test_three_dead_switches_under_a_live_gateway_are_a_site_event_not_blindness():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    dead = {"switch:1": False, "switch:2": False, "host:9": False}
    state, events, summary = run(state, dead, now=180, gateway_ok=True)
    state, events, summary = run(state, dead, now=360, gateway_ok=True)
    assert not summary["blind"]
    assert sorted(e["key"] for e in events if e.get("edge") == "down") == ["host:9", "switch:1", "switch:2"]


def test_everything_failing_at_once_is_blind_even_with_no_gateway_answer():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    dead = {"switch:1": False, "switch:2": False, "host:9": False}
    state, events, summary = run(state, dead, now=180, gateway_ok=None)
    state, events, summary = run(state, dead, now=360, gateway_ok=None)
    assert summary["blind"] and events == []  # the "blind" edge came on the first cycle


def test_skipped_targets_do_not_move():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    for n in (1, 2, 3):
        state, events, summary = run(state, {"switch:1": None, "switch:2": True, "host:9": True}, now=n * 180)
        assert events == [] and summary["skipped"] == 1
    assert state["targets"]["switch:1"]["state"] == "up"


def test_targets_removed_from_the_list_are_dropped():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    state, _, summary = run(state, {"switch:1": True}, now=180, targets=T[:1])
    assert set(state["targets"]) == {"switch:1"} and summary["targets"] == 1


# --- the report --------------------------------------------------------------------------


def test_pending_events_are_capped_and_the_drop_is_counted():
    rep = None
    ev = [{"key": "k", "edge": "down", "at": i} for i in range(watch.MAX_PENDING_EVENTS + 7)]
    rep = watch.merge_report(rep, 1, {"at": 0}, ev, None)
    assert len(rep["events"]) == watch.MAX_PENDING_EVENTS and rep["dropped_events"] == 7
    assert rep["events"][0]["at"] == 7  # oldest dropped first


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setattr(watch, "TARGETS_FILE", tmp_path / "watch-targets.json")
    monkeypatch.setattr(watch, "STATE_FILE", tmp_path / "watch-state.json")
    monkeypatch.setattr(watch, "REPORT_FILE", tmp_path / "watch-report.json")
    return tmp_path


def test_a_refused_list_keeps_the_previous_targets_and_reports_the_refusal(files):
    watch.accept_targets({"version": 1, "targets": T})
    watch.accept_targets({"version": 2, "targets": [{"key": "k", "ip": "evil.example"}]})
    stored = json.loads(watch.TARGETS_FILE.read_text())
    assert [t["key"] for t in stored["targets"]] == ["switch:1", "switch:2", "host:9"]
    assert stored["refused"] and stored["refused_version"] == 2


def test_same_version_is_not_rewritten(files):
    watch.accept_targets({"version": 5, "targets": T})
    before = watch.TARGETS_FILE.stat().st_mtime_ns
    watch.accept_targets({"version": 5, "targets": T[:1]})
    assert watch.TARGETS_FILE.stat().st_mtime_ns == before


def test_a_cycle_accumulates_until_cleared(files, monkeypatch):
    watch.accept_targets({"version": 1, "targets": T})
    monkeypatch.setattr(watch, "_ping", lambda ip: ip != "10.0.0.2")
    # First cycle: 10.0.0.2 never answered → "never", no events, but a summary.
    rep = watch.run_cycle(lambda: "10.0.0.1")
    assert rep["last"]["never"] == 1 and rep["events"] == []
    assert watch.pending_report() is not None
    watch.clear_report()
    assert watch.pending_report() is None


def test_nothing_to_watch_is_a_no_op(files):
    called = []
    assert watch.run_cycle(lambda: called.append(1) or "10.0.0.1") is None
    assert watch.pending_report() is None
    assert called == [], "with no list, not even the gateway lookup runs"
    assert not list(files.iterdir()), "no file is created"


def test_a_readdressed_device_must_earn_the_positive_control_again():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    moved = [dict(T[0], ip="10.9.9.9")] + T[1:]
    for n in (1, 2, 3):
        state, events, _ = run(state, {"switch:1": False, "switch:2": True, "host:9": True}, now=n * 180, targets=moved)
        assert events == []
    assert state["targets"]["switch:1"]["state"] == "never"


# --- review fixes -------------------------------------------------------------------------


def test_visibility_changes_are_events_so_a_blind_stretch_leaves_a_trace():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    dead = {"switch:1": False, "switch:2": False, "host:9": False}
    state, _, _ = run({}, up, now=0)
    state, ev1, _ = run(state, dead, now=180, gateway_ok=False)
    state, ev2, _ = run(state, dead, now=360, gateway_ok=False)
    state, ev3, _ = run(state, up, now=540, gateway_ok=True)
    assert [e["edge"] for e in ev1] == ["blind"] and ev2 == [] and [e["edge"] for e in ev3] == ["sighted"]
    rep = None
    for summary in ({"blind": True}, {"blind": True}, {"blind": False}):
        rep = watch.merge_report(rep, 1, summary, [], None)
    assert rep["blind_cycles"] == 2 and rep["cycles"] == 3, "the count survives a healthy last cycle"


def test_every_event_has_an_increasing_seq_that_survives_across_cycles():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    one_down = {"switch:1": False, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    state, _, _ = run(state, one_down, now=180)
    state, ev_down, _ = run(state, one_down, now=360)
    state, ev_up, _ = run(state, up, now=540)
    assert ev_down[0]["seq"] < ev_up[0]["seq"] and state["seq"] == ev_up[-1]["seq"]


def test_readdressing_a_down_device_closes_it_out():
    up = {"switch:1": True, "switch:2": True, "host:9": True}
    one_down = {"switch:1": False, "switch:2": True, "host:9": True}
    state, _, _ = run({}, up, now=0)
    state, _, _ = run(state, one_down, now=180)
    state, _, _ = run(state, one_down, now=360)
    moved = [dict(T[0], ip="10.9.9.9")] + T[1:]
    state, events, _ = run(state, one_down, now=540, targets=moved)
    assert [(e["key"], e["edge"], e["ip"]) for e in events] == [("switch:1", "cleared", "10.0.0.2")]


@pytest.mark.parametrize("ip", ["2001:db8::1%eth0", "fe80::1%eth0", "::ffff:127.0.0.1"])
def test_scoped_and_mapped_loopback_addresses_are_refused(ip):
    assert watch.validate_targets([{"key": "k", "ip": ip}])[1]


def test_ipv4_mapped_addresses_are_normalised():
    out, _ = watch.validate_targets([{"key": "k", "ip": "::ffff:10.0.0.1"}])
    assert out[0]["ip"] == "10.0.0.1"


def test_the_report_carries_a_snapshot_and_the_refused_version(files, monkeypatch):
    watch.accept_targets({"version": "a", "targets": T})
    watch.accept_targets({"version": "b", "targets": [{"key": "k", "ip": "evil.example"}]})
    monkeypatch.setattr(watch, "_ping", lambda ip: True)
    rep = watch.run_cycle(lambda: None)
    assert set(rep["states"]) == {"switch:1", "switch:2", "host:9"}
    assert rep["states"]["switch:1"]["state"] == "up"
    assert rep["refused"] and rep["refused_version"] == "b" and rep["version"] == "a"


def test_the_report_is_written_before_the_state(files, monkeypatch):
    watch.accept_targets({"version": 1, "targets": T})
    monkeypatch.setattr(watch, "_ping", lambda ip: True)
    order = []
    real = watch._write_json_atomic
    monkeypatch.setattr(watch, "_write_json_atomic", lambda p, d: (order.append(p.name), real(p, d)))
    watch.run_cycle(lambda: None)
    assert order == ["watch-report.json", "watch-state.json"]


def test_a_tampered_targets_file_is_revalidated_on_read(files, monkeypatch):
    watch.TARGETS_FILE.write_text(json.dumps({"version": 1, "targets": [{"key": "k", "ip": "-c9999"}]}), encoding="utf-8")
    pinged = []
    monkeypatch.setattr(watch, "_ping", lambda ip: pinged.append(ip) or True)
    rep = watch.run_cycle(lambda: None)
    assert pinged == [] and rep["refused"]


# --- the real run_checkin (behavioural wiring) ----------------------------------------


def _checkin_harness(monkeypatch, tmp_path, *, checkin_ok, resp_watch=None):
    from types import SimpleNamespace

    import collector as collector_pkg
    import collector.latency  # noqa: F401 — so the package attribute exists to patch
    from collector import checkin

    monkeypatch.setattr(watch, "TARGETS_FILE", tmp_path / "watch-targets.json")
    monkeypatch.setattr(watch, "STATE_FILE", tmp_path / "watch-state.json")
    monkeypatch.setattr(watch, "REPORT_FILE", tmp_path / "watch-report.json")
    monkeypatch.setattr(watch, "_ping", lambda ip: ip != "10.0.0.2")
    settings = SimpleNamespace(
        dashboard_url="https://dash", enroll_token="tok", update_channel="stable",
        latency_enabled=False, latency_targets="", voice_enabled=False, speedtest_enabled=False,
        speedtest_schedule_sec=21600, snmp_enabled=False, snmp_communities="", snmp_exclude="",
        snmp_topology_enabled=False, snmp_topology_scope="", snmp_topology_max_depth=2,
        snmp_topology_interval=3600, bundle_transport="blob", capture_seconds=120,
        capture_interval=900, rescan_interval=3600,
    )
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DIR", tmp_path / "spool")
    monkeypatch.setattr(checkin, "get_settings", lambda: settings)
    monkeypatch.setattr(checkin, "_current_token", lambda _s: "tok")
    monkeypatch.setattr(checkin, "wait_for_db", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_read_applied_version", lambda: 7)
    monkeypatch.setattr(checkin, "_local_net", lambda: ("10.0.0.50", "eth0", "10.0.0.0/24"))
    monkeypatch.setattr(checkin, "_current_sha", lambda: "abc")
    monkeypatch.setattr(checkin, "_last_update", lambda: None)
    monkeypatch.setattr(checkin, "_last_host_action", lambda: None)
    monkeypatch.setattr(checkin, "_interfaces", lambda: [])
    monkeypatch.setattr(checkin, "_note_checkin_auth", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_egress_report", lambda: None)
    monkeypatch.setattr(checkin.host_metrics_mod, "collect", lambda: {})
    for name in ("_maybe_scheduled_iperf", "_maybe_scheduled_speedtest", "_maybe_webperf", "_maybe_latency",
                 "_maybe_voice", "_wan_path_on_failure", "_wan_path_on_success", "_report_wan_path",
                 "_drain_result_spool", "_missed_speedtest_on_failure"):
        monkeypatch.setattr(checkin, name, lambda *a, **k: None)
    monkeypatch.setattr(collector_pkg, "latency", SimpleNamespace(default_gateway=lambda: "10.0.0.1"))
    bodies = []

    def post_status(url, token, body):
        bodies.append(body)
        if not checkin_ok:
            return None, None
        return {"config": None, "commands": [], "watch": resp_watch}, 200

    monkeypatch.setattr(checkin, "_post_status", post_status)
    return checkin, bodies


def test_checkin_accepts_the_list_then_watches_after_the_post(monkeypatch, tmp_path):
    checkin, bodies = _checkin_harness(monkeypatch, tmp_path, checkin_ok=True, resp_watch={"version": "v1", "targets": T})
    assert checkin.run_checkin() == 0
    assert bodies[0]["watch"] is None, "nothing pending on the first check-in"
    rep = watch.pending_report()
    assert rep is not None and rep["version"] == "v1" and rep["last"]["probed"] == 3


def test_an_unreachable_dashboard_keeps_and_grows_the_report(monkeypatch, tmp_path):
    checkin, _ = _checkin_harness(monkeypatch, tmp_path, checkin_ok=True, resp_watch={"version": "v1", "targets": T})
    checkin.run_checkin()
    checkin, bodies = _checkin_harness(monkeypatch, tmp_path, checkin_ok=False)
    assert checkin.run_checkin() == 1
    assert bodies[0]["watch"]["cycles"] == 1, "the pending report went out in the body"
    assert watch.pending_report()["cycles"] == 2, "kept (not cleared) and grown by the offline cycle"


def test_a_successful_checkin_clears_what_it_carried(monkeypatch, tmp_path):
    checkin, _ = _checkin_harness(monkeypatch, tmp_path, checkin_ok=True, resp_watch={"version": "v1", "targets": T})
    checkin.run_checkin()
    checkin, bodies = _checkin_harness(monkeypatch, tmp_path, checkin_ok=True, resp_watch={"version": "v1", "targets": T})
    checkin.run_checkin()
    assert bodies[0]["watch"]["cycles"] == 1
    assert watch.pending_report()["cycles"] == 1, "cleared after the POST, then this cycle's fresh report"
