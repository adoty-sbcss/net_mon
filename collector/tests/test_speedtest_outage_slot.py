"""A WAN outage must leave a RECORD on the speed channel, not silence.

`_maybe_scheduled_speedtest` lives below `run_checkin`'s failure early-return, so
during a real outage the scheduled slot was simply skipped: a day's
speedtest_samples went 4 -> 3 -> 0 with not one failure on file. Zero rows is the
one result a reader cannot interpret, and downstream it was read BACKWARDS — the
dashboard's nightly prompt treats "no samples and no refusals" as "nothing arrived
at all, a sensor or upload question, not a bandwidth one". So a three-day WAN
outage on a perfectly healthy sensor pointed the tech at the sensor. That is the
same GAP-not-a-ROW mistake the latency probe already fixed one channel over (see
test_checkin_offline_latency.py).

The rules under test:
  * a due slot on the failure path is RECORDED as a non-attempt — a fourth
    status value, distinct from a measurement, from a failed transfer, and from
    the provider refusing us;
  * no probe is run: on a box whose check-in just died in the network, a speed
    test is 16 parallel streams each free to burn their full 60s timeout, on the
    one code path that exists to exit fast, for a result that is very likely
    undeliverable anyway;
  * it is SPOOLED, never POSTed — the dashboard is known unreachable this cycle;
  * the real slot is NOT consumed: the genuine test runs on the first healthy
    check-in after the link returns, exactly once, with no retroactive backlog;
  * the record is capped at ONE row per schedule interval, so a multi-day outage
    cannot flood (and thereby evict the onset from) the file-capped result spool;
  * a dashboard that ANSWERED (502 mid-deploy, 401 on a rotated token) records
    nothing — that says nothing about this box's path to the internet;
  * a provider cooldown, or speedtest disabled, records nothing.

Pure unit tests: no network, no DB. The prober and `_post` are the chokepoints and
are stubbed to FAIL if reached; every ledger is redirected into tmp_path.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from collector import checkin


def _settings(**over):
    # NETMON_SPEEDTEST_SCHEDULE_SEC default: 6h -> ~4 slots/day.
    base = {"speedtest_enabled": True, "speedtest_schedule_sec": 6 * 3600}
    base.update(over)
    return SimpleNamespace(**base)


def _arrange(monkeypatch, tmp_path):
    """Redirect every ledger + the spool into tmp_path, and make the two things
    that must NOT happen on this path (a probe, a POST) fail loudly if they do."""
    spool = tmp_path / "result-spool"
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DIR", spool)
    monkeypatch.setattr(checkin, "SPEEDTEST_LAST_FILE", tmp_path / "speedtest-last-run")
    monkeypatch.setattr(checkin, "SPEEDTEST_COOLDOWN_FILE", tmp_path / "speedtest-cooldown-until")
    monkeypatch.setattr(checkin, "SPEEDTEST_MISSED_FILE", tmp_path / "speedtest-missed-slot")

    import collector.speedtest as st

    monkeypatch.setattr(
        st,
        "run_speedtest",
        lambda *a, **k: pytest.fail("a speed test must NOT be probed during an outage"),
    )
    monkeypatch.setattr(
        checkin,
        "_post",
        lambda *a, **k: pytest.fail("the dashboard is known unreachable — no POST"),
    )
    return spool


def _spooled(spool) -> list[dict]:
    """Every spooled payload, oldest-first (filenames sort that way by design)."""
    out: list[dict] = []
    for f in sorted(spool.glob("*.json")):
        doc = json.loads(f.read_text())
        assert doc["endpoint"] == "/api/sensor/speedtest-result"
        out.extend(doc.get("payloads") or [doc["payload"]])
    return out


def _due(tmp_path, *, ago: float = 7 * 3600) -> None:
    """Put the real scheduler's ledger far enough back that the slot is due."""
    (tmp_path / "speedtest-last-run").write_text(str(time.time() - ago))


def test_a_due_slot_during_an_outage_is_recorded_not_skipped(monkeypatch, tmp_path):
    spool = _arrange(monkeypatch, tmp_path)
    _due(tmp_path)

    checkin._missed_speedtest_on_failure("https://dash", "tok", _settings(), None)

    rows = _spooled(spool)
    assert len(rows) == 1, "the slot came due and the box could not attempt it"
    row = rows[0]
    # Copied verbatim from a real _report_speedtest(spool_only=True) payload built
    # from collector.speedtest.not_attempted(...) — not typed from memory.
    assert row["status"] == "not_attempted"
    assert row["ok"] is False
    assert row["trigger"] == "scheduled"
    assert row["provider"] == "cloudflare"
    # NOTHING is asserted about the link's speed: every measurement field is null.
    # A row that says "we did not measure this" is the entire point.
    for field in (
        "downloadMbps",
        "uploadMbps",
        "latencyMs",
        "jitterMs",
        "lossPct",
        "server",
        "isp",
        "resultUrl",
        "externalIp",
    ):
        assert row[field] is None, field
    assert row["error"].startswith("not attempted"), row["error"]
    assert row["raw"] == {
        "not_attempted": True,
        "reason": "checkin_unreachable",
        "schedule_sec": 21600,
    }
    assert row["startedAt"], "stamped at record time so a late drain lands in the right bucket"


def test_the_recorded_status_is_not_a_measurement_and_not_a_refusal():
    """The four values are distinct, and the new one is its own.

    `failed` means we TRIED and the transfer broke — evidence about the link.
    `unavailable` means the PROVIDER refused us and the row says nothing about the
    link; rendering an outage that way would put "Cloudflare rate-limited us" in
    front of a tech whose WAN is down. Neither is what happened here.
    """
    from collector import speedtest as st

    assert st.STATUS_NOT_ATTEMPTED == "not_attempted"
    assert len({st.STATUS_OK, st.STATUS_FAILED, st.STATUS_UNAVAILABLE,
                st.STATUS_NOT_ATTEMPTED}) == 4
    res = st.not_attempted("no path", reason="checkin_unreachable")
    assert res["ok"] is False and res["status"] == "not_attempted"
    # Same dict shape every other non-ok outcome uses, so the wire payload cannot
    # drift between the healthy and the outage path.
    assert set(res) == {"ok", "status", "provider", "error", "raw"}


def test_the_real_slot_is_not_consumed_and_recovery_runs_it_once(monkeypatch, tmp_path):
    """The scheduler contract: record the miss, then let the genuine test run.

    Consuming SPEEDTEST_LAST_FILE here would make the box wait another full
    interval after the link returned — measuring nothing for the 6 hours the
    district most wants measured. Not consuming it must also NOT produce a
    backlog: a day of outage owes exactly one test on recovery, not four.
    """
    spool = _arrange(monkeypatch, tmp_path)
    last_file = tmp_path / "speedtest-last-run"
    _due(tmp_path, ago=25 * 3600)
    before = last_file.read_text()

    checkin._missed_speedtest_on_failure("https://dash", "tok", _settings(), None)

    assert last_file.read_text() == before, "the real slot must stay unconsumed"
    assert len(_spooled(spool)) == 1

    # Link is back. The genuine scheduled test runs on this very check-in, once.
    import collector.speedtest as st

    ran: list[int] = []
    monkeypatch.setattr(
        st, "run_speedtest", lambda *a, **k: ran.append(1) or {"ok": True, "status": "ok"}
    )
    reported: list[str] = []
    monkeypatch.setattr(
        checkin,
        "_report_speedtest",
        lambda _u, _t, res, trig, **kw: reported.append(res["status"]),
    )

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())
    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert ran == [1], "one real test on recovery — no retroactive backlog of slots"
    assert reported == ["ok"]
    assert float(last_file.read_text()) > float(before), "now the slot IS consumed"


def test_a_long_outage_records_one_row_per_interval_not_one_per_checkin(
    monkeypatch, tmp_path
):
    """Check-in runs every ~3 minutes; the speed slot is every 6 hours.

    Without its own ledger a 24h outage would spool ~480 identical rows — on its
    own enough to evict the outage's ONSET from the file-capped result spool,
    which is the exact failure the spool's per-cycle batching exists to prevent.
    """
    spool = _arrange(monkeypatch, tmp_path)
    t0 = time.time()
    (tmp_path / "speedtest-last-run").write_text(str(t0 - 6 * 3600))

    clock = {"now": t0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])

    for step in range(480):  # 480 x 180s = exactly 24 hours of failed check-ins
        clock["now"] = t0 + step * 180
        checkin._missed_speedtest_on_failure("https://dash", "tok", _settings(), None)

    rows = _spooled(spool)
    assert len(rows) == 4, "one recorded non-attempt per 6h slot over 24h, not 480"
    assert {r["status"] for r in rows} == {"not_attempted"}


@pytest.mark.parametrize("http_status", [502, 401, 500, 200])
def test_a_dashboard_that_answered_records_nothing(monkeypatch, tmp_path, http_status):
    """Same gate as _wan_path_on_failure. A 502 mid-deploy or a 401 on a rotated
    token is a fact about the DASHBOARD; this box's link is fine and the real
    speed test will run on the next check-in a few minutes later. Claiming "no
    path off the site" there would be a verdict we did not measure."""
    spool = _arrange(monkeypatch, tmp_path)
    _due(tmp_path)

    checkin._missed_speedtest_on_failure("https://dash", "tok", _settings(), http_status)

    assert not list(spool.glob("*.json"))
    assert not (tmp_path / "speedtest-missed-slot").exists()


def test_a_slot_that_is_not_due_records_nothing(monkeypatch, tmp_path):
    spool = _arrange(monkeypatch, tmp_path)
    (tmp_path / "speedtest-last-run").write_text(str(time.time() - 60))

    checkin._missed_speedtest_on_failure("https://dash", "tok", _settings(), None)

    assert not list(spool.glob("*.json")), "nothing was missed — the slot isn't due"


def test_a_provider_cooldown_suppresses_the_record(monkeypatch, tmp_path):
    """No probe was going to be attempted this cycle anyway, so blaming the
    absent sample on the outage would misattribute it. The refusal is already on
    record as its own `unavailable` row."""
    spool = _arrange(monkeypatch, tmp_path)
    _due(tmp_path)
    (tmp_path / "speedtest-cooldown-until").write_text(str(time.time() + 1800))

    checkin._missed_speedtest_on_failure("https://dash", "tok", _settings(), None)

    assert not list(spool.glob("*.json"))


def test_an_opted_out_sensor_records_nothing(monkeypatch, tmp_path):
    spool = _arrange(monkeypatch, tmp_path)
    _due(tmp_path)

    checkin._missed_speedtest_on_failure(
        "https://dash", "tok", _settings(speedtest_enabled=False), None
    )

    assert not list(spool.glob("*.json"))


def test_the_scheduler_and_the_recorder_share_one_interval(monkeypatch, tmp_path):
    """A 15-minute floor applies to both. If they disagreed, the recorder would
    invent non-attempts for cycles the real test would have skipped."""
    assert checkin._speedtest_interval_sec(_settings(speedtest_schedule_sec=60)) == 900.0
    assert checkin._speedtest_interval_sec(_settings(speedtest_schedule_sec=7200)) == 7200.0


# --- the wiring, which is where the defect actually lived --------------------


def _checkin_harness(monkeypatch, tmp_path):
    """Stand run_checkin up on its FAILURE path with every unrelated edge stubbed.

    The bug was never in the scheduler itself — it was that the scheduler sat
    below the early return. So this asserts the call site, not the helper.
    """
    spool = tmp_path / "result-spool"
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DIR", spool)
    monkeypatch.setattr(checkin, "SPEEDTEST_LAST_FILE", tmp_path / "speedtest-last-run")
    monkeypatch.setattr(checkin, "SPEEDTEST_COOLDOWN_FILE", tmp_path / "speedtest-cooldown-until")
    monkeypatch.setattr(checkin, "SPEEDTEST_MISSED_FILE", tmp_path / "speedtest-missed-slot")
    monkeypatch.setattr(
        checkin,
        "get_settings",
        lambda: SimpleNamespace(
            dashboard_url="https://dash",
            enroll_token="tok",
            update_channel="stable",
            speedtest_enabled=True,
            speedtest_schedule_sec=6 * 3600,
            snmp_enabled=False,
            snmp_communities="",
            snmp_exclude="",
            snmp_topology_enabled=False,
            snmp_topology_scope="",
            snmp_topology_max_depth=2,
            snmp_topology_interval=3600,
            bundle_transport="blob",
            capture_seconds=120,
            capture_interval=900,
            rescan_interval=3600,
        ),
    )
    monkeypatch.setattr(checkin, "_current_token", lambda _s: "tok")
    monkeypatch.setattr(checkin, "wait_for_db", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_read_applied_version", lambda: 7)
    monkeypatch.setattr(checkin, "_local_net", lambda: ("10.8.2.100", "eth0", "10.8.2.0/24"))
    monkeypatch.setattr(checkin, "_current_sha", lambda: "abc123")
    monkeypatch.setattr(checkin, "_last_update", lambda: None)
    monkeypatch.setattr(checkin, "_last_host_action", lambda: None)
    monkeypatch.setattr(checkin, "_interfaces", lambda: [])
    monkeypatch.setattr(checkin, "_note_checkin_auth", lambda *a, **k: None)
    monkeypatch.setattr(checkin.host_metrics_mod, "collect", lambda: {})
    # Not under test here: the latency probe (test_checkin_offline_latency.py) and
    # the WAN-path capture (test_checkin_wan_path.py) own those.
    monkeypatch.setattr(checkin, "_maybe_latency", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_wan_path_on_failure", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: None)
    return spool


def test_run_checkin_records_the_missed_slot_on_the_failure_path(monkeypatch, tmp_path):
    spool = _checkin_harness(monkeypatch, tmp_path)
    (tmp_path / "speedtest-last-run").write_text(str(time.time() - 7 * 3600))
    # A request that never completed: no HTTP status at all.
    monkeypatch.setattr(checkin, "_post_status", lambda *a, **k: (None, None))
    import collector.speedtest as st

    monkeypatch.setattr(
        st, "run_speedtest", lambda *a, **k: pytest.fail("no probe on the outage path")
    )

    rc = checkin.run_checkin()

    assert rc == 1, "a failed check-in still reports failure"
    rows = _spooled(spool)
    assert [r["status"] for r in rows] == ["not_attempted"], (
        "the scheduled slot must leave evidence, not a hole in the timeline"
    )


def test_run_checkin_leaves_the_healthy_path_alone(monkeypatch, tmp_path):
    """Positive control: on a healthy check-in the real scheduler still runs and
    the missed-slot ledger is never touched."""
    spool = _checkin_harness(monkeypatch, tmp_path)
    (tmp_path / "speedtest-last-run").write_text(str(time.time() - 7 * 3600))
    monkeypatch.setattr(
        checkin, "_post_status", lambda *a, **k: ({"config": None, "commands": []}, 200)
    )
    monkeypatch.setattr(checkin, "_maybe_scheduled_iperf", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_maybe_webperf", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_wan_path_on_success", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_report_wan_path", lambda *a, **k: None)
    # Delivery SUCCEEDS on this path (the harness default is the outage case), so
    # the real result is POSTed rather than spooled.
    monkeypatch.setattr(checkin, "_post", lambda *a, **k: {})
    import collector.speedtest as st

    ran: list[int] = []
    monkeypatch.setattr(
        st,
        "run_speedtest",
        lambda *a, **k: ran.append(1) or {"ok": True, "status": "ok", "download_mbps": 910.0},
    )

    checkin.run_checkin()

    assert ran == [1], "the healthy path still takes the real measurement"
    assert not (tmp_path / "speedtest-missed-slot").exists()
    assert not list(spool.glob("*.json")), "nothing spooled when delivery succeeds"
