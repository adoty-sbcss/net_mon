"""The passive-capture window must be pushable, validated, and bounded.

`capture_seconds` sets how long tshark listens per scan. It was absent from the
desired-config key list, so it could only be changed by touching each box — and
the fleet ran two different defaults depending on provisioning path (config.py
said 120, lib/advanced.sh prompted 60). Two sensors could legitimately disagree
about their own sampling window, which makes any per-site comparison of
capture-derived rates unsound.

The rules under test:
  * it goes through the SAME validated path as every other tunable — bounds, the
    control-character/env-injection guard, and hard-reject-the-generation on
    failure (never a silent clamp or a half-applied push);
  * the cadence cross-checks hold: the window has to fit inside capture_interval
    and rescan_interval, because run_scan BLOCKS for its whole length;
  * a push that raises capture_seconds and rescan_interval TOGETHER is judged
    against the value the push will leave on the box, not the one it replaces;
  * the effective value is reported back, so drift is visible and not merely
    settable.

Pure unit tests: the env write is recorded instead of performed and get_settings
is stubbed, so there is no /etc and no DB.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from collector import checkin


def _settings(**over):
    base = {"capture_interval": 900, "rescan_interval": 3600, "capture_seconds": 120}
    base.update(over)
    return SimpleNamespace(**base)


def _apply(data: dict, monkeypatch, **settings_over) -> dict:
    """Run _apply_config with the env write captured; returns the mapping."""
    writes: list[tuple[Path, dict]] = []
    monkeypatch.setattr(
        checkin, "_update_env_file", lambda path, mapping: writes.append((path, mapping))
    )
    monkeypatch.setattr(checkin, "get_settings", lambda: _settings(**settings_over))
    checkin._apply_config(data)
    return writes[0][1] if writes else {}


# --- it is actually pushable ------------------------------------------------


def test_capture_seconds_reaches_the_env_file(monkeypatch):
    mapping = _apply({"capture_seconds": 90}, monkeypatch)
    assert mapping["NETMON_CAPTURE_SECONDS"] == "90"


def test_it_is_in_the_validated_bounds_table(monkeypatch):
    """Not a bespoke check bolted on beside the others — the same table, so
    _validate_desired_config covers it without _apply_config being reached."""
    assert checkin._CONFIG_INT_BOUNDS["capture_seconds"] == (1, 3600)


@pytest.mark.parametrize("bad", [0, -5, 3601, 100000])
def test_out_of_range_is_refused(bad, monkeypatch):
    with pytest.raises(ValueError, match="capture_seconds must be between"):
        _apply({"capture_seconds": bad}, monkeypatch)


@pytest.mark.parametrize("bad", ["90; rm -rf /", "9\n0", True, None, "", "0x5a"])
def test_non_integers_are_refused(bad, monkeypatch):
    """Including bool — `True` is an int in Python and would silently become a
    1-second window. And a string carrying a newline must never reach the env
    writer, which is the whole point of routing this through _bounded_config_int
    rather than str().
    """
    if bad is None:
        # `None` means "not being pushed" everywhere else in _apply_config; keep
        # that contract rather than raising.
        assert _apply({"capture_seconds": None}, monkeypatch) == {}
        return
    with pytest.raises(ValueError, match="capture_seconds must be an integer"):
        _apply({"capture_seconds": bad}, monkeypatch)


def test_a_rejected_capture_seconds_aborts_the_WHOLE_generation(monkeypatch):
    """The push is atomic: a bad capture_seconds must not let a co-pushed key
    land. Half-applied config is what makes a box's state unexplainable."""
    with pytest.raises(ValueError):
        _apply(
            {"capture_seconds": 99999, "snmp_communities": "public"}, monkeypatch
        )


# --- the cadence cross-checks ------------------------------------------------


def test_window_must_fit_inside_capture_interval(monkeypatch):
    """900s light-pass interval, 900s window: the pass can never finish before the
    next one is due."""
    with pytest.raises(ValueError, match="less than the current capture_interval"):
        _apply({"capture_seconds": 900}, monkeypatch, capture_interval=900)


def test_window_must_fit_inside_rescan_interval(monkeypatch):
    with pytest.raises(ValueError, match="less than the rescan_interval"):
        _apply(
            {"capture_seconds": 3000}, monkeypatch,
            capture_interval=0, rescan_interval=3000,
        )


def test_capture_interval_of_zero_disables_only_that_check(monkeypatch):
    """0 disables the light pass entirely, so there is no interval to fit inside —
    but rescan_interval still binds."""
    mapping = _apply({"capture_seconds": 1200}, monkeypatch, capture_interval=0)
    assert mapping["NETMON_CAPTURE_SECONDS"] == "1200"


def test_a_co_pushed_rescan_interval_is_what_binds_not_the_stale_one(monkeypatch):
    """The trap this exists to catch: rescan_interval can be raised in the SAME
    generation. Judged against the OLD value this legitimate pair is rejected;
    judged against the value the push leaves behind, it is fine."""
    mapping = _apply(
        {"capture_seconds": 1800, "rescan_interval": 7200},
        monkeypatch,
        capture_interval=0,
        rescan_interval=3600,   # the stale value a naive check would use
    )
    assert mapping["NETMON_CAPTURE_SECONDS"] == "1800"
    assert mapping["NETMON_RESCAN_INTERVAL"] == "7200"


def test_a_co_pushed_rescan_interval_that_is_still_too_small_is_refused(monkeypatch):
    """The inverse: lowering rescan_interval in the same push must be able to make
    an otherwise-fine capture_seconds invalid."""
    with pytest.raises(ValueError, match="less than the rescan_interval"):
        _apply(
            {"capture_seconds": 1800, "rescan_interval": 600},
            monkeypatch,
            capture_interval=0,
            rescan_interval=7200,   # the stale value that would have let it pass
        )


# --- drift is visible, not just settable -------------------------------------


def test_the_effective_window_is_reported_back(monkeypatch, tmp_path):
    """A setter without a readback leaves the original defect in place: you still
    cannot tell whether two sensors agree. The cross-check bounds ride along
    because the rejection messages are stated in terms of them.

    Asserts on the BODY actually posted. An earlier version of this test grepped
    inspect.getsource(run_checkin) for the three literals — which would have passed
    with all three lines commented out.

    Self-contained on purpose: importing the sibling test module's harness
    (`from tests....`) works locally but not under CI's `cd collector && pytest
    tests -q`, where `tests` is not an importable package.
    """
    settings = _settings(
        dashboard_url="https://dash", enroll_token="tok", update_channel="stable",
        latency_enabled=False, snmp_enabled=False, snmp_communities="",
        snmp_exclude="", snmp_topology_enabled=False, snmp_topology_scope="",
        snmp_topology_max_depth=2, snmp_topology_interval=3600,
        bundle_transport="blob",
    )
    for name, stub in [
        ("get_settings", lambda: settings),
        ("_current_token", lambda _s: "tok"),
        ("wait_for_db", lambda *a, **k: None),
        ("_read_applied_version", lambda: 7),
        ("_local_net", lambda: ("10.8.2.100", "eth0", "10.8.2.0/24")),
        ("_current_sha", lambda: "abc123"),
        ("_last_update", lambda: None),
        ("_last_host_action", lambda: None),
        ("_interfaces", lambda: []),
        ("_note_checkin_auth", lambda *a, **k: None),
        ("_maybe_scheduled_iperf", lambda *a, **k: None),
        ("_maybe_scheduled_speedtest", lambda *a, **k: None),
        ("_maybe_webperf", lambda *a, **k: None),
        ("_maybe_latency", lambda *a, **k: None),
    ]:
        monkeypatch.setattr(checkin, name, stub)
    monkeypatch.setattr(checkin.host_metrics_mod, "collect", lambda: {})

    bodies: list[dict] = []
    monkeypatch.setattr(
        checkin,
        "_post_status",
        lambda url, tok, body: (
            bodies.append(body), ({"config": None, "commands": []}, 200)
        )[1],
    )

    checkin.run_checkin()

    cc = bodies[0]["currentConfig"]
    # The fake settings' values, echoed back — deliberately NOT the real defaults,
    # so this proves the block reports what the box is running rather than a
    # constant that happens to match.
    assert cc["capture_seconds"] == 120
    assert cc["capture_interval"] == 900
    assert cc["rescan_interval"] == 3600


# --- the three defaults must agree -------------------------------------------


def test_every_surface_declares_the_same_capture_window_default():
    """THE defect, pinned so it cannot come back.

    Three places declare this default and they must not drift:
      * collector/src/collector/config.py  — what a box with no key runs
      * .env.example                       — SEEDED onto netmon.env by
        bin/netmon-wizard on every fresh box, so it is what the fleet actually runs
      * lib/advanced.sh                    — the prompt an operator sees

    config.py said 120 while the other two said 60. Because the wizard seeds the
    template, an explicit 60 lands on effectively every field sensor whether or not
    anyone opens the opt-in cadence prompt — so 120 was the number almost nothing
    ran, and two sensors could still disagree about the window every
    capture-derived rate is measured over.

    Reads the real files rather than restating the number, so editing any ONE of
    the three breaks this test.
    """
    from collector.config import Settings

    root = Path(__file__).resolve().parents[2]

    code = Settings.model_fields["capture_seconds"].default

    env_line = next(
        ln for ln in (root / ".env.example").read_text().splitlines()
        if ln.strip().startswith("NETMON_CAPTURE_SECONDS=")
    )
    seeded = int(env_line.split("=", 1)[1].strip().strip('"').strip("'"))

    sh_line = next(
        ln for ln in (root / "lib" / "advanced.sh").read_text().splitlines()
        if "prompt NETMON_CAPTURE_SECONDS" in ln
    )
    prompted = int(sh_line.rsplit('"', 2)[1])

    assert code == seeded == prompted, (
        f"capture window defaults disagree: config.py={code}, "
        f".env.example={seeded}, lib/advanced.sh={prompted}"
    )


# --- the multiplication across VLANs ----------------------------------------


def _warnings(monkeypatch):
    """Capture poller warnings. structlog writes to stdout, NOT through the stdlib
    handler caplog installs — using caplog here reports zero warnings while the
    real one is plainly printed, i.e. a test that passes for the wrong reason."""
    from collector import poller

    got: list[tuple[str, dict]] = []
    monkeypatch.setattr(poller, "_capture_budget_warned", False)
    monkeypatch.setattr(
        poller.log, "warning", lambda msg, **kw: got.append((msg, kw))
    )
    return poller, got


def test_capture_budget_warns_when_vlans_multiply_the_window(monkeypatch):
    """Interfaces are scanned SEQUENTIALLY and each blocks for the full window, so
    the real cost of a pass is monitored x capture_seconds. Nothing bounds that at
    config time (the VLAN count is a runtime fact), so it has to be said out loud."""
    poller, got = _warnings(monkeypatch)
    settings = _settings(capture_seconds=120, capture_interval=900)

    poller._warn_capture_budget(settings, 6)    # 6 x 120 = 720s: still fits
    assert got == []

    poller._warn_capture_budget(settings, 8)    # 8 x 120 = 960s > 900s
    assert len(got) == 1
    # The message must name the numbers that bind — the recurring failure in this
    # product is a budget silently exceeded with no message naming the limit.
    assert got[0][1] == {
        "monitored_interfaces": 8,
        "capture_seconds": 120,
        "total_capture_seconds": 960,
        "capture_interval": 900,
    }


def test_capture_budget_warning_is_latched_not_logged_every_tick(monkeypatch):
    """tick() runs every ~30s; a standing misconfiguration must not drown the log."""
    poller, got = _warnings(monkeypatch)
    settings = _settings(capture_seconds=120, capture_interval=900)
    for _ in range(5):
        poller._warn_capture_budget(settings, 8)
    assert len(got) == 1


def test_capture_budget_warning_rearms_after_the_condition_clears(monkeypatch):
    poller, got = _warnings(monkeypatch)
    settings = _settings(capture_seconds=120, capture_interval=900)
    poller._warn_capture_budget(settings, 8)   # warns
    poller._warn_capture_budget(settings, 2)   # clears
    poller._warn_capture_budget(settings, 8)   # must warn AGAIN
    assert len(got) == 2


def test_capture_budget_is_silent_when_the_light_pass_is_disabled(monkeypatch):
    """capture_interval=0 turns light passes off entirely; there is no budget to
    blow, and warning about one would be noise on a deliberately-configured box."""
    poller, got = _warnings(monkeypatch)
    poller._warn_capture_budget(_settings(capture_seconds=3000, capture_interval=0), 8)
    assert got == []
