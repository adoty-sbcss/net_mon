"""A self-inflicted 429 must back OFF, not retry on the same cadence.

The Cucamonga rate limit was our own load: three sensors behind one shared
egress IP, each generating hundreds of requests per run, on independent
schedules with no awareness of each other. Retrying at the normal interval
just feeds the limiter.

The rules under test:
  * a REFUSED run (`status == "unavailable"`) parks the scheduler;
  * a genuinely FAILED run does NOT — a broken district link is exactly the
    signal we must keep measuring, and backing off there would recreate the
    "outage is a GAP, not a bad row" problem the fleet already has;
  * a successful run CLEARS a previous cooldown, so one refusal cannot wedge a
    sensor past the point where the provider is happy again;
  * an implausible cooldown (a box whose clock jumped forward) is ignored rather
    than obeyed forever;
  * the cooldown gates the run BEFORE the probe is executed — the point is to
    stop generating traffic, so a skipped cycle must not call the prober at all.

Pure unit tests: no network, no DB. The prober and the result POST are the
chokepoints and are monkeypatched; the ledger files are redirected to tmp_path.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from collector import checkin


def _settings(**over):
    base = {"speedtest_enabled": True, "speedtest_schedule_sec": 900}
    base.update(over)
    return SimpleNamespace(**base)


def _arrange(monkeypatch, tmp_path, result: dict):
    """Redirect both ledgers into tmp_path and stub the prober + the POST.
    Returns a dict recording whether the probe actually ran."""
    monkeypatch.setattr(checkin, "SPEEDTEST_LAST_FILE", tmp_path / "speedtest-last-run")
    monkeypatch.setattr(checkin, "SPEEDTEST_COOLDOWN_FILE", tmp_path / "speedtest-cooldown-until")

    calls = {"ran": 0, "reported": 0}

    def _fake_run(_provider="cloudflare", **_kw):
        calls["ran"] += 1
        return result

    import collector.speedtest as st

    monkeypatch.setattr(st, "run_speedtest", _fake_run)
    monkeypatch.setattr(
        checkin,
        "_report_speedtest",
        lambda *_a, **_kw: calls.__setitem__("reported", calls["reported"] + 1),
    )
    return calls


REFUSED = {
    "ok": False,
    "status": "unavailable",
    "error": "download not measured — speed.cloudflare.com refused the probe (HTTP 429)",
}
BROKEN = {"ok": False, "status": "failed", "error": "download moved 0 bytes"}
MEASURED = {"ok": True, "status": "ok", "download_mbps": 910.0}


def test_a_refused_run_arms_the_cooldown(monkeypatch, tmp_path):
    calls = _arrange(monkeypatch, tmp_path, REFUSED)

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert calls["ran"] == 1
    until = float(checkin.SPEEDTEST_COOLDOWN_FILE.read_text())
    assert until > time.time(), "a refusal must park the scheduler"
    assert until <= time.time() + checkin.SPEEDTEST_REFUSED_COOLDOWN_SEC + 5


def test_a_broken_link_does_not_back_off(monkeypatch, tmp_path):
    """A real WAN failure is the signal we want. Backing off there would thin out
    the evidence during exactly the outage we are trying to see."""
    _arrange(monkeypatch, tmp_path, BROKEN)

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert not checkin.SPEEDTEST_COOLDOWN_FILE.exists()


def test_the_scheduler_skips_and_runs_nothing_while_cooling_off(monkeypatch, tmp_path):
    calls = _arrange(monkeypatch, tmp_path, MEASURED)
    checkin.SPEEDTEST_COOLDOWN_FILE.write_text(str(time.time() + 600))

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert calls["ran"] == 0, "the whole point is to stop GENERATING requests"
    assert calls["reported"] == 0


def test_an_expired_cooldown_lets_the_probe_run_again(monkeypatch, tmp_path):
    calls = _arrange(monkeypatch, tmp_path, MEASURED)
    checkin.SPEEDTEST_COOLDOWN_FILE.write_text(str(time.time() - 1))

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert calls["ran"] == 1


def test_a_successful_run_clears_a_previous_cooldown(monkeypatch, tmp_path):
    _arrange(monkeypatch, tmp_path, MEASURED)
    checkin.SPEEDTEST_COOLDOWN_FILE.write_text(str(time.time() - 1))

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert not checkin.SPEEDTEST_COOLDOWN_FILE.exists(), (
        "one refusal must not wedge a sensor after the provider is happy again"
    )


def test_an_implausible_cooldown_is_ignored(monkeypatch, tmp_path):
    """A box whose clock jumped forward once must not stop speed-testing forever.
    Nothing we write can be further out than the cooldown length."""
    calls = _arrange(monkeypatch, tmp_path, MEASURED)
    checkin.SPEEDTEST_COOLDOWN_FILE.write_text(
        str(time.time() + checkin.SPEEDTEST_REFUSED_COOLDOWN_SEC * 100)
    )

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert calls["ran"] == 1


def test_a_corrupt_cooldown_file_does_not_block_the_probe(monkeypatch, tmp_path):
    calls = _arrange(monkeypatch, tmp_path, MEASURED)
    checkin.SPEEDTEST_COOLDOWN_FILE.write_text("not-a-number")

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings())

    assert calls["ran"] == 1


def test_the_cooldown_outlasts_a_short_configured_interval(monkeypatch, tmp_path):
    """The pathological case: a district on the 15-minute floor with three
    sensors. The refusal cooldown has to be longer than the interval or it
    changes nothing."""
    calls = _arrange(monkeypatch, tmp_path, REFUSED)
    settings = _settings(speedtest_schedule_sec=900)

    checkin._maybe_scheduled_speedtest("https://dash", "tok", settings)
    assert calls["ran"] == 1

    # Fast-forward past the normal interval but not past the cooldown.
    checkin.SPEEDTEST_LAST_FILE.write_text(str(time.time() - 1000))
    checkin._maybe_scheduled_speedtest("https://dash", "tok", settings)

    assert calls["ran"] == 1, "the interval elapsed, but the cooldown must still hold"


def test_a_disabled_sensor_never_probes(monkeypatch, tmp_path):
    calls = _arrange(monkeypatch, tmp_path, MEASURED)

    checkin._maybe_scheduled_speedtest("https://dash", "tok", _settings(speedtest_enabled=False))

    assert calls["ran"] == 0
