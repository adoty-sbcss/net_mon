"""Tests for the device-SSH auth circuit breaker (NCM-6).

The breaker exists for one scenario: a district-wide credential typo or a rotation
nobody told NetMon about. Without it, a pass walks the whole fleet offering the same
rejected password to every switch — which is how a shared read-only account gets
locked out everywhere at once, and how a district DoSes its own RADIUS/TACACS while
merely trying to back up configs.

It originally guarded only `test_targets` (the operator-initiated "Test SSH"). The
two UNSUPERVISED paths — `fetch_all`, used by both "Back up now" and the unattended
nightly pass — had none, which is exactly backwards: the nightly pass is the one
nobody is watching. These tests pin the protection to BOTH.

Everything here drives the real orchestration functions with `_fetch_one` stubbed,
so a regression that removes the breaker from either path fails loudly.
"""

from __future__ import annotations

import pytest

from collector.discovery import device_config


# --- helpers -----------------------------------------------------------------


def _targets(n: int) -> list[dict[str, object]]:
    return [{"target_id": i, "host": f"10.0.0.{i}", "label": f"sw{i}", "platform": "cisco_ios"}
            for i in range(1, n + 1)]


def _ok(target: dict[str, object]) -> dict[str, object]:
    return {"target_id": target["target_id"], "host": target["host"], "status": "ok"}


def _fail(target: dict[str, object], stage: str, code: str) -> dict[str, object]:
    return {"target_id": target["target_id"], "host": target["host"],
            "status": "error", "stage": stage, "code": code, "error": code}


def _install(monkeypatch, responder) -> list[dict[str, object]]:
    """Stub `_fetch_one` and record every device actually ATTEMPTED.

    The attempt log is the real assertion surface: the breaker's promise is about how
    many logins reach the devices, not about what the summary says afterwards.
    """
    attempted: list[dict[str, object]] = []

    def fake_fetch_one(target, *, key, ssh_timeout, discard_output=False):
        attempted.append(target)
        return responder(target)

    monkeypatch.setattr(device_config, "_fetch_one", fake_fetch_one)
    monkeypatch.setattr(device_config, "_redact_key", lambda: b"k" * 32)
    return attempted


# --- the counter itself ------------------------------------------------------


def test_breaker_trips_on_the_third_consecutive_rejection():
    b = device_config._AuthBreaker()
    for _ in range(2):
        b.record({"status": "error", "stage": "auth", "code": "auth.rejected"})
        assert not b.tripped
    b.record({"status": "error", "stage": "auth", "code": "auth.rejected"})
    assert b.tripped


def test_success_resets_the_counter():
    b = device_config._AuthBreaker()
    b.record({"status": "error", "stage": "auth"})
    b.record({"status": "error", "stage": "auth"})
    b.record({"status": "ok"})
    b.record({"status": "error", "stage": "auth"})
    assert not b.tripped, "a working credential in between is not an outage"


def test_authz_denial_never_trips_the_breaker():
    """`authz` means the password WORKED and the role is missing.

    Counting it would stop a whole pass over a provisioning gap that locks nothing —
    and hide every other device's real status behind it.
    """
    b = device_config._AuthBreaker()
    for _ in range(5):
        b.record({"status": "error", "stage": "authz", "code": "authz.no_read_access"})
    assert not b.tripped


def test_unreachable_devices_are_neutral_and_cannot_defeat_the_breaker():
    """Reach/SSH failures say nothing about the credential, so they neither trip nor
    reset. If they reset, a few dead hosts sprinkled between live ones would let a
    bad password walk the entire fleet."""
    b = device_config._AuthBreaker()
    b.record({"status": "error", "stage": "auth"})
    b.record({"status": "error", "stage": "reach", "code": "reach.host_silent"})
    b.record({"status": "error", "stage": "auth"})
    b.record({"status": "error", "stage": "ssh", "code": "ssh.banner_timeout"})
    assert not b.tripped
    b.record({"status": "error", "stage": "auth"})
    assert b.tripped, "reach failures must not reset the count"


# --- fetch_all: the nightly pass + "Back up now" ------------------------------


def test_fetch_all_stops_after_three_rejections(monkeypatch):
    """THE regression test. `fetch_all` runs unattended nightly across the fleet."""
    attempted = _install(monkeypatch, lambda t: _fail(t, "auth", "auth.rejected"))

    res = device_config.fetch_all(_targets(110))

    assert len(attempted) == 3, (
        f"a district-wide typo offered the bad credential to {len(attempted)} devices; "
        "the breaker must stop the pass at 3"
    )
    assert res["stats"]["stopped_early"] is True
    assert res["stats"]["skipped"] == 107


def test_fetch_all_skipped_devices_carry_the_taxonomy_code(monkeypatch):
    """Skipped rows must say 'we did not try', not look like a device failure.

    The dashboard renders `job.*` codes as muted 'didn't run' copy; free text falls
    through to a generic red 'Failed' badge, which sends an operator to power-cycle
    healthy switches.
    """
    _install(monkeypatch, lambda t: _fail(t, "auth", "auth.rejected"))

    res = device_config.fetch_all(_targets(10))

    skipped = [d for d in res["devices"] if d["status"] == "skipped"]
    assert skipped, "expected the tail to be skipped"
    for d in skipped:
        assert d["code"] == "job.stopped_auth_failures"
        assert d["error"] == d["code"], "legacy field must mirror the code, never free text"


def test_fetch_all_budget_exhaustion_uses_a_taxonomy_code(monkeypatch):
    """The old free-text 'time budget exhausted' rendered as a generic failure."""
    _install(monkeypatch, _ok)
    monkeypatch.setattr(device_config.time, "monotonic", _clock(step=1000))

    res = device_config.fetch_all(_targets(4), time_budget=1)

    skipped = [d for d in res["devices"] if d["status"] == "skipped"]
    assert skipped and all(d["code"] == "job.budget_exhausted" for d in skipped)
    assert res["stats"]["budget_exhausted"] is True


def test_fetch_all_healthy_fleet_is_untouched(monkeypatch):
    """The breaker must be invisible when credentials work."""
    attempted = _install(monkeypatch, _ok)

    res = device_config.fetch_all(_targets(25))

    assert len(attempted) == 25
    assert res["stats"]["stopped_early"] is False
    assert res["stats"]["ok"] == 25


def test_fetch_all_authz_failures_do_not_stop_the_pass(monkeypatch):
    """Least-privilege rollout gaps must not abort the fleet's backup."""
    attempted = _install(monkeypatch, lambda t: _fail(t, "authz", "authz.no_read_access"))

    res = device_config.fetch_all(_targets(20))

    assert len(attempted) == 20
    assert res["stats"]["stopped_early"] is False


# --- test_targets: the on-demand "Test SSH" -----------------------------------


def test_test_targets_stops_within_one_wave(monkeypatch):
    """Concurrent runs read the counter between waves, so the bound is one opening
    wave (`max_workers`), not the fleet. 12 targets must not become 12 logins."""
    attempted = _install(monkeypatch, lambda t: _fail(t, "auth", "auth.rejected"))

    res = device_config.test_targets(max_workers=4)

    assert len(attempted) == 4, f"{len(attempted)} logins attempted; expected one wave"
    assert res["stats"]["stopped_early"] is True


def test_test_targets_narrows_the_wave_once_the_counter_is_armed(monkeypatch):
    """After a partial wave of rejections the next wave must not overshoot.

    One rejection in the opening wave leaves headroom 2, so at most 2 more logins may
    be in flight — a fixed-width wave would put 4 more on the wire.
    """
    seen: list[int] = []

    def responder(t):
        seen.append(t["target_id"])
        # Only the first device rejects; the rest are unreachable (neutral), so the
        # counter stays armed at 1 and never resets.
        if t["target_id"] == 1:
            return _fail(t, "auth", "auth.rejected")
        return _fail(t, "reach", "reach.host_silent")

    attempted = _install(monkeypatch, responder)

    device_config.test_targets(max_workers=4)

    # Wave 1 = 4 (counter cold), then headroom 2 -> waves of 2 for the remaining 8.
    assert len(attempted) == 12
    assert seen[:4] == [1, 2, 3, 4]


def test_test_targets_keeps_full_concurrency_when_healthy(monkeypatch):
    """Shrinking waves must not throttle a fleet whose credentials are fine."""
    attempted = _install(monkeypatch, _ok)

    res = device_config.test_targets()

    assert len(attempted) == 12
    assert res["stats"]["stopped_early"] is False
    assert res["stats"]["passed"] == 12


@pytest.fixture(autouse=True)
def _targets_on_disk(monkeypatch):
    """`test_targets` reads the box's own 0600 target list; `fetch_all` is handed one.

    Stubbing it here keeps the containment property honest in tests too: nothing in
    these tests hands the sensor an address from outside.
    """
    monkeypatch.setattr(device_config, "load_targets", lambda: _targets(12))


def _clock(step: int):
    """A monotonic clock that jumps `step` seconds per call, to trip a time budget
    deterministically instead of sleeping."""
    state = {"t": 0}

    def now() -> float:
        state["t"] += step
        return float(state["t"])

    return now
