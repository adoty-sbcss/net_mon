"""Guards Fable audit 01 finding #5: a box whose stored enroll token dies
(rotated / revoked / cleared dashboard-side) used to 401 on every check-in
FOREVER — auto-enroll only runs when the token is EMPTY, so a stale token never
healed, and every failure was a swallowed warning. The dashboard's own re-pair
flow ("clear the enrollment to let the box auto-re-pair") silently assumed this
self-heal existed.

The rules under test:
  * three CONSECUTIVE check-in 401s clear a FILE-sourced token (then the next
    cycle's auto-enroll takes over);
  * an ENV-sourced token (NETMON_ENROLL_TOKEN) is NEVER deleted — the operator
    pinned it; we log instead;
  * anything other than a 401 — success, other errors, or plain network failure
    — resets the streak, so an outage or deploy blip can't cost a healthy box
    its token;
  * after the dashboard REFUSES an enroll (4xx: bad key / 409 already-enrolled),
    auto-enroll backs off instead of re-asking every cycle — a 409 needs a
    superadmin, and hammering it floods the security-event log. Network failure
    does NOT back off (retrying an outage next cycle is correct).

Pure unit tests: no network, no DB — the state files are redirected to tmp_path
and the HTTP chokepoint (_post_status) is monkeypatched.
"""

from __future__ import annotations

from types import SimpleNamespace

from collector import checkin


def _redirect_state(monkeypatch, tmp_path):
    token = tmp_path / "enroll-token"
    count = tmp_path / "checkin-401-count"
    backoff = tmp_path / "enroll-backoff"
    monkeypatch.setattr(checkin, "TOKEN_FILE", token)
    monkeypatch.setattr(checkin, "CHECKIN_401_COUNT_FILE", count)
    monkeypatch.setattr(checkin, "ENROLL_BACKOFF_FILE", backoff)
    return token, count, backoff


def _settings(**over):
    base = {
        "enroll_token": "",
        "bootstrap_key": "bk",
        "district_slug": "d",
        "school_slug": "s",
        "device_slug": "dev",
    }
    base.update(over)
    return SimpleNamespace(**base)


# --- consecutive-401 token clearing -----------------------------------------


def test_three_consecutive_401s_clear_a_file_token(monkeypatch, tmp_path):
    token, count, _ = _redirect_state(monkeypatch, tmp_path)
    token.write_text("nms1_dead")
    s = _settings()

    checkin._note_checkin_auth(s, 401)
    checkin._note_checkin_auth(s, 401)
    assert token.exists(), "two 401s must NOT clear the token yet"
    assert int(count.read_text()) == 2

    checkin._note_checkin_auth(s, 401)
    assert not token.exists(), "the third consecutive 401 clears the dead token"
    assert int(count.read_text()) == 0, "counter resets after the clear"


def test_success_resets_the_streak(monkeypatch, tmp_path):
    token, count, _ = _redirect_state(monkeypatch, tmp_path)
    token.write_text("nms1_ok")
    s = _settings()

    checkin._note_checkin_auth(s, 401)
    checkin._note_checkin_auth(s, 401)
    checkin._note_checkin_auth(s, 200)  # dashboard accepted us again
    checkin._note_checkin_auth(s, 401)
    checkin._note_checkin_auth(s, 401)
    assert token.exists(), "non-consecutive 401s must never clear the token"
    assert int(count.read_text()) == 2


def test_network_failure_resets_the_streak(monkeypatch, tmp_path):
    token, _, _ = _redirect_state(monkeypatch, tmp_path)
    token.write_text("nms1_ok")
    s = _settings()

    checkin._note_checkin_auth(s, 401)
    checkin._note_checkin_auth(s, 401)
    checkin._note_checkin_auth(s, None)  # timeout/DNS — says nothing about the token
    checkin._note_checkin_auth(s, 401)
    assert token.exists(), "an outage between 401s must not count toward the clear"


def test_env_token_is_never_deleted(monkeypatch, tmp_path):
    token, count, _ = _redirect_state(monkeypatch, tmp_path)
    token.write_text("nms1_file_backup")  # even with a file present…
    s = _settings(enroll_token="nms1_pinned_by_operator")

    for _ in range(5):
        checkin._note_checkin_auth(s, 401)
    assert token.exists(), "an operator-pinned env token means we never delete state"
    assert int(count.read_text()) == 5, "…but the streak is still tracked and logged"


# --- enroll refusal backoff ---------------------------------------------------


def test_enroll_409_sets_backoff_and_skips_next_attempt(monkeypatch, tmp_path):
    _, _, backoff = _redirect_state(monkeypatch, tmp_path)
    calls: list[str] = []

    def refuse(url, token, body):
        calls.append(url)
        return None, 409  # identity already enrolled

    monkeypatch.setattr(checkin, "_post_status", refuse)
    s = _settings()

    assert checkin._auto_enroll(s, "https://dash") == ""
    assert backoff.exists(), "a refused enroll records the refusal time"
    assert len(calls) == 1

    # Next cycle: still inside the backoff window — must not even POST.
    assert checkin._auto_enroll(s, "https://dash") == ""
    assert len(calls) == 1, "within the backoff window no enroll request is sent"


def test_enroll_backoff_expires(monkeypatch, tmp_path):
    _, _, backoff = _redirect_state(monkeypatch, tmp_path)
    # A refusal recorded LONGER ago than the window → attempts resume.
    backoff.write_text("0")  # epoch 0 = long past
    calls: list[str] = []

    def grant(url, token, body):
        calls.append(url)
        return {"token": "nms1_new"}, 200

    monkeypatch.setattr(checkin, "_post_status", grant)
    token_file = checkin.TOKEN_FILE

    got = checkin._auto_enroll(_settings(), "https://dash")
    assert got == "nms1_new"
    assert len(calls) == 1
    assert token_file.read_text() == "nms1_new"
    assert not backoff.exists(), "a successful enroll clears the backoff"


def test_network_failure_does_not_back_off(monkeypatch, tmp_path):
    _, _, backoff = _redirect_state(monkeypatch, tmp_path)

    monkeypatch.setattr(checkin, "_post_status", lambda *a, **k: (None, None))
    assert checkin._auto_enroll(_settings(), "https://dash") == ""
    assert not backoff.exists(), "an unreachable dashboard is retried next cycle, not backed off"
