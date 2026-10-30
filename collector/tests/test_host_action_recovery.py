"""Host actions interrupted by a reboot, power loss or a kill must not vanish.

2026-10-30: a new box picked up `host-apply-vlan`, was re-cabled (rebooted) 2.5
minutes in, and the action was simply gone — host-action.sh clears the request
before running and wrote the result only after, so there was no result, no retry,
and the dashboard showed "scheduled" forever. These tests source the REAL
scripts/host-action.sh in bash with run_action and boot_id stubbed, and state
files in a temp dir.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_ACTION = REPO_ROOT / "scripts" / "host-action.sh"
CHECKIN_SH = REPO_ROOT / "scripts" / "netmon-checkin.sh"


def _bash() -> str:
    if sys.platform == "win32":
        git = shutil.which("git")
        candidates = [d / "bin" / "bash.exe" for d in Path(git).parents] if git else []
        found = next((str(c) for c in candidates if c.exists()), None)
    else:
        found = shutil.which("bash")
    if not found:
        pytest.skip("bash is required")
    return found


# run_action stub: records each call to $ST/calls. Behaviour per action via files:
#   $ST/fail-<action>   present => the action fails
#   $ST/die-<action>    present => the action kills its own shell (SIGKILL) mid-run
#   $ST/stdin-<action>  present => the action reads stdin (like docker compose)
PRELUDE = r'''
set -uo pipefail
export NETMON_STATE_DIR="$ST"
export NETMON_LOCK_DIR="$ST"
source "$HA"
logger() { :; }
log() { printf 'LOG %s\n' "$*"; }
boot_id() { cat "$ST/boot"; }
run_action() {
    printf '%s\n' "$1" >> "$ST/calls"
    [ -e "$ST/stdin-$1" ] && cat >/dev/null
    [ -e "$ST/die-$1" ] && kill -9 $$
    [ -e "$ST/fail-$1" ] && return 1
    return 0
}
'''


def _run(st: Path, body: str) -> subprocess.CompletedProcess:
    script = st / "t.sh"
    script.write_text(PRELUDE + body, encoding="utf-8", newline="\n")
    env = {**os.environ, "ST": st.as_posix(), "HA": HOST_ACTION.as_posix()}
    return subprocess.run(
        [_bash(), script.as_posix()], capture_output=True, text=True, env=env,
        stdin=subprocess.DEVNULL,
    )


@pytest.fixture
def st(tmp_path: Path) -> Path:
    _w((tmp_path / "boot"), "boot-B\n")
    return tmp_path


def _w(p: Path, text: str) -> None:
    """LF only, as the box writes it (Windows text mode would add CRs)."""
    p.write_bytes(text.encode("utf-8"))


def _result(st: Path) -> dict:
    return json.loads((st / "host-action-result").read_text(encoding="utf-8"))


def _calls(st: Path) -> list[str]:
    p = st / "calls"
    return p.read_text().split() if p.exists() else []


def _inflight(st: Path, cid: str, action: str, boot: str, attempt: int) -> None:
    _w((st / "host-action-inflight"), 
        f"{cid}\t{action}\t{boot}\t{attempt}\t2026-10-30T17:24:50+00:00\n"
    )


def _empty(p: Path) -> bool:
    return not p.exists() or p.read_text().strip() == ""


def test_a_normal_drain_reports_ok_with_the_command_id(st: Path) -> None:
    _w((st / "host-action-request"), "121\thost-apply-vlan\n")
    proc = _run(st, 'main --drain\n')
    assert proc.returncode == 0, proc.stderr
    assert _calls(st) == ["host-apply-vlan"]
    r = _result(st)
    assert (r["action"], r["status"], r["commandId"], r["attempt"]) == ("host-apply-vlan", "ok", 121, 1)
    assert _empty(st / "host-action-request")
    assert _empty(st / "host-action-inflight")


def test_an_action_killed_mid_run_is_retried_on_the_next_boot(st: Path) -> None:
    """End to end: the first run really dies part-way; a drain after a reboot finds it."""
    _w((st / "host-action-request"), "121\thost-apply-vlan\n")
    _w((st / "boot"), "boot-A\n")
    (st / "die-host-apply-vlan").touch()
    _run(st, 'main --drain\n')  # killed inside run_action
    assert _calls(st) == ["host-apply-vlan"]
    assert _result(st)["status"] == "running"          # what the next check-in reports
    assert not _empty(st / "host-action-inflight")     # the evidence survived
    assert _empty(st / "host-action-request")          # the request itself was cleared

    (st / "die-host-apply-vlan").unlink()
    _w((st / "boot"), "boot-B\n")               # the box rebooted
    proc = _run(st, 'main --drain\n')
    assert proc.returncode == 0, proc.stderr
    assert _calls(st) == ["host-apply-vlan", "host-apply-vlan"]
    r = _result(st)
    assert (r["status"], r["commandId"], r["attempt"]) == ("ok", 121, 2)
    assert _empty(st / "host-action-inflight")
    assert "restarted" in proc.stdout


def test_a_kill_without_a_reboot_is_called_killed_or_timed_out(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-B", 1)   # same boot as now
    proc = _run(st, 'main --drain\n')
    assert _calls(st) == ["host-apply-vlan"]
    assert "killed or timed out" in proc.stdout
    assert _result(st)["status"] == "ok"


@pytest.mark.parametrize("action", ["host-reboot", "host-rollback", "host-rebuild", "host-restart", "host-cis-apply"])
def test_disruptive_actions_are_reported_not_rerun(st: Path, action: str) -> None:
    _inflight(st, "7", action, "boot-A", 1)
    _run(st, 'main --drain\n')
    assert _calls(st) == []
    r = _result(st)
    assert (r["action"], r["status"], r["commandId"]) == (action, "interrupted", 7)
    assert "restarted" in r["reason"] and "not retried" in r["reason"]
    assert _empty(st / "host-action-inflight")


def test_a_second_interruption_is_not_retried_again(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 2)
    _run(st, 'main --drain\n')
    assert _calls(st) == []
    r = _result(st)
    assert (r["status"], r["attempt"]) == ("interrupted", 2)


def test_a_newer_request_for_the_same_action_supersedes_the_retry(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    _w((st / "host-action-request"), "130\thost-apply-vlan\n")
    _run(st, 'main --drain\n')
    assert _calls(st) == ["host-apply-vlan"]               # once, for 130
    r = _result(st)
    assert (r["status"], r["commandId"], r["attempt"]) == ("ok", 130, 1)


def test_a_failed_action_is_reported_and_leaves_no_inflight_record(st: Path) -> None:
    _w((st / "host-action-request"), "5\thost-wifi-join\n")
    (st / "fail-host-wifi-join").touch()
    _run(st, 'main --drain\n')
    r = _result(st)
    assert (r["status"], r["commandId"]) == ("failed", 5)
    assert _empty(st / "host-action-inflight")


def test_an_action_reading_stdin_does_not_eat_the_rest_of_the_queue(st: Path) -> None:
    _w((st / "host-action-request"), "1\thost-restart\n2\thost-apply-vlan\n")
    (st / "stdin-host-restart").touch()
    _run(st, 'main --drain\n')
    assert _calls(st) == ["host-restart", "host-apply-vlan"]


def test_the_result_stays_valid_json_for_hostile_strings(st: Path) -> None:
    _w((st / "host-action-request"), 'abc\tx"y\\z\n')
    _run(st, 'main --drain\n')
    r = _result(st)  # json.loads must not raise
    assert r["action"] == 'x"y\\z'
    assert "commandId" not in r                            # non-numeric id is not reported


def test_an_empty_drain_touches_nothing(st: Path) -> None:
    proc = _run(st, 'main --drain\n')
    assert proc.returncode == 0
    assert _calls(st) == []
    assert not (st / "host-action-result").exists()


def test_a_direct_run_is_tracked_too(st: Path) -> None:
    proc = _run(st, 'main host-apply-vlan\n')
    assert proc.returncode == 0, proc.stderr
    r = _result(st)
    assert (r["status"], r["attempt"]) == ("ok", 1)
    assert "commandId" not in r


def test_checkin_drains_leftovers_on_ordinary_checkins() -> None:
    """A request queued just before a reboot has no exit 12 to trigger its drain."""
    text = CHECKIN_SH.read_text(encoding="utf-8")
    for rc in ('"$rc" = "10"', '"$rc" = "0"'):
        arm = text[text.index(rc):]
        arm = arm[: arm.index("exit 0")]
        assert "drain_leftover_host_actions" in arm, rc
    assert 'HOST_ACTION_INFLIGHT="/var/lib/netmon/host-action-inflight"' in text


# --- a failure says WHY ---------------------------------------------------------

LOUD = r'''
run_action() {
    printf '%s\n' "$1" >> "$ST/calls"
    log "ACTION apply-vlan: build VLAN sub-interfaces"
    log "  ==> NetworkManager backend — configuring VLANs via nmcli instead of netplan."
    printf '[2026-10-30T13:15:30-07:00]   \033[33m  !!\033[0m could not inspect NM connection netmon-vlan4.\n'
    printf '[2026-10-30T13:15:31-07:00]   \033[33m  !!\033[0m VLAN(s) not configured — a non-NetMon NM profile holds the name: 4 5\n'
    return 1
}
'''


def test_a_failure_reports_the_actions_own_warnings(st: Path) -> None:
    _w((st / "host-action-request"), "122\thost-apply-vlan\n")
    proc = _run(st, LOUD + "export NETMON_LOG_DIR=\"$ST\"; HOST_ACTION_LOG=\"$ST/host-action.log\"\nmain --drain\n")
    assert proc.returncode == 0, proc.stderr
    r = _result(st)
    assert (r["status"], r["commandId"]) == ("failed", 122)
    assert r["reason"].startswith("action failed: ")
    assert "could not inspect NM connection netmon-vlan4." in r["reason"]
    assert "a non-NetMon NM profile holds the name: 4 5" in r["reason"]
    assert "\x1b" not in r["reason"] and "[2026-10-30" not in r["reason"]
    # The whole output is also kept for collect-logs, colour-free, under a header.
    log = (st / "host-action.log").read_text(encoding="utf-8")
    assert "=== " in log and "host-apply-vlan id=122 attempt=1 rc=1" in log
    assert "NetworkManager backend" in log and "\x1b" not in log
    # And it still reaches the caller's stdout (netmon-checkin.sh logs it).
    assert "could not inspect NM connection" in proc.stdout


def test_a_silent_failure_falls_back_to_its_last_lines(st: Path) -> None:
    body = r'''
run_action() { echo "NETMON_TRUNK_VLANS empty — nothing to apply (clearing is host-remove-vlan)"; return 1; }
HOST_ACTION_LOG="$ST/host-action.log"
main host-apply-vlan
'''
    _run(st, body)
    r = _result(st)
    assert r["status"] == "failed"
    assert "NETMON_TRUNK_VLANS empty" in r["reason"]


def test_a_failure_with_no_output_says_so(st: Path) -> None:
    _run(st, 'run_action() { return 1; }\nHOST_ACTION_LOG="$ST/host-action.log"\nmain host-restart\n')
    assert _result(st)["reason"] == "action failed: no output — check the box journal"


def test_the_failure_detail_is_bounded(st: Path) -> None:
    body = r'''
run_action() { local i; for i in 1 2 3 4 5; do printf '  !! %s\n' "$(printf 'x%.0s' $(seq 1 400))"; done; return 1; }
HOST_ACTION_LOG="$ST/host-action.log"
main host-apply-vlan
'''
    _run(st, body)
    assert len(_result(st)["reason"]) <= len("action failed: ") + 600


def test_checkin_scrubs_and_bounds_the_reported_reason(monkeypatch, tmp_path) -> None:
    from collector import checkin

    f = tmp_path / "host-action-result"
    _w(f, json.dumps({"action": "host-wifi-join", "status": "failed",
                             "reason": "action failed: psk=hunter2 " + "y" * 3000}))
    real_path = checkin.Path
    monkeypatch.setattr(checkin, "Path", lambda p: f if p == "/var/lib/netmon/host-action-result" else real_path(p))
    data = checkin._last_host_action()
    assert data is not None
    assert "hunter2" not in data["reason"]
    assert len(data["reason"]) <= 1000


def test_collect_logs_includes_the_host_action_log() -> None:
    import inspect

    from collector import checkin

    assert '"host-action.log"' in inspect.getsource(checkin._collect_logs)


# --- leftovers run only while fresh ---------------------------------------------


def _age(p: Path, minutes: int) -> None:
    import time

    t = time.time() - minutes * 60
    os.utime(p, (t, t))


def test_a_fresh_leftover_request_runs(st: Path) -> None:
    req = st / "host-action-request"
    _w(req, "121\thost-apply-vlan\n")
    _age(req, 10)
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == ["host-apply-vlan"]
    assert _result(st)["status"] == "ok"


def test_a_stale_leftover_request_is_expired_not_run(st: Path) -> None:
    """A reboot request stuck in the file for days must not fire on the next check-in."""
    req = st / "host-action-request"
    _w(req, "9\thost-reboot\n")
    _age(req, 3 * 24 * 60)
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == []
    r = _result(st)
    assert (r["action"], r["status"], r["commandId"]) == ("host-reboot", "expired", 9)
    assert _empty(req)


def test_a_stale_request_expires_on_an_explicit_drain_too(st: Path) -> None:
    """Exit 12 drains whatever is queued — including one left from a skipped cycle."""
    req = st / "host-action-request"
    _w(req, "9\thost-restart\n")
    _age(req, 3 * 24 * 60)
    _run(st, "main --drain\n")
    assert _calls(st) == []
    assert (_result(st)["status"], _result(st)["commandId"]) == ("expired", 9)


def test_a_fresh_request_runs_on_an_explicit_drain(st: Path) -> None:
    _w(st / "host-action-request", "9\thost-restart\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-restart"]


def test_an_interrupted_action_is_recovered_by_a_leftover_drain(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == ["host-apply-vlan"]
    assert _result(st)["attempt"] == 2


def test_checkin_uses_the_age_limited_drain_for_leftovers() -> None:
    text = CHECKIN_SH.read_text(encoding="utf-8")
    fn = text[text.index("drain_leftover_host_actions() {"):]
    fn = fn[: fn.index("\n}\n")]
    assert "--drain-leftover" in fn and "--drain " not in fn



# --- review round 1 (Fable + Codex, 2026-10-30) ----------------------------------


def _history(st: Path) -> list[dict]:
    p = st / "host-action-results"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_every_command_in_one_drain_is_settled_not_just_the_last(st: Path) -> None:
    """The latest-result file holds one outcome; the history holds each command's."""
    _w((st / "host-action-request"), "1\thost-restart\n2\thost-apply-vlan\n")
    (st / "fail-host-restart").touch()
    _run(st, "main --drain\n")
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(1, "failed"), (2, "ok")]
    assert all(h["status"] != "running" for h in _history(st))


def test_a_superseded_interruption_is_still_reported_in_the_history(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    _w((st / "host-action-request"), "130\thost-apply-vlan\n")
    _run(st, "main --drain\n")
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(121, "interrupted"), (130, "ok")]


def test_a_newer_remove_supersedes_retrying_an_interrupted_apply(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    _w((st / "host-action-request"), "130\thost-remove-vlan\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-remove-vlan"]
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(121, "interrupted"), (130, "ok")]


def test_power_loss_mid_queue_keeps_the_unstarted_requests(st: Path) -> None:
    """A, B queued; the box dies during A. B must survive and run on the next boot."""
    _w((st / "host-action-request"), "1\thost-restart\n2\thost-apply-vlan\n")
    _w((st / "boot"), "boot-A\n")
    (st / "die-host-restart").touch()
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-restart"]
    assert (st / "host-action-request").read_text().strip() == "2\thost-apply-vlan"
    (st / "die-host-restart").unlink()
    _w((st / "boot"), "boot-B\n")
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == ["host-restart", "host-apply-vlan"]   # restart NOT re-run
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(1, "interrupted"), (2, "ok")]


def test_nothing_runs_when_the_request_cannot_be_removed(st: Path) -> None:
    """A request that stays queued would run again on every check-in: a reboot loop."""
    _w((st / "host-action-request"), "9\thost-reboot\n")
    _run(st, '_queue_set() { return 1; }\nmain --drain\n')
    assert _calls(st) == []
    assert _empty(st / "host-action-inflight")
    r = _result(st)
    # Still queued, so NOT a terminal "failed" that its later run would contradict.
    assert (r["status"], r["commandId"]) == ("deferred", 9) and "could not remove" in r["reason"]
    assert _history(st) == []


def test_nothing_runs_when_the_inflight_record_cannot_be_written(st: Path) -> None:
    _w((st / "host-action-request"), "9\thost-reboot\n")
    body = (
        'eval "orig_$(declare -f _write_state)"\n'
        '_write_state() { [ "$1" = "$INFLIGHT_FILE" ] && return 1; orig__write_state "$@"; }\n'
        "main --drain\n"
    )
    _run(st, body)
    assert _calls(st) == []
    assert (st / "host-action-request").read_text().startswith("9\thost-reboot")   # left queued
    assert _result(st)["status"] == "deferred" and _history(st) == []


def test_the_retry_limit_holds_when_the_attempt_cannot_be_recorded(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    body = (
        'eval "orig_$(declare -f _write_state)"\n'
        '_write_state() { [ "$1" = "$INFLIGHT_FILE" ] && return 1; orig__write_state "$@"; }\n'
        "main --drain\nmain --drain\n"
    )
    _run(st, body)
    assert _calls(st) == []


def test_recorded_but_never_claimed_runs_once_from_the_queue(st: Path) -> None:
    """Stopped between the in-flight write and the queue removal: not an interruption."""
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    _w((st / "host-action-request"), "121\thost-apply-vlan\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-apply-vlan"]
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(121, "ok")]


def test_an_interrupted_manual_run_keeps_its_fields(st: Path) -> None:
    """No command id: a leading empty field would shift the record (TAB is IFS whitespace)."""
    _w((st / "boot"), "boot-A\n")
    (st / "die-host-apply-vlan").touch()
    _run(st, "main host-apply-vlan\n")
    assert (st / "host-action-inflight").read_text().startswith("-\thost-apply-vlan\t")
    (st / "die-host-apply-vlan").unlink()
    _w((st / "boot"), "boot-B\n")
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == ["host-apply-vlan", "host-apply-vlan"]
    assert (_result(st)["action"], _result(st)["status"]) == ("host-apply-vlan", "ok")


def test_control_characters_in_the_output_keep_the_result_parseable(st: Path) -> None:
    body = r'''
run_action() { printf 'step one\n\033[Kerror: \a broke\b here\f\n  !! bad \033]0;title\a thing\n'; return 1; }
HOST_ACTION_LOG="$ST/host-action.log"
main host-apply-vlan
'''
    _run(st, body)
    raw = (st / "host-action-result").read_text(encoding="utf-8")
    r = json.loads(raw)   # strict, like the collector used to be
    assert r["status"] == "failed" and "bad" in r["reason"]
    assert not any(ord(c) < 32 for c in r["reason"])


@pytest.mark.parametrize(("action", "minutes", "runs"), [
    ("host-reboot", 20, False),       # disruptive: 15-minute limit
    ("host-reboot", 5, True),
    ("host-apply-vlan", 20, True),    # convergent: 120-minute limit
    ("host-apply-vlan", 130, False),
])
def test_leftover_age_limits_depend_on_the_action(st: Path, action: str, minutes: int, runs: bool) -> None:
    req = st / "host-action-request"
    _w(req, f"9\t{action}\n")
    _age(req, minutes)
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == ([action] if runs else [])
    if not runs:
        assert (_result(st)["status"], _result(st)["commandId"]) == ("expired", 9)


def test_the_run_lock_is_never_replaced_and_fails_closed() -> None:
    """git pull replaces the script file, and an atomic rename would replace a lock
    file too: either way two starters lock different inodes. Open with >> only."""
    text = HOST_ACTION.read_text(encoding="utf-8")
    take = text[text.index("_take_lock() {"):]
    take = take[: take.index("\n}\n")]
    assert 'exec 9>>"$LOCK_FILE"' in take
    assert "BASH_SOURCE" not in take and "_write_state" not in take
    assert "return 2" in take                              # can't open: fail closed
    assert 'LOCK_FILE="${NETMON_LOCK_DIR:-/run/lock}/netmon-host-action.lock"' in text


def test_an_unopenable_lock_runs_nothing(st: Path) -> None:
    _w(st / "host-action-request", "1\thost-reboot\n")
    proc = _run(st, "flock() { return 0; }\nLOCK_FILE=/nonexistent-dir/x.lock\nmain --drain\n")
    assert _calls(st) == []
    assert "cannot open" in proc.stdout


def test_collector_reports_the_history_and_survives_odd_bytes(monkeypatch, tmp_path) -> None:
    from collector import checkin

    hist = tmp_path / "host-action-results"
    hist.write_bytes(
        b'{"action":"host-restart","status":"failed","reason":"x\x1b[K psk=hunter2","commandId":1}\n'
        b"not json\n"
        b'{"action":"host-apply-vlan","status":"ok","reason":"cut \xe2\x80","commandId":2}\n'
    )
    real_path = checkin.Path
    monkeypatch.setattr(
        checkin, "Path", lambda p: hist if p == "/var/lib/netmon/host-action-results" else real_path(p)
    )
    out = checkin._host_action_history()
    assert [(r["commandId"], r["status"]) for r in out] == [(1, "failed"), (2, "ok")]
    assert "hunter2" not in out[0]["reason"]


def test_leftovers_wait_while_an_update_is_running() -> None:
    text = CHECKIN_SH.read_text(encoding="utf-8")
    fn = text[text.index("drain_leftover_host_actions() {"):]
    fn = fn[: fn.index("\n}\n")]
    assert fn.index("systemctl is-active --quiet netmon-update.service") < fn.index("--drain-leftover")



# --- review round 2 (Codex fix pass) ----------------------------------------------


def test_each_request_keeps_its_own_age_through_a_claim(st: Path) -> None:
    """The file's mtime is refreshed by every claim; a request's own stamp is not."""
    import time

    old = int(time.time()) - 20 * 60
    _w(st / "host-action-request", "1\thost-apply-vlan\n2\thost-reboot\n")
    _w(st / "host-action-seen", f"2\t{old}\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-apply-vlan"]             # the fresh one ran
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(1, "ok"), (2, "expired")]


def test_a_claim_preserves_the_stamps_of_the_requests_behind_it(st: Path) -> None:
    import time

    old = int(time.time()) - 5 * 60
    _w(st / "host-action-request", "1\thost-restart\n2\thost-reboot\n")
    _w(st / "host-action-seen", f"1\t{old}\n2\t{old}\n")
    (st / "boot").write_text("boot-A\n")
    (st / "die-host-restart").touch()
    _run(st, "main --drain\n")
    assert (st / "host-action-request").read_text().strip() == "2\thost-reboot"   # format unchanged
    assert f"2\t{old}" in (st / "host-action-seen").read_text()


def test_stamp_mode_dates_new_requests_by_the_file_mtime(st: Path) -> None:
    req = st / "host-action-request"
    _w(req, "1\thost-reboot\n")
    _age(req, 30)
    mtime = int(req.stat().st_mtime)
    _run(st, "main --stamp\n")
    assert _calls(st) == []
    assert req.read_text() == "1\thost-reboot\n"                 # the queue is never rewritten
    cid, ts = (st / "host-action-seen").read_text().strip().split("\t")
    assert cid == "1" and abs(int(ts) - mtime) <= 1


def test_a_failed_replacement_leaves_the_file_intact(st: Path) -> None:
    """Atomic writes: a failed rename must not leave a truncated file behind."""
    f = st / "host-action-request"
    _w(f, "1\thost-restart\n2\thost-apply-vlan\n")
    proc = _run(st, 'mv() { return 1; }\nSUDO=(false)\n_write_state "$REQUEST_FILE" "2\thost-apply-vlan"; echo "rc=$?"\n')
    assert "rc=1" in proc.stdout
    assert f.read_text() == "1\thost-restart\n2\thost-apply-vlan\n"
    assert not list(st.glob("*.tmp.*"))                   # no temp files left behind


def test_a_failed_queue_replacement_during_a_claim_runs_nothing(st: Path) -> None:
    """Only the request-file replacement fails; the in-flight write before it succeeded."""
    _w(st / "host-action-request", "1\thost-restart\n2\thost-apply-vlan\n")
    body = (
        'eval "orig_$(declare -f _write_state)"\n'
        '_write_state() { if [ "$1" = "$REQUEST_FILE" ]; then echo "QWRITE" >> "$ST/attempts"; return 1; fi; orig__write_state "$@"; }\n'
        "main --drain\n"
    )
    _run(st, body)
    assert (st / "attempts").read_text().split() == ["QWRITE"]   # the replacement WAS attempted
    assert _calls(st) == []
    assert (st / "host-action-request").read_text() == "1\thost-restart\n2\thost-apply-vlan\n"
    assert _empty(st / "host-action-inflight")
    assert (_result(st)["status"], _result(st)["commandId"]) == ("deferred", 1)


def test_a_retry_that_cannot_be_recorded_is_deferred_not_failed(st: Path) -> None:
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    body = (
        'eval "orig_$(declare -f _write_state)"\n'
        '_write_state() { [ "$1" = "$INFLIGHT_FILE" ] && return 1; orig__write_state "$@"; }\n'
        "main --drain\n"
    )
    _run(st, body)
    assert _calls(st) == []
    assert (_result(st)["status"], _result(st)["commandId"]) == ("deferred", 121)
    assert _history(st) == []
    assert "\t1\t" in (st / "host-action-inflight").read_text()   # retry still pending


def test_checkin_stamps_before_the_checkin_and_serialises_itself() -> None:
    text = CHECKIN_SH.read_text(encoding="utf-8")
    lock = text.index('exec 8>>"${NETMON_LOCK_DIR:-/run/lock}/netmon-checkin.lock"')
    stamp = text.index('host-action.sh" --stamp 8>&- >/dev/null 2>&1\n\nout=')
    checkin = text.index("exec -T collector python -m collector checkin")
    assert lock < stamp < checkin
    # every host-action call drops the check-in lock fd
    for call in ("--drain 8>&-", "--drain-leftover 8>&-"):
        assert call in text


def test_checkin_stamps_the_queue_when_it_leaves_it_for_later() -> None:
    text = CHECKIN_SH.read_text(encoding="utf-8")
    fn = text[text.index("drain_leftover_host_actions() {"):]
    fn = fn[: fn.index("\n}\n")]
    wait = fn[fn.index("systemctl is-active"):]
    wait = wait[: wait.index("return 0")]
    assert "--stamp" in wait



def test_the_queue_waits_while_a_deferred_retry_is_pending(st: Path) -> None:
    """Strict order: a newer command must not settle while an older one is still owed a run."""
    _inflight(st, "121", "host-apply-vlan", "boot-A", 1)
    _w(st / "host-action-request", "130\thost-restart\n")
    body = (
        'eval "orig_$(declare -f _write_state)"\n'
        '_write_state() { [ "$1" = "$INFLIGHT_FILE" ] && return 1; orig__write_state "$@"; }\n'
        "main --drain\n"
    )
    _run(st, body)
    assert _calls(st) == []
    assert (st / "host-action-request").read_text().startswith("130\thost-restart")



# --- review round 3 (Codex pass 3) ------------------------------------------------


def test_a_stuck_legacy_request_stays_old_after_a_new_append(st: Path) -> None:
    """Stamped BEFORE the check-in appends, so the new append's mtime can't rejuvenate it."""
    req = st / "host-action-request"
    _w(req, "1\thost-reboot\n")
    _age(req, 3 * 24 * 60)
    _run(st, "main --stamp\n")                              # netmon-checkin.sh, pre-check-in
    with req.open("ab") as fh:                                 # the check-in appends
        fh.write(b"2\thost-apply-vlan\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-apply-vlan"]
    assert [(h["commandId"], h["status"]) for h in _history(st)] == [(1, "expired"), (2, "ok")]
    assert _empty(st / "host-action-seen")                     # nothing queued: pruned


@pytest.mark.parametrize(("action", "runs"), [("host-reboot", False), ("host-apply-vlan", True)])
def test_a_stamp_from_the_future_is_unknown_age(st: Path, action: str, runs: bool) -> None:
    import time

    _w(st / "host-action-request", f"1\t{action}\n")
    _w(st / "host-action-seen", f"1\t{int(time.time()) + 3600}\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ([action] if runs else [])


def test_a_malformed_seen_entry_is_restamped_not_trusted(st: Path) -> None:
    req = st / "host-action-request"
    _w(req, "1\thost-reboot\n")
    _w(st / "host-action-seen", "1\tgarbage\nxx\t5\n")
    _run(st, "main --drain\n")
    assert _calls(st) == ["host-reboot"]                       # dated by the fresh append


def test_seen_keeps_the_in_flight_request(st: Path) -> None:
    (st / "boot").write_text("boot-A\n")
    _w(st / "host-action-request", "1\thost-restart\n2\thost-apply-vlan\n")
    (st / "die-host-restart").touch()
    _run(st, "main --drain\n")
    seen = (st / "host-action-seen").read_text()
    assert seen.startswith("1\t") or "\n1\t" in seen       # in flight: kept
    assert "2\t" in seen                                      # still queued: kept
