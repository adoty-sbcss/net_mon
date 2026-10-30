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
    (tmp_path / "boot").write_text("boot-B\n")
    return tmp_path


def _result(st: Path) -> dict:
    return json.loads((st / "host-action-result").read_text(encoding="utf-8"))


def _calls(st: Path) -> list[str]:
    p = st / "calls"
    return p.read_text().split() if p.exists() else []


def _inflight(st: Path, cid: str, action: str, boot: str, attempt: int) -> None:
    (st / "host-action-inflight").write_text(
        f"{cid}\t{action}\t{boot}\t{attempt}\t2026-10-30T17:24:50+00:00\n"
    )


def _empty(p: Path) -> bool:
    return not p.exists() or p.read_text().strip() == ""


def test_a_normal_drain_reports_ok_with_the_command_id(st: Path) -> None:
    (st / "host-action-request").write_text("121\thost-apply-vlan\n")
    proc = _run(st, 'main --drain\n')
    assert proc.returncode == 0, proc.stderr
    assert _calls(st) == ["host-apply-vlan"]
    r = _result(st)
    assert (r["action"], r["status"], r["commandId"], r["attempt"]) == ("host-apply-vlan", "ok", 121, 1)
    assert _empty(st / "host-action-request")
    assert _empty(st / "host-action-inflight")


def test_an_action_killed_mid_run_is_retried_on_the_next_boot(st: Path) -> None:
    """End to end: the first run really dies part-way; a drain after a reboot finds it."""
    (st / "host-action-request").write_text("121\thost-apply-vlan\n")
    (st / "boot").write_text("boot-A\n")
    (st / "die-host-apply-vlan").touch()
    _run(st, 'main --drain\n')  # killed inside run_action
    assert _calls(st) == ["host-apply-vlan"]
    assert _result(st)["status"] == "running"          # what the next check-in reports
    assert not _empty(st / "host-action-inflight")     # the evidence survived
    assert _empty(st / "host-action-request")          # the request itself was cleared

    (st / "die-host-apply-vlan").unlink()
    (st / "boot").write_text("boot-B\n")               # the box rebooted
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
    (st / "host-action-request").write_text("130\thost-apply-vlan\n")
    _run(st, 'main --drain\n')
    assert _calls(st) == ["host-apply-vlan"]               # once, for 130
    r = _result(st)
    assert (r["status"], r["commandId"], r["attempt"]) == ("ok", 130, 1)


def test_a_failed_action_is_reported_and_leaves_no_inflight_record(st: Path) -> None:
    (st / "host-action-request").write_text("5\thost-wifi-join\n")
    (st / "fail-host-wifi-join").touch()
    _run(st, 'main --drain\n')
    r = _result(st)
    assert (r["status"], r["commandId"]) == ("failed", 5)
    assert _empty(st / "host-action-inflight")


def test_an_action_reading_stdin_does_not_eat_the_rest_of_the_queue(st: Path) -> None:
    (st / "host-action-request").write_text("1\thost-restart\n2\thost-apply-vlan\n")
    (st / "stdin-host-restart").touch()
    _run(st, 'main --drain\n')
    assert _calls(st) == ["host-restart", "host-apply-vlan"]


def test_the_result_stays_valid_json_for_hostile_strings(st: Path) -> None:
    (st / "host-action-request").write_text('abc\tx"y\\z\n')
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
    (st / "host-action-request").write_text("122\thost-apply-vlan\n")
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
    f.write_text(json.dumps({"action": "host-wifi-join", "status": "failed",
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
    req.write_text("121\thost-apply-vlan\n")
    _age(req, 10)
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == ["host-apply-vlan"]
    assert _result(st)["status"] == "ok"


def test_a_stale_leftover_request_is_expired_not_run(st: Path) -> None:
    """A reboot request stuck in the file for days must not fire on the next check-in."""
    req = st / "host-action-request"
    req.write_text("9\thost-reboot\n")
    _age(req, 3 * 24 * 60)
    _run(st, "main --drain-leftover\n")
    assert _calls(st) == []
    r = _result(st)
    assert (r["action"], r["status"], r["commandId"]) == ("host-reboot", "expired", 9)
    assert _empty(req)


def test_a_stale_request_still_runs_on_an_explicit_drain(st: Path) -> None:
    """--drain is exit 12: the agent queued it on this very check-in."""
    req = st / "host-action-request"
    req.write_text("9\thost-restart\n")
    _age(req, 3 * 24 * 60)
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
