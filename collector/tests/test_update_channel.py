"""The update channel must hold: a hold or a pin never degrades to following main.

Unlike test_update_contract.py these tests EXECUTE the channel logic. The block
is lifted verbatim out of the real script and run by bash against a scratch git
repository, because the two failures this pins were both behaviours, not text:

  * auto-update.sh logged a WARN and tracked origin/main when the pinned ref did
    not resolve — the opposite of what a pin asks for;
  * weekly-deep-refresh.sh pulled origin/main without reading the channel at all,
    moving a held or pinned box onto main once a week.
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
UPDATER = (REPO_ROOT / "scripts" / "auto-update.sh").read_text(encoding="utf-8")
REFRESH = (REPO_ROOT / "scripts" / "weekly-deep-refresh.sh").read_text(encoding="utf-8")


def _bash() -> str:
    if sys.platform == "win32":
        # PATH may resolve `bash` to the WSL launcher; these need Git's bash.
        git = shutil.which("git")
        candidates = [d / "bin" / "bash.exe" for d in Path(git).parents] if git else []
        found = next((str(c) for c in candidates if c.exists()), None)
    else:
        found = shutil.which("bash")
    if not found or not shutil.which("git"):
        pytest.skip("bash and git are required")
    return found


def _between(text: str, start: str, end: str) -> str:
    a = text.index(start)
    return text[a : text.index(end, a)]


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )
    return out.stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> dict[str, str]:
    """A checkout sitting on commit A while origin/main has moved on to B."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "f").write_text("a\n")
    _git(root, "add", "f")
    _git(root, "commit", "-q", "-m", "A")
    a = _git(root, "rev-parse", "HEAD")
    (root / "f").write_text("b\n")
    _git(root, "commit", "-q", "-am", "B")
    b = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", "refs/remotes/origin/main", b)
    _git(root, "checkout", "-q", "--detach", a)
    return {"root": str(root), "a": a, "b": b}


# --- auto-update.sh -------------------------------------------------------

CHANNEL_BLOCK = _between(UPDATER, "channel_env_known() {", "\n# Reconcile image")

UPDATER_HARNESS = """\
set -euo pipefail
log() { printf 'LOG %s\\n' "$*"; }
read_env() {
    case "$1" in
        NETMON_UPDATE_CHANNEL) printf '%s' "${T_CHANNEL-}" ;;
        NETMON_UPDATE_REF) printf '%s' "${T_REF-}" ;;
    esac
}
sudo() { return 1; }
ENV_FILE="${T_ENV_FILE:-/nonexistent-netmon-dir/netmon.env}"
RESULT_STATUS="unset"; RESULT_REASON="unset"; REMOTE=""; IMAGE_TAG=""
trap 'printf "STATUS=%s\\nREASON=%s\\nREMOTE=%s\\nIMAGE_TAG=%s\\n" "$RESULT_STATUS" "$RESULT_REASON" "$REMOTE" "$IMAGE_TAG"' EXIT
LOCAL=$(git rev-parse HEAD)
"""


def _resolve(
    repo: dict[str, str], tmp_path: Path, channel: str, ref: str, env_file: str = ""
) -> dict[str, str]:
    script = tmp_path / "channel.sh"
    script.write_text(UPDATER_HARNESS + CHANNEL_BLOCK + "\n", encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [_bash(), script.as_posix()], cwd=repo["root"], capture_output=True, text=True,
        env={**os.environ, "T_CHANNEL": channel, "T_REF": ref, "T_ENV_FILE": env_file},
    )
    fields = dict(
        ln.split("=", 1) for ln in proc.stdout.splitlines() if "=" in ln and not ln.startswith("LOG ")
    )
    fields["rc"] = str(proc.returncode)
    fields["log"] = proc.stdout + proc.stderr
    return fields


@pytest.mark.parametrize("channel", ["stable", "", "Stable", "nightly"])
def test_resolvable_pin_is_honoured(repo, tmp_path, channel) -> None:
    out = _resolve(repo, tmp_path, channel, repo["a"])
    assert out["rc"] == "0", out["log"]
    assert out["REMOTE"] == repo["a"] == out["IMAGE_TAG"]


@pytest.mark.parametrize("spell", ["abbrev", "upper", "padded"])
def test_pin_spellings_the_dashboard_accepts_still_resolve(repo, tmp_path, spell) -> None:
    # The dashboard forwards what the operator typed: 7-40 hex, either case.
    # Failing closed on any of these would freeze a correctly pinned fleet.
    ref = {"abbrev": repo["a"][:7], "upper": repo["a"].upper(), "padded": f" {repo['a']}\r"}[spell]
    out = _resolve(repo, tmp_path, "stable", ref)
    assert out["rc"] == "0", out["log"]
    assert out["REMOTE"] == repo["a"]


def test_a_pin_must_be_on_main_not_merely_present(repo, tmp_path) -> None:
    # A commit this checkout holds but main does not contain is not a release.
    root = Path(repo["root"])
    (root / "f").write_text("off-main\n")
    _git(root, "commit", "-q", "-am", "side")
    side = _git(root, "rev-parse", "HEAD")
    _git(root, "checkout", "-q", "--detach", repo["a"])

    out = _resolve(repo, tmp_path, "stable", side)

    assert out["rc"] == "1", out["log"]
    assert out["REMOTE"] != side or out["IMAGE_TAG"] == ""
    assert out["IMAGE_TAG"] == ""
    assert out["STATUS"] == "failed"
    # Positive control: main's own tip is accepted by the same check.
    assert _resolve(repo, tmp_path, "stable", repo["b"])["IMAGE_TAG"] == repo["b"]


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a file the test user genuinely cannot read",
)
def test_unreadable_env_file_stops_the_run_instead_of_following_main(repo, tmp_path) -> None:
    # read_env returns "" on any error, and "" means "follow main". An env file
    # that exists but cannot be read must therefore stop the run.
    env_file = tmp_path / "netmon.env"
    env_file.write_text("NETMON_UPDATE_CHANNEL=hold\n")
    env_file.chmod(0o000)

    out = _resolve(repo, tmp_path, "", "", env_file=env_file.as_posix())

    assert out["rc"] == "1", out["log"]
    assert out["STATUS"] == "failed"
    assert out["REMOTE"] == "" and out["IMAGE_TAG"] == ""
    assert "cannot read the env file" in out["REASON"]


def test_a_readable_or_absent_env_file_does_not_stop_the_run(repo, tmp_path) -> None:
    # Positive control for the test above, on every platform.
    env_file = tmp_path / "netmon.env"
    env_file.write_text("POSTGRES_USER=netmon\n")
    assert _resolve(repo, tmp_path, "", "", env_file=env_file.as_posix())["REMOTE"] == repo["b"]
    assert _resolve(repo, tmp_path, "", "", env_file=(tmp_path / "absent.env").as_posix())["REMOTE"] == repo["b"]


@pytest.mark.parametrize("channel", ["stable", "", "nightly"])
@pytest.mark.parametrize(
    "ref",
    [
        "0123456789abcdef0123456789abcdef01234567",  # well-formed, not in the repo
        "no-such-branch",
        "-n",  # looks like an option
        "v1.2.3\\",
    ],
)
def test_unresolvable_pin_stays_put_and_reports_why(repo, tmp_path, channel, ref) -> None:
    out = _resolve(repo, tmp_path, channel, ref)
    assert out["rc"] == "1", out["log"]
    # No target was chosen at all — in particular, not origin/main.
    assert out["REMOTE"] == "" and out["IMAGE_TAG"] == ""
    assert out["STATUS"] == "failed"
    assert "not found on origin/main" in out["REASON"]
    assert f"staying on {repo['a'][:8]}" in out["REASON"]
    assert "tracking origin/main" not in out["log"]
    # record_result interpolates the reason into a JSON string verbatim.
    assert json.loads('{"reason":"' + out["REASON"] + '"}')["reason"] == out["REASON"]


def test_pin_reason_cannot_break_the_result_json(repo, tmp_path) -> None:
    out = _resolve(repo, tmp_path, "stable", 'x","status":"ok')
    assert out["rc"] == "1"
    assert '"' not in out["REASON"] and "\\" not in out["REASON"]


@pytest.mark.parametrize("channel", ["hold", "Hold", "HOLD ", "'hold'", "hold\r"])
def test_hold_holds_however_it_is_spelled(repo, tmp_path, channel) -> None:
    # With and without a pin: hold wins either way.
    for ref in ("", repo["b"]):
        out = _resolve(repo, tmp_path, channel, ref)
        assert out["rc"] == "0", out["log"]
        assert out["STATUS"] == "skipped"
        assert out["REMOTE"] == ""


def test_unpinned_stable_and_canary_follow_main(repo, tmp_path) -> None:
    assert _resolve(repo, tmp_path, "stable", "")["REMOTE"] == repo["b"]
    assert _resolve(repo, tmp_path, "", "")["REMOTE"] == repo["b"]
    # canary means "latest main" by definition, so it ignores a pin — even a bad one.
    assert _resolve(repo, tmp_path, "canary", "no-such-branch")["REMOTE"] == repo["b"]


# --- weekly-deep-refresh.sh -----------------------------------------------

REFRESH_FUNCS = _between(REFRESH, 'ENV_FILE="/etc/netmon/netmon.env"', "\n# Pull the latest code first")


def _follows_main(tmp_path: Path, env_text: str | None, *, unreadable: bool = False) -> tuple[bool, str]:
    env_file = tmp_path / "etc" / "netmon.env"
    env_file.parent.mkdir(exist_ok=True)
    if env_text is not None:
        env_file.write_text(env_text, encoding="utf-8", newline="\n")
        if unreadable:
            env_file.chmod(0o000)
    funcs = REFRESH_FUNCS.replace('ENV_FILE="/etc/netmon/netmon.env"', f'ENV_FILE="{env_file.as_posix()}"')
    assert env_file.as_posix() in funcs
    script = tmp_path / "refresh.sh"
    script.write_text(
        "set -euo pipefail\nsudo() { return 1; }\n" + funcs
        + '\nif channel_follows_main; then echo "PULL"; else echo "NOPULL $CHANNEL_NOTE"; fi\n',
        encoding="utf-8", newline="\n",
    )
    proc = subprocess.run([_bash(), script.as_posix()], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.startswith("PULL"), proc.stdout.strip()


@pytest.mark.parametrize(
    "env_text",
    [
        "NETMON_UPDATE_CHANNEL=hold\n",
        'NETMON_UPDATE_CHANNEL="Hold"\n',
        "NETMON_UPDATE_CHANNEL=hold\r\n",
        "NETMON_UPDATE_CHANNEL=stable\nNETMON_UPDATE_CHANNEL=hold\n",  # last one wins
        "NETMON_UPDATE_CHANNEL=stable\nNETMON_UPDATE_REF=abc1234\n",
        "NETMON_UPDATE_REF=abc1234\n",  # channel unset == stable
        "NETMON_UPDATE_CHANNEL=nightly\nNETMON_UPDATE_REF=abc1234\n",
        "NETMON_UPDATE_CHANNEL=hold\nNETMON_UPDATE_REF=abc1234\n",
    ],
)
def test_weekly_refresh_does_not_pull_on_a_held_or_pinned_box(tmp_path, env_text) -> None:
    follows, out = _follows_main(tmp_path, env_text)
    assert not follows, out
    assert "hold" in out or "pinned" in out


@pytest.mark.parametrize(
    "env_text",
    [
        None,  # no env file yet (box not set up)
        "POSTGRES_USER=netmon\n",
        "NETMON_UPDATE_CHANNEL=stable\nNETMON_UPDATE_REF=\n",
        'NETMON_UPDATE_CHANNEL=stable\nNETMON_UPDATE_REF=""\n',
        "NETMON_UPDATE_CHANNEL=canary\nNETMON_UPDATE_REF=abc1234\n",
        "NOT_NETMON_UPDATE_CHANNEL=hold\n",
        "# NETMON_UPDATE_CHANNEL=hold\n",
    ],
)
def test_weekly_refresh_still_pulls_when_the_box_follows_main(tmp_path, env_text) -> None:
    follows, out = _follows_main(tmp_path, env_text)
    assert follows, out


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a file the test user genuinely cannot read",
)
def test_weekly_refresh_fails_closed_when_the_channel_cannot_be_read(tmp_path) -> None:
    follows, out = _follows_main(tmp_path, "NETMON_UPDATE_CHANNEL=hold\n", unreadable=True)
    assert not follows
    assert "cannot read" in out


def test_weekly_refresh_consults_the_channel_before_any_pull() -> None:
    gate = REFRESH.index("if ! channel_follows_main; then")
    assert gate < REFRESH.index("git fetch --quiet origin main") < REFRESH.index("git pull --ff-only")
    code = "\n".join(ln for ln in REFRESH.splitlines() if not ln.lstrip().startswith("#"))
    assert code.count("git pull --") == 1
