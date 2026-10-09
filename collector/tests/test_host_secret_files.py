"""Static contract for where the host scripts put secrets.

Same approach as test_update_contract.py: these scripts need Docker, sudo and
/var/lib/netmon, so the suite pins the text rather than running them.

Two things are pinned. A database snapshot is a full copy of the database —
SNMP communities included — so it must not be readable by other local accounts.
And the database password must never be placed on a command line, where `ps`
shows it to every local account.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
SNAPSHOT = (SCRIPTS / "db-snapshot.sh").read_text(encoding="utf-8")
ROLLBACK = (SCRIPTS / "rollback.sh").read_text(encoding="utf-8")
PATHS = (REPO_ROOT / "lib" / "paths.sh").read_text(encoding="utf-8")


def _code(text: str) -> str:
    """The script with comment-only lines dropped, so prose can name the old form."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _host_shell_sources() -> list[Path]:
    files = [*SCRIPTS.glob("*.sh"), *(REPO_ROOT / "lib").glob("*.sh")]
    files += [REPO_ROOT / name for name in ("netmon", "install.sh", "setup.sh")]
    return [f for f in files if f.is_file()]


def test_snapshot_directory_is_private_everywhere_it_is_created() -> None:
    # Both creators must agree: `install -d` re-applies its mode to an existing
    # directory, so a 0755 left in either one would undo the other on its next run.
    assert 'install -d -m 700 -o "$SNAP_OWNER" -g "$SNAP_OWNER" "$SNAP_DIR"' in SNAPSHOT
    snap_dir_lines = [ln for ln in _code(PATHS).splitlines() if '"$NETMON_DB_SNAPSHOTS_DIR"' in ln]
    assert snap_dir_lines, "lib/paths.sh no longer creates the snapshot directory"
    assert all("install -d -m 700 " in ln for ln in snap_dir_lines)
    for text in (SNAPSHOT, PATHS):
        assert not re.search(r"install -d -m 0?7[1-7][0-7].*SNAP", _code(text))


def test_snapshot_file_is_created_private() -> None:
    # The dump is written by a shell redirect, so its mode comes from the umask.
    code = _code(SNAPSHOT)
    assert code.index("umask 077") < code.index('| gzip > "$TARGET"')


def test_existing_snapshots_are_tightened_before_a_new_one_is_taken() -> None:
    # Boxes installed before this change hold 0644 dumps in a 0755 directory.
    code = _code(SNAPSHOT)
    sweep = code.index("-exec chmod 600 {} +")
    assert "-name 'netmon_*.sql.gz'" in code
    assert code.index("install -d -m 700") < sweep < code.index('| gzip > "$TARGET"')
    # ...and before the early "postgres not running" exit, which takes no snapshot.
    assert sweep < code.index("postgres container not running")


def test_database_password_never_rides_a_command_line() -> None:
    for path in _host_shell_sources():
        code = _code(path.read_text(encoding="utf-8"))
        # `-e PGPASSWORD=<value>` / `env PGPASSWORD=<value> cmd` put it in argv.
        assert not re.search(r"PGPASSWORD=\\?[\"']?\$\{?[A-Z_]*P(W|ASS)", code.replace(
            'PGPASSWORD="${POSTGRES_PASSWORD:-}"', ""
        )), path.name
        assert "PG_PW" not in code, path.name
        # Stronger than the pattern above, which a command substitution would
        # slip past: the name may appear ONLY inside the in-container script.
        assert "PGPASSWORD" not in code.replace('\'PGPASSWORD="${POSTGRES_PASSWORD:-}" exec ', ""), path.name


def test_password_is_supplied_inside_the_container() -> None:
    # The only argv carrying the word is a single-quoted script that the
    # container's own shell expands from the container's own environment.
    inner = "'PGPASSWORD=\"${POSTGRES_PASSWORD:-}\" exec "
    assert inner + "pg_dump " in SNAPSHOT
    assert inner + "psql " in ROLLBACK
    for text in (SNAPSHOT, ROLLBACK):
        assert "exec -T postgres sh -c" in _code(text)
        assert "POSTGRES_PASSWORD=" not in _code(text).replace("${POSTGRES_PASSWORD:-}", "")


def test_rollback_can_find_a_snapshot_it_cannot_read_directly() -> None:
    # The directory is 0700: a rollback run by another account must not read
    # "cannot search this directory" as "there is no snapshot" and skip the restore.
    code = _code(ROLLBACK)
    assert "if snap_exists; then" in code
    assert '[[ -e "$LATEST_SNAP" ]] || sudo -n test -e "$LATEST_SNAP"' in code
    assert 'sudo -n gunzip -c "$LATEST_SNAP"' in code
    assert code.count('gunzip -c "$LATEST_SNAP"') == 2  # direct + sudo, both in snap_cat


def test_rollback_checks_the_snapshot_is_whole_before_dropping_anything() -> None:
    # The DROP and the dump travel on one stream and psql commits at end of
    # input, so a snapshot that cannot be read must be detected before the DROP
    # is ever sent. Order is the whole point here.
    code = _code(ROLLBACK)
    gate = code.index("if ! snap_intact; then")
    drop = code.index("printf 'DROP SCHEMA public CASCADE")
    assert gate < drop
    assert code.count("DROP SCHEMA") == 1
    assert "elif { printf 'DROP SCHEMA public CASCADE" in code


def test_wifi_artifacts_are_not_world_readable() -> None:
    for name in ("netmon-wifi-survey.sh", "netmon-wifi-experience.sh"):
        code = _code((SCRIPTS / name).read_text(encoding="utf-8"))
        publish = [ln for ln in code.splitlines() if "install -m" in ln and '"$OUT"' in ln]
        assert publish, name
        assert all("install -m 0600 " in ln for ln in publish), name
