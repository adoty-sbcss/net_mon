"""rollback.sh must never drop the schema for a snapshot it cannot fully read.

The restore sends `DROP SCHEMA public CASCADE; CREATE SCHEMA public;` and then
the decompressed dump down ONE pipe into psql. psql commits when its input
ends; it cannot see that gunzip upstream failed. So if the snapshot is
unreadable or truncated, the DROP commits and the database is left empty —
while the script, seeing the failure only afterwards through pipefail, logs
that nothing changed.

These tests execute the real snap_cat / snap_intact functions lifted from the
script against real gzip files.
"""
from __future__ import annotations

import gzip
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLLBACK = (REPO_ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8")

DUMP = (
    "--\n-- PostgreSQL database dump\n--\n\n"
    + "CREATE TABLE t (id integer);\nCOPY t (id) FROM stdin;\n"
    + "".join(f"{i}\n" for i in range(5000))
    + "\\.\n\n--\n-- PostgreSQL database dump complete\n--\n\n"
)


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


def _funcs() -> str:
    a = ROLLBACK.index("snap_exists() {")
    return ROLLBACK[a : ROLLBACK.index('\ncd "$REPO_DIR"', a)]


def _intact(tmp_path: Path, snapshot: Path | None) -> bool:
    target = snapshot if snapshot is not None else tmp_path / "missing.sql.gz"
    script = tmp_path / "gate.sh"
    script.write_text(
        "set -euo pipefail\n"
        "sudo() { return 1; }\n"  # no sudo: the direct read is all there is
        f'LATEST_SNAP="{target.as_posix()}"\n'
        + _funcs()
        + '\nif snap_intact; then echo INTACT; else echo BAD; fi\n',
        encoding="utf-8", newline="\n",
    )
    proc = subprocess.run([_bash(), script.as_posix()], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() in ("INTACT", "BAD"), proc.stdout
    return proc.stdout.strip() == "INTACT"


def _gz(path: Path, text: str) -> Path:
    with gzip.open(path, "wb") as fh:
        fh.write(text.encode())
    return path


def test_a_complete_snapshot_passes(tmp_path) -> None:
    # Positive control: the gate must not refuse a good snapshot, or every
    # rollback would silently skip its database restore.
    assert _intact(tmp_path, _gz(tmp_path / "ok.sql.gz", DUMP))


def test_a_missing_snapshot_is_refused(tmp_path) -> None:
    assert not _intact(tmp_path, None)


def test_an_empty_file_is_refused(tmp_path) -> None:
    empty = tmp_path / "empty.sql.gz"
    empty.write_bytes(b"")
    assert not _intact(tmp_path, empty)


def test_a_file_that_is_not_gzip_is_refused(tmp_path) -> None:
    junk = tmp_path / "junk.sql.gz"
    junk.write_text(DUMP)  # the right words, but not compressed
    assert not _intact(tmp_path, junk)


@pytest.mark.parametrize("keep", [0.1, 0.5, 0.9, 0.999])
def test_a_truncated_gzip_is_refused(tmp_path, keep) -> None:
    whole = _gz(tmp_path / "whole.sql.gz", DUMP).read_bytes()
    cut = tmp_path / "cut.sql.gz"
    cut.write_bytes(whole[: int(len(whole) * keep)])
    assert not _intact(tmp_path, cut)


def test_a_valid_gzip_of_an_empty_dump_is_refused(tmp_path) -> None:
    # gunzip succeeds and emits nothing: only the DROP would reach psql.
    assert not _intact(tmp_path, _gz(tmp_path / "void.sql.gz", ""))


def test_a_dump_that_pg_dump_never_finished_is_refused(tmp_path) -> None:
    # A snapshot taken while pg_dump was dying is a valid gzip of half a dump.
    half = DUMP[: len(DUMP) // 2]
    assert not _intact(tmp_path, _gz(tmp_path / "half.sql.gz", half))
