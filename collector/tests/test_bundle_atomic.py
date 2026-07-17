"""Hourly bundle ZIPs are published atomically (F-COL-24).

Pure unit tests against `_atomic_zip` — no DB, no network, just a tmp dir.

The hazard: the dashboard's `upload-now` builds the hour in a SEPARATE process
(checkin.py) and derives the same hour/filename as the uploader's own pass, so two
builders can target one path at once. Writing straight to the final path could
interleave into a truncated ZIP, and a crash mid-write left a corrupt one — either
way the sensor ships a broken bundle and the hour's scans are lost.
"""
from __future__ import annotations

import zipfile

import pytest

from collector import bundle


def test_final_path_does_not_exist_until_the_build_completes(tmp_path):
    final = tmp_path / "netmon-2026071715.zip"

    with bundle._atomic_zip(final) as z:
        z.writestr("a.txt", "hello")
        # Mid-build the bundle must be invisible: an uploader that saw it here
        # would ship a partial ZIP.
        assert not final.exists()

    assert final.exists()
    with zipfile.ZipFile(final) as z:
        assert z.read("a.txt") == b"hello"
        assert z.testzip() is None


def test_no_temp_file_is_left_behind_on_success(tmp_path):
    final = tmp_path / "netmon-2026071715.zip"

    with bundle._atomic_zip(final) as z:
        z.writestr("a.txt", "hello")

    assert [p.name for p in tmp_path.iterdir()] == [final.name]


def test_a_failed_build_publishes_nothing_and_cleans_up(tmp_path):
    final = tmp_path / "netmon-2026071715.zip"

    with pytest.raises(RuntimeError, match="boom"):
        with bundle._atomic_zip(final) as z:
            z.writestr("a.txt", "hello")
            raise RuntimeError("boom")

    # A crash mid-write must never leave a corrupt bundle at the real path...
    assert not final.exists()
    # ...nor a partial temp to accumulate on a box that keeps failing.
    assert list(tmp_path.iterdir()) == []


def test_a_crash_does_not_clobber_an_existing_good_bundle(tmp_path):
    """A rebuild of an hour that already shipped must leave the previous file
    intact if it fails partway."""
    final = tmp_path / "netmon-2026071715.zip"
    with bundle._atomic_zip(final) as z:
        z.writestr("a.txt", "first good build")

    with pytest.raises(RuntimeError):
        with bundle._atomic_zip(final) as z:
            z.writestr("a.txt", "doomed rebuild")
            raise RuntimeError("boom")

    with zipfile.ZipFile(final) as z:
        assert z.read("a.txt") == b"first good build"


def test_concurrent_builders_never_expose_a_partial_file(tmp_path):
    """Two builders racing on one hour: they use distinct temps, so whoever lands
    last wins with a COMPLETE file — the old shared-handle write could interleave
    into a truncated ZIP."""
    final = tmp_path / "netmon-2026071715.zip"

    with bundle._atomic_zip(final) as a:
        a.writestr("who.txt", "builder-a")
        with bundle._atomic_zip(final) as b:
            b.writestr("who.txt", "builder-b")
            assert not final.exists()
        # b published a whole, valid bundle while a is still writing.
        with zipfile.ZipFile(final) as z:
            assert z.read("who.txt") == b"builder-b"
            assert z.testzip() is None

    # a then replaced it with its own equally complete bundle.
    with zipfile.ZipFile(final) as z:
        assert z.read("who.txt") == b"builder-a"
        assert z.testzip() is None
    assert [p.name for p in tmp_path.iterdir()] == [final.name]
