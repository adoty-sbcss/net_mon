"""Failure-injection tests for dashboard-pushed sensor configuration."""

import os
import stat
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from collector import checkin
from collector.config import Settings


def test_atomic_applied_version_write(monkeypatch) -> None:
    version_file = Path.cwd() / f".test-applied-config-{uuid4().hex}"
    monkeypatch.setattr(checkin, "APPLIED_VERSION_FILE", version_file)
    try:
        checkin._write_applied_version(17)

        assert version_file.read_text() == "17"
        assert not version_file.with_name(version_file.name + ".tmp").exists()
    finally:
        version_file.unlink(missing_ok=True)
        version_file.with_name(version_file.name + ".tmp").unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("writer", "argument"),
    [
        ("_write_applied_version", 2),
        ("_write_iperf_schedules", []),
        ("_write_wifi_profiles", []),
        ("_write_webperf_urls", []),
    ],
)
def test_config_state_writer_failure_is_not_swallowed(monkeypatch, writer, argument) -> None:
    def fail_write(*args, **kwargs):
        raise OSError("injected disk failure")

    monkeypatch.setattr(checkin, "_write_file_atomic", fail_write)

    with pytest.raises(OSError, match="injected disk failure"):
        getattr(checkin, writer)(argument)


def test_side_file_failure_prevents_config_acknowledgement(monkeypatch) -> None:
    env_was_written = False

    def fail_schedule_write(schedules):
        raise OSError("read-only state directory")

    def record_env_write(path, mapping):
        nonlocal env_was_written
        env_was_written = True

    monkeypatch.setattr(checkin, "_write_iperf_schedules", fail_schedule_write)
    monkeypatch.setattr(checkin, "_update_env_file", record_env_write)

    with pytest.raises(OSError, match="read-only state directory"):
        checkin._apply_config(
            {"iperf_schedules": [], "snmp_enabled": True}
        )

    assert env_was_written is False


def test_host_wrapper_retries_config_after_recreate_failure() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = (repo_root / "scripts" / "netmon-checkin.sh").read_text(encoding="utf-8")
    config_only_branch = wrapper[
        wrapper.index('if [ "$rc" = "10" ]') : wrapper.index('elif [ "$rc" = "11" ]')
    ]

    assert "mark_config_pending" in config_only_branch
    assert "exit 1" in config_only_branch
    assert wrapper.count("mark_config_pending || true") == 3


@pytest.mark.parametrize(
    "override",
    [
        {"NETMON_POLL_INTERVAL": 0},
        {"NETMON_SNMP_POLL_MAX_CANDIDATES": 0},
        {"NETMON_SFTP_PORT": 70000},
    ],
)
def test_field_bounds_reject_unsafe_numeric_values(override) -> None:
    # Per-field bounds still hard-fail at construction. The collector's OWN load
    # clamps these instead of crashing (test_get_settings_clamps_out_of_range_env);
    # dashboard-pushed config is hard-rejected upstream (_validate_desired_config).
    with pytest.raises(ValidationError):
        Settings(**override)


def test_get_settings_clamps_out_of_range_env_instead_of_crashing(monkeypatch) -> None:
    # A box whose EXISTING env holds an out-of-bounds value must not crash-loop
    # the collector — get_settings() clamps to the bound and warns.
    from collector import config

    monkeypatch.setenv("NETMON_POLL_INTERVAL", "0")               # below ge=1
    monkeypatch.setenv("NETMON_SNMP_POLL_TIME_BUDGET", "999999")  # above le=3600
    monkeypatch.setattr(config, "_settings", None)

    settings = config.get_settings()

    assert settings.poll_interval == 1
    assert settings.snmp_poll_time_budget == 3600


def test_get_settings_tolerates_bad_cadence_relationship(monkeypatch) -> None:
    # A bad cross-field relationship used to raise at load and crash-loop the
    # collector on a box whose env predated the check; now it warns and loads.
    from collector import config

    monkeypatch.setenv("NETMON_CAPTURE_INTERVAL", "4000")
    monkeypatch.setenv("NETMON_RESCAN_INTERVAL", "3600")
    monkeypatch.setattr(config, "_settings", None)

    settings = config.get_settings()  # must not raise

    assert settings.capture_interval == 4000
    assert settings.rescan_interval == 3600


def test_dashboard_numeric_config_is_rejected_before_write(monkeypatch) -> None:
    wrote_env = False
    monkeypatch.setattr(
        checkin,
        "get_settings",
        lambda: type("Current", (), {"capture_interval": 900})(),
    )

    def record_write(path, mapping):
        nonlocal wrote_env
        wrote_env = True

    monkeypatch.setattr(checkin, "_update_env_file", record_write)

    with pytest.raises(ValueError, match="rescan_interval"):
        checkin._apply_config({"rescan_interval": 300})

    assert wrote_env is False


def test_command_results_use_the_durable_result_spool() -> None:
    source = Path(checkin.__file__).read_text(encoding="utf-8")
    command_loop = source[source.index("for cmd in resp.get") : source.index("# Redeliver any perf results")]

    assert '"/api/sensor/result"' in command_loop
    assert "_post_result(" in command_loop


# --- File-ownership behavior of the atomic writers ---------------------------
# The collector runs as root inside the container while /etc/netmon and
# /var/lib/netmon are host bind mounts owned by the unprivileged service user.
# An atomic rewrite creates a new inode owned by the writer, which flipped
# netmon.env to root:root 0600 and made every host-side `docker compose` read
# fail with "permission denied" (update AND rollback — Monitor1 was down ~1.3
# days). _write_file_atomic must re-own what it writes to the parent dir's
# owner, best-effort. Real chown needs root, so these tests pin the ATTEMPT
# and its failure tolerance via monkeypatched os.stat/os.chown.


def _stat_result_with_owner(real: os.stat_result, uid: int, gid: int) -> os.stat_result:
    values = list(real)
    values[stat.ST_UID] = uid
    values[stat.ST_GID] = gid
    return os.stat_result(values)


def _fake_stat_reporting_dir_owner(dir_path: Path, uid: int, gid: int):
    """A delegating os.stat whose answer for dir_path claims the given owner."""
    real_stat = os.stat

    def fake_stat(p, *args, **kwargs):
        res = real_stat(p, *args, **kwargs)
        if Path(str(p)) == dir_path:
            return _stat_result_with_owner(res, uid, gid)
        return res

    return fake_stat


def test_write_file_atomic_reowns_new_file_to_parent_dir_owner(tmp_path, monkeypatch) -> None:
    target = tmp_path / "netmon.env"
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(
        checkin.os,
        "chown",
        lambda p, u, g: chowned.append((str(p), u, g)),
        raising=False,  # os.chown does not exist on Windows dev boxes
    )
    monkeypatch.setattr(checkin.os, "stat", _fake_stat_reporting_dir_owner(tmp_path, 1234, 4321))

    checkin._write_file_atomic(target, "KEY=value\n")

    assert target.read_text() == "KEY=value\n"
    assert chowned == [(str(target), 1234, 4321)]
    assert not target.with_name(target.name + ".tmp").exists()


def test_write_file_atomic_ownership_is_best_effort_never_fatal(tmp_path, monkeypatch) -> None:
    # A failed chown (collector running unprivileged, odd filesystem) must NOT
    # break the succeed-or-raise write contract: the payload still lands, the
    # mode is still restrictive, and no exception escapes.
    target = tmp_path / "netmon.env"

    def failing_chown(p, u, g):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(checkin.os, "chown", failing_chown, raising=False)
    monkeypatch.setattr(checkin.os, "stat", _fake_stat_reporting_dir_owner(tmp_path, 1234, 4321))

    checkin._write_file_atomic(target, "KEY=value\n")  # must not raise

    assert target.read_text() == "KEY=value\n"
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_write_file_atomic_never_chowns_into_root(tmp_path, monkeypatch) -> None:
    # A root-owned parent dir carries no signal about the host service user;
    # actively handing the file to root:root is the exact failure being fixed.
    target = tmp_path / "state.json"
    chowned: list[tuple] = []
    monkeypatch.setattr(
        checkin.os, "chown", lambda *args: chowned.append(args), raising=False
    )
    monkeypatch.setattr(checkin.os, "stat", _fake_stat_reporting_dir_owner(tmp_path, 0, 0))

    checkin._write_file_atomic(target, "{}")

    assert target.read_text() == "{}"
    assert chowned == []


def test_write_file_atomic_skips_chown_when_owner_already_matches(tmp_path, monkeypatch) -> None:
    target = tmp_path / "state.json"
    real_stat = os.stat

    def fake_stat(p, *args, **kwargs):
        # Dir AND file both report the same non-root owner -> nothing to do.
        return _stat_result_with_owner(real_stat(p, *args, **kwargs), 1234, 4321)

    chowned: list[tuple] = []
    monkeypatch.setattr(
        checkin.os, "chown", lambda *args: chowned.append(args), raising=False
    )
    monkeypatch.setattr(checkin.os, "stat", fake_stat)

    checkin._write_file_atomic(target, "{}")

    assert target.read_text() == "{}"
    assert chowned == []


def test_env_file_write_flows_through_the_owned_atomic_writer(tmp_path, monkeypatch) -> None:
    # netmon.env is the file whose root-ownership drift took Monitor1 down; pin
    # that its rewrite rides _write_file_atomic (atomicity + re-owning) rather
    # than a bespoke writer that would silently miss the ownership fix.
    env = tmp_path / "netmon.env"
    env.write_text("NETMON_A=1\nKEEP=x\n")
    seen: list[tuple[Path, str, int]] = []

    def record(path, payload, mode=0o600):
        seen.append((path, payload, mode))

    monkeypatch.setattr(checkin, "_write_file_atomic", record)

    checkin._update_env_file(env, {"NETMON_A": "2", "NETMON_B": "3"})

    assert seen == [(env, "NETMON_A=2\nKEEP=x\nNETMON_B=3\n", 0o600)]
