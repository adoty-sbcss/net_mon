"""Failure-injection tests for dashboard-pushed sensor configuration."""

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
        {"NETMON_CAPTURE_INTERVAL": 900, "NETMON_RESCAN_INTERVAL": 900},
        {"NETMON_CAPTURE_INTERVAL": 60, "NETMON_COOLDOWN_SECONDS": 61},
        {"NETMON_SNMP_POLL_MAX_CANDIDATES": 0},
        {"NETMON_SFTP_PORT": 70000},
    ],
)
def test_runtime_settings_reject_unsafe_numeric_values(override) -> None:
    with pytest.raises(ValidationError):
        Settings(**override)


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
