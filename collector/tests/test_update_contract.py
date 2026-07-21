"""Regression tests for the host-side updater's safety contract.

These are deliberately static: the updater runs on Ubuntu hosts with Docker and
systemd, while the normal unit suite also runs on developer workstations. The
tests pin the ordering and commands that previously let a failed update report
the wrong running version or skip recovery on the next timer run.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UPDATER = (REPO_ROOT / "scripts" / "auto-update.sh").read_text(encoding="utf-8")
ROLLBACK = (REPO_ROOT / "scripts" / "rollback.sh").read_text(encoding="utf-8")
CHECKIN = (REPO_ROOT / "scripts" / "netmon-checkin.sh").read_text(encoding="utf-8")
BUILD_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "build-collector.yml"
).read_text(encoding="utf-8")


def test_updater_uses_failing_readiness_command() -> None:
    assert "python -m collector healthcheck --verbose" in UPDATER
    assert "python -m collector selftest" not in UPDATER


def test_current_sha_is_recorded_only_after_healthcheck_passes() -> None:
    healthcheck = UPDATER.index("python -m collector healthcheck --verbose")
    record_after_update = UPDATER.index("record_current_sha", healthcheck)

    assert record_after_update > healthcheck
    channel_logic = UPDATER.index('case "$UPDATE_CHANNEL" in')
    assert "record_current_sha" not in UPDATER[channel_logic:healthcheck]


def test_current_source_still_reconciles_image_and_container() -> None:
    current_block_start = UPDATER.index('if [[ "$LOCAL" == "$REMOTE" ]]')
    pull = UPDATER.index("docker compose pull collector")
    current_block = UPDATER[current_block_start:pull]

    assert "reconciling image and container state" in current_block
    assert "exit 0" not in current_block


def test_all_update_channels_select_immutable_commit_image() -> None:
    case_start = UPDATER.index('case "$UPDATE_CHANNEL" in')
    channel_logic = UPDATER[case_start : UPDATER.index("esac", case_start)]

    assert channel_logic.count('IMAGE_TAG="$REMOTE"') == 4
    assert 'IMAGE_TAG="stable"' not in channel_logic
    assert 'IMAGE_TAG="canary"' not in channel_logic


def test_image_tag_is_persisted_only_after_pull_or_build() -> None:
    pull = UPDATER.index("docker compose pull collector")
    build = UPDATER.index("docker compose build", pull)
    persist = UPDATER.index('write_image_tag_env "$IMAGE_TAG"')

    assert pull < build < persist
    assert 'NETMON_IMAGE_TAG="$IMAGE_TAG" docker compose pull' in UPDATER
    assert 'NETMON_IMAGE_TAG="$IMAGE_TAG" docker compose build' in UPDATER


def test_ci_publishes_immutable_image_only_after_main_ci_passes() -> None:
    assert "workflow_run:" in BUILD_WORKFLOW
    assert "workflows: [CI]" in BUILD_WORKFLOW
    assert "workflow_run.conclusion == 'success'" in BUILD_WORKFLOW
    assert "github.event.workflow_run.head_sha || github.sha" in BUILD_WORKFLOW
    assert "${{ env.IMAGE }}:${{ env.COMMIT_SHA }}" in BUILD_WORKFLOW


def test_updater_self_heals_unreadable_env_before_any_compose_use() -> None:
    # A root-owned 0600 netmon.env (rewritten by the root collector container on
    # a config push) makes every unprivileged `docker compose` invocation fail
    # with "permission denied" — the update fails AND the rollback safety net
    # fails the same way (Monitor1 was down ~1.3 days). The updater must heal
    # the file before anything reads the env or parses the compose model.
    define = UPDATER.index("ensure_env_readable() {")
    call = UPDATER.index("\nensure_env_readable\n")

    assert call > define
    assert call < UPDATER.index("read_env NETMON_UPDATE_CHANNEL")
    assert call < UPDATER.index("db-snapshot.sh")
    assert call < UPDATER.index("docker compose pull collector")
    assert call < UPDATER.index("docker compose $COMPOSE_ARGS")


def test_env_self_heal_is_passwordless_sudo_and_non_fatal() -> None:
    body = UPDATER[UPDATER.index("ensure_env_readable() {") :]
    body = body[: body.index("\n}") + 2]

    # Mirrors ensure_repo_ownership: sudo -n (never prompt on a timer), a loud
    # actionable WARN on failure, and NEVER a hard exit — compose still gets its
    # chance and the existing rollback path stays in charge of failures.
    assert 'sudo -n chown "$me:$grp" "$ENV_FILE"' in body
    assert "WARN" in body
    assert "exit" not in body
    assert body.count("return 0") == 2  # absent env + already-readable env no-op


def test_rollback_also_self_heals_unreadable_env_before_compose() -> None:
    define = ROLLBACK.index("ensure_env_readable() {")
    call = ROLLBACK.index("\nensure_env_readable\n")

    assert define < call < ROLLBACK.index('"${DC[@]}" down')
    assert 'sudo -n chown "$me:$grp" "$ENV_FILE"' in ROLLBACK


def test_checkin_wrapper_self_heals_unreadable_env_before_compose() -> None:
    # The config-apply -> recreate path is the drift ORIGIN: the collector
    # rewrites netmon.env (root-owned) then this wrapper runs compose
    # unprivileged. Heal before the FIRST compose call (the `ps` probe), else a
    # drifted box silently reports "collector not running" and skips forever.
    define = CHECKIN.index("ensure_env_readable() {")
    call = CHECKIN.index("\nensure_env_readable\n")

    assert define < call < CHECKIN.index('"${DC[@]}" ps')
    assert 'sudo -n chown "$me:$grp" "$ENV_FILE"' in CHECKIN
