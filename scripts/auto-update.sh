#!/usr/bin/env bash
# auto-update.sh — pull latest NetMon from main and apply, with rollback safety.
#
# Designed for nightly systemd timer execution. Safe to run by hand too.
# Logs to syslog via `logger` so journalctl picks it up; also echoes to stdout
# for interactive runs.
#
# Behavior:
#   1. git fetch — bail clean if remote is unreachable
#   2. Compare HEAD to origin/main — exit 0 if already up to date
#   3. Pre-update safety:
#        - pg_dump current DB to /var/lib/netmon/db-snapshots/
#        - Tag current docker image as netmon/collector:previous
#        - Save current SHA to /var/lib/netmon/last-known-good-sha
#   4. git pull --ff-only
#   5. Rebuild if container code changed
#   6. docker compose up -d  (applies migrations on collector startup)
#   7. Post-update healthcheck (wait 2min, run collector selftest)
#   8. On healthcheck failure: invoke scripts/rollback.sh automatically
#
# Exit codes:
#   0 — success or no-op (already up to date) — OR successful auto-rollback
#   1 — recoverable failure (network, git, docker, healthcheck) — try again next run
#   2 — non-recoverable (working tree dirty, fast-forward not possible)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

SHA_FILE="/var/lib/netmon/last-known-good-sha"
CURRENT_SHA_FILE="/var/lib/netmon/current-sha"   # reported to the dashboard at check-in
ENV_FILE="/etc/netmon/netmon.env"
HEALTHCHECK_WAIT_SECONDS="${NETMON_HEALTHCHECK_WAIT:-120}"

# Read a NETMON_* key from the env file (root-owned 0600). Empty if absent.
read_env() {
    sudo grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true
}
# Persist the live commit SHA so the dashboard can show exactly which release a
# box is on (release-channel rollout view). Best-effort.
record_current_sha() {
    sudo install -d -m 755 /var/lib/netmon 2>/dev/null || true
    git rev-parse HEAD 2>/dev/null | sudo tee "$CURRENT_SHA_FILE" >/dev/null 2>&1 || true
}

LOG_TAG="netmon-update"
log() {
    local msg="$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$msg"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$msg"
}

# Source paths.sh so we can run ensure_paths after the git pull lands new
# code. Migrating from the old in-repo layout to /etc/netmon + /var/lib/netmon
# happens on the next call. Older clones won't have lib/, so guard the source.
ensure_paths_if_available() {
    if [[ -f "$REPO_DIR/lib/common.sh" ]] && [[ -f "$REPO_DIR/lib/paths.sh" ]]; then
        # shellcheck source=/dev/null
        . "$REPO_DIR/lib/common.sh"
        # shellcheck source=/dev/null
        . "$REPO_DIR/lib/paths.sh"
        ensure_paths
    fi
}

# Refuse to run on a dirty working tree — we'd lose local changes.
if [[ -n "$(git status --porcelain)" ]]; then
    log "FATAL: working tree has uncommitted changes; refusing to auto-update"
    log "Resolve manually:  cd $REPO_DIR && git status"
    exit 2
fi

# 1. Fetch latest refs.
if ! git fetch --quiet origin main 2>/dev/null; then
    log "git fetch failed (network down?); will retry next run"
    exit 1
fi

LOCAL=$(git rev-parse HEAD)

# 1b. Release channel: resolve the TARGET this box should converge to. Default
# (unset/unknown channel) == 'stable' with no pin == track origin/main, i.e. the
# historical behavior — so shipping this is a no-op until channels are set from
# the dashboard. 'canary' tracks origin/main (latest); 'hold' pauses updates;
# 'stable' with a pin (NETMON_UPDATE_REF) converges to that exact commit.
UPDATE_CHANNEL="$(read_env NETMON_UPDATE_CHANNEL)"
UPDATE_REF="$(read_env NETMON_UPDATE_REF)"
case "$UPDATE_CHANNEL" in
    hold)
        log "update channel=hold; skipping auto-update"
        record_current_sha
        exit 0
        ;;
    canary)
        REMOTE=$(git rev-parse origin/main)
        log "update channel=canary -> origin/main ${REMOTE:0:8}"
        ;;
    stable|"")
        if [[ -n "$UPDATE_REF" ]] && REMOTE=$(git rev-parse --verify "${UPDATE_REF}^{commit}" 2>/dev/null); then
            log "update channel=stable; pinned ${UPDATE_REF} -> ${REMOTE:0:8}"
        else
            [[ -n "$UPDATE_REF" ]] && log "WARN: pinned ref '${UPDATE_REF}' not found after fetch; tracking origin/main"
            REMOTE=$(git rev-parse origin/main)
            log "update channel=stable -> origin/main ${REMOTE:0:8}"
        fi
        ;;
    *)
        REMOTE=$(git rev-parse origin/main)
        log "WARN: unknown update channel '${UPDATE_CHANNEL}'; tracking origin/main"
        ;;
esac

if [[ "$LOCAL" == "$REMOTE" ]]; then
    log "already up to date at ${LOCAL:0:8}"
    record_current_sha
    # Even when we don't pull, record the current SHA as last-known-good
    # so manual rollback has a target.
    if [[ ! -f "$SHA_FILE" ]] || [[ "$(cat "$SHA_FILE")" != "$LOCAL" ]]; then
        sudo install -d -m 755 /var/lib/netmon
        echo "$LOCAL" | sudo tee "$SHA_FILE" >/dev/null
    fi
    exit 0
fi

log "update available: ${LOCAL:0:8} -> ${REMOTE:0:8} (channel=${UPDATE_CHANNEL:-stable})"

# 2. Inspect what changed.
CHANGED=$(git diff --name-only "$LOCAL" "$REMOTE")
log "files changed:"
echo "$CHANGED" | while read -r f; do log "  $f"; done

NEEDS_BUILD=0
if echo "$CHANGED" | grep -qE '^(collector/(Dockerfile|pyproject\.toml|src/)|collector/entrypoint\.sh)'; then
    NEEDS_BUILD=1
fi

NEEDS_RECREATE=0
if echo "$CHANGED" | grep -qE '^docker-compose\.yml$'; then
    NEEDS_RECREATE=1
fi

# 3. Pre-update snapshot. We want a fresh DB dump and a saved image tag
# BEFORE we change anything so rollback has something to restore from.
log "pre-update: saving rollback state"

# 3a. Save current SHA as the rollback target.
sudo install -d -m 755 /var/lib/netmon
echo "$LOCAL" | sudo tee "$SHA_FILE" >/dev/null
log "  saved current SHA $LOCAL as rollback target"

# 3b. pg_dump. Skip silently if the script isn't present (very old clones).
if [[ -x "$REPO_DIR/scripts/db-snapshot.sh" ]]; then
    log "  taking pre-update DB snapshot"
    if ! "$REPO_DIR/scripts/db-snapshot.sh" 2>&1 | while read -r ln; do log "    $ln"; done; then
        log "WARN: pre-update snapshot failed; rollback will lose any new DB state"
    fi
fi

# 3c. Tag the current collector image as :previous so rollback can swap back.
if docker image inspect netmon/collector:latest >/dev/null 2>&1; then
    docker tag netmon/collector:latest netmon/collector:previous 2>/dev/null || true
    log "  tagged current image as netmon/collector:previous"
fi

# 4. Move to the resolved target (channel-aware). reset --hard is safe here: the
# dirty-tree guard at the top already refused to run with local changes, and
# REMOTE is always a fetched commit (origin/main or a verified pin). This handles
# pinned downgrades and canary-ahead alike, where a plain --ff-only could not.
if ! git reset --hard --quiet "$REMOTE"; then
    log "FATAL: git reset to ${REMOTE:0:8} failed; manual intervention needed"
    exit 2
fi
NEW_HEAD=$(git rev-parse HEAD)
record_current_sha
log "updated to ${NEW_HEAD:0:8}"

# 4b. Run path migration with the freshly-pulled code.
log "ensuring canonical paths (and migrating legacy layout if needed)"
ensure_paths_if_available 2>&1 | while read -r ln; do log "  $ln"; done

# 4c. If install-auto-update.sh or any systemd unit file changed in this
# pull AND the boxes' update timer is already installed (i.e. setup.sh has
# been run at least once), re-run the installer so any NEW timers added
# in this release land on the box automatically. Skips if the user never
# enabled the timers in the first place.
if systemctl list-unit-files netmon-update.timer 2>/dev/null | grep -q netmon-update; then
    if echo "$CHANGED" | grep -qE '^(scripts/install-auto-update\.sh|systemd/)'; then
        log "systemd units or installer changed; re-running install-auto-update.sh"
        if [[ -x "$REPO_DIR/scripts/install-auto-update.sh" ]]; then
            "$REPO_DIR/scripts/install-auto-update.sh" 2>&1 \
                | while read -r ln; do log "  $ln"; done || \
                log "WARN: installer re-run reported errors"
        fi
    fi
fi

# 5. Rebuild only if container code changed. Always --pull so we pick up
# any security patches in the python:3.12-slim base image.
if [[ $NEEDS_BUILD -eq 1 ]]; then
    log "rebuilding collector image (with --pull for base-image security updates)"
    if ! docker compose build --pull --quiet collector 2>&1 | while read -r ln; do log "  $ln"; done; then
        log "ERROR: docker compose build failed"
        exit 1
    fi
fi

# 6. Bring containers up.
COMPOSE_ARGS="up -d --remove-orphans"
if [[ $NEEDS_RECREATE -eq 1 ]]; then
    COMPOSE_ARGS="up -d --force-recreate --remove-orphans"
fi
log "docker compose $COMPOSE_ARGS"
if ! docker compose $COMPOSE_ARGS 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "ERROR: docker compose up failed — invoking rollback"
    if [[ -x "$REPO_DIR/scripts/rollback.sh" ]]; then
        "$REPO_DIR/scripts/rollback.sh" 2>&1 | while read -r ln; do log "  $ln"; done || true
    fi
    exit 1
fi

# Collector applies any pending db/migrations/*.sql at startup.
if echo "$CHANGED" | grep -q '^db/migrations/'; then
    log "new schema migrations included; collector will apply on startup"
fi

# 7. Post-update healthcheck. Wait HEALTHCHECK_WAIT_SECONDS for the collector
# to settle, then run selftest. If it fails, the new release is broken —
# auto-rollback to the saved SHA + :previous image + latest snapshot.
log "post-update healthcheck: waiting ${HEALTHCHECK_WAIT_SECONDS}s for collector to settle"
sleep "$HEALTHCHECK_WAIT_SECONDS"

if docker compose exec -T collector python -m collector selftest >/dev/null 2>&1; then
    log "healthcheck passed; update complete at ${NEW_HEAD:0:8}"
    exit 0
fi

# Healthcheck failed.
log "CRITICAL: post-update healthcheck failed — invoking auto-rollback"
log "  failed update was ${LOCAL:0:8} -> ${NEW_HEAD:0:8}"
log "  rollback target: ${LOCAL:0:8}"

if [[ ! -x "$REPO_DIR/scripts/rollback.sh" ]]; then
    log "FATAL: scripts/rollback.sh missing — box is stuck on ${NEW_HEAD:0:8}"
    log "       manual recovery: git reset --hard $LOCAL && docker compose up -d --force-recreate"
    exit 1
fi

if "$REPO_DIR/scripts/rollback.sh" 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "auto-rollback completed; box is back on ${LOCAL:0:8}"
    exit 0
else
    log "FATAL: auto-rollback also failed — manual intervention required"
    exit 1
fi
