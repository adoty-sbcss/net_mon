#!/usr/bin/env bash
# auto-update.sh — pull latest NetMon from main and apply.
#
# Designed for nightly systemd timer execution. Safe to run by hand too.
# Logs to syslog via `logger` so journalctl picks it up; also echoes to stdout
# for interactive runs.
#
# Behavior:
#   1. git fetch — bail clean if remote is unreachable
#   2. Compare HEAD to origin/main — exit 0 if already up to date
#   3. Detect which paths changed:
#        - collector/, Dockerfile, pyproject.toml  → docker compose build
#        - db/migrations/                          → collector applies on next start
#        - docker-compose.yml                      → recreate containers
#        - setup.sh, scripts/, systemd/            → no container action
#   4. git pull --ff-only
#   5. Rebuild if needed
#   6. docker compose up -d  (applies migrations on collector startup)
#
# Exit codes:
#   0 — success or no-op (already up to date)
#   1 — recoverable failure (network, git, docker) — try again next run
#   2 — non-recoverable (working tree dirty, fast-forward not possible)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

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
REMOTE=$(git rev-parse origin/main)

if [[ "$LOCAL" == "$REMOTE" ]]; then
    log "already up to date at ${LOCAL:0:8}"
    exit 0
fi

log "update available: ${LOCAL:0:8} -> ${REMOTE:0:8}"

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

# 3. Pull.
if ! git pull --ff-only --quiet origin main; then
    log "FATAL: fast-forward pull failed; manual intervention needed"
    exit 2
fi
NEW_HEAD=$(git rev-parse HEAD)
log "pulled to ${NEW_HEAD:0:8}"

# 3b. Run path migration with the freshly-pulled code. This is what moves
# legacy in-repo state (./.env, ./bundles, ./logs, ./config/snmp.yaml) into
# /etc/netmon + /var/lib/netmon + /var/log/netmon. Idempotent.
log "ensuring canonical paths (and migrating legacy layout if needed)"
ensure_paths_if_available 2>&1 | while read -r ln; do log "  $ln"; done

# 4. Rebuild only if container code changed. Always --pull so we pick up
# any security patches in the python:3.12-slim base image. Without --pull
# Docker keeps using the cached base layer indefinitely.
if [[ $NEEDS_BUILD -eq 1 ]]; then
    log "rebuilding collector image (with --pull for base-image security updates)"
    if ! docker compose build --pull --quiet collector 2>&1 | while read -r ln; do log "  $ln"; done; then
        log "ERROR: docker compose build failed"
        exit 1
    fi
fi

# 5. Bring containers up. `--remove-orphans` cleans up containers from services
# that may have been removed from compose. `up -d` is a no-op for services
# whose config hasn't changed.
COMPOSE_ARGS="up -d --remove-orphans"
if [[ $NEEDS_RECREATE -eq 1 ]]; then
    COMPOSE_ARGS="up -d --force-recreate --remove-orphans"
fi
log "docker compose $COMPOSE_ARGS"
if ! docker compose $COMPOSE_ARGS 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "ERROR: docker compose up failed"
    exit 1
fi

# Collector applies any pending db/migrations/*.sql at startup. We log a hint
# so the operator can find them in collector logs.
if echo "$CHANGED" | grep -q '^db/migrations/'; then
    log "new schema migrations included; collector will apply on startup"
    log "  to verify:  docker compose logs --tail 50 collector"
fi

log "update complete: now at ${NEW_HEAD:0:8}"
exit 0
