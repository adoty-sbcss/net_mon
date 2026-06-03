#!/usr/bin/env bash
# weekly-deep-refresh.sh — force a full rebuild that re-fetches apt and pip
# packages, picking up security patches that aren't in the cached layers.
#
# auto-update.sh runs nightly and uses --pull to refresh the base image, but
# the apt-get and pip-install layers stay cached as long as their inputs
# (Dockerfile + pyproject.toml) don't change. That means a CVE in nmap or
# paramiko doesn't reach us unless we --no-cache rebuild.
#
# This script does that, and runs weekly via netmon-deep-refresh.timer.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

LOG_TAG="netmon-deep-refresh"
log() {
    local msg="$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$msg"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$msg"
}

log "starting weekly deep refresh"

# Pull the latest code first so we rebuild against current source.
if [[ -n "$(git status --porcelain)" ]]; then
    log "WARN: working tree dirty; building current state without git pull"
else
    if git fetch --quiet origin main 2>/dev/null; then
        if ! git pull --ff-only --quiet origin main; then
            log "WARN: ff-only pull failed; building current HEAD"
        fi
    else
        log "WARN: git fetch failed; building current HEAD"
    fi
fi

# Update the Postgres image too. The collector image we build ourselves, but
# postgres:16-alpine is a pulled tag that `up -d` never re-fetches once present,
# so Alpine CVEs and Postgres 16.x patch releases would otherwise never land.
# `pull` grabs the current 16-alpine; `up -d postgres` only recreates if the
# image digest actually changed (brief DB blip, data persists on the volume).
log "pulling latest postgres image"
if ! docker compose pull postgres 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "WARN: postgres image pull failed; continuing with current image"
else
    log "applying postgres image (recreates only if the digest changed)"
    if ! docker compose up -d postgres 2>&1 | while read -r ln; do log "  $ln"; done; then
        log "WARN: postgres up -d reported errors"
    fi
fi

log "running: docker compose build --pull --no-cache collector"
if ! docker compose build --pull --no-cache collector 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "ERROR: deep rebuild failed"
    exit 1
fi

log "restarting collector with fresh image"
if ! docker compose up -d --force-recreate collector 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "ERROR: restart failed"
    exit 1
fi

# Apt-style image cleanup: dangling images can accumulate after --no-cache rebuilds.
log "pruning dangling images"
docker image prune -f >/dev/null 2>&1 || true

log "deep refresh complete"
