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

# Which commit this box runs is auto-update.sh's decision, made from the update
# channel. This script used to `git pull origin main` unconditionally, which
# moved a held or pinned box onto main once a week. So read the channel first,
# and pull only when the box is one that follows main anyway.
#
# channel_follows_main answers "may this run pull main?". It must fail CLOSED:
# if the env file is there but cannot be read, the channel is unknown, and an
# unknown channel is treated as a hold rather than as "no hold set".
ENV_FILE="/etc/netmon/netmon.env"
CHANNEL_NOTE=""
read_env_file() {
    if [[ -r "$ENV_FILE" ]]; then
        cat "$ENV_FILE"
    elif sudo -n true 2>/dev/null; then
        if sudo -n test -e "$ENV_FILE"; then sudo -n cat "$ENV_FILE"; fi
    elif [[ -e "$ENV_FILE" || ! -x "$(dirname "$ENV_FILE")" ]]; then
        return 1    # present (or its directory is closed to us) and no sudo
    fi
}
env_value() {  # last assignment of KEY in the text on stdin, unquoted
    { grep -E "^$1=" || true; } | tail -1 | cut -d= -f2- | tr -d "\"'[:space:]"
}
channel_follows_main() {
    local env_text channel ref
    if ! env_text="$(read_env_file)"; then
        CHANNEL_NOTE="cannot read $ENV_FILE to learn the update channel"
        return 1
    fi
    channel="$(printf '%s\n' "$env_text" | env_value NETMON_UPDATE_CHANNEL | tr '[:upper:]' '[:lower:]')"
    ref="$(printf '%s\n' "$env_text" | env_value NETMON_UPDATE_REF)"
    if [[ "$channel" == "hold" ]]; then
        CHANNEL_NOTE="update channel=hold"
        return 1
    fi
    # Mirrors auto-update.sh: canary ignores a pin; every other channel honours it.
    if [[ "$channel" != "canary" && -n "$ref" ]]; then
        CHANNEL_NOTE="pinned release (NETMON_UPDATE_REF is set)"
        return 1
    fi
    return 0
}

# Pull the latest code first so we rebuild against current source.
if ! channel_follows_main; then
    log "$CHANNEL_NOTE; rebuilding the commit already checked out ($(git rev-parse --short HEAD 2>/dev/null || echo unknown)) without git pull"
elif [[ -n "$(git status --porcelain)" ]]; then
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
