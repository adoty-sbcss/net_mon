#!/usr/bin/env bash
# netmon-config-backup.sh — invoke `python -m collector config-backup` inside
# the collector container. Called nightly by netmon-config-backup.timer.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

LOG_TAG="netmon-config-backup"
log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$*"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    DC=(docker compose)
else
    DC=(sudo docker compose)
fi

if ! "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-collector; then
    log "collector not running; skipping nightly config-backup"
    exit 0
fi

if ! "${DC[@]}" exec -T collector python -m collector config-backup 2>&1 \
        | while read -r ln; do log "  $ln"; done; then
    log "config-backup failed (see lines above)"
    exit 1
fi
log "config-backup ok"
exit 0
