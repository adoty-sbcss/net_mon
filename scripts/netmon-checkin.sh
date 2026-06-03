#!/usr/bin/env bash
# netmon-checkin.sh — outbound dashboard check-in inside the collector container.
# Runs `python -m collector checkin`; if it applied new config (exit 10), restart
# the collector so the new config takes effect. Called every few minutes by
# netmon-checkin.timer. Outbound HTTPS only; opens no inbound path.

set -uo pipefail   # intentionally NOT -e: we must inspect the exit code

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

LOG_TAG="netmon-checkin"
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
    log "collector not running; skipping check-in"
    exit 0
fi

out="$("${DC[@]}" exec -T collector python -m collector checkin 2>&1)"
rc=$?
while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done <<< "$out"

if [ "$rc" = "10" ]; then
    # MUST recreate, not restart: the collector reads its config from the
    # process environment that compose injects from env_file at CREATE time.
    # `docker compose restart` reuses the existing container, so a rewritten
    # netmon.env is NOT picked up. `up -d --force-recreate` rebuilds the
    # container with the new environment.
    log "config changed; recreating collector to load new env"
    if "${DC[@]}" up -d --force-recreate collector >/dev/null 2>&1; then
        log "collector recreated"
    else
        log "collector recreate FAILED"
    fi
    exit 0
elif [ "$rc" = "0" ]; then
    log "check-in ok"
    exit 0
else
    log "check-in failed (rc=$rc)"
    exit 1
fi
