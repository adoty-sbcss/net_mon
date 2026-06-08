#!/usr/bin/env bash
# netmon-console-poll.sh — fast interactive-command poll inside the collector
# container. Runs `python -m collector console-poll` every ~30s (much lighter
# than the full check-in) purely so a queued live-console request is picked up in
# seconds instead of after the next ~10-min check-in. Outbound HTTPS only; opens
# no inbound path. Always a no-op unless a console session is waiting.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

LOG_TAG="netmon-console-poll"
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

# Quiet no-op if the collector isn't running (this fires every ~30s — don't spam).
if ! "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-collector; then
    exit 0
fi

out="$("${DC[@]}" exec -T collector python -m collector console-poll 2>&1)"
# Only surface non-empty output (a spawned session logs; an idle poll is silent).
while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done <<< "$out"
exit 0
