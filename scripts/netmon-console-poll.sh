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

# --- Arm host-side PTY servers for full (HOST root) shell sessions (CON-7) ---
# The in-container poll appends "<sid>\t<nonce>" to this file when it claims a
# mode=full open-console. Full shell = the real host root, and the container can't
# spawn a host process — so launch a per-session host PTY server on the HOST that
# the container's console-session bridges to over a Unix socket. Snapshot+clear
# first (the file is written from the container AS ROOT, so a non-root host runner
# needs sudo to clear it — mirror scripts/host-action.sh).
REQ="/var/lib/netmon/host-console-request"
if [ -s "$REQ" ]; then
    if [ "$(id -u)" -eq 0 ]; then SUDO=(); else SUDO=(sudo -n); fi
    PENDING="$(cat "$REQ" 2>/dev/null || "${SUDO[@]}" cat "$REQ" 2>/dev/null || true)"
    { : > "$REQ"; } 2>/dev/null || "${SUDO[@]}" rm -f "$REQ" 2>/dev/null || true
    while IFS=$'\t' read -r sid nonce; do
        [ -z "${sid:-}" ] && continue
        [ -z "${nonce:-}" ] && continue
        log "arming host shell for sid=${sid}"
        # Transient root unit: journald logging + RuntimeMaxSec hard time-box
        # backstop (~61 min, matching the collector's MAX_SESSION_SEC); --setenv
        # keeps the nonce off argv; --collect GCs the unit when the session ends.
        if "${SUDO[@]}" systemd-run \
                --collect \
                --unit="netmon-hostshell-${sid}" \
                --property=RuntimeMaxSec=3660 \
                --setenv=NETMON_HOST_CONSOLE_NONCE="${nonce}" \
                /usr/bin/python3 "$REPO_DIR/scripts/netmon-host-console.py" --sid "${sid}" \
                >/dev/null 2>&1; then
            log "  host shell server started (unit netmon-hostshell-${sid})"
        else
            log "  WARN: could not start host shell server for ${sid} (systemd-run failed)"
        fi
    done <<< "$PENDING"
fi

exit 0
