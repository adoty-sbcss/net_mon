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
# the container's console-session bridges to over a Unix socket.
#
# Launching the server AND draining this root-owned file both need root. On a box
# without passwordless sudo the full shell simply can't work, so detect that ONCE
# (cached in /tmp — avoids a sudo probe + WARN every 30s) and skip quietly; the
# operator still gets a fail-closed error via the bridge's connect timeout.
REQ="/var/lib/netmon/host-console-request"
if [ -s "$REQ" ]; then
    CAP=/tmp/.netmon-host-console-cap   # cached root-capability, per boot
    SUDO=(); can_root=0
    if [ "$(id -u)" -eq 0 ]; then
        can_root=1
    elif [ -f "$CAP" ]; then
        [ "$(cat "$CAP" 2>/dev/null)" = yes ] && { can_root=1; SUDO=(sudo -n); }
    elif sudo -n true 2>/dev/null; then
        can_root=1; SUDO=(sudo -n); echo yes > "$CAP" 2>/dev/null || true
    else
        echo no > "$CAP" 2>/dev/null || true
        log "host shell requested but this box has no passwordless sudo — full shell unavailable (fail-closed); leaving $REQ for an admin"
    fi
    if [ "$can_root" -eq 1 ]; then
        # Atomic snapshot (rename) instead of read-then-truncate, so a concurrent
        # append can't be lost to a TOCTOU; anything written after the rename lands
        # in a fresh file, drained next cycle.
        SNAP="${REQ}.draining"
        if "${SUDO[@]}" mv -f "$REQ" "$SNAP" 2>/dev/null; then
            "${SUDO[@]}" cat "$SNAP" 2>/dev/null | while IFS=$'\t' read -r sid nonce; do
                [ -z "${sid:-}" ] && continue
                [ -z "${nonce:-}" ] && continue
                log "arming host shell for sid=${sid}"
                # Transient root unit: journald logging + RuntimeMaxSec hard time-box
                # backstop (~61 min, matching the collector's MAX_SESSION_SEC);
                # --setenv keeps the nonce off argv; --collect GCs the finished unit.
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
            done
            "${SUDO[@]}" rm -f "$SNAP" 2>/dev/null || true
        fi
    fi
fi

exit 0
