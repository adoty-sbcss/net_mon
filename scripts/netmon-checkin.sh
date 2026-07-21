#!/usr/bin/env bash
# netmon-checkin.sh — outbound dashboard check-in inside the collector container.
# Runs `python -m collector checkin`; if it applied new config (exit 10), restart
# the collector so the new config takes effect. Called every few minutes by
# netmon-checkin.timer. Outbound HTTPS only; opens no inbound path.

set -uo pipefail   # intentionally NOT -e: we must inspect the exit code

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

LOG_TAG="netmon-checkin"
APPLIED_VERSION_FILE="/var/lib/netmon/applied-config-version"
log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$*"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

mark_config_pending() {
    # The collector records the desired version before asking this host wrapper
    # to recreate it. If recreation fails, remove that acknowledgement so the
    # next check-in reapplies the config and retries the recreate.
    if rm -f "$APPLIED_VERSION_FILE" 2>/dev/null; then
        log "config left pending for retry"
    elif sudo -n rm -f "$APPLIED_VERSION_FILE" 2>/dev/null; then
        log "config left pending for retry"
    else
        log "ERROR: could not mark config pending after recreate failure"
        return 1
    fi
}

# Self-heal a root-owned netmon.env before ANY compose call (mirrors
# ensure_env_readable in scripts/auto-update.sh + rollback.sh). This wrapper is
# the drift ORIGIN: the collector applies a pushed config and — before the
# collector-side ownership fix in checkin.py — rewrote netmon.env as root:root
# 0600, then this wrapper's unprivileged `docker compose` (even the `ps` probe
# below reads env_file while building its project model) failed with
# "permission denied" — so a drifted box silently reports "collector not
# running" and skips check-in forever. chown never touches the 0600 mode.
ENV_FILE="/etc/netmon/netmon.env"
ensure_env_readable() {
    [[ -e "$ENV_FILE" ]] || return 0    # pre-setup box: nothing to heal
    [[ -r "$ENV_FILE" ]] && return 0    # already readable: silent no-op
    local me grp owner
    me="$(id -un)"; grp="$(id -gn)"; owner="$(stat -c %U "$ENV_FILE" 2>/dev/null || echo '?')"
    log "env file $ENV_FILE is owned by '$owner' and unreadable by '$me' — docker compose would fail with 'permission denied'. Self-healing."
    if sudo -n chown "$me:$grp" "$ENV_FILE" 2>/dev/null; then
        log "self-healed: chowned $ENV_FILE back to $me:$grp (root-owned env drift from a root-run config apply; mode stays 0600)"
    else
        log "WARN: could not chown $ENV_FILE (no passwordless sudo). If compose fails with 'permission denied', run:  sudo chown $me:$grp $ENV_FILE"
    fi
}

if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    DC=(docker compose)
else
    DC=(sudo docker compose)
fi
ensure_env_readable

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
        mark_config_pending || true
        exit 1
    fi
    exit 0
elif [ "$rc" = "11" ]; then
    # Dashboard queued an "update". 11 implies the config-recreate of 10, so
    # first apply any config pushed this cycle, then hand the CODE update to
    # netmon-update.service — which has the privileges, the 30-min timeout, and
    # the post-update healthcheck + auto-rollback. We must NOT run the update
    # inline: it rebuilds the very stack our `compose exec ... checkin` just used.
    log "dashboard requested update; recreating collector, then triggering auto-update"
    if "${DC[@]}" up -d --force-recreate collector >/dev/null 2>&1; then
        log "collector recreated (any pushed config applied)"
    else
        log "collector recreate FAILED"
        mark_config_pending || true
    fi
    if systemctl list-unit-files netmon-update.service 2>/dev/null | grep -q netmon-update; then
        if [ "$(id -u)" = "0" ]; then
            START_UPDATE=(systemctl start --no-block netmon-update.service)
        else
            START_UPDATE=(sudo systemctl start --no-block netmon-update.service)
        fi
        if "${START_UPDATE[@]}"; then
            log "netmon-update.service started (git pull + rebuild + healthcheck/rollback)"
        else
            log "could not start netmon-update.service; running auto-update.sh inline"
            "$REPO_DIR/scripts/auto-update.sh" 2>&1 \
                | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done || true
        fi
    else
        log "netmon-update.service not installed; running auto-update.sh inline"
        "$REPO_DIR/scripts/auto-update.sh" 2>&1 \
            | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done || true
    fi
    exit 0
elif [ "$rc" = "12" ]; then
    # Dashboard queued a HOST-LEVEL action (restart/rebuild/reboot/rollback) the
    # in-container agent recorded to /var/lib/netmon/host-action-request. 12
    # implies the config-recreate of 10, so apply any pushed config first, then
    # hand the action(s) to scripts/host-action.sh (the host-side allow-list).
    log "host action requested; recreating collector, then draining host-action queue"
    if "${DC[@]}" up -d --force-recreate collector >/dev/null 2>&1; then
        log "collector recreated (any pushed config applied)"
    else
        log "collector recreate FAILED"
        mark_config_pending || true
    fi
    if [ -x "$REPO_DIR/scripts/host-action.sh" ]; then
        "$REPO_DIR/scripts/host-action.sh" --drain 2>&1 \
            | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done || true
    else
        log "scripts/host-action.sh missing; cannot run host action"
    fi
    exit 0
elif [ "$rc" = "0" ]; then
    log "check-in ok"
    exit 0
else
    log "check-in failed (rc=$rc)"
    exit 1
fi
