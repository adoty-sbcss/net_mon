#!/usr/bin/env bash
# host-action.sh — execute allow-listed HOST-LEVEL maintenance actions that the
# in-container agent cannot perform itself (it runs inside the very container
# some of these replace). Requests are recorded by the agent to
# /var/lib/netmon/host-action-request (checkin.py:_request_host_action) and
# drained here by netmon-checkin.sh on exit code 12.
#
# Usage:
#   scripts/host-action.sh --drain          # run + clear every queued request
#   scripts/host-action.sh <action>         # run a single action directly
#
# SECURITY: these are state-changing + privileged. The dashboard gates each
# behind an explicit operator confirm + approval + audit before it ever reaches
# the queue; this script is the authoritative host-side allow-list (defense in
# depth). Keep ALLOWED tight and mirrored with checkin.py:_HOST_ACTIONS. Vet any
# addition with the security chat before shipping.
#
# Outcomes are observed on the NEXT dashboard check-in (uptime reset, recreated
# container, rolled-back agentVersion); this script does not POST results itself.

set -uo pipefail   # NOT -e: inspect each action's result, keep draining

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

REQUEST_FILE="/var/lib/netmon/host-action-request"
RESULT_FILE="/var/lib/netmon/host-action-result"
LOG_TAG="netmon-host-action"

log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$*"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

# Record an action's outcome to a bind-mounted file the in-container agent reports
# at check-in (checkin.py:_last_host_action) -> the dashboard. Mirrors auto-update.sh's
# last-update-result so a failed host action (e.g. a VLAN apply that crashed netplan)
# is visible on the dashboard, not just buried in the box journal.
write_result() {  # action status reason
    local a="$1" s="$2" r="${3:-}"
    r="${r//\\/\\\\}"; r="${r//\"/\\\"}"; r="$(printf '%s' "$r" | tr '\n\t' '  ')"
    local json
    json="$(printf '{"action":"%s","status":"%s","reason":"%s","at":"%s"}' \
        "$a" "$s" "$r" "$(date -Iseconds 2>/dev/null || date)")"
    printf '%s\n' "$json" > "$RESULT_FILE" 2>/dev/null \
        || printf '%s\n' "$json" | "${SUDO[@]}" tee "$RESULT_FILE" >/dev/null 2>&1 \
        || true
}

# docker compose, with sudo when the runner isn't in the docker group.
if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    DC=(docker compose)
else
    DC=(sudo docker compose)
fi
# systemctl/reboot need root; the update user has passwordless sudo (installed by
# install-auto-update.sh). Run directly if we're already root.
if [ "$(id -u)" = "0" ]; then
    SUDO=()
else
    SUDO=(sudo)
fi

# The authoritative host-side allow-list. Anything not matched is refused + logged.
run_action() {
    local action="$1"
    case "$action" in
        restart|host-restart)
            log "ACTION restart: docker compose restart (no rebuild)"
            "${DC[@]}" restart 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            ;;
        rebuild|host-rebuild)
            log "ACTION rebuild: rebuild collector image + recreate (keeps DB/config/logs)"
            if "${DC[@]}" build --pull collector 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done; then
                "${DC[@]}" up -d --force-recreate --remove-orphans 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            else
                log "  rebuild: image build failed; NOT recreating"
                return 1
            fi
            ;;
        reboot|host-reboot)
            log "ACTION reboot: rebooting host in 5s"
            # Detach so this script (and the check-in that called it) can exit
            # cleanly and the result POST flushes before the box goes down.
            ( sleep 5; "${SUDO[@]}" systemctl reboot ) >/dev/null 2>&1 &
            ;;
        rollback|host-rollback)
            log "ACTION rollback: scripts/rollback.sh -> last-known-good"
            if [ -x "$REPO_DIR/scripts/rollback.sh" ]; then
                "$REPO_DIR/scripts/rollback.sh" 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            else
                log "  rollback: scripts/rollback.sh missing or not executable"
                return 1
            fi
            ;;
        apply-vlan|host-apply-vlan)
            log "ACTION apply-vlan: build VLAN sub-interfaces from NETMON_TRUNK_* (netplan, routes-off)"
            # Subshell so the sourced libs (which redefine log/ok/warn) don't clobber
            # this script's own logging. apply_vlan_netplan_headless is guarded —
            # it auto-reverts if the box's default route is lost.
            (
                for lib in common.sh paths.sh envfile.sh trunk.sh; do
                    # shellcheck source=/dev/null
                    [ -f "$REPO_DIR/lib/$lib" ] && . "$REPO_DIR/lib/$lib"
                done
                t_parent="$(current_value NETMON_TRUNK_PARENT 2>/dev/null || true)"
                t_vlans="$(current_value NETMON_TRUNK_VLANS 2>/dev/null || true)"
                t_statics="$(current_value NETMON_TRUNK_STATICS 2>/dev/null || true)"
                [ -z "$t_vlans" ] && { echo "NETMON_TRUNK_VLANS empty — nothing to apply"; exit 1; }
                [ -z "$t_parent" ] && t_parent="$(_trunk_default_parent)"
                apply_vlan_netplan_headless "$t_parent" "$t_vlans" "$t_statics"
            ) 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            ;;
        cis-apply|host-cis-apply)
            log "ACTION cis-apply: apply the CIS safe subset (scripts/cis-apply.sh --apply)"
            # The apply has its own self-healing guard: it auto-reverts if SSH or
            # outbound connectivity is lost, so a remote box can't strand itself.
            if [ -x "$REPO_DIR/scripts/cis-apply.sh" ]; then
                "${SUDO[@]}" bash "$REPO_DIR/scripts/cis-apply.sh" --apply 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            else
                log "  cis-apply: scripts/cis-apply.sh missing or not executable"
                return 1
            fi
            ;;
        cis-revert|host-cis-revert)
            log "ACTION cis-revert: undo the CIS safe subset (scripts/cis-apply.sh --revert)"
            if [ -x "$REPO_DIR/scripts/cis-apply.sh" ]; then
                "${SUDO[@]}" bash "$REPO_DIR/scripts/cis-apply.sh" --revert 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            else
                log "  cis-revert: scripts/cis-apply.sh missing or not executable"
                return 1
            fi
            ;;
        *)
            log "REFUSED unknown host action: '$action' (not in allow-list)"
            return 1
            ;;
    esac
}

# --- direct single-action invocation --------------------------------------
if [ "${1:-}" != "--drain" ] && [ -n "${1:-}" ]; then
    run_action "$1"; rc=$?
    [ "$rc" -eq 0 ] && write_result "$1" "ok" "" || write_result "$1" "failed" "action failed — see logs"
    exit "$rc"
fi

# --- drain mode (called by netmon-checkin.sh) -----------------------------
if [ ! -s "$REQUEST_FILE" ]; then
    exit 0
fi

# Snapshot + clear up front so a queued reboot can't strand un-run later lines,
# and a failing action can't loop forever.
PENDING="$(cat "$REQUEST_FILE" 2>/dev/null || "${SUDO[@]}" cat "$REQUEST_FILE" 2>/dev/null || true)"
# The agent writes this file from inside the container AS ROOT, so a non-root host
# runner can't truncate it (Permission denied) — fall back to sudo, else a failed
# action loops every check-in.
{ : > "$REQUEST_FILE"; } 2>/dev/null || "${SUDO[@]}" rm -f "$REQUEST_FILE" 2>/dev/null || true

while IFS=$'\t' read -r cid action; do
    [ -z "${action:-}" ] && continue
    log "draining host action id=${cid:-?} action=${action}"
    if run_action "$action"; then
        write_result "$action" "ok" ""
    else
        write_result "$action" "failed" "action failed — run 'collect-logs' or check the box journal"
        log "  action '${action}' reported a failure"
    fi
done <<< "$PENDING"

exit 0
