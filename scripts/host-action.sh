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
#
# Interrupted actions: the request is cleared BEFORE an action runs (so a reboot
# action can't loop), which used to mean a box that rebooted or lost power mid-
# action lost it without a trace — no result, nothing retried, and the dashboard
# showed "scheduled" forever (2026-10-30: a re-cable rebooted a new box 2.5 min
# into host-apply-vlan). Now each action is recorded to INFLIGHT_FILE before it
# starts and removed when it ends. The next drain finds a leftover record, reports
# the action as interrupted, and re-runs it once if it is safe to repeat.

set -uo pipefail   # NOT -e: inspect each action's result, keep draining

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# Overridable only so the tests can point it at a temp dir.
STATE_DIR="${NETMON_STATE_DIR:-/var/lib/netmon}"
REQUEST_FILE="$STATE_DIR/host-action-request"
RESULT_FILE="$STATE_DIR/host-action-result"
INFLIGHT_FILE="$STATE_DIR/host-action-inflight"
LOG_TAG="netmon-host-action"
# Runs per request: the first plus one automatic retry after an interruption.
MAX_ATTEMPTS=2
# A request left in the queue (never drained) runs only if it is younger than this.
LEFTOVER_MAX_AGE_MIN="${NETMON_LEFTOVER_MAX_AGE_MIN:-120}"
[[ "$LEFTOVER_MAX_AGE_MIN" =~ ^[0-9]{1,5}$ ]] || LEFTOVER_MAX_AGE_MIN=120

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
# status: running | ok | failed | interrupted. commandId (the dashboard's queue id,
# when numeric) lets the dashboard close that command's "scheduled" row.
_json_str() {
    local v="$1"
    v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    printf '%s' "$v" | tr '\n\t\r' '   '
}
write_result() {  # action status reason [command-id] [attempt]
    local a s r cid="${4:-}" attempt="${5:-1}" extra=""
    a="$(_json_str "$1")"; s="$(_json_str "$2")"; r="$(_json_str "${3:-}")"
    [[ "$cid" =~ ^[0-9]{1,18}$ ]] && extra+=",\"commandId\":$((10#$cid))"
    [[ "$attempt" =~ ^[0-9]{1,3}$ ]] && extra+=",\"attempt\":$((10#$attempt))"
    local json
    json="$(printf '{"action":"%s","status":"%s","reason":"%s","at":"%s"%s}' \
        "$a" "$s" "$r" "$(date -Iseconds 2>/dev/null || date)" "$extra")"
    _write_state "$RESULT_FILE" "$json"
}

# State files live in a root-owned directory the container writes as root; write
# directly when we can, else through sudo (same fallback write_result always had).
_write_state() {  # file content
    printf '%s\n' "$2" > "$1" 2>/dev/null \
        || printf '%s\n' "$2" | "${SUDO[@]}" tee "$1" >/dev/null 2>&1 \
        || true
}
_read_state() {
    cat "$1" 2>/dev/null || "${SUDO[@]}" cat "$1" 2>/dev/null || true
}
_clear_state() {
    { : > "$1"; } 2>/dev/null || "${SUDO[@]}" rm -f "$1" 2>/dev/null || true
}

# Changes on every boot, so a leftover in-flight record from another boot means
# the box restarted mid-action. A function so the tests can stub it.
boot_id() {
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown
}

# Actions that converge on the desired state from the env file and are guarded,
# so running one again after an interruption is safe. NOT reboot/rollback/
# rebuild/restart (a repeat is a second disruptive event the operator did not
# ask for) and not cis-apply or wifi-experience (one-shot by design).
_retry_safe() {
    case "$1" in
        host-apply-vlan|apply-vlan|host-remove-vlan|remove-vlan) return 0 ;;
        host-wifi-join|wifi-join|host-wifi-leave|wifi-leave) return 0 ;;
        *) return 1 ;;
    esac
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
                # Empty is refused, never read as "remove everything": an unreadable
                # env file also reads back empty. Clearing is host-remove-vlan.
                [ -z "$t_vlans" ] && { echo "NETMON_TRUNK_VLANS empty — nothing to apply (clearing is host-remove-vlan)"; exit 1; }
                [ -z "$t_parent" ] && t_parent="$(_trunk_default_parent)"
                apply_vlan_netplan_headless "$t_parent" "$t_vlans" "$t_statics"
            ) 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            ;;
        remove-vlan|host-remove-vlan)
            log "ACTION remove-vlan: remove the VLAN sub-interfaces NetMon created (netplan file / netmon-vlan<id> NM connections)"
            # The clear path for an emptied VLAN list. Touches only what NetMon
            # created, never the parent; guarded — it restores the removed config if
            # the box's default route is lost. Independent of NETMON_TRUNK_*: it
            # removes what NetMon OWNS, whatever the env says.
            (
                for lib in common.sh paths.sh envfile.sh trunk.sh; do
                    # shellcheck source=/dev/null
                    [ -f "$REPO_DIR/lib/$lib" ] && . "$REPO_DIR/lib/$lib"
                done
                remove_vlan_interfaces_headless
            ) 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            ;;
        wifi-join|host-wifi-join)
            log "ACTION wifi-join: join NETMON_WIFI_JOIN_* on the analysis radio (lib/wifi.sh, routes-off)"
            # Subshell so the sourced libs' log/ok/warn/SUDO don't clobber this script's.
            # lib/wifi.sh joins with never-default + a default-route guard (auto-revert),
            # so the analysis radio can never steal the box's uplink/upload path.
            (
                for lib in common.sh paths.sh envfile.sh wifi.sh; do
                    # shellcheck source=/dev/null
                    [ -f "$REPO_DIR/lib/$lib" ] && . "$REPO_DIR/lib/$lib"
                done
                w_enabled="$(current_value NETMON_WIFI_JOIN_ENABLED 2>/dev/null || true)"
                case "${w_enabled,,}" in
                    true|1|yes) ;;
                    *) echo "NETMON_WIFI_JOIN_ENABLED not true — tearing down netmon Wi-Fi"; wifi_leave_all; exit 0 ;;
                esac
                w_ssid="$(current_value NETMON_WIFI_JOIN_SSID 2>/dev/null || true)"
                [ -z "$w_ssid" ] && { echo "NETMON_WIFI_JOIN_SSID empty — nothing to join"; exit 1; }
                w_iface="$(current_value NETMON_WIFI_JOIN_IFACE 2>/dev/null || true)"
                [ -z "$w_iface" ] && w_iface="$(wifi_analysis_iface)"
                [ -z "$w_iface" ] && { echo "no spare Wi-Fi NIC (only radio owns the default route) — refusing"; exit 1; }
                w_auth="$(current_value NETMON_WIFI_JOIN_AUTH 2>/dev/null || true)"
                w_id="$(current_value NETMON_WIFI_JOIN_IDENTITY 2>/dev/null || true)"
                w_sec="$(current_value NETMON_WIFI_JOIN_SECRET 2>/dev/null || true)"
                # Reconcile to exactly the wanted network: drop any prior netmon Wi-Fi first.
                wifi_leave_all
                wifi_join "$w_iface" "$w_ssid" "${w_auth:-open}" "$w_id" "$w_sec"
            ) 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            ;;
        wifi-leave|host-wifi-leave)
            log "ACTION wifi-leave: tear down all netmon-owned Wi-Fi connections"
            (
                for lib in common.sh paths.sh envfile.sh wifi.sh; do
                    # shellcheck source=/dev/null
                    [ -f "$REPO_DIR/lib/$lib" ] && . "$REPO_DIR/lib/$lib"
                done
                wifi_leave_all
            ) 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            ;;
        wifi-experience|host-wifi-experience)
            log "ACTION wifi-experience: run the WIFI-3 client-experience battery (join->measure->leave, routes-off)"
            if [ -x "$REPO_DIR/scripts/netmon-wifi-experience.sh" ]; then
                "$REPO_DIR/scripts/netmon-wifi-experience.sh" 2>&1 | while IFS= read -r ln; do [ -n "$ln" ] && log "  $ln"; done
            else
                log "  wifi-experience: scripts/netmon-wifi-experience.sh missing or not executable"
                return 1
            fi
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

# Run one action with an in-flight record around it, so a reboot, power loss or
# systemd kill part-way through is found by the next drain instead of vanishing.
run_tracked() {  # command-id action attempt
    local cid="$1" action="$2" attempt="${3:-1}" rc out
    _write_state "$INFLIGHT_FILE" \
        "$(printf '%s\t%s\t%s\t%s\t%s' "$cid" "$action" "$(boot_id)" "$attempt" "$(date -Iseconds 2>/dev/null || date)")"
    write_result "$action" "running" "" "$cid" "$attempt"
    # The action's own output, kept so a failure can say WHY. It used to be only
    # "action failed — check the box journal", and the journal is the one place
    # nobody can reach without SSH (2026-10-30: a VLAN apply failing in 30 s on a
    # new box, with no way to see its error from the dashboard).
    out="$(mktemp 2>/dev/null || echo "/tmp/netmon-host-action.$$")"
    # 9<&-: children must not inherit the run lock (a backgrounded reboot would hold it).
    if run_action "$action" 9<&- >"$out" 2>&1; then rc=0; else rc=1; fi
    cat "$out" 2>/dev/null || true
    _append_action_log "$action" "$cid" "$attempt" "$rc" "$out"
    if [ "$rc" -eq 0 ]; then
        write_result "$action" "ok" "" "$cid" "$attempt"
    else
        write_result "$action" "failed" "$(_failure_detail "$out")" "$cid" "$attempt"
        log "  action '${action}' reported a failure"
    fi
    rm -f "$out" 2>/dev/null || true
    _clear_state "$INFLIGHT_FILE"
    return "$rc"
}

# The lines that say why an action failed, for the dashboard: the libs' warnings
# ("!!"), errors ("ERR", "FAIL:") or refusals, else the last lines it printed.
# Colour codes and our log prefix stripped; bounded so it fits the check-in.
_failure_detail() {  # output-file
    local lines
    lines="$(sed -e 's/\x1b\[[0-9;]*m//g' -e 's/^\[[^]]*\] *//' -e 's/^ *//' "$1" 2>/dev/null \
        | grep -v '^$' | grep -v '^ACTION ')"
    local picked
    picked="$(grep -E '(^| )(!!|ERR|FAIL:|REFUSED|WARN)' <<< "$lines" | tail -n 3)"
    [ -n "$picked" ] || picked="$(tail -n 3 <<< "$lines")"
    picked="$(printf '%s' "$picked" | tr '\n' '|' | sed 's/|/ | /g')"
    [ -n "$picked" ] || picked="no output — check the box journal"
    printf 'action failed: %s' "${picked:0:600}"
}

# Every action's output, appended to a log the dashboard's collect-logs returns
# (the collector container mounts /var/log/netmon). Trimmed to its newest lines.
HOST_ACTION_LOG="${NETMON_LOG_DIR:-/var/log/netmon}/host-action.log"
_append_action_log() {  # action command-id attempt rc output-file
    local hdr
    hdr="$(printf '=== %s %s id=%s attempt=%s rc=%s' "$(date -Iseconds 2>/dev/null || date)" "$1" "${2:--}" "$3" "$4")"
    { printf '%s\n' "$hdr"; sed 's/\x1b\[[0-9;]*m//g' "$5" 2>/dev/null; } \
        | { cat >> "$HOST_ACTION_LOG" 2>/dev/null || "${SUDO[@]}" tee -a "$HOST_ACTION_LOG" >/dev/null 2>&1 || true; }
    local n
    n="$(wc -l < "$HOST_ACTION_LOG" 2>/dev/null || echo 0)"
    if [ "${n:-0}" -gt 4000 ] 2>/dev/null; then
        local keep
        keep="$(tail -n 2000 "$HOST_ACTION_LOG" 2>/dev/null)" && _write_state "$HOST_ACTION_LOG" "$keep"
    fi
}

# A leftover in-flight record means the last action never finished. Report it as
# interrupted, and re-run it once when that is safe — unless a newer request for
# the same action is already queued (it supersedes the retry).
recover_interrupted() {  # pending-requests
    local pending="${1:-}" rec cid action boot attempt started why
    [ -s "$INFLIGHT_FILE" ] || return 0
    rec="$(_read_state "$INFLIGHT_FILE")"
    _clear_state "$INFLIGHT_FILE"
    IFS=$'\t' read -r cid action boot attempt started <<< "$rec"
    [ -n "${action:-}" ] || return 0
    [[ "${attempt:-}" =~ ^[0-9]{1,3}$ ]] || attempt=1
    if [ "${boot:-}" != "$(boot_id)" ]; then
        why="the box restarted while it was running (started ${started:-?})"
    else
        why="it stopped before finishing — killed or timed out (started ${started:-?})"
    fi
    if grep -qF -- "$(printf '\t%s' "$action")" <<< "$pending"; then
        log "RECOVER: '${action}' id=${cid:-?} was interrupted — ${why}; a newer request supersedes the retry"
        write_result "$action" "interrupted" "interrupted: ${why}; superseded by a newer request" "$cid" "$attempt"
    elif _retry_safe "$action" && (( 10#$attempt < MAX_ATTEMPTS )); then
        log "RECOVER: '${action}' id=${cid:-?} was interrupted — ${why}; retrying (attempt $((10#$attempt + 1)) of ${MAX_ATTEMPTS})"
        run_tracked "$cid" "$action" "$((10#$attempt + 1))" || true
    else
        log "RECOVER: '${action}' id=${cid:-?} was interrupted — ${why}; not retried"
        write_result "$action" "interrupted" "interrupted: ${why}; not retried automatically — queue it again from the dashboard" "$cid" "$attempt"
    fi
}

# One run at a time, so a drain never mistakes a live action (a manual run, say)
# for an interrupted one. flock on this script's own file: no extra lock file to own.
_take_lock() {
    command -v flock >/dev/null 2>&1 || return 0
    exec 9<"${BASH_SOURCE[0]}" || return 0
    flock -n 9
}

main() {
    if ! _take_lock; then
        log "another host action is running; leaving the queue for the next check-in"
        return 0
    fi

    local mode="${1:-}"
    # --- direct single-action invocation ------------------------------------
    if [ "$mode" != "--drain" ] && [ "$mode" != "--drain-leftover" ] && [ -n "$mode" ]; then
        recover_interrupted ""
        run_tracked "" "$1" 1
        return $?
    fi

    # --- drain mode (netmon-checkin.sh: --drain on exit 12, --drain-leftover
    # on any other successful check-in) ----------------------------------------
    if [ ! -s "$REQUEST_FILE" ] && [ ! -s "$INFLIGHT_FILE" ]; then
        return 0
    fi

    # A leftover is only run while it is fresh. A box that rebooted between the
    # check-in that queued it and the drain gets here minutes later; a request
    # stuck in the file for days (an old box whose truncation failed) is not
    # something the operator still expects to happen — report it, don't run it.
    local stale=""
    if [ "$mode" = "--drain-leftover" ] && [ -s "$REQUEST_FILE" ] \
        && [ -n "$(find "$REQUEST_FILE" -mmin "+${LEFTOVER_MAX_AGE_MIN}" 2>/dev/null)" ]; then
        stale=1
    fi

    # Snapshot + clear up front so a queued reboot can't strand un-run later lines,
    # and a failing action can't loop forever.
    local pending cid action
    pending="$(_read_state "$REQUEST_FILE")"
    # The agent writes this file from inside the container AS ROOT, so a non-root host
    # runner can't truncate it (Permission denied) — fall back to sudo, else a failed
    # action loops every check-in.
    _clear_state "$REQUEST_FILE"

    if [ -n "$stale" ]; then
        while IFS=$'\t' read -r -u 3 cid action; do
            [ -z "${action:-}" ] && continue
            log "EXPIRED: host action id=${cid:-?} action=${action} was queued over ${LEFTOVER_MAX_AGE_MIN} min ago and never run; not running it now"
            write_result "$action" "expired" \
                "queued over ${LEFTOVER_MAX_AGE_MIN} minutes ago and never run; not run now — queue it again from the dashboard" "$cid" 1
        done 3<<< "$pending"
        pending=""
    fi

    recover_interrupted "$pending"

    # fd 3, not stdin: an action that reads stdin (docker compose) must not eat
    # the rest of the queue.
    while IFS=$'\t' read -r -u 3 cid action; do
        [ -z "${action:-}" ] && continue
        log "draining host action id=${cid:-?} action=${action}"
        run_tracked "$cid" "$action" 1 || true
    done 3<<< "$pending"
    return 0
}

# Sourced by the tests; run when executed.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
    exit $?
fi
