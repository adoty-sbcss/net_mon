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
# Interrupted actions: a box that rebooted or lost power mid-action used to lose
# it without a trace — the whole queue was cleared up front, the result written
# only after, so there was no result, nothing retried, and the dashboard showed
# "scheduled" forever (2026-10-30: a re-cable rebooted a new box 2.5 min into
# host-apply-vlan). Now requests are claimed ONE AT A TIME: the action is recorded
# to INFLIGHT_FILE, then removed from the queue, and only when both writes
# succeeded does it run (a request that can't be removed would run again on every
# check-in — a reboot loop). The next drain finds a leftover in-flight record,
# reports it interrupted, and re-runs it once if it is safe to repeat. Terminal
# outcomes also go to HISTORY_FILE, so every command settles on the dashboard even
# when one drain runs several.

set -uo pipefail   # NOT -e: inspect each action's result, keep draining

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# Overridable only so the tests can point it at a temp dir.
STATE_DIR="${NETMON_STATE_DIR:-/var/lib/netmon}"
REQUEST_FILE="$STATE_DIR/host-action-request"
RESULT_FILE="$STATE_DIR/host-action-result"
HISTORY_FILE="$STATE_DIR/host-action-results"
INFLIGHT_FILE="$STATE_DIR/host-action-inflight"
# When this script first saw each queued request ("<command-id>\t<epoch>"). Kept
# BESIDE the queue, not in it: the queue's format stays what the agent writes and
# what an older host-action.sh (after a rollback) can read, and this file has no
# writer but this script, under its lock.
SEEN_FILE="$STATE_DIR/host-action-seen"
# Outside the checkout on purpose: git pull REPLACES this script's file, so a lock
# on the script's own inode would not exclude a run started after the pull. Opened
# with >> (created if missing, never replaced): two starters must share one inode.
LOCK_FILE="${NETMON_LOCK_DIR:-/run/lock}/netmon-host-action.lock"
LOG_TAG="netmon-host-action"
# Runs per request: the first plus one automatic retry after an interruption.
MAX_ATTEMPTS=2
# A request left in the queue (never drained) runs only while it is younger than
# this — and a disruptive one (reboot, rollback, …) only within the short limit, so
# a box back from a long outage does not surprise anyone with a reboot.
LEFTOVER_MAX_AGE_MIN="${NETMON_LEFTOVER_MAX_AGE_MIN:-120}"
[[ "$LEFTOVER_MAX_AGE_MIN" =~ ^[0-9]{1,5}$ ]] || LEFTOVER_MAX_AGE_MIN=120
DISRUPTIVE_MAX_AGE_MIN=15
HISTORY_KEEP=50

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
# status: running | ok | failed | interrupted | expired | deferred. commandId (the
# dashboard's queue id, when numeric) lets the dashboard close that command's
# "scheduled" row. "deferred" is NOT terminal: the request is still queued (or its
# retry still pending) and runs at a later check-in, so it must not settle anything.
# Every control character is removed, not just newlines: the reason now quotes the
# action's own output, and one raw ESC or BEL makes the collector's json.loads
# refuse the whole file — the report would silently vanish.
_json_str() {
    local v="$1"
    v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    printf '%s' "$v" | tr '\n\t\r' '   ' | tr -d '\000-\037\177'
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
    # The latest-result file holds ONE outcome; a drain that runs two actions (or
    # reports a superseded one) would overwrite the first before any check-in reads
    # it. Terminal outcomes with a command id also go to a short history.
    case "$2" in
        ok|failed|interrupted|expired)
            [[ "$cid" =~ ^[0-9]{1,18}$ ]] && _append_history "$json" ;;
    esac
    return 0
}
_append_history() {
    { printf '%s\n' "$1" >> "$HISTORY_FILE"; } 2>/dev/null \
        || printf '%s\n' "$1" | "${SUDO[@]}" tee -a "$HISTORY_FILE" >/dev/null 2>&1 \
        || return 0
    local n keep
    n="$(wc -l < "$HISTORY_FILE" 2>/dev/null || echo 0)"
    if [ "${n:-0}" -gt $(( HISTORY_KEEP * 2 )) ] 2>/dev/null; then
        keep="$(tail -n "$HISTORY_KEEP" "$HISTORY_FILE" 2>/dev/null)" && _write_state "$HISTORY_FILE" "$keep"
    fi
    return 0
}

# State files live in a root-owned directory the container writes as root; write
# directly when we can, else through sudo. These RETURN the real outcome: running
# an action whose request could not be removed, or whose in-flight record could not
# be written, is how a reboot request loops or a retry limit stops holding.
# Atomic: a temp file in the same directory, then rename. Writing in place truncates
# first, so power lost mid-write erased the queue's tail (the requests behind the
# one being claimed) or left a half in-flight record.
_write_state() {  # file content
    local tmp="$1.tmp.$$"
    if { printf '%s\n' "$2" > "$tmp"; } 2>/dev/null && mv -f "$tmp" "$1" 2>/dev/null; then
        return 0
    fi
    rm -f "$tmp" 2>/dev/null
    if printf '%s\n' "$2" | "${SUDO[@]}" tee "$tmp" >/dev/null 2>&1 \
        && "${SUDO[@]}" mv -f "$tmp" "$1" 2>/dev/null; then
        return 0
    fi
    "${SUDO[@]}" rm -f "$tmp" 2>/dev/null
    return 1
}
_read_state() {
    cat "$1" 2>/dev/null || "${SUDO[@]}" cat "$1" 2>/dev/null || true
}
_clear_state() {
    { : > "$1"; } 2>/dev/null || "${SUDO[@]}" rm -f "$1" 2>/dev/null
    [ ! -s "$1" ]
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

# Actions that undo or redo one another: a newer one of the same family queued
# behind an interrupted one makes retrying the old one pointless (an apply retried
# just before a remove, or the reverse, is churn that ends where the newer one does).
_family() {
    case "$1" in
        host-apply-vlan|apply-vlan|host-remove-vlan|remove-vlan) printf 'vlan' ;;
        host-wifi-join|wifi-join|host-wifi-leave|wifi-leave) printf 'wifi' ;;
        *) printf '%s' "$1" ;;
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

# The in-flight record: command id ("-" when there is none — a leading empty
# field would vanish, since TAB is IFS whitespace and `read` drops it), action,
# boot id, attempt, start time.
_inflight_rec() {  # command-id action attempt
    printf '%s\t%s\t%s\t%s\t%s' "${1:--}" "$2" "$(boot_id)" "$3" "$(date -Iseconds 2>/dev/null || date)"
}

# Run an action that is already recorded in flight (and, from the queue, already
# claimed), then report it and clear the record.
_run_claimed() {  # command-id action attempt
    local cid="$1" action="$2" attempt="${3:-1}" rc out=""
    write_result "$action" "running" "" "$cid" "$attempt"
    # The action's own output, kept so a failure can say WHY. It used to be only
    # "action failed — check the box journal", and the journal is the one place
    # nobody can reach without SSH (2026-10-30: a VLAN apply failing in 30 s on a
    # new box, with no way to see its error from the dashboard). If no temp file
    # can be made, run it uncaptured rather than not at all.
    out="$(mktemp 2>/dev/null)" || out=""
    # 9<&-: children must not inherit the run lock (a backgrounded reboot would hold it).
    if [ -n "$out" ]; then
        if run_action "$action" 9<&- >"$out" 2>&1; then rc=0; else rc=1; fi
        cat "$out" 2>/dev/null || true
    else
        log "  (could not create a temp file; the failure reason will not quote the output)"
        if run_action "$action" 9<&-; then rc=0; else rc=1; fi
        out=/dev/null
    fi
    _append_action_log "$action" "$cid" "$attempt" "$rc" "$out"
    if [ "$rc" -eq 0 ]; then
        write_result "$action" "ok" "" "$cid" "$attempt"
    else
        write_result "$action" "failed" "$(_failure_detail "$out")" "$cid" "$attempt"
        log "  action '${action}' reported a failure"
    fi
    [ "$out" = /dev/null ] || rm -f "$out" 2>/dev/null || true
    _clear_state "$INFLIGHT_FILE" || log "  WARN: could not clear ${INFLIGHT_FILE}"
    return "$rc"
}

# Record, then run (direct invocation and retries). Nothing runs unless the
# in-flight record was written.
run_tracked() {  # command-id action attempt
    local cid="$1" action="$2" attempt="${3:-1}"
    if ! _write_state "$INFLIGHT_FILE" "$(_inflight_rec "$cid" "$action" "$attempt")"; then
        log "cannot record '${action}' as in flight (${INFLIGHT_FILE} not writable); not running it"
        if (( attempt > 1 )); then
            # A retry: the earlier attempt's record is still there, so the next drain
            # tries again. Not a terminal outcome — it must not settle the command.
            write_result "$action" "deferred" "not retried yet: the box could not record it as in progress (state directory not writable); it tries again at the next check-in" "$cid" "$attempt"
        else
            write_result "$action" "failed" "not run: the box could not record it as in progress (state directory not writable)" "$cid" "$attempt"
        fi
        return 1
    fi
    _run_claimed "$cid" "$action" "$attempt"
}

# The lines that say why an action failed, for the dashboard: the libs' warnings
# ("!!"), errors ("ERR", "FAIL:") or refusals, else the last lines it printed.
# Colour codes and our log prefix stripped; bounded so it fits the check-in.
_failure_detail() {  # output-file
    # Character-wise slicing below: in a C locale bash cuts BYTES, and a cut through
    # an em dash is invalid UTF-8 the collector would refuse.
    local LC_ALL=C.UTF-8
    local lines
    lines="$(sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e 's/^\[[^]]*\] *//' -e 's/^ *//' "$1" 2>/dev/null \
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
    { printf '%s\n' "$hdr"; sed 's/\x1b\[[0-9;]*[A-Za-z]//g' "$5" 2>/dev/null; } \
        | { cat >> "$HOST_ACTION_LOG" 2>/dev/null || "${SUDO[@]}" tee -a "$HOST_ACTION_LOG" >/dev/null 2>&1 || true; }
    local n
    n="$(wc -l < "$HOST_ACTION_LOG" 2>/dev/null || echo 0)"
    if [ "${n:-0}" -gt 4000 ] 2>/dev/null; then
        local keep
        keep="$(tail -n 2000 "$HOST_ACTION_LOG" 2>/dev/null)" && _write_state "$HOST_ACTION_LOG" "$keep"
    fi
}

# --- the queue: one request per line, "<command-id>\t<action>", oldest first ----

# The first request: sets Q_CID, Q_ACTION and Q_REST (the lines after it).
# Returns 1 when the queue is empty.
_queue_head() {
    local q line found=""
    Q_CID=""; Q_ACTION=""; Q_REST=""
    q="$(_read_state "$REQUEST_FILE")"
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [ -n "${line//[[:space:]]/}" ] || continue
        if [ -z "$found" ]; then
            IFS=$'\t' read -r Q_CID Q_ACTION _ <<< "$line"
            found=1
        else
            Q_REST+="${line}"$'\n'
        fi
    done <<< "$q"
    [ -n "$found" ]
}

# Each request's age comes from SEEN_FILE, not the queue file's mtime (every claim
# rewrites the file and every append refreshes it). A command id seen for the first
# time is dated by the queue file's mtime — its last append. That is exact when
# stamping runs at the right moments: netmon-checkin.sh stamps BEFORE each check-in
# (so whatever was already queued keeps the time it was really appended — an old
# box's stuck request stays old and expires) and the drain stamps again right after
# (dating what this check-in appended). Entries for requests no longer queued or in
# flight are dropped.
_stamp_queue() {
    local q line cid a seen keep="" m inflight_cid=""
    m="$(stat -c %Y "$REQUEST_FILE" 2>/dev/null)" || m=0
    q="$(_read_state "$REQUEST_FILE")"
    seen="$(_read_state "$SEEN_FILE")"
    IFS=$'\t' read -r inflight_cid _ <<< "$(_read_state "$INFLIGHT_FILE")"
    local -A stamp=()
    while IFS=$'\t' read -r cid a; do
        [[ "${cid:-}" =~ ^[0-9]{1,18}$ && "${a:-}" =~ ^[0-9]{1,12}$ ]] && stamp[$cid]="$a"
    done <<< "$seen"
    while IFS= read -r line; do
        line="${line%$'\r'}"
        IFS=$'\t' read -r cid a _ <<< "$line"
        [[ "${cid:-}" =~ ^[0-9]{1,18}$ ]] || continue
        [ -n "${stamp[$cid]:-}" ] || stamp[$cid]="$m"
        keep+="${cid}"$'\t'"${stamp[$cid]}"$'\n'
        unset 'stamp[$cid]'
    done <<< "$q"
    if [[ "${inflight_cid:-}" =~ ^[0-9]{1,18}$ ]] && [ -n "${stamp[$inflight_cid]:-}" ]; then
        keep+="${inflight_cid}"$'\t'"${stamp[$inflight_cid]}"$'\n'
    fi
    [ "${keep%$'\n'}" = "${seen%$'\n'}" ] && return 0
    if [ -z "$keep" ]; then
        _clear_state "$SEEN_FILE"
    else
        _write_state "$SEEN_FILE" "${keep%$'\n'}"
    fi
}
# The stamp recorded for a command id ("" when none).
_stamp_of() {  # command-id
    local cid ts
    while IFS=$'\t' read -r cid ts; do
        [ "${cid:-}" = "$1" ] && { printf '%s' "${ts:-}"; return 0; }
    done <<< "$(_read_state "$SEEN_FILE")"
    return 0
}
_queue_set() {  # remaining-lines
    if [ -z "$1" ]; then
        _clear_state "$REQUEST_FILE"
    else
        _write_state "$REQUEST_FILE" "${1%$'\n'}"
    fi
}
# Does the queue hold a request of the same family as <action>?
_queue_has_family() {  # action
    local fam line cid a
    fam="$(_family "$1")"
    while IFS= read -r line; do
        IFS=$'\t' read -r cid a _ <<< "$line"
        [ -n "${a:-}" ] && [ "$(_family "$a")" = "$fam" ] && return 0
    done <<< "$(_read_state "$REQUEST_FILE")"
    return 1
}
# Is a request with this command id still queued (recorded, never claimed)?
_queue_has_cid() {  # command-id
    local line cid a
    while IFS= read -r line; do
        IFS=$'\t' read -r cid a _ <<< "$line"
        [ "${cid:-}" = "$1" ] && return 0
    done <<< "$(_read_state "$REQUEST_FILE")"
    return 1
}

# A leftover in-flight record means the last action never finished. Report it as
# interrupted, and re-run it once when that is safe — unless a newer request of the
# same family is queued (it supersedes the retry).
recover_interrupted() {
    local rec cid action boot attempt started why
    [ -s "$INFLIGHT_FILE" ] || return 0
    rec="$(_read_state "$INFLIGHT_FILE")"
    IFS=$'\t' read -r cid action boot attempt started <<< "$rec"
    [ "${cid:-}" = "-" ] && cid=""
    if [ -z "${action:-}" ]; then
        _clear_state "$INFLIGHT_FILE" || true
        return 0
    fi
    [[ "${attempt:-}" =~ ^[0-9]{1,3}$ ]] || attempt=1
    # Recorded but never claimed (stopped between the two writes): it is still
    # queued and runs from there, once.
    if [ -n "$cid" ] && _queue_has_cid "$cid"; then
        _clear_state "$INFLIGHT_FILE" || true
        return 0
    fi
    if [ "${boot:-}" != "$(boot_id)" ]; then
        why="the box restarted while it was running (started ${started:-?})"
    else
        why="it stopped before finishing — killed or timed out (started ${started:-?})"
    fi
    if _queue_has_family "$action"; then
        log "RECOVER: '${action}' id=${cid:-?} was interrupted — ${why}; a newer request supersedes the retry"
        write_result "$action" "interrupted" "interrupted: ${why}; superseded by a newer request" "$cid" "$attempt"
        _clear_state "$INFLIGHT_FILE" || log "  WARN: could not clear ${INFLIGHT_FILE}"
    elif _retry_safe "$action" && (( 10#$attempt < MAX_ATTEMPTS )); then
        log "RECOVER: '${action}' id=${cid:-?} was interrupted — ${why}; retrying (attempt $((10#$attempt + 1)) of ${MAX_ATTEMPTS})"
        # run_tracked rewrites the record as the next attempt FIRST and refuses to
        # run if it can't, so the attempt count — the retry limit — always holds.
        run_tracked "$cid" "$action" "$((10#$attempt + 1))" || true
    else
        log "RECOVER: '${action}' id=${cid:-?} was interrupted — ${why}; not retried"
        write_result "$action" "interrupted" "interrupted: ${why}; not retried automatically — queue it again from the dashboard" "$cid" "$attempt"
        _clear_state "$INFLIGHT_FILE" || log "  WARN: could not clear ${INFLIGHT_FILE}"
    fi
}

# How old a request is, in whole minutes, from its own stamp — taken right before
# it would run, not once per drain (a slow earlier action ages the ones behind it).
# Undated reads as very old: a request we cannot date is not run. A stamp more than
# five minutes in the future means the clock stepped back since: the true age is
# unknown, so a disruptive action treats it as old (expires) and a convergent one
# as new (runs — repeating a VLAN apply is harmless, a surprise reboot is not).
_request_age_min() {  # stamp action
    [[ "${1:-}" =~ ^[0-9]{1,12}$ ]] || { echo 999999; return; }
    local now age
    now="$(date +%s)"
    if (( 10#$1 > now + 300 )); then
        if _retry_safe "${2:-}"; then echo 0; else echo 999999; fi
        return
    fi
    age=$(( (now - 10#$1) / 60 ))
    (( age < 0 )) && age=0
    echo "$age"
}

drain_queue() {  # mode
    local mode="$1" age n=0 cid action limit
    while _queue_head; do
        (( ++n <= 64 )) || { log "the queue did not shrink; stopping"; return 1; }
        cid="$Q_CID"; action="$Q_ACTION"
        [ -n "${action:-}" ] || { _queue_set "$Q_REST" || return 1; continue; }
        # Every request is age-checked, on --drain too: a request queued this cycle is
        # seconds old, but one left from a skipped cycle (an update was running) can
        # be hours old by the next exit 12.
        age="$(_request_age_min "$(_stamp_of "$cid")" "$action")"
        limit="$LEFTOVER_MAX_AGE_MIN"
        _retry_safe "$action" || limit="$DISRUPTIVE_MAX_AGE_MIN"
        if (( age > limit )); then
                _queue_set "$Q_REST" || { log "cannot update ${REQUEST_FILE}; stopping"; return 1; }
                log "EXPIRED: host action id=${cid:-?} action=${action} was queued ${age} min ago (limit ${limit}); not running it now"
                write_result "$action" "expired" \
                    "queued ${age} minutes ago and never run; too old to run now — queue it again from the dashboard" "$cid" 1
                continue
        fi
        # Claim: in flight first, then off the queue. A crash between the two leaves
        # it in both, and recovery sees it still queued. Either write failing stops
        # the drain before anything runs.
        # It stays queued in both failure cases and runs at a later check-in, so the
        # report is "deferred", never a terminal "failed" the later run contradicts.
        if ! _write_state "$INFLIGHT_FILE" "$(_inflight_rec "$cid" "$action" 1)"; then
            log "cannot record '${action}' as in flight (${INFLIGHT_FILE} not writable); leaving the queue as it is"
            write_result "$action" "deferred" "not run yet: the box could not record it as in progress (state directory not writable); it tries again at the next check-in" "$cid" 1
            return 1
        fi
        if ! _queue_set "$Q_REST"; then
            _clear_state "$INFLIGHT_FILE" || true
            log "cannot remove '${action}' from ${REQUEST_FILE}; not running it (it would run again on every check-in)"
            write_result "$action" "deferred" "not run yet: the box could not remove it from its queue (state directory not writable); it tries again at the next check-in" "$cid" 1
            return 1
        fi
        log "draining host action id=${cid:-?} action=${action}"
        _run_claimed "$cid" "$action" 1 || true
    done
    return 0
}

# One run at a time, so a drain never mistakes a live action (a manual run, say)
# for an interrupted one. Fails closed: no lock, no run. Returns 2 when the lock
# cannot be opened at all, 1 when another run holds it.
_take_lock() {
    command -v flock >/dev/null 2>&1 || return 0
    { exec 9>>"$LOCK_FILE"; } 2>/dev/null || return 2
    flock -n 9 || return 1
}

main() {
    local lk=0
    _take_lock || lk=$?
    if (( lk == 2 )); then
        log "cannot open ${LOCK_FILE}; not running host actions (the queue stays for the next check-in)"
        return 1
    elif (( lk != 0 )); then
        log "another host action is running; leaving the queue for the next check-in"
        return 0
    fi

    local mode="${1:-}"
    # --- stamp only (netmon-checkin.sh: before each check-in, and when it ---
    # leaves the queue for later) ------------------------------------------------
    if [ "$mode" = "--stamp" ]; then
        _stamp_queue || true
        return 0
    fi
    # --- direct single-action invocation ------------------------------------
    if [ "$mode" != "--drain" ] && [ "$mode" != "--drain-leftover" ] && [ -n "$mode" ]; then
        recover_interrupted
        run_tracked "" "$1" 1
        return $?
    fi

    # --- drain mode (netmon-checkin.sh: --drain on exit 12, --drain-leftover
    # on any other successful check-in) ----------------------------------------
    if [ ! -s "$REQUEST_FILE" ] && [ ! -s "$INFLIGHT_FILE" ]; then
        return 0
    fi
    _stamp_queue || log "WARN: could not record request times in ${SEEN_FILE}; undated requests will expire"
    recover_interrupted
    # An in-flight record still there means its retry is deferred (the record could
    # not be rewritten). Hold the queue: requests run strictly in order, so a newer
    # one never overtakes an older one still owed its retry.
    if [ -s "$INFLIGHT_FILE" ]; then
        log "an interrupted action is still pending; leaving the queue for the next check-in"
        return 0
    fi
    drain_queue "$mode" || true
    _stamp_queue || true   # drop the ages of what was just claimed
    return 0
}

# Sourced by the tests; run when executed.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
    exit $?
fi
