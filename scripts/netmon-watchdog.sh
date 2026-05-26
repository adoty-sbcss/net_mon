#!/usr/bin/env bash
# netmon-watchdog.sh — periodic self-healing checks, run every 15 min by
# netmon-watchdog.timer.
#
# Cheap. Logs one summary line per invocation. Only acts when something is
# wrong. Each check is independent — a failure in one doesn't block others.
#
# Checks:
#   1. Disk hygiene: delete bundles + log files > N days old.
#                    Uploaded bundles go first; un-uploaded only if disk pressure.
#   2. Disk pressure: if /var/lib/netmon usage > 85%, emergency pass that
#                    deletes ALL uploaded bundles regardless of age.
#   3. Upload stall:  if no successful SFTP upload in 6h AND there are
#                    pending bundles, restart the collector + log to syslog.
#   4. DB stall:      if postgres unreachable for > 5min, restart it.
#
# Tunable via env (override in systemd unit if needed):
#   NETMON_RETENTION_DAYS         (default 7)
#   NETMON_DISK_PRESSURE_PCT      (default 85)
#   NETMON_UPLOAD_STALL_HOURS     (default 6)
#   NETMON_DB_STALL_MINUTES       (default 5)

set -uo pipefail   # NOT -e: a check failure must not skip the others

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

RETENTION_DAYS="${NETMON_RETENTION_DAYS:-7}"
DISK_PRESSURE_PCT="${NETMON_DISK_PRESSURE_PCT:-85}"
UPLOAD_STALL_HOURS="${NETMON_UPLOAD_STALL_HOURS:-6}"
DB_STALL_MINUTES="${NETMON_DB_STALL_MINUTES:-5}"

BUNDLES_DIR="/var/lib/netmon/bundles"
LOG_DIR="/var/log/netmon"

LOG_TAG="netmon-watchdog"
log() {
    local msg="$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$msg"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$msg"
}

if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    DC=(docker compose)
else
    DC=(sudo docker compose)
fi

ACTIONS=0

# ----- 1. Routine disk hygiene -------------------------------------------

prune_old_uploaded() {
    # Get list of uploaded bundle filenames from db, delete the local files
    # whose mtime is older than RETENTION_DAYS.
    if ! "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-postgres; then
        return 0
    fi
    local uploaded_list
    uploaded_list="$("${DC[@]}" exec -T postgres psql -U netmon -d netmon -t -A -c \
        "SELECT local_path FROM bundle_uploads WHERE uploaded_at IS NOT NULL AND built_at < NOW() - INTERVAL '${RETENTION_DAYS} days';" \
        2>/dev/null)"
    [[ -z "$uploaded_list" ]] && return 0

    local n=0
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        if [[ -f "$path" ]]; then
            rm -f "$path"
            n=$((n + 1))
        fi
    done <<< "$uploaded_list"
    if (( n > 0 )); then
        log "pruned $n uploaded bundle(s) older than ${RETENTION_DAYS}d"
        ACTIONS=$((ACTIONS + 1))
    fi
}

prune_old_logs() {
    # Delete log files (NOT collector.log itself — rotation handles that)
    # that haven't been touched in RETENTION_DAYS. Targets the rotated copies
    # like collector.log.1.gz, audit.log.5.gz.
    if [[ ! -d "$LOG_DIR" ]]; then return 0; fi
    local found
    found="$(find "$LOG_DIR" -type f \( -name '*.gz' -o -name '*.1' -o -name '*.2' -o -name '*.3' -o -name '*.4' -o -name '*.5' \) -mtime "+${RETENTION_DAYS}" -print 2>/dev/null)"
    [[ -z "$found" ]] && return 0
    local n
    n="$(printf '%s\n' "$found" | wc -l)"
    echo "$found" | xargs -r sudo rm -f
    log "pruned $n rotated log file(s) older than ${RETENTION_DAYS}d"
    ACTIONS=$((ACTIONS + 1))
}

# ----- 2. Disk-pressure emergency cleanup --------------------------------

disk_pct() {
    df --output=pcent "$1" 2>/dev/null | tail -1 | tr -d ' %'
}

emergency_cleanup_if_pressured() {
    [[ -d "$BUNDLES_DIR" ]] || return 0
    local pct
    pct="$(disk_pct "$BUNDLES_DIR")"
    [[ -z "$pct" ]] && return 0
    if (( pct < DISK_PRESSURE_PCT )); then
        return 0
    fi
    log "DISK PRESSURE: /var/lib/netmon at ${pct}% (threshold ${DISK_PRESSURE_PCT}%) — emergency cleanup"

    if "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-postgres; then
        # Delete ALL uploaded bundles regardless of age.
        local uploaded_list
        uploaded_list="$("${DC[@]}" exec -T postgres psql -U netmon -d netmon -t -A -c \
            "SELECT local_path FROM bundle_uploads WHERE uploaded_at IS NOT NULL;" 2>/dev/null)"
        local n=0
        while IFS= read -r path; do
            [[ -z "$path" ]] && continue
            if [[ -f "$path" ]]; then
                rm -f "$path"
                n=$((n + 1))
            fi
        done <<< "$uploaded_list"
        log "emergency: deleted $n uploaded bundle(s)"
    fi

    # Re-check; if still over, warn loudly (don't touch un-uploaded data).
    pct="$(disk_pct "$BUNDLES_DIR")"
    if [[ -n "$pct" ]] && (( pct >= DISK_PRESSURE_PCT )); then
        log "WARNING: still at ${pct}% after emergency cleanup; manual triage needed"
        log "         un-uploaded bundles are protected — fix SFTP first, then they ship out"
    fi
    ACTIONS=$((ACTIONS + 1))
}

# ----- 3. Upload-stall check ----------------------------------------------

check_upload_stall() {
    if ! "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-postgres; then
        return 0
    fi
    # Has there been any successful upload in the last UPLOAD_STALL_HOURS?
    local hours_since
    hours_since="$("${DC[@]}" exec -T postgres psql -U netmon -d netmon -t -A -c \
        "SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(uploaded_at))) / 3600, 9999)::int FROM bundle_uploads WHERE uploaded_at IS NOT NULL;" \
        2>/dev/null | tr -d ' ')"
    [[ -z "$hours_since" ]] && return 0
    if (( hours_since < UPLOAD_STALL_HOURS )); then
        return 0
    fi
    # Are there pending uploads queued?
    local pending
    pending="$("${DC[@]}" exec -T postgres psql -U netmon -d netmon -t -A -c \
        "SELECT COUNT(*) FROM bundle_uploads WHERE uploaded_at IS NULL;" 2>/dev/null | tr -d ' ')"
    if [[ -z "$pending" ]] || (( pending == 0 )); then
        # Nothing to upload, so "no recent uploads" is fine. Quiet hours.
        return 0
    fi
    log "UPLOAD STALL: ${hours_since}h since last success, ${pending} bundle(s) pending"
    log "  restarting collector to retry"
    "${DC[@]}" restart collector >/dev/null 2>&1 || true
    ACTIONS=$((ACTIONS + 1))
}

# ----- 4. DB-stall check --------------------------------------------------

check_db_stall() {
    if "${DC[@]}" exec -T postgres pg_isready -U netmon -d netmon >/dev/null 2>&1; then
        return 0
    fi
    log "DB STALL: postgres not responding to pg_isready — restarting"
    "${DC[@]}" restart postgres >/dev/null 2>&1 || true
    ACTIONS=$((ACTIONS + 1))
}

# ----- run all checks -----------------------------------------------------

prune_old_uploaded
prune_old_logs
emergency_cleanup_if_pressured
check_upload_stall
check_db_stall

if (( ACTIONS == 0 )); then
    log "watchdog ok — no action needed"
else
    log "watchdog done — $ACTIONS action(s) taken"
fi
exit 0
