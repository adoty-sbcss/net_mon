#!/usr/bin/env bash
# scripts/netmon-wifi-experience-tick.sh — WIFI-6 unattended scheduler tick.
#
# The client-experience battery (netmon-wifi-experience.sh) is disruptive (it takes
# the analysis radio through join->measure->leave per profile), so it must NOT run
# every timer fire. This tick runs from netmon-wifi-experience.timer every ~15 min
# and starts the battery only when:
#   - NETMON_WIFI_JOIN_ENABLED is true, AND
#   - NETMON_WIFI_JOIN_SCHEDULE_SEC > 0 (scheduling on; 0 = manual / dashboard "Test
#     now" only), AND
#   - at least SCHEDULE_SEC has elapsed since the last run, AND
#   - the current box-LOCAL hour is outside the optional NETMON_WIFI_JOIN_QUIET window.
#
# The cadence + quiet window are pushed from the dashboard (checkin._apply_config).
# The last-run time is stamped BEFORE the battery starts, so a long or failed run
# waits a full cadence before retrying instead of hammering every tick.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
for _lib in common.sh paths.sh envfile.sh; do
    # shellcheck source=/dev/null
    [ -f "$REPO_DIR/lib/$_lib" ] && . "$REPO_DIR/lib/$_lib"
done

STATE_DIR="${NETMON_STATE_DIR:-/var/lib/netmon}"
LAST_FILE="${STATE_DIR}/wifi-experience-last"

# 1. feature gate
enabled="$(current_value NETMON_WIFI_JOIN_ENABLED 2>/dev/null || true)"
case "${enabled,,}" in true|1|yes) ;; *) exit 0 ;; esac

# 2. scheduling on?
sched="$(current_value NETMON_WIFI_JOIN_SCHEDULE_SEC 2>/dev/null || echo 0)"
[[ "$sched" =~ ^[0-9]+$ ]] || sched=0
(( sched <= 0 )) && exit 0

# 3. cadence elapsed?
now="$(date +%s)"
last=0
[[ -f "$LAST_FILE" ]] && last="$(cat "$LAST_FILE" 2>/dev/null || echo 0)"
[[ "$last" =~ ^[0-9]+$ ]] || last=0
(( now - last < sched )) && exit 0

# 4. quiet hours (box-local, 24h, may wrap midnight — e.g. "22-6")
quiet="$(current_value NETMON_WIFI_JOIN_QUIET 2>/dev/null || true)"
if [[ "$quiet" =~ ^([0-9]{1,2})-([0-9]{1,2})$ ]]; then
    qs="${BASH_REMATCH[1]}"; qe="${BASH_REMATCH[2]}"; h="$(date +%-H)"
    if (( qs <= qe )); then
        (( h >= qs && h < qe )) && exit 0
    else
        (( h >= qs || h < qe )) && exit 0   # window wraps midnight
    fi
fi

# Due — stamp the attempt up-front, then run the battery.
mkdir -p "$STATE_DIR" 2>/dev/null || true
echo "$now" > "$LAST_FILE" 2>/dev/null || true
exec "$REPO_DIR/scripts/netmon-wifi-experience.sh"
