# lib/advanced.sh — advanced-settings prompts (scan cadence, log level, mode).
#
# Source AFTER common.sh, envfile.sh.

[[ -n "${_NETMON_ADVANCED_SH:-}" ]] && return 0
_NETMON_ADVANCED_SH=1

prompt_scan_cadence() {
    echo ""
    echo "${C_INFO}=== Scan cadence ===${C_OFF}"
    echo "The collector continuously monitors every active network and re-scans"
    echo "each one on the interval below. Defaults are fine for most sites."
    echo ""
    echo "Note: the capture window is PER INTERFACE and blocks for its full length."
    echo "On a trunk, each monitored VLAN pays it in turn — 8 VLANs x 60s = 8 min"
    echo "per pass. Keep (VLANs x window) well under the light-capture interval."
    echo ""
    prompt NETMON_RESCAN_INTERVAL  "Re-scan each network every (seconds, 3600=hourly)" "3600"
    # 60 here, in .env.example, and in config.py's capture_seconds — all three now
    # agree. They did not before: config.py said 120. Because bin/netmon-wizard SEEDS
    # netmon.env from .env.example on every fresh box, an explicit 60 already lands on
    # effectively every field sensor, so 120 was the number almost nothing ran while
    # still being what a box with no key would have used. Reconciling DOWN to 60 is
    # the direction that matches the fleet instead of silently doubling its window.
    prompt NETMON_CAPTURE_SECONDS  "Capture window per scan (seconds, per interface)" "60"
    prompt NETMON_POLL_INTERVAL    "Interface poll tick (seconds)" "30"
    prompt NETMON_COOLDOWN_SECONDS "Anti-flap floor between scans of same network (seconds)" "300"
}

prompt_log_level() {
    echo ""
    echo "${C_INFO}=== Log verbosity ===${C_OFF}"
    echo "  DEBUG    = very chatty; only for troubleshooting"
    echo "  INFO     = default; one line per scan event"
    echo "  WARNING  = quiet; only flags problems"
    echo "  ERROR    = silent unless something fails"
    echo ""
    local current default
    current="$(current_value NETMON_LOG_LEVEL)"
    default="${current:-INFO}"
    while true; do
        read -r -p "Log level [$default]: " level || level=""
        level="${level:-$default}"
        level="${level^^}"
        case "$level" in
            DEBUG|INFO|WARNING|ERROR)
                set_value NETMON_LOG_LEVEL "$level"; break ;;
            *) echo "  ! must be one of DEBUG, INFO, WARNING, ERROR" ;;
        esac
    done
}

prompt_advanced_config() {
    prompt_scan_cadence
    prompt_log_level
}
