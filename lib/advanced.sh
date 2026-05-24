# lib/advanced.sh — advanced-settings prompts (scan cadence, log level, mode).
#
# Source AFTER common.sh, envfile.sh.

[[ -n "${_NETMON_ADVANCED_SH:-}" ]] && return 0
_NETMON_ADVANCED_SH=1

prompt_scan_cadence() {
    echo ""
    echo "${C_INFO}=== Scan cadence ===${C_OFF}"
    echo "These control how long the collector listens during a scan and how"
    echo "often it checks for new networks. Defaults are fine for most sites."
    echo ""
    prompt NETMON_CAPTURE_SECONDS  "Capture window per scan (seconds)" "60"
    prompt NETMON_POLL_INTERVAL    "Interface poll interval (seconds)" "30"
    prompt NETMON_COOLDOWN_SECONDS "Cooldown between scans of same network (seconds)" "300"
}

prompt_scan_mode() {
    echo ""
    echo "${C_INFO}=== Scan mode ===${C_OFF}"
    echo "  field   = scan once per network plug-in, then idle (site visits)"
    echo "  monitor = scan every time interface state changes (continuous)"
    echo ""
    local current default
    current="$(current_value NETMON_MODE)"
    default="${current:-field}"
    while true; do
        read -r -p "Scan mode [$default]: " mode || mode=""
        mode="${mode:-$default}"
        if [[ "$mode" == "field" ]] || [[ "$mode" == "monitor" ]]; then
            set_value NETMON_MODE "$mode"
            break
        fi
        echo "  ! must be 'field' or 'monitor'"
    done
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
    prompt_scan_mode
    prompt_scan_cadence
    prompt_log_level
}
