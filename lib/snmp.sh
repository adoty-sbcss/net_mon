# lib/snmp.sh — SNMP prompt flow. Source AFTER common.sh, envfile.sh.

[[ -n "${_NETMON_SNMP_SH:-}" ]] && return 0
_NETMON_SNMP_SH=1

# prompt_snmp_config — ask whether SNMP polling should be enabled and, if so,
# collect community strings.
prompt_snmp_config() {
    echo ""
    echo "${C_INFO}=== Optional: SNMP polling ===${C_OFF}"
    echo "If you have read community strings for switches/routers on the network,"
    echo "NetMon can poll them for richer topology data (MAC tables, interface"
    echo "counters, etc.). Polling targets the gateway and LLDP-discovered switches"
    echo "only — not random hosts."
    echo ""

    local current_enabled default_enabled
    current_enabled="$(current_value NETMON_SNMP_ENABLED)"
    default_enabled="N"
    [[ "$current_enabled" == "true" ]] && default_enabled="Y"

    if prompt_yesno "Enable SNMP polling?" "$default_enabled"; then
        set_value NETMON_SNMP_ENABLED "true"
        echo ""
        echo "Enter one or more read communities to try, comma-separated."
        echo "The collector probes each device with each string and remembers"
        echo "which one works per-device, so subsequent scans skip the trial."
        echo "Example:  public, ourreadonly, special-string"
        echo ""
        prompt NETMON_SNMP_COMMUNITIES "SNMP communities to try" "public"
    else
        set_value NETMON_SNMP_ENABLED "false"
    fi
}
