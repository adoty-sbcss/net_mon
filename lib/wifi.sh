#  lib/wifi.sh — Wi-Fi monitoring prompts. Source AFTER common.sh, envfile.sh.
#
# Two prompt flows:
#   prompt_wifi_profile  — pick survey (mobile, long scans) vs monitor
#                          (stationary, hourly quick snapshots)
#   prompt_wifi_config   — main flow: detect adapter, ask enable + interface,
#                          and the profile prompt above.

[[ -n "${_NETMON_WIFI_SH:-}" ]] && return 0
_NETMON_WIFI_SH=1

# List Wi-Fi interfaces visible to the host. Empty output = no Wi-Fi NIC.
_wifi_list_interfaces() {
    if ! command -v iw >/dev/null 2>&1; then
        return 0
    fi
    iw dev 2>/dev/null | awk '/Interface/ {print $2}'
}

# Does the host's primary radio support monitor mode? Used only as a hint;
# Phase 1 doesn't require monitor mode (iw scan works without it).
_wifi_supports_monitor() {
    if ! command -v iw >/dev/null 2>&1; then
        return 1
    fi
    iw list 2>/dev/null | sed -n '/Supported interface modes/,/^[[:space:]]*[A-Za-z]/p' \
        | grep -q '\* monitor'
}

prompt_wifi_profile() {
    echo ""
    echo "${C_INFO}Box profile${C_OFF}"
    echo "  survey   = mobile laptop / field tool. Wi-Fi spectrum survey is the"
    echo "             primary job. Long scans (~5 min) on manual trigger."
    echo "  monitor  = stationary box. Wired collection is primary. Wi-Fi gets"
    echo "             a 90-second snapshot once per hour."
    echo ""
    local current default
    current="$(current_value NETMON_PROFILE)"
    default="${current:-monitor}"
    while true; do
        read -r -p "Profile [$default]: " profile || profile=""
        profile="${profile:-$default}"
        case "$profile" in
            survey|monitor)
                set_value NETMON_PROFILE "$profile"
                break ;;
            *) echo "  ! must be 'survey' or 'monitor'" ;;
        esac
    done
}

prompt_wifi_config() {
    echo ""
    echo "${C_INFO}=== Optional: Wi-Fi monitoring ===${C_OFF}"
    echo "Listen to the airwaves around this box: nearby APs, channels,"
    echo "encryption, signal strength, and basic anomaly flags (open / WEP /"
    echo "duplicate-SSID / channel saturation). Works on any Wi-Fi adapter —"
    echo "monitor mode is NOT required for Phase 1."
    echo ""

    local current_enabled default_enabled
    current_enabled="$(current_value NETMON_WIFI_ENABLED)"
    default_enabled="N"
    [[ "$current_enabled" == "true" ]] && default_enabled="Y"

    if ! prompt_yesno "Enable Wi-Fi monitoring?" "$default_enabled"; then
        set_value NETMON_WIFI_ENABLED "false"
        return 0
    fi
    set_value NETMON_WIFI_ENABLED "true"

    # Show what we detected so the operator picks the right interface.
    local detected
    detected="$(_wifi_list_interfaces | tr '\n' ' ')"
    if [[ -n "$detected" ]]; then
        echo ""
        echo "Detected Wi-Fi interfaces: $detected"
    else
        echo ""
        warn "No Wi-Fi interfaces detected via 'iw dev'."
        warn "If you plan to plug in a USB Wi-Fi adapter, you can set the name"
        warn "now and configure later. Otherwise disable Wi-Fi for this box."
    fi
    if _wifi_supports_monitor; then
        ok "Built-in adapter advertises monitor mode (good — Phase 2 will use it)"
    else
        echo "(Phase 1 doesn't need monitor mode; informational only.)"
    fi

    # First detected interface is the default; operator can override.
    local first_iface default_iface
    first_iface="$(_wifi_list_interfaces | head -1)"
    default_iface="$(current_value NETMON_WIFI_INTERFACE)"
    default_iface="${default_iface:-$first_iface}"
    prompt NETMON_WIFI_INTERFACE "Wi-Fi interface name" "${default_iface:-wlp0s20f3}"

    prompt_wifi_profile

    echo ""
    echo "(Advanced: scan duration follows the profile by default. Override with"
    echo " NETMON_WIFI_SCAN_SECONDS in /etc/netmon/netmon.env if you need to.)"
}
