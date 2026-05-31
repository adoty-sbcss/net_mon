# lib/dashboard.sh — dashboard control-plane prompt flow. Source AFTER
# common.sh, envfile.sh.

[[ -n "${_NETMON_DASHBOARD_SH:-}" ]] && return 0
_NETMON_DASHBOARD_SH=1

# prompt_dashboard_config — opt the box into the dashboard control plane and set
# the shared bootstrap key for auto-enrollment. Outbound HTTPS only; no inbound.
prompt_dashboard_config() {
    echo ""
    echo "${C_INFO}=== Optional: Dashboard control plane ===${C_OFF}"
    echo "Let this box check in to the NetMon dashboard (OUTBOUND HTTPS only — it"
    echo "opens NO inbound ports) so admins can see it, push SNMP config, and run"
    echo "commands. Enrollment uses ONE shared bootstrap key — the same key on"
    echo "every box; the box auto-registers and gets its own token on first check-in."
    echo ""

    prompt NETMON_DASHBOARD_URL "Dashboard URL (blank to skip control plane)" \
        "$(current_value NETMON_DASHBOARD_URL)"

    local url
    url="$(current_value NETMON_DASHBOARD_URL)"
    if [[ -z "$url" ]]; then
        return 0
    fi

    # If a per-sensor token is already present (manual enrollment), leave it.
    if [[ -n "$(current_value NETMON_ENROLL_TOKEN)" ]]; then
        echo "  A per-sensor enrollment token is already set; keeping it."
        return 0
    fi

    echo ""
    echo "Paste the shared BOOTSTRAP KEY from the dashboard:"
    echo "  Settings → SFTP ingestion → Sensor auto-enrollment."
    echo "The same key works for every deployment."
    echo ""
    prompt NETMON_BOOTSTRAP_KEY "Bootstrap key (blank to skip auto-enroll)" \
        "$(current_value NETMON_BOOTSTRAP_KEY)"
}
