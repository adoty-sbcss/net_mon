# lib/dashboard.sh — dashboard control-plane prompt flow. Source AFTER
# common.sh, envfile.sh.

[[ -n "${_NETMON_DASHBOARD_SH:-}" ]] && return 0
_NETMON_DASHBOARD_SH=1

# prompt_dashboard_config — opt the box into the dashboard control plane and set
# the shared bootstrap key for auto-enrollment. Outbound HTTPS only; no inbound.
#
# The dashboard URL and bootstrap key are the SAME on every box, so they're
# typically pre-filled from a site provisioning file (config/provisioning.env;
# see lib/provisioning.sh). When that's in place the tech just presses Enter at
# both prompts. Values shown in [brackets] are the baked-in defaults.
prompt_dashboard_config() {
    echo ""
    echo "${C_INFO}=== Dashboard control plane + auto-enrollment ===${C_OFF}"
    echo "Let this box check in to the NetMon dashboard (OUTBOUND HTTPS only — it"
    echo "opens NO inbound ports) so admins can see it, push config, and run"
    echo "commands. Enrollment uses ONE shared bootstrap key — the same key on"
    echo "every box; the box auto-registers and gets its own token on first check-in."

    # Defaults: whatever's already in netmon.env (seeded from provisioning),
    # else read straight from the provisioning file as a fallback.
    local url_default key_default
    url_default="$(current_value NETMON_DASHBOARD_URL)"
    [[ -z "$url_default" ]] && url_default="$(provisioning_default NETMON_DASHBOARD_URL)"
    key_default="$(current_value NETMON_BOOTSTRAP_KEY)"
    [[ -z "$key_default" ]] && key_default="$(provisioning_default NETMON_BOOTSTRAP_KEY)"

    if [[ -n "$url_default" ]]; then
        echo "${C_DIM}  (pre-filled from site provisioning — press Enter to accept)${C_OFF}"
    fi
    echo ""

    prompt NETMON_DASHBOARD_URL "Dashboard URL (blank to skip control plane)" \
        "$url_default"

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
    if [[ -z "$key_default" ]]; then
        echo "Paste the shared BOOTSTRAP KEY from the dashboard:"
        echo "  Settings → SFTP ingestion → Sensor auto-enrollment."
        echo "The same key works for every deployment."
        echo ""
    fi
    prompt NETMON_BOOTSTRAP_KEY "Bootstrap key (blank to skip auto-enroll)" \
        "$key_default"
}
