# lib/sftp.sh — SFTP prompt flow. Source AFTER common.sh, envfile.sh, validate.sh.

[[ -n "${_NETMON_SFTP_SH:-}" ]] && return 0
_NETMON_SFTP_SH=1

# _sftp_provisioned — true if the upload destination is already fully set (host +
# user + password), e.g. seeded from config/provisioning.env. Lets the first-boot
# wizard SKIP the SFTP prompts entirely instead of making the tech Enter through
# pre-filled values.
_sftp_provisioned() {
    [[ -n "$(current_value NETMON_SFTP_HOST)" ]] \
        && [[ -n "$(current_value NETMON_SFTP_USER)" ]] \
        && [[ -n "$(current_value NETMON_SFTP_PASSWORD)" ]]
}

# prompt_sftp_config — interactive walk through the SFTP destination fields.
# Stores values in /etc/netmon/netmon.env via set_value. Also sets
# NETMON_SFTP_ENABLED=true at the end so the uploader starts shipping.
#
# Args (optional): "default_device_name" — used as default for NETMON_DEVICE_NAME
#                  if the env file doesn't already have one.
prompt_sftp_config() {
    local default_device="${1:-$(hostname)}"

    echo ""
    echo "${C_INFO}=== NetMon SFTP configuration ===${C_OFF}"
    echo "Press Enter to keep the current/default value shown in brackets."
    echo ""

    prompt NETMON_DEVICE_NAME "Device name (used in upload filenames)" "$default_device"

    echo ""
    echo "  Tip: enter the hostname only (e.g. sftp.example.com or, for Azure Blob:"
    echo "       <account>.blob.core.windows.net). The username goes on the next line."
    echo ""
    prompt NETMON_SFTP_HOST "SFTP server hostname or IP" ""

    # Guard: if the user pasted user@host into the host field, offer to split.
    local host_value split
    host_value="$(current_value NETMON_SFTP_HOST)"
    if split="$(detect_userhost_in_host "$host_value")"; then
        local suggested_user="${split% *}"
        local suggested_host="${split#* }"
        echo ""
        warn "The host you entered contains '@':"
        warn "    $host_value"
        warn "That's a combined user@host string, not a hostname — DNS can't resolve it."
        if prompt_yesno "Split it into user='$suggested_user' and host='$suggested_host'?" "Y"; then
            set_value NETMON_SFTP_HOST "$suggested_host"
            set_value NETMON_SFTP_USER "$suggested_user"
            ok "split: host=$suggested_host, user=$suggested_user"
        fi
    fi

    prompt NETMON_SFTP_PORT "SFTP port" "22"
    prompt NETMON_SFTP_USER "SFTP username" ""
    prompt_secret NETMON_SFTP_PASSWORD "SFTP password"
    prompt NETMON_SFTP_REMOTE_PATH "Remote directory for uploads" "/"

    set_value NETMON_SFTP_ENABLED "true"
}
