# lib/identity.sh — district / school / device naming hierarchy prompts.
#
# Stores into /etc/netmon/netmon.env:
#   NETMON_DISTRICT       — human-readable name typed by the operator
#   NETMON_DISTRICT_SLUG  — auto-derived path-safe slug
#   NETMON_SCHOOL         — human-readable
#   NETMON_SCHOOL_SLUG    — slug
#   NETMON_DEVICE         — human-readable (e.g. "Library IDF", "Server Room")
#   NETMON_DEVICE_SLUG    — slug
#   NETMON_DEVICE_NAME    — friendly name used in upload filenames (defaults
#                           to NETMON_DEVICE if blank)
#
# Source AFTER common.sh, envfile.sh, validate.sh.

[[ -n "${_NETMON_IDENTITY_SH:-}" ]] && return 0
_NETMON_IDENTITY_SH=1

# prompt_one_identity — read a name, slugify, show the slug, save both.
#
#   _name_var:  env var holding the human-readable value (e.g. NETMON_DISTRICT)
#   _slug_var:  env var holding the slug (e.g. NETMON_DISTRICT_SLUG)
#   _label:     prompt label
#   _example:   shown as a hint, e.g. "San Bernardino County USD"
_prompt_one_identity() {
    local name_var="$1" slug_var="$2" label="$3" example="$4"
    local current_name current_slug new_name new_slug
    current_name="$(current_value "$name_var")"
    current_slug="$(current_value "$slug_var")"

    while true; do
        if [[ -n "$current_name" ]]; then
            read -r -p "$label [$current_name]: " new_name || new_name=""
            new_name="${new_name:-$current_name}"
        else
            echo "  e.g. \"$example\""
            read -r -p "$label: " new_name || new_name=""
        fi
        new_name="$(printf '%s' "$new_name" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        if [[ -z "$new_name" ]]; then
            echo "  ! a value is required"
            continue
        fi
        new_slug="$(slugify "$new_name")"
        if ! is_valid_slug "$new_slug"; then
            echo "  ! couldn't derive a valid slug from \"$new_name\" — try plain ASCII letters/numbers"
            continue
        fi
        if [[ "$new_slug" != "$current_slug" ]] && [[ -n "$current_slug" ]]; then
            echo "  slug will change: '$current_slug' -> '$new_slug'"
        else
            echo "  slug: $new_slug"
        fi
        break
    done
    set_value "$name_var" "$new_name"
    set_value "$slug_var" "$new_slug"
}

prompt_identity_config() {
    echo ""
    echo "${C_INFO}=== Box identity ===${C_OFF}"
    echo "These names tag every scan and organize uploads on the SFTP server"
    echo "into <district>/<school>/<device>/ folders."
    echo ""

    _prompt_one_identity NETMON_DISTRICT NETMON_DISTRICT_SLUG \
        "District name" "San Bernardino County USD"
    _prompt_one_identity NETMON_SCHOOL   NETMON_SCHOOL_SLUG \
        "School / site name" "Big Bear Elementary"
    _prompt_one_identity NETMON_DEVICE   NETMON_DEVICE_SLUG \
        "Device / location label" "Library IDF"

    # NETMON_DEVICE_NAME is the legacy "friendly name" used in bundle filenames.
    # Default it to the device value the operator just typed. Phase 3 will
    # rewrite filenames to use the slugs; until then keep the existing pattern.
    local device_name current_device_name
    current_device_name="$(current_value NETMON_DEVICE_NAME)"
    device_name="$(current_value NETMON_DEVICE)"
    if [[ -z "$current_device_name" ]] || [[ "$current_device_name" == "$(hostname)" ]]; then
        set_value NETMON_DEVICE_NAME "$device_name"
    fi

    echo ""
    ok "identity saved:"
    echo "  district: $(current_value NETMON_DISTRICT) ($(current_value NETMON_DISTRICT_SLUG))"
    echo "  school:   $(current_value NETMON_SCHOOL) ($(current_value NETMON_SCHOOL_SLUG))"
    echo "  device:   $(current_value NETMON_DEVICE) ($(current_value NETMON_DEVICE_SLUG))"
}
