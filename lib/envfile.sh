# lib/envfile.sh — read/write/prompt helpers for /etc/netmon/netmon.env.
#
# All writes go through set_value so the file is always in canonical form
# (KEY="value", chmod 600, owned by NETMON_OWNER_USER).
#
# Source AFTER common.sh and paths.sh.

[[ -n "${_NETMON_ENVFILE_SH:-}" ]] && return 0
_NETMON_ENVFILE_SH=1

# Path the helpers operate on. Override by exporting NETMON_ENV_FILE_TARGET
# before sourcing. Defaults to the canonical /etc/netmon/netmon.env.
NETMON_ENV_FILE_TARGET="${NETMON_ENV_FILE_TARGET:-$NETMON_ENV_FILE}"

env_file() { printf '%s' "$NETMON_ENV_FILE_TARGET"; }

env_ensure_file() {
    # Create the env file if it doesn't exist yet, with safe perms.
    local f
    f="$(env_file)"
    if [[ ! -f "$f" ]]; then
        $SUDO install -m 600 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" \
            /dev/null "$f"
    fi
}

current_value() {
    local name="$1"
    local f
    f="$(env_file)"
    [[ -f "$f" ]] || { printf ''; return 0; }
    # Read with sudo in case the file is root-owned but we're not.
    $SUDO grep -E "^${name}=" "$f" 2>/dev/null | head -1 | \
        sed -E "s/^${name}=//; s/^\"//; s/\"$//" || true
}

set_value() {
    local name="$1"
    local value="$2"
    env_ensure_file
    local f
    f="$(env_file)"
    local escaped
    escaped=$(printf '%s' "$value" | sed -e 's/[\/&|]/\\&/g')
    if $SUDO grep -qE "^${name}=" "$f"; then
        $SUDO sed -i -E "s|^${name}=.*|${name}=\"${escaped}\"|" "$f"
    else
        printf '%s="%s"\n' "$name" "$value" | $SUDO tee -a "$f" >/dev/null
    fi
    # Re-assert ownership/perms in case anyone touched it manually.
    $SUDO chmod 600 "$f"
    $SUDO chown "$NETMON_OWNER_USER:$NETMON_OWNER_USER" "$f"
}

# prompt VAR_NAME "label" "default"
#   Shows current/default in brackets. Empty answer keeps current/default.
prompt() {
    local name="$1" label="$2" default="$3"
    local current shown answer
    current="$(current_value "$name")"
    shown="${current:-$default}"
    if [[ -n "$shown" ]]; then
        read -r -p "$label [$shown]: " answer || answer=""
    else
        read -r -p "$label: " answer || answer=""
    fi
    answer="${answer:-$shown}"
    set_value "$name" "$answer"
}

# prompt_secret VAR_NAME "label"
#   Silent input. Empty answer keeps current value if any, else re-prompts.
prompt_secret() {
    local name="$1" label="$2"
    local current hint answer
    current="$(current_value "$name")"
    hint="enter to keep current"
    [[ -z "$current" ]] && hint="required"
    read -r -s -p "$label ($hint): " answer || answer=""
    echo
    if [[ -z "$answer" ]]; then
        if [[ -z "$current" ]]; then
            echo "  ! value is required, try again"
            prompt_secret "$name" "$label"
            return
        fi
        return
    fi
    set_value "$name" "$answer"
}

# prompt_yesno "label" "Y" -> 0 if yes, 1 if no. Default is the second arg ("Y" or "N").
prompt_yesno() {
    local label="$1" default="${2:-N}" answer hint
    if [[ "${default^^}" == "Y" ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
    read -r -p "$label $hint: " answer || answer=""
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy]$ ]]
}

# Seed the env file from .env.example if it doesn't exist yet. Used on fresh
# installs so first-time prompts have sensible defaults.
seed_env_from_example() {
    local example="$1"
    env_ensure_file
    local f
    f="$(env_file)"
    # Only seed if the target is empty (size 0).
    if [[ -f "$f" ]] && [[ ! -s "$f" ]] && [[ -f "$example" ]]; then
        log "Seeding $f from $example"
        $SUDO install -m 600 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" \
            "$example" "$f"
    fi
}
