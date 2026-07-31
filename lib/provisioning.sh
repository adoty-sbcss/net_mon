# lib/provisioning.sh — pre-provisioned default values for one-time setup.
#
# A site can drop a "provisioning defaults" file so the first-boot wizard
# pre-fills fields that are the SAME on every box — most importantly the
# dashboard URL and the shared enrollment bootstrap key. The technician then
# just presses Enter at each prompt to accept the baked-in value, or types a
# different one to override.
#
# Lookup order (first file that exists wins for a given key):
#   1. $NETMON_PROVISIONING_FILE        — explicit override (export before run)
#   2. <repo>/config/provisioning.env   — git-ignored; pulled in per-site
#   3. /etc/netmon/provisioning.env     — placed by a golden image / config mgmt
#
# Format is a plain KEY=VALUE list using the SAME names as netmon.env, e.g.:
#   NETMON_DASHBOARD_URL=https://netmon.example.org
#   NETMON_BOOTSTRAP_KEY=nmk_xxxxxxxxxxxxxxxxxxxxxxxx
#
# SECURITY: the bootstrap key is a shared secret and this repo is PUBLIC, so
# config/provisioning.env is git-ignored and must NEVER be committed. Generate
# its contents from the dashboard (Settings -> Ingestion -> Sensor
# auto-enrollment) and place it on each box out-of-band.
#
# Source AFTER common.sh, paths.sh, envfile.sh.

[[ -n "${_NETMON_PROVISIONING_SH:-}" ]] && return 0
_NETMON_PROVISIONING_SH=1

# Echo the list of candidate provisioning files, highest priority first.
_provisioning_files() {
    [[ -n "${NETMON_PROVISIONING_FILE:-}" ]] && printf '%s\n' "$NETMON_PROVISIONING_FILE"
    [[ -n "${REPO_DIR:-}" ]] && printf '%s\n' "$REPO_DIR/config/provisioning.env"
    printf '%s\n' "/etc/netmon/provisioning.env"
}

# provisioning_file_path — echo the first provisioning file that exists, if any.
provisioning_file_path() {
    local f
    while IFS= read -r f; do
        [[ -f "$f" ]] && { printf '%s' "$f"; return 0; }
    done < <(_provisioning_files)
    printf ''
}

# provisioning_default VAR — echo the first value found for VAR across the
# candidate files, else empty. Tolerates optional surrounding quotes.
provisioning_default() {
    local name="$1" f line val
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        # Read with sudo in case the file (esp. /etc/netmon) is root-owned.
        line="$($SUDO grep -E "^[[:space:]]*${name}=" "$f" 2>/dev/null | head -1)" || true
        [[ -z "$line" ]] && continue
        val="${line#*=}"
        # Strip optional surrounding single or double quotes.
        val="${val%\"}"; val="${val#\"}"
        val="${val%\'}"; val="${val#\'}"
        printf '%s' "$val"
        return 0
    done < <(_provisioning_files)
    printf ''
}

# seed_env_from_provisioning — for each KEY=VALUE in the highest-priority
# provisioning file, write it into netmon.env ONLY if that key is currently
# empty/unset. This makes the values show up as the bracketed default at each
# prompt, so the tech can accept with Enter. Existing values are never
# clobbered, so re-running the wizard is safe.
seed_env_from_provisioning() {
    local src
    src="$(provisioning_file_path)"
    [[ -z "$src" ]] && return 0

    log "Applying provisioning defaults from $src (press Enter at prompts to accept)"

    local line name val current
    # Read with sudo in case the file is root-owned.
    while IFS= read -r line; do
        # Skip blanks and comments.
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Must look like KEY=VALUE with a NETMON_/POSTGRES_ style key.
        [[ "$line" =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
        name="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        # Strip optional surrounding quotes.
        val="${val%\"}"; val="${val#\"}"
        val="${val%\'}"; val="${val#\'}"
        current="$(current_value "$name")"
        if [[ -z "$current" ]]; then
            set_value "$name" "$val"
        fi
    done < <($SUDO grep -E '^[[:space:]]*[A-Z]' "$src" 2>/dev/null || true)
}
