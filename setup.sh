#!/usr/bin/env bash
# App_Mon interactive setup. Run on the Ubuntu box after `git clone`.
# Re-run any time to update settings.

set -euo pipefail

cd "$(dirname "$0")"

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"

if [[ ! -f "$EXAMPLE_FILE" ]]; then
    echo "ERROR: $EXAMPLE_FILE not found. Run this from the App_Mon directory."
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    cp "$EXAMPLE_FILE" "$ENV_FILE"
fi

# --- helpers ---------------------------------------------------------------

current_value() {
    local name="$1"
    grep -E "^${name}=" "$ENV_FILE" 2>/dev/null | head -1 | sed -E "s/^${name}=//; s/^\"//; s/\"$//" || true
}

set_value() {
    # set_value NAME VALUE  — writes/updates NAME="VALUE" in $ENV_FILE
    local name="$1"
    local value="$2"
    # Escape & and / for sed.
    local escaped
    escaped=$(printf '%s' "$value" | sed -e 's/[\/&|]/\\&/g')
    if grep -qE "^${name}=" "$ENV_FILE"; then
        sed -i -E "s|^${name}=.*|${name}=\"${escaped}\"|" "$ENV_FILE"
    else
        printf '%s="%s"\n' "$name" "$value" >> "$ENV_FILE"
    fi
}

prompt() {
    # prompt NAME "Prompt text" "default value"
    local name="$1"
    local label="$2"
    local default="$3"
    local current
    current="$(current_value "$name")"
    local shown="${current:-$default}"
    local answer=""
    if [[ -n "$shown" ]]; then
        read -r -p "$label [$shown]: " answer
    else
        read -r -p "$label: " answer
    fi
    answer="${answer:-$shown}"
    set_value "$name" "$answer"
}

prompt_secret() {
    # prompt_secret NAME "Prompt text"
    local name="$1"
    local label="$2"
    local current
    current="$(current_value "$name")"
    local hint="enter to keep current"
    if [[ -z "$current" ]]; then
        hint="required"
    fi
    local answer=""
    read -r -s -p "$label ($hint): " answer
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

# --- postgres password (auto-gen if still the placeholder) ----------------

current_pgpw="$(current_value POSTGRES_PASSWORD)"
if [[ -z "$current_pgpw" || "$current_pgpw" == "change-me-please" ]]; then
    new_pgpw="$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    set_value POSTGRES_PASSWORD "$new_pgpw"
    echo "Generated a random POSTGRES_PASSWORD."
fi

# --- friendly device name -------------------------------------------------

echo ""
echo "=== App_Mon SFTP configuration ==="
echo "Press Enter to keep the current/default value shown in brackets."
echo ""

default_device="$(hostname)"
prompt APPMON_DEVICE_NAME       "Device name (used in upload filenames)" "$default_device"

# --- SFTP target ----------------------------------------------------------

prompt APPMON_SFTP_HOST         "SFTP server hostname or IP"             ""
prompt APPMON_SFTP_PORT         "SFTP port"                              "22"
prompt APPMON_SFTP_USER         "SFTP username"                          ""
prompt_secret APPMON_SFTP_PASSWORD "SFTP password"
prompt APPMON_SFTP_REMOTE_PATH  "Remote directory for uploads"           "/"

# Enable upload by default once the user has filled in details.
set_value APPMON_SFTP_ENABLED "true"

# --- lock down the file ---------------------------------------------------

chmod 600 "$ENV_FILE"
echo ""
echo "Settings written to $ENV_FILE (chmod 600)."

# --- offer to test --------------------------------------------------------

echo ""
read -r -p "Test the SFTP connection now? [Y/n]: " do_test
do_test="${do_test:-Y}"
if [[ "$do_test" =~ ^[Yy]$ ]]; then
    echo "Starting containers (if not already running)..."
    docker compose up -d
    echo "Waiting for the collector to come up..."
    # Give postgres a moment, then run the test.
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if docker compose exec -T collector python -m collector upload-test 2>/dev/null; then
            break
        fi
        sleep 3
    done
fi

echo ""
echo "Done."
echo ""
echo "Next steps:"
echo "  1. Plug a network cable into the box (auto-scan triggers on link-up)"
echo "  2. Check activity:  docker compose logs -f collector"
echo "  3. Force an upload now (no wait):"
echo "       docker compose exec collector python -m collector upload-now"
