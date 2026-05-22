#!/usr/bin/env bash
# App_Mon setup. Run on a fresh Ubuntu box after `git clone`.
#
# This script is the single entry point for deployment. It:
#   1. Bootstraps system deps (docker, docker compose v2, openssl) automatically,
#      resolving the most common conflicts on the fly (e.g. docker.io vs
#      docker-ce, missing compose plugin).
#   2. Creates the directories the containers need.
#   3. Prompts interactively for SFTP host / port / user / password / path.
#   4. Writes .env, locks it down, and optionally tests the SFTP connection.
#
# Safe to re-run any time. Each section detects what's already in place and
# only fixes what's missing. No interactive prompts in the bootstrap phase —
# you only get prompted for SFTP details.

set -euo pipefail

cd "$(dirname "$0")"

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"

# --- console formatting ---------------------------------------------------

if [[ -t 1 ]]; then
    C_OK=$'\033[1;32m'
    C_WARN=$'\033[1;33m'
    C_ERR=$'\033[1;31m'
    C_INFO=$'\033[1;36m'
    C_OFF=$'\033[0m'
else
    C_OK= C_WARN= C_ERR= C_INFO= C_OFF=
fi

log()  { printf '%s==>%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s  !!%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '%sFAIL:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

# --- sudo wrapper ---------------------------------------------------------
# Use sudo when needed, no-op when already root.

if [[ ${EUID} -eq 0 ]]; then
    SUDO=""
else
    if ! command -v sudo >/dev/null 2>&1; then
        die "This script needs root or sudo. Install sudo or re-run as root."
    fi
    SUDO="sudo"
    if ! sudo -n true 2>/dev/null; then
        log "Some steps need sudo. You may be prompted for your password."
        sudo -v || die "Could not obtain sudo."
        # keep sudo cred fresh in the background
        ( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
        SUDO_KEEPER=$!
        trap '[[ -n "${SUDO_KEEPER:-}" ]] && kill "$SUDO_KEEPER" 2>/dev/null || true' EXIT
    fi
fi

# --- platform check -------------------------------------------------------

if [[ "$(uname -s)" != "Linux" ]]; then
    die "This script must be run on Linux (Ubuntu). For development, use docker compose directly."
fi
if ! command -v apt-get >/dev/null 2>&1; then
    die "apt-get not found. This script only supports Debian/Ubuntu-family distros."
fi

# --- helpers --------------------------------------------------------------

pkg_installed() {
    # Returns 0 if pkg is installed (and "ii" status), 1 otherwise.
    dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null | grep -q "install ok installed"
}

pkg_available() {
    # Returns 0 if pkg is available in apt, 1 otherwise.
    apt-cache show "$1" >/dev/null 2>&1
}

apt_install() {
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "$@" >/dev/null
}

# Cache `apt-get update` to once per script run, but only when needed.
APT_UPDATED=0
apt_update_once() {
    if [[ $APT_UPDATED -eq 0 ]]; then
        log "apt update..."
        $SUDO apt-get update -qq >/dev/null
        APT_UPDATED=1
    fi
}

# --- 1. Essential apt packages -------------------------------------------

log "Checking essential packages..."
NEED_PKGS=()
for pkg in ca-certificates curl openssl git; do
    if ! pkg_installed "$pkg"; then
        NEED_PKGS+=("$pkg")
    fi
done

if (( ${#NEED_PKGS[@]} > 0 )); then
    apt_update_once
    log "Installing: ${NEED_PKGS[*]}"
    apt_install "${NEED_PKGS[@]}"
fi
ok "essentials present"

# --- 2. Docker engine -----------------------------------------------------

log "Checking docker..."
if command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1; then
    ok "docker present: $(docker --version)"
else
    # Prefer Ubuntu's docker.io — least conflict potential. We deliberately
    # avoid `curl get.docker.com | sh` because if docker.io was ever installed
    # (even partly), the docker-ce package conflicts at the file level and
    # dpkg refuses to proceed.
    apt_update_once
    log "Installing docker.io (Ubuntu's docker engine)..."
    apt_install docker.io
    log "Enabling and starting docker service..."
    $SUDO systemctl enable --now docker >/dev/null
    ok "docker installed: $(docker --version)"
fi

# Catch the rare bad state where both docker.io and docker-ce got installed.
if pkg_installed docker.io && pkg_installed docker-ce; then
    warn "Both docker.io and docker-ce are installed — that's a conflict."
    warn "Removing docker-ce to keep docker.io (Ubuntu's package)."
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get remove -y -qq docker-ce docker-ce-cli >/dev/null || true
fi

# --- 3. Docker compose v2 plugin -----------------------------------------

log "Checking docker compose v2..."
if docker compose version >/dev/null 2>&1; then
    ok "docker compose present: $(docker compose version | head -1)"
else
    apt_update_once
    # Ubuntu 24.04+ has 'docker-compose-v2'. Older Ubuntu may have
    # 'docker-compose-plugin' via Docker Inc.'s repo (if get.docker.com ran).
    if pkg_available docker-compose-v2; then
        log "Installing docker-compose-v2 (Ubuntu's compose v2 plugin)..."
        apt_install docker-compose-v2
    elif pkg_available docker-compose-plugin; then
        log "Installing docker-compose-plugin..."
        apt_install docker-compose-plugin
    else
        die "Neither docker-compose-v2 nor docker-compose-plugin is available in apt. \
Try enabling the 'universe' component: \
'$SUDO add-apt-repository -y universe && $SUDO apt-get update', then re-run this script."
    fi
    # Sanity-check the plugin is reachable
    if ! docker compose version >/dev/null 2>&1; then
        die "docker compose plugin installed but 'docker compose version' still fails."
    fi
    ok "docker compose installed: $(docker compose version | head -1)"
fi

# --- 4. Docker group membership ------------------------------------------

log "Checking docker group membership..."
CURRENT_USER="${SUDO_USER:-${USER:-$(id -un)}}"
if id -nG "$CURRENT_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    ok "$CURRENT_USER is in the docker group"
else
    log "Adding $CURRENT_USER to the docker group..."
    $SUDO usermod -aG docker "$CURRENT_USER"
    warn "Group change applied. For future sessions you can run 'docker' without sudo."
    warn "This script will use sudo for docker commands in the current shell."
    NEEDS_REGROUP=1
fi

# Helper: docker compose with sudo if needed
dc() {
    if [[ ${NEEDS_REGROUP:-0} -eq 1 ]]; then
        $SUDO docker compose "$@"
    else
        docker compose "$@"
    fi
}

# --- 5. Required directories ---------------------------------------------

log "Creating bundles/ and config/ directories..."
mkdir -p bundles config
ok "directories ready"

# --- 6. .env scaffolding --------------------------------------------------

if [[ ! -f "$EXAMPLE_FILE" ]]; then
    die "$EXAMPLE_FILE not found. Run this from the App_Mon directory."
fi
if [[ ! -f "$ENV_FILE" ]]; then
    log "Creating .env from .env.example"
    cp "$EXAMPLE_FILE" "$ENV_FILE"
fi

current_value() {
    local name="$1"
    grep -E "^${name}=" "$ENV_FILE" 2>/dev/null | head -1 | sed -E "s/^${name}=//; s/^\"//; s/\"$//" || true
}

set_value() {
    local name="$1"
    local value="$2"
    local escaped
    escaped=$(printf '%s' "$value" | sed -e 's/[\/&|]/\\&/g')
    if grep -qE "^${name}=" "$ENV_FILE"; then
        sed -i -E "s|^${name}=.*|${name}=\"${escaped}\"|" "$ENV_FILE"
    else
        printf '%s="%s"\n' "$name" "$value" >> "$ENV_FILE"
    fi
}

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

# --- 7. Auto-generate POSTGRES_PASSWORD if still the placeholder ---------

current_pgpw="$(current_value POSTGRES_PASSWORD)"
if [[ -z "$current_pgpw" || "$current_pgpw" == "change-me-please" ]]; then
    new_pgpw="$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    set_value POSTGRES_PASSWORD "$new_pgpw"
    log "Generated random POSTGRES_PASSWORD."
fi

# --- 8. Interactive SFTP config ------------------------------------------

echo ""
echo "${C_INFO}=== App_Mon SFTP configuration ===${C_OFF}"
echo "Press Enter to keep the current/default value shown in brackets."
echo ""

default_device="$(hostname)"
prompt APPMON_DEVICE_NAME       "Device name (used in upload filenames)" "$default_device"
prompt APPMON_SFTP_HOST         "SFTP server hostname or IP"             ""
prompt APPMON_SFTP_PORT         "SFTP port"                              "22"
prompt APPMON_SFTP_USER         "SFTP username"                          ""
prompt_secret APPMON_SFTP_PASSWORD "SFTP password"
prompt APPMON_SFTP_REMOTE_PATH  "Remote directory for uploads"           "/"

# Enable upload by default once the user has filled in details.
set_value APPMON_SFTP_ENABLED "true"

# --- 9. Lock down the env file -------------------------------------------

chmod 600 "$ENV_FILE"
ok "settings written to $ENV_FILE (chmod 600)"

# --- 10. Build, start, optional SFTP test --------------------------------

echo ""
log "Building containers (first build takes a few minutes)..."
dc build

log "Starting containers..."
dc up -d

log "Waiting for the collector to come up..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if dc exec -T collector python -m collector --version >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

echo ""
read -r -p "Test the SFTP connection now? [Y/n]: " do_test || do_test=""
do_test="${do_test:-Y}"
if [[ "$do_test" =~ ^[Yy]$ ]]; then
    if dc exec -T collector python -m collector upload-test; then
        ok "SFTP test passed"
    else
        warn "SFTP test failed. Re-run ./setup.sh to update credentials."
    fi
fi

echo ""
ok "Setup complete."
echo ""
# Decide which prefix the user should use, based on whether they're already
# in the docker group in this shell. Until they re-login, sudo is required.
if [[ ${NEEDS_REGROUP:-0} -eq 1 ]]; then
    DC_CMD="sudo docker compose"
else
    DC_CMD="docker compose"
fi

echo "Next steps:"
echo "  1. Plug a network cable into the box (auto-scan triggers on link-up)"
echo ""
echo "  2. Watch the collector activity:"
echo "       $DC_CMD logs -f collector"
echo ""
echo "  3. List scans collected so far:"
echo "       $DC_CMD exec collector python -m collector list"
echo ""
echo "  4. Force an upload now (bundles + ships the most recent hour):"
echo "       $DC_CMD exec collector python -m collector upload-now"
echo ""

[[ ${NEEDS_REGROUP:-0} -eq 1 ]] && {
    warn "You were added to the docker group. Log out and back in (or run"
    warn "'newgrp docker') so you can run 'docker compose' without 'sudo'."
}
