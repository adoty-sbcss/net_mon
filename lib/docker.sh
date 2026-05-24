# lib/docker.sh — docker + docker compose installation, group membership,
# and a `dc` wrapper that picks sudo automatically.
#
# Source AFTER common.sh and pkg.sh.

[[ -n "${_NETMON_DOCKER_SH:-}" ]] && return 0
_NETMON_DOCKER_SH=1

# Set by ensure_docker_membership if the current user was just added to docker
# and hasn't re-logged-in. `dc` honors this and prepends sudo.
NETMON_NEEDS_REGROUP=0

ensure_docker_engine() {
    log "Checking docker..."
    if command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1; then
        ok "docker present: $(docker --version)"
        return 0
    fi
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

    # Catch the rare bad state where both docker.io and docker-ce got installed.
    if pkg_installed docker.io && pkg_installed docker-ce; then
        warn "Both docker.io and docker-ce are installed — that's a conflict."
        warn "Removing docker-ce to keep docker.io (Ubuntu's package)."
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get remove -y -qq docker-ce docker-ce-cli >/dev/null || true
    fi
}

ensure_docker_compose() {
    log "Checking docker compose v2..."
    if docker compose version >/dev/null 2>&1; then
        ok "docker compose present: $(docker compose version | head -1)"
        return 0
    fi
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
    if ! docker compose version >/dev/null 2>&1; then
        die "docker compose plugin installed but 'docker compose version' still fails."
    fi
    ok "docker compose installed: $(docker compose version | head -1)"
}

ensure_docker_membership() {
    log "Checking docker group membership..."
    local user="${SUDO_USER:-${USER:-$(id -un)}}"
    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        ok "$user is in the docker group"
        NETMON_NEEDS_REGROUP=0
        return 0
    fi
    log "Adding $user to the docker group..."
    $SUDO usermod -aG docker "$user"
    warn "Group change applied. For future sessions you can run 'docker' without sudo."
    warn "This script will use sudo for docker commands in the current shell."
    NETMON_NEEDS_REGROUP=1
}

# docker compose wrapper. Use as: dc up -d   /   dc exec collector ...
dc() {
    if [[ ${NETMON_NEEDS_REGROUP:-0} -eq 1 ]]; then
        $SUDO docker compose "$@"
    else
        docker compose "$@"
    fi
}
