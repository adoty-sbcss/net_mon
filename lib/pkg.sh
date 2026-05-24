# lib/pkg.sh — apt helpers. Source AFTER common.sh.

[[ -n "${_NETMON_PKG_SH:-}" ]] && return 0
_NETMON_PKG_SH=1

pkg_installed() {
    dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null | grep -q "install ok installed"
}

pkg_available() {
    apt-cache show "$1" >/dev/null 2>&1
}

apt_install() {
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "$@" >/dev/null
}

# Cache `apt-get update` to once per script run, but only when needed.
_NETMON_APT_UPDATED=0
apt_update_once() {
    if [[ $_NETMON_APT_UPDATED -eq 0 ]]; then
        log "apt update..."
        $SUDO apt-get update -qq >/dev/null
        _NETMON_APT_UPDATED=1
    fi
}

# Ensure a list of packages is installed; apt-update only if at least one is missing.
ensure_packages() {
    local need=()
    for pkg in "$@"; do
        if ! pkg_installed "$pkg"; then
            need+=("$pkg")
        fi
    done
    if (( ${#need[@]} > 0 )); then
        apt_update_once
        log "Installing: ${need[*]}"
        apt_install "${need[@]}"
    fi
}
