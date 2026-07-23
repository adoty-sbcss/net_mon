# lib/common.sh — shared helpers for NetMon shell scripts.
#
# Source this from any setup/menu/wizard script:
#     . "$(dirname "$0")/lib/common.sh"
#
# Provides:
#   - C_OK / C_WARN / C_ERR / C_INFO / C_HEAD / C_DIM / C_OFF  (color codes)
#   - log / ok / warn / err / die                              (stderr-friendly output)
#   - SUDO                                                     (empty if root, else "sudo")
#   - require_linux                                            (fatal if not on Linux)

# Guard against double-sourcing.
[[ -n "${_NETMON_COMMON_SH:-}" ]] && return 0
_NETMON_COMMON_SH=1

# --- colors ---------------------------------------------------------------

if [[ -t 1 ]]; then
    C_OK=$'\033[1;32m'
    C_WARN=$'\033[1;33m'
    C_ERR=$'\033[1;31m'
    C_INFO=$'\033[1;36m'
    C_HEAD=$'\033[1;36m'
    C_DIM=$'\033[2m'
    C_OFF=$'\033[0m'
else
    C_OK= C_WARN= C_ERR= C_INFO= C_HEAD= C_DIM= C_OFF=
fi

# --- log primitives -------------------------------------------------------

log()  { printf '%s==>%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s  !!%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
err()  { printf '%s ERR%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; }
die()  { printf '%sFAIL:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

# --- sudo wrapper ---------------------------------------------------------
# Use as: $SUDO command ...
# Empty when running as root; "sudo" otherwise. Acquires + refreshes credentials
# in the background so long scripts don't stall mid-run asking for a password.

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
        ( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
        _NETMON_SUDO_KEEPER=$!
        trap '[[ -n "${_NETMON_SUDO_KEEPER:-}" ]] && kill "$_NETMON_SUDO_KEEPER" 2>/dev/null || true' EXIT
    fi
fi

# --- platform guard -------------------------------------------------------

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        die "This script must be run on Linux (Ubuntu). For development, use docker compose directly."
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        die "apt-get not found. This script only supports Debian/Ubuntu-family distros."
    fi
}
