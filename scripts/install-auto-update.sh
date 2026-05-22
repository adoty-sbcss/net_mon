#!/usr/bin/env bash
# install-auto-update.sh — installs the systemd timer that runs auto-update.sh
# nightly. Run from the App_Mon directory:
#
#   ./scripts/install-auto-update.sh
#
# The companion uninstaller is install-auto-update.sh --uninstall.
# Idempotent: re-running is safe.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_USER="${SUDO_USER:-${USER}}"

SERVICE_DEST="/etc/systemd/system/appmon-update.service"
TIMER_DEST="/etc/systemd/system/appmon-update.timer"

SUDO=""
if [[ ${EUID} -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: need root or sudo" >&2
        exit 1
    fi
    SUDO="sudo"
fi

# --- uninstall path --------------------------------------------------------

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "Disabling and removing appmon-update.timer..."
    $SUDO systemctl disable --now appmon-update.timer 2>/dev/null || true
    $SUDO rm -f "$SERVICE_DEST" "$TIMER_DEST"
    $SUDO systemctl daemon-reload
    echo "Uninstalled."
    exit 0
fi

# --- install ---------------------------------------------------------------

if [[ ! -x "$REPO_DIR/scripts/auto-update.sh" ]]; then
    echo "ERROR: $REPO_DIR/scripts/auto-update.sh missing or not executable" >&2
    exit 1
fi

echo "Installing systemd units for nightly auto-update..."
echo "  user:      $TARGET_USER"
echo "  repo_dir:  $REPO_DIR"

# Render the service file from template.
SERVICE_TEMPLATE="$REPO_DIR/systemd/appmon-update.service.template"
if [[ ! -f "$SERVICE_TEMPLATE" ]]; then
    echo "ERROR: $SERVICE_TEMPLATE missing" >&2
    exit 1
fi

# Use envsubst-style substitution but with sed so we don't need envsubst installed.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
sed -e "s|\${USER}|$TARGET_USER|g" \
    -e "s|\${REPO_DIR}|$REPO_DIR|g" \
    "$SERVICE_TEMPLATE" > "$TMP"

$SUDO install -m 644 "$TMP" "$SERVICE_DEST"
$SUDO install -m 644 "$REPO_DIR/systemd/appmon-update.timer" "$TIMER_DEST"

$SUDO systemctl daemon-reload
$SUDO systemctl enable --now appmon-update.timer

echo ""
echo "Installed. Useful commands:"
echo "  systemctl status appmon-update.timer       # timer state"
echo "  systemctl list-timers appmon-update.timer  # next scheduled run"
echo "  journalctl -u appmon-update.service -n 50  # last update output"
echo "  $REPO_DIR/scripts/auto-update.sh           # run now manually"
echo "  $0 --uninstall                             # remove timer"
echo ""

# Show next scheduled run if available.
$SUDO systemctl list-timers --no-pager appmon-update.timer 2>/dev/null || true
