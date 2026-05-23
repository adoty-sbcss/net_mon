#!/usr/bin/env bash
# install-auto-update.sh — installs the systemd timers that keep this box
# fresh: nightly auto-update (cheap, base-image refresh) + weekly deep
# refresh (heavier, no-cache rebuild for layer-cached CVEs).
#
# Run from the App_Mon directory:
#   ./scripts/install-auto-update.sh
#
# Or uninstall:
#   ./scripts/install-auto-update.sh --uninstall
#
# Idempotent: re-running is safe.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_USER="${SUDO_USER:-${USER}}"

UNITS=(
    "appmon-update"
    "appmon-deep-refresh"
)

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
    echo "Disabling and removing App_Mon update timers..."
    for unit in "${UNITS[@]}"; do
        $SUDO systemctl disable --now "${unit}.timer" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/${unit}.service" \
                    "/etc/systemd/system/${unit}.timer"
    done
    $SUDO systemctl daemon-reload
    echo "Uninstalled."
    exit 0
fi

# --- install ---------------------------------------------------------------

for unit in "${UNITS[@]}"; do
    script="$REPO_DIR/scripts/$(echo "$unit" | sed 's/^appmon-//').sh"
    # `appmon-update` -> `update.sh`? No — our scripts are `auto-update.sh` and
    # `weekly-deep-refresh.sh`. Map explicitly:
    case "$unit" in
        appmon-update)        script="$REPO_DIR/scripts/auto-update.sh" ;;
        appmon-deep-refresh)  script="$REPO_DIR/scripts/weekly-deep-refresh.sh" ;;
    esac
    if [[ ! -x "$script" ]]; then
        echo "ERROR: $script missing or not executable" >&2
        exit 1
    fi
done

echo "Installing systemd units for App_Mon update timers..."
echo "  user:      $TARGET_USER"
echo "  repo_dir:  $REPO_DIR"
echo "  units:     ${UNITS[*]}"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

for unit in "${UNITS[@]}"; do
    tmpl="$REPO_DIR/systemd/${unit}.service.template"
    timer="$REPO_DIR/systemd/${unit}.timer"
    if [[ ! -f "$tmpl" ]]; then
        echo "ERROR: $tmpl missing" >&2
        exit 1
    fi
    if [[ ! -f "$timer" ]]; then
        echo "ERROR: $timer missing" >&2
        exit 1
    fi

    sed -e "s|\${USER}|$TARGET_USER|g" \
        -e "s|\${REPO_DIR}|$REPO_DIR|g" \
        "$tmpl" > "$TMP"

    $SUDO install -m 644 "$TMP" "/etc/systemd/system/${unit}.service"
    $SUDO install -m 644 "$timer" "/etc/systemd/system/${unit}.timer"
done

$SUDO systemctl daemon-reload
for unit in "${UNITS[@]}"; do
    $SUDO systemctl enable --now "${unit}.timer"
done

echo ""
echo "Installed. Useful commands:"
echo "  systemctl list-timers 'appmon-*.timer'        # next scheduled runs"
echo "  systemctl status appmon-update.timer          # nightly timer state"
echo "  systemctl status appmon-deep-refresh.timer    # weekly timer state"
echo "  journalctl -u appmon-update.service -n 50     # last nightly run"
echo "  journalctl -u appmon-deep-refresh.service -n 50  # last deep refresh"
echo "  $REPO_DIR/scripts/auto-update.sh              # run nightly now"
echo "  $REPO_DIR/scripts/weekly-deep-refresh.sh      # run weekly now"
echo "  $0 --uninstall                                # remove both timers"
echo ""

$SUDO systemctl list-timers --no-pager 'appmon-*.timer' 2>/dev/null || true
