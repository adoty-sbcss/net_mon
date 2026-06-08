#!/usr/bin/env bash
# install-auto-update.sh — installs the systemd timers that keep this box
# fresh: nightly auto-update (cheap, base-image refresh) + weekly deep
# refresh (heavier, no-cache rebuild for layer-cached CVEs).
#
# Run from the NetMon directory:
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
    "netmon-update"
    "netmon-deep-refresh"
    "netmon-watchdog"
    "netmon-config-backup"
    "netmon-checkin"
    "netmon-console-poll"
)

# Legacy unit names from before the App_Mon → NetMon rename. We disable
# and remove them on every install so boxes that ran the old installer
# don't keep firing the old timers alongside the new ones.
LEGACY_UNITS=(
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
    echo "Disabling and removing NetMon update timers (and any legacy appmon-* units)..."
    for unit in "${UNITS[@]}" "${LEGACY_UNITS[@]}"; do
        $SUDO systemctl disable --now "${unit}.timer" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/${unit}.service" \
                    "/etc/systemd/system/${unit}.timer"
    done
    $SUDO rm -f /etc/sudoers.d/netmon-update
    $SUDO systemctl daemon-reload
    echo "Uninstalled (timers + sudoers drop-in removed)."
    exit 0
fi

# --- always clean up the legacy units before installing ------------------

for legacy in "${LEGACY_UNITS[@]}"; do
    if [[ -f "/etc/systemd/system/${legacy}.timer" ]] \
       || [[ -f "/etc/systemd/system/${legacy}.service" ]]; then
        echo "Removing legacy systemd unit: $legacy"
        $SUDO systemctl disable --now "${legacy}.timer" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/${legacy}.service" \
                    "/etc/systemd/system/${legacy}.timer"
    fi
done

# --- install ---------------------------------------------------------------

for unit in "${UNITS[@]}"; do
    case "$unit" in
        netmon-update)         script="$REPO_DIR/scripts/auto-update.sh" ;;
        netmon-deep-refresh)   script="$REPO_DIR/scripts/weekly-deep-refresh.sh" ;;
        netmon-watchdog)       script="$REPO_DIR/scripts/netmon-watchdog.sh" ;;
        netmon-config-backup)  script="$REPO_DIR/scripts/netmon-config-backup.sh" ;;
        netmon-checkin)        script="$REPO_DIR/scripts/netmon-checkin.sh" ;;
        netmon-console-poll)   script="$REPO_DIR/scripts/netmon-console-poll.sh" ;;
        *) echo "ERROR: no script mapping for unit $unit" >&2; exit 1 ;;
    esac
    if [[ ! -x "$script" ]]; then
        echo "ERROR: $script missing or not executable" >&2
        exit 1
    fi
done

echo "Installing systemd units for NetMon update timers..."
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

# --- passwordless sudo for the unattended update path ---------------------
# The timers run auto-update.sh / db-snapshot.sh / watchdog as $TARGET_USER
# (non-interactive). Those scripts need root to write /var/lib/netmon, read
# the root-owned /etc/netmon secrets, and drive docker/systemctl. Without a
# NOPASSWD grant, sudo prompts for a password that no TTY can answer, so every
# scheduled run dies at the first sudo (this is what froze the pilot box at an
# old commit). Grant the update user passwordless sudo so the timers work.
#
# This is the standard posture for a single-purpose appliance where the admin
# account already has full control. If your security policy forbids it, remove
# this drop-in and instead run the timers' service units as User=root.
SUDOERS_FILE="/etc/sudoers.d/netmon-update"
if [[ ! -f "$SUDOERS_FILE" ]]; then
    TMP_SUDO="$(mktemp)"
    {
        echo "# Installed by netmon scripts/install-auto-update.sh."
        echo "# Lets the scheduled auto-update / snapshot / watchdog run unattended."
        echo "${TARGET_USER} ALL=(ALL) NOPASSWD:ALL"
    } > "$TMP_SUDO"
    # Validate syntax before installing — a broken sudoers file can lock you out.
    if $SUDO visudo -cf "$TMP_SUDO" >/dev/null 2>&1; then
        $SUDO install -m 440 -o root -g root "$TMP_SUDO" "$SUDOERS_FILE"
        echo "Granted passwordless sudo to $TARGET_USER ($SUDOERS_FILE) for unattended updates."
    else
        echo "WARN: generated sudoers file failed validation; NOT installing it." >&2
        echo "      Scheduled updates will fail until $TARGET_USER has passwordless sudo." >&2
    fi
    rm -f "$TMP_SUDO"
else
    echo "Sudoers drop-in already present ($SUDOERS_FILE)."
fi

echo ""
echo "Installed. Useful commands:"
echo "  systemctl list-timers 'netmon-*.timer'           # next scheduled runs"
echo "  journalctl -u netmon-update.service -n 50        # last nightly auto-update"
echo "  journalctl -u netmon-deep-refresh.service -n 50  # last weekly deep refresh"
echo "  journalctl -u netmon-watchdog.service -n 20      # last watchdog tick"
echo "  journalctl -u netmon-config-backup.service -n 20 # last config backup"
echo "  $REPO_DIR/scripts/auto-update.sh                 # run nightly now"
echo "  $REPO_DIR/scripts/netmon-watchdog.sh             # run watchdog now"
echo "  $REPO_DIR/scripts/netmon-config-backup.sh        # back up config now"
echo "  $0 --uninstall                                   # remove all timers"
echo ""

$SUDO systemctl list-timers --no-pager 'netmon-*.timer' 2>/dev/null || true
