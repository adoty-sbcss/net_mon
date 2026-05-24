#!/usr/bin/env bash
# NetMon setup. Run on a fresh Ubuntu box after `git clone`.
#
# This is a thin orchestrator. Each step lives in lib/*.sh so the same
# helpers can be reused by the first-boot wizard, operator menu, and
# auto-update script. To see what any step actually does, read the
# matching lib file.
#
# Idempotent: safe to re-run any time. Each section detects what's
# already in place and only fixes what's missing.

set -euo pipefail
cd "$(dirname "$0")"
REPO_DIR="$(pwd)"

# --- load shared modules --------------------------------------------------

. "./lib/common.sh"
. "./lib/paths.sh"
. "./lib/pkg.sh"
. "./lib/docker.sh"
. "./lib/envfile.sh"
. "./lib/validate.sh"

# --- platform + paths -----------------------------------------------------

require_linux

# Create /etc/netmon, /var/lib/netmon, /var/log/netmon and migrate any
# legacy in-repo state (./.env, ./config/snmp.yaml, ./bundles, ./logs)
# into the new layout. Idempotent.
ensure_paths

# --- 1. Essential apt packages -------------------------------------------

log "Checking essential packages..."
# unattended-upgrades keeps the Ubuntu host current with security patches
# (the containers get refreshed by netmon-update / netmon-deep-refresh timers).
ensure_packages ca-certificates curl openssl git unattended-upgrades

if pkg_installed unattended-upgrades; then
    if ! systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        log "Enabling unattended-upgrades for Ubuntu security patches..."
        $SUDO systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    fi
fi
ok "essentials present"

# --- 2. Docker engine + compose + group membership -----------------------

ensure_docker_engine
ensure_docker_compose
ensure_docker_membership

# --- 3. Install netmon-wizard + first-boot profile snippet ---------------

log "Linking netmon-wizard into /usr/local/sbin..."
# Symlink, not copy: any git pull that updates bin/netmon-wizard is picked
# up automatically. The wizard discovers its lib/ relative to its own
# location, so the symlink target (in-repo) resolves the right lib/.
$SUDO ln -sf "$REPO_DIR/bin/netmon-wizard" /usr/local/sbin/netmon-wizard
ok "netmon-wizard linked (-> $REPO_DIR/bin/netmon-wizard)"

log "Installing first-boot login prompt to /etc/profile.d/..."
$SUDO install -m 644 -o root -g root "$REPO_DIR/scripts/netmon-firstboot.sh" \
    /etc/profile.d/netmon-firstboot.sh
ok "first-boot prompt installed"

# --- 4. Run the wizard ----------------------------------------------------

WIZARD_SENTINEL="${NETMON_VAR_DIR}/.wizard-done"
run_wizard=1
if [[ -f "$WIZARD_SENTINEL" ]]; then
    ok "wizard already completed on this box"
    if ! prompt_yesno "Re-run the full wizard (keeps current values as defaults)?" "N"; then
        run_wizard=0
    fi
fi

if [[ $run_wizard -eq 1 ]]; then
    /usr/local/sbin/netmon-wizard
fi

# --- 5. Build, start, optional SFTP test ---------------------------------

echo ""
log "Building containers (first build takes a few minutes)..."
dc build

log "Starting containers..."
dc up -d

log "Waiting for the collector to come up..."
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if dc exec -T collector python -m collector --version >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

echo ""
if prompt_yesno "Test the SFTP connection now?" "Y"; then
    if dc exec -T collector python -m collector upload-test; then
        ok "SFTP test passed"
    else
        warn "SFTP test failed. Re-run 'sudo netmon-wizard sftp' to update credentials."
    fi
fi

# --- 6. Optional: install nightly auto-update timer ----------------------

echo ""
echo "${C_INFO}=== Optional: nightly auto-update ===${C_OFF}"
echo "Install a systemd timer that runs 'git pull' + rebuild + restart every"
echo "night around 03:00 (with ~30min jitter). Schema migrations apply"
echo "automatically. You can uninstall any time with:"
echo "    ./scripts/install-auto-update.sh --uninstall"
echo ""

already_installed=0
if systemctl list-unit-files netmon-update.timer 2>/dev/null | grep -q netmon-update; then
    already_installed=1
fi

if [[ $already_installed -eq 1 ]]; then
    ok "auto-update timer already installed"
    do_install=0
    if prompt_yesno "Re-install (to pick up any updated paths/user)?" "N"; then
        do_install=1
    fi
else
    do_install=1
    if ! prompt_yesno "Install the nightly auto-update timer?" "Y"; then
        do_install=0
    fi
fi

if [[ $do_install -eq 1 ]]; then
    if [[ -x ./scripts/install-auto-update.sh ]]; then
        ./scripts/install-auto-update.sh
    else
        warn "scripts/install-auto-update.sh missing or not executable. Skipping."
    fi
fi

echo ""
ok "Setup complete."
echo ""
echo "Config lives at:  $NETMON_ENV_FILE"
echo "Bundles land at:  $NETMON_BUNDLES_DIR"
echo "Logs land at:     $NETMON_LOG_DIR"
echo ""
echo "Next steps:"
echo "  1. Plug a network cable into the box (auto-scan triggers on link-up)"
echo ""
echo "  2. Use the operator console for everything:"
echo "       ./netmon              # interactive menu"
echo "       ./netmon status       # one-shot status"
echo "       ./netmon logs         # tail live logs"
echo "       ./netmon scan eth0    # manual scan"
echo "       ./netmon upload-now   # force upload"
echo "       ./netmon help         # full list"
echo ""
echo "  3. Reconfigure any time:"
echo "       sudo netmon-wizard               # full re-run"
echo "       sudo netmon-wizard identity      # just district/school/device"
echo "       sudo netmon-wizard sftp          # just SFTP destination"
echo "       sudo netmon-wizard snmp          # just SNMP communities"
echo "       sudo netmon-wizard advanced      # scan mode / cadence / log level"
echo ""

[[ ${NETMON_NEEDS_REGROUP:-0} -eq 1 ]] && {
    warn "You were added to the docker group. Log out and back in (or run"
    warn "'newgrp docker') so you can run 'docker compose' without 'sudo'."
}
