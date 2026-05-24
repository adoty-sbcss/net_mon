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

# --- load shared modules --------------------------------------------------

. "./lib/common.sh"
. "./lib/paths.sh"
. "./lib/pkg.sh"
. "./lib/docker.sh"
. "./lib/envfile.sh"
. "./lib/validate.sh"
. "./lib/sftp.sh"
. "./lib/snmp.sh"

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

# --- 3. Seed netmon.env from .env.example on first run -------------------

seed_env_from_example "./.env.example"

# --- 4. Auto-generate POSTGRES_PASSWORD if still the placeholder ---------

current_pgpw="$(current_value POSTGRES_PASSWORD)"
if [[ -z "$current_pgpw" || "$current_pgpw" == "change-me-please" ]]; then
    new_pgpw="$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    set_value POSTGRES_PASSWORD "$new_pgpw"
    log "Generated random POSTGRES_PASSWORD."
fi

# --- 5. Interactive SFTP + SNMP config -----------------------------------

prompt_sftp_config "$(hostname)"
prompt_snmp_config

ok "settings written to $NETMON_ENV_FILE (chmod 600)"

# --- 6. Build, start, optional SFTP test ---------------------------------

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
        warn "SFTP test failed. Re-run ./setup.sh to update credentials."
    fi
fi

# --- 7. Optional: install nightly auto-update timer ---------------------

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
    do_install=1
    if ! prompt_yesno "Re-install (to pick up any updated paths/user)?" "N"; then
        do_install=0
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

[[ ${NETMON_NEEDS_REGROUP:-0} -eq 1 ]] && {
    warn "You were added to the docker group. Log out and back in (or run"
    warn "'newgrp docker') so you can run 'docker compose' without 'sudo'."
}
