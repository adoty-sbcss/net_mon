#!/usr/bin/env bash
# install.sh — full-auto NetMon sensor install (non-interactive).
#
# The dashboard "Deploy a sensor here" page generates a provisioning file for a
# specific district/school landing spot (dashboard URL + scoped enroll key +
# slugs + that district's SFTP creds). On a fresh Ubuntu box:
#
#     git clone <collector-repo> NetMon && cd NetMon
#     # save the file from the dashboard at config/provisioning.env
#     sudo ./install.sh
#
# It applies that config, installs Docker if missing, prints a CIS hardening
# REPORT (report-only — changes nothing, never blocks), starts the collector,
# and installs the check-in + auto-update timers. The box auto-enrolls into its
# landing spot on the first check-in. Idempotent — safe to re-run.
#
# This is the non-interactive sibling of setup.sh (the interactive wizard); both
# reuse the same lib/*.sh so config is written identically.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"
. ./lib/common.sh
. ./lib/paths.sh
. ./lib/pkg.sh
. ./lib/docker.sh
. ./lib/envfile.sh
. ./lib/provisioning.sh
. ./lib/trunk.sh

# --- 0. Privilege ---------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    err "Run as root, or install sudo first."
    exit 1
fi

# --- 1. Locate the deploy-page provisioning file --------------------------
PROV="$(provisioning_file_path 2>/dev/null || true)"
if [[ -z "${PROV:-}" ]]; then
    err "No provisioning file found."
    err "Save the file from the dashboard 'Deploy a sensor here' page at:"
    err "    $REPO_DIR/config/provisioning.env   (or /etc/netmon/provisioning.env)"
    err "then re-run:  sudo ./install.sh"
    exit 1
fi
log "Provisioning from: $PROV"

# --- 2. Canonical paths + env file ----------------------------------------
ensure_paths
env_ensure_file

# --- 3. Apply config NON-INTERACTIVELY ------------------------------------
# Copy every NETMON_* assignment from the provisioning file straight into the
# live env file (the wizard uses these as prompt defaults; we apply as-is).
applied=0
while IFS= read -r line; do
    [[ "$line" =~ ^NETMON_[A-Z0-9_]+= ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}"
    val="${val#\"}" # strip one pair of surrounding quotes if present
    set_value "$key" "$val"
    applied=$((applied + 1))
done < "$PROV"
ok "applied $applied setting(s) to $NETMON_ENV_FILE"

# --- 4. Docker engine + compose -------------------------------------------
ensure_docker_engine
ensure_docker_compose
ensure_docker_membership

# --- 4.5 VLAN trunk sub-interfaces (if the deploy page provisioned them) ---
# When the installer carries NETMON_TRUNK_VLANS, set up the 802.1Q sub-interfaces
# now (netplan, routes-off) so the collector scans those VLANs. Headless + guarded
# (auto-reverts if the box's default route is lost); the parent NIC is never touched.
trunk_vlans="$(current_value NETMON_TRUNK_VLANS 2>/dev/null || true)"
if [[ -n "${trunk_vlans:-}" ]]; then
    trunk_parent="$(current_value NETMON_TRUNK_PARENT 2>/dev/null || true)"
    [[ -z "${trunk_parent:-}" ]] && trunk_parent="$(_trunk_default_parent)"
    trunk_statics="$(current_value NETMON_TRUNK_STATICS 2>/dev/null || true)"
    log "Configuring VLAN trunk monitoring: VLANs ${trunk_vlans} on ${trunk_parent}"
    if apply_vlan_netplan_headless "$trunk_parent" "$trunk_vlans" "${trunk_statics:-}"; then
        ok "VLAN sub-interfaces configured"
    else
        warn "VLAN setup had issues (see above) — the box stays on its existing network; re-run 'sudo ./netmon trunk' to retry."
    fi
fi

# --- 5. CIS hardening: report, then APPLY the safe subset if enabled -------
echo ""
echo "==================== CIS hardening ===================="
if [[ -x ./scripts/cis-check.sh ]]; then
    ./scripts/cis-check.sh || true   # always show the report
fi
cis_harden="$(current_value NETMON_CIS_HARDEN 2>/dev/null || true)"
if [[ "${cis_harden:-}" == "true" || "${cis_harden:-}" == "1" ]]; then
    if [[ -x ./scripts/cis-apply.sh ]]; then
        echo ""
        log "Applying the CIS safe subset (SSH untouched; reversible; see docs/HARDENING.md)..."
        ./scripts/cis-apply.sh --apply || warn "CIS apply reported issues (non-fatal)"
    else
        warn "NETMON_CIS_HARDEN is set but scripts/cis-apply.sh is missing."
    fi
else
    echo "(report-only — tick 'CIS hardened' on the deploy page to auto-apply the safe subset)"
fi
echo "=============================================================="
echo ""

# --- 6. Pull (or build) + start the collector -----------------------------
# REL-3: pull the prebuilt image from GHCR (seconds). Fall back to a local build
# only if the registry is unreachable (e.g. a school that blocks ghcr.io) — the
# build is reliable again now that the Ookla install was removed.
log "Fetching the collector image..."
if dc pull collector; then
    ok "pulled prebuilt collector image"
else
    log "Image pull failed (registry unreachable?); building locally (a few minutes)..."
    dc build
fi
log "Starting containers..."
# --force-recreate so a RE-RUN after a config change actually reloads the env
# file. docker compose only injects netmon.env at container-create time, so a
# plain `up -d` on an existing container keeps the old env (this is how a box
# can end up with valid SFTP creds but uploads still disabled).
dc up -d --force-recreate
log "Waiting for the collector to come up..."
for _ in $(seq 1 15); do
    if dc exec -T collector python -m collector --version >/dev/null 2>&1; then
        ok "collector is running"
        break
    fi
    sleep 2
done

# --- 7. Timers: check-in (auto-enroll + control plane) + auto-update ------
if [[ -x ./scripts/install-auto-update.sh ]]; then
    log "Installing check-in + auto-update timers..."
    ./scripts/install-auto-update.sh || warn "timer install reported a problem (non-fatal)"
else
    warn "scripts/install-auto-update.sh missing — check-in timer NOT installed; the box won't auto-enroll."
fi

# --- 8. Quiet the interactive first-boot prompt ---------------------------
${SUDO:-} touch "${NETMON_VAR_DIR}/.wizard-done" 2>/dev/null || true

echo ""
ok "Install complete."
echo "  Landing spot : $(current_value NETMON_DISTRICT_SLUG)/$(current_value NETMON_SCHOOL_SLUG)/$(current_value NETMON_DEVICE_SLUG)"
echo "  Dashboard    : $(current_value NETMON_DASHBOARD_URL)"
echo "  The box auto-enrolls on its next check-in (within a few minutes)."
echo "  Status: ./netmon status     Logs: ./netmon logs"
