#!/usr/bin/env bash
# cis-apply.sh — APPLY the NetMon-vetted safe subset of CIS Ubuntu hardening.
#
# Companion to the report-only scripts/cis-check.sh. This one CHANGES the system,
# but only the controls reviewed as safe for a NetMon sensor — and it is built to
# never break the collector, the VLAN feature, or field access.
#
#   sudo ./cis-apply.sh --apply     # apply the safe subset (backs up every change)
#   sudo ./cis-apply.sh --revert    # restore the most recent backup + undo
#   sudo ./cis-apply.sh --dry-run   # print what it WOULD do, change nothing
#
# DELIBERATELY APPLIED (safe):
#   - ufw: allow 22/tcp FIRST, then default-deny INBOUND + allow-ALL-OUTBOUND,
#     enable. (No egress filtering — that would kill scanning + check-in + SFTP.)
#   - unattended-upgrades: install + enable, with auto-REBOOT OFF.
#   - time sync (systemd-timesyncd), auditd, AppArmor (docker-default only),
#     core-dump restriction, libpam-pwquality (installed, not strict-enforced).
#
# DELIBERATELY NOT TOUCHED (would break NetMon / lock us out) — see docs/HARDENING.md:
#   - SSH (root login, password auth, MaxAuthTries) — left exactly as-is so field
#     access can't break during testing/deploy.
#   - Docker privileged / host-network / NET_ADMIN+NET_RAW — the collector needs them.
#   - Kernel modules (esp. 8021q for VLAN sub-interfaces), promiscuous mode, raw
#     sockets — required for capture + VLAN monitoring.
#   - Egress firewall filtering, strict reverse-path filtering (rp_filter).
#
# Idempotent; every run is logged. Keep this list in lockstep with docs/HARDENING.md.

set -uo pipefail

MODE=""
case "${1:-}" in
  --apply)   MODE=apply ;;
  --revert)  MODE=revert ;;
  --dry-run) MODE=dryrun ;;
  *) echo "usage: $0 --apply | --revert | --dry-run" >&2; exit 2 ;;
esac

if [ "$(id -u)" != "0" ]; then
  if command -v sudo >/dev/null 2>&1; then exec sudo "$0" "$@"; fi
  echo "ERROR: need root" >&2; exit 1
fi

TS="$(date +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="/var/lib/netmon/cis-backups"
BACKUP_DIR="$BACKUP_ROOT/$TS"
LATEST="$BACKUP_ROOT/latest"

log() { printf '[cis-apply] %s\n' "$*"; }
run() {
  # run a state-changing command, or just print it in dry-run.
  if [ "$MODE" = dryrun ]; then printf '  would: %s\n' "$*"; else eval "$@"; fi
}

# Back up a file before we touch it (only once per file, only if it exists).
backup_file() {
  local f="$1"
  [ "$MODE" = dryrun ] && { printf '  would back up: %s\n' "$f"; return 0; }
  mkdir -p "$BACKUP_DIR"
  if [ -e "$f" ] && [ ! -e "$BACKUP_DIR$f" ]; then
    mkdir -p "$BACKUP_DIR$(dirname "$f")"
    cp -a "$f" "$BACKUP_DIR$f"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# REVERT
# ---------------------------------------------------------------------------
do_revert() {
  if [ ! -d "$LATEST" ]; then log "no backup at $LATEST — nothing to revert"; exit 0; fi
  log "reverting from $(readlink -f "$LATEST")"
  # Restore any backed-up files.
  ( cd "$LATEST" && find . -type f 2>/dev/null | sed 's|^\.||' ) | while read -r f; do
    [ -n "$f" ] || continue
    log "restore $f"
    cp -a "$LATEST$f" "$f"
  done
  # Remove drop-ins we created (they have a NetMon marker name).
  rm -f /etc/sysctl.d/60-netmon-cis.conf \
        /etc/security/limits.d/60-netmon-cis.conf \
        /etc/apt/apt.conf.d/52netmon-no-reboot 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
  if have ufw; then log "disabling ufw"; ufw --force disable >/dev/null 2>&1 || true; fi
  log "revert done. (Installed packages — auditd, unattended-upgrades, pam_pwquality — are left in place; remove by hand if desired.)"
}

# ---------------------------------------------------------------------------
# CONTROLS (apply)
# ---------------------------------------------------------------------------

# Firewall: the ONE that can lock us out, so order matters — allow SSH FIRST.
c_firewall() {
  if ! have ufw; then
    log "ufw: installing"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y -q ufw >/dev/null 2>&1 || true"
  fi
  have ufw || { log "ufw: not available, skipping firewall"; return; }
  log "ufw: allow 22/tcp (SSH) BEFORE enabling, so we can't lock out"
  run "ufw allow 22/tcp >/dev/null 2>&1 || true"
  log "ufw: default deny INCOMING, allow OUTGOING (no egress filtering — scanning + check-in + SFTP must work)"
  run "ufw default deny incoming >/dev/null 2>&1 || true"
  run "ufw default allow outgoing >/dev/null 2>&1 || true"
  log "ufw: enable"
  run "ufw --force enable >/dev/null 2>&1 || true"
}

c_unattended() {
  if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    log "unattended-upgrades: installing"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y -q unattended-upgrades >/dev/null 2>&1 || true"
  fi
  log "unattended-upgrades: enable periodic + DISABLE auto-reboot (a sensor must not reboot itself)"
  backup_file /etc/apt/apt.conf.d/20auto-upgrades
  run "cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
EOF"
  run "cat > /etc/apt/apt.conf.d/52netmon-no-reboot <<'EOF'
// NetMon: security updates install automatically, but the box never reboots on
// its own (an unplanned reboot takes a sensor offline mid-day).
Unattended-Upgrade::Automatic-Reboot \"false\";
EOF"
}

c_timesync() {
  if have timedatectl; then
    log "time sync: enable systemd-timesyncd + set-ntp on"
    run "timedatectl set-ntp true >/dev/null 2>&1 || true"
    run "systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true"
  fi
}

c_auditd() {
  if ! dpkg -s auditd >/dev/null 2>&1; then
    log "auditd: installing"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y -q auditd >/dev/null 2>&1 || true"
  fi
  log "auditd: enable"
  run "systemctl enable --now auditd >/dev/null 2>&1 || true"
}

c_apparmor() {
  # AppArmor is on by default on Ubuntu; just ensure it's enabled. We do NOT add
  # any strict profile over the collector — it needs raw capture (tshark/nmap).
  if have aa-status; then
    log "apparmor: ensure enabled (docker-default profile only — no strict profiles added)"
    run "systemctl enable --now apparmor >/dev/null 2>&1 || true"
  else
    log "apparmor: tools not present, skipping"
  fi
}

c_coredumps() {
  log "core dumps: restrict (fs.suid_dumpable=0 + hard core 0)"
  run "cat > /etc/sysctl.d/60-netmon-cis.conf <<'EOF'
# NetMon CIS: restrict core dumps. Deliberately does NOT set rp_filter (strict
# reverse-path filtering breaks VLAN sub-interface / asymmetric monitoring) or
# disable IP features the collector relies on.
fs.suid_dumpable = 0
EOF"
  run "sysctl --system >/dev/null 2>&1 || true"
  run "cat > /etc/security/limits.d/60-netmon-cis.conf <<'EOF'
* hard core 0
EOF"
}

c_pwquality() {
  if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    log "pam_pwquality: installing (present-only; not strict-enforced, to avoid locking the admin out)"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y -q libpam-pwquality >/dev/null 2>&1 || true"
  else
    log "pam_pwquality: already installed"
  fi
}

do_apply() {
  log "applying NetMon-vetted CIS safe subset (mode=$MODE)"
  [ "$MODE" = apply ] && { mkdir -p "$BACKUP_DIR"; ln -sfn "$BACKUP_DIR" "$LATEST"; log "backups -> $BACKUP_DIR"; }
  log "NOTE: SSH (root/password/MaxAuthTries), Docker privileges, kernel modules"
  log "      (8021q etc.), promisc/raw sockets, and egress filtering are LEFT ALONE"
  log "      on purpose — see docs/HARDENING.md."
  c_firewall
  c_unattended
  c_timesync
  c_auditd
  c_apparmor
  c_coredumps
  c_pwquality
  log "done."
  [ "$MODE" = apply ] && log "revert anytime with: sudo $0 --revert"
}

case "$MODE" in
  revert) do_revert ;;
  apply|dryrun) do_apply ;;
esac
exit 0
