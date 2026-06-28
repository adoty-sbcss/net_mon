#!/usr/bin/env bash
# cis-apply.sh — APPLY the NetMon-vetted safe subset of CIS Ubuntu hardening.
#
# Companion to the report-only scripts/cis-check.sh. This one CHANGES the system,
# but only the controls reviewed as safe for a NetMon sensor — and it is built to
# never break the collector, the VLAN feature, or field access.
#
#   sudo ./cis-apply.sh --apply       # apply the safe subset (backs up every change)
#   sudo ./cis-apply.sh --revert      # undo the safe subset (does NOT touch SSH)
#   sudo ./cis-apply.sh --dry-run     # print what the safe subset WOULD do, change nothing
#   sudo ./cis-apply.sh --ssh-harden [--dry-run]   # OPT-IN key-only SSH (see below)
#   sudo ./cis-apply.sh --ssh-revert  # undo ONLY the SSH hardening (restore password login)
#
# The safe subset and the SSH hardening are INDEPENDENT — each has its own revert,
# so undoing key-only SSH never tears down the firewall (and vice versa).
#
# DELIBERATELY APPLIED (safe):
#   - ufw: allow 22/tcp FIRST, then default-deny INBOUND + allow-ALL-OUTBOUND,
#     enable. (No egress filtering — that would kill scanning + check-in + SFTP.)
#   - unattended-upgrades: install + enable, with auto-REBOOT OFF.
#   - time sync (systemd-timesyncd), auditd, AppArmor (docker-default only),
#     core-dump restriction, libpam-pwquality (installed, not strict-enforced).
#
# DELIBERATELY NOT TOUCHED by --apply (would break NetMon / lock us out) — see docs/HARDENING.md:
#   - SSH (root login, password auth, MaxAuthTries) — the SAFE SUBSET never touches
#     SSH so field access can't break. Key-only SSH is a SEPARATE, opt-in step
#     (--ssh-harden, below) so ticking the normal "CIS hardened" box can never lock
#     anyone out.
#   - Docker privileged / host-network / NET_ADMIN+NET_RAW — the collector needs them.
#   - Kernel modules (esp. 8021q for VLAN sub-interfaces), promiscuous mode, raw
#     sockets — required for capture + VLAN monitoring.
#   - Egress firewall filtering, strict reverse-path filtering (rp_filter).
#
# --ssh-harden (OPT-IN, key-only): writes a drop-in disabling password auth +
# making root key-only (PasswordAuthentication no / PermitRootLogin prohibit-password
# / KbdInteractive no / MaxAuthTries 3). It is LOCKOUT-GUARDED — it REFUSES unless a
# shell user already has a usable SSH public key — validates with `sshd -t` before
# `systemctl reload ssh` (reload, NOT restart, so the current session survives), and
# is reverted by `--ssh-revert` (removes the drop-in + reloads). NOT part of --apply.
#
# Idempotent; every run is logged. Keep this list in lockstep with docs/HARDENING.md.

set -uo pipefail

MODE=""
SSH_DRY=0
case "${1:-}" in
  --apply)      MODE=apply ;;
  --revert)     MODE=revert ;;
  --dry-run)    MODE=dryrun ;;
  --ssh-harden) MODE=sshharden; [ "${2:-}" = "--dry-run" ] && SSH_DRY=1 ;;
  --ssh-revert) MODE=sshrevert ;;
  *) echo "usage: $0 --apply | --revert | --dry-run | --ssh-harden [--dry-run] | --ssh-revert" >&2; exit 2 ;;
esac

if [ "$(id -u)" != "0" ]; then
  if command -v sudo >/dev/null 2>&1; then exec sudo "$0" "$@"; fi
  echo "ERROR: need root" >&2; exit 1
fi

TS="$(date +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="/var/lib/netmon/cis-backups"
BACKUP_DIR="$BACKUP_ROOT/$TS"
LATEST="$BACKUP_ROOT/latest"
# Opt-in SSH hardening lives in a marker-named drop-in (additive — removing it
# restores prior behavior, so revert needs no file backup). Ubuntu's stock
# sshd_config has `Include /etc/ssh/sshd_config.d/*.conf` near the top, so this
# drop-in wins over the defaults.
SSH_DROPIN="/etc/ssh/sshd_config.d/60-netmon-ssh-harden.conf"

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
# Undo the SAFE SUBSET only. Deliberately does NOT touch SSH hardening — that has
# its own --ssh-revert, so undoing the firewall/etc. and undoing key-only SSH are
# independent operations (reverting one must never silently undo the other).
do_revert() {
  if [ ! -d "$LATEST" ]; then log "no safe-subset backup at $LATEST — nothing to revert (SSH hardening, if any, is undone with --ssh-revert)"; exit 0; fi
  log "reverting safe subset from $(readlink -f "$LATEST")"
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
  log "safe-subset revert done. (Installed packages — auditd, unattended-upgrades, pam_pwquality — are left in place; remove by hand if desired.) SSH hardening is separate (--ssh-revert)."
}

# Undo ONLY the opt-in SSH hardening: remove the drop-in + reload. Restores
# password login. Leaves the safe subset untouched.
do_ssh_revert() {
  if [ ! -e "$SSH_DROPIN" ]; then log "no SSH hardening drop-in at $SSH_DROPIN — nothing to revert"; exit 0; fi
  log "removing SSH hardening drop-in ($SSH_DROPIN) + reloading ssh (restores password login)"
  rm -f "$SSH_DROPIN" 2>/dev/null || true
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
  log "SSH hardening reverted — verify with: sudo sshd -T | grep -i passwordauthentication"
}

# ---------------------------------------------------------------------------
# OPT-IN SSH HARDENING (key-only) — separate from --apply; lockout-guarded.
# ---------------------------------------------------------------------------

# Lockout guard: is key-based SSH actually possible? Returns 0 if at least one
# shell user (root or any /home user) has a non-empty authorized_keys with a real
# public key. We NEVER disable password auth without this — it's the safety net.
has_authorized_key() {
  local f
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] || continue
    if grep -qE '^[[:space:]]*(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-(ssh-ed25519|ecdsa))' "$f" 2>/dev/null; then
      log "lockout guard: usable SSH public key found in $f"
      return 0
    fi
  done
  return 1
}

do_ssh_harden() {
  log "SSH hardening (key-only) — OPT-IN, lockout-guarded, reversible"
  if ! have sshd; then log "sshd not found — skipping (is this an SSH server?)"; exit 0; fi

  # LOCKOUT GUARD — refuse to disable password auth unless a key login exists.
  if ! has_authorized_key; then
    log "REFUSING: no usable SSH public key in /root/.ssh/authorized_keys or /home/*/.ssh/authorized_keys."
    log "  Install your admin user's public key FIRST (ssh-copy-id / authorized_keys), then re-run."
    log "  (Disabling password auth now would lock you out — not doing that.)"
    exit 3
  fi

  if [ "$SSH_DRY" = 1 ]; then
    log "DRY-RUN — would write $SSH_DROPIN:"
    printf '    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    ChallengeResponseAuthentication no\n    PermitRootLogin prohibit-password\n    PermitEmptyPasswords no\n    MaxAuthTries 3\n'
    log "  would 'sshd -t' then 'systemctl reload ssh' (reload, NOT restart — current session survives)."
    log "  revert with: sudo $0 --ssh-revert"
    return 0
  fi

  mkdir -p /etc/ssh/sshd_config.d
  # Write to a temp, then validate the WHOLE sshd config with the drop-in in place
  # BEFORE committing, so a bad config never reaches a reload.
  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<'EOF'
# NetMon SSH hardening (PROV-3, opt-in). Key-only access from here.
# Revert: remove this file + `systemctl reload ssh`, or run cis-apply.sh --revert.
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 3
EOF
  install -m 0644 "$tmp" "$SSH_DROPIN"; rm -f "$tmp"

  local err; err="$(mktemp)"
  if ! sshd -t 2>"$err"; then
    log "sshd -t FAILED with the new drop-in — REMOVING it, SSH left unchanged:"
    sed 's/^/    /' "$err" 2>/dev/null || true
    rm -f "$SSH_DROPIN" "$err"
    exit 4
  fi
  rm -f "$err"
  log "sshd -t OK — reloading ssh (existing sessions stay up)"
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
  log "SSH is now KEY-ONLY: password auth disabled, root login key-only. Drop-in: $SSH_DROPIN"
  log "REVERT anytime with: sudo $0 --ssh-revert  (removes the drop-in + reloads ssh)"
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
  sshharden) do_ssh_harden ;;
  sshrevert) do_ssh_revert ;;
esac
exit 0
