#!/usr/bin/env bash
# cis-check.sh — NetMon sensor host hardening gate (REPORT-ONLY starter set).
#
# A pragmatic subset of the CIS Ubuntu 22.04 Benchmark focused on the controls
# that actually matter for a headless, single-purpose sensor box sitting on a
# school network. REPORT-ONLY by design: it checks, prints PASS/FAIL/WARN, and
# ALWAYS exits 0 — it never changes the system and never blocks. The dashboard
# provisioning installer runs this before enrolling so the tech can see (and
# choose to fix) gaps; a later pass may add an opt-in `--apply`.
#
#   sudo ./cis-check.sh            # human-readable report
#   sudo ./cis-check.sh --json     # machine-readable summary (one JSON object)
#
# STATUS: starter set, pending vetting (roadmap item 11). Coordinate the final
# control list with the security review. Each control is independent + additive.

set -uo pipefail

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

PASS=0; FAIL=0; WARN=0
RESULTS=()   # "id|status|title|detail"

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" = "0" ]; }

# record <id> <status PASS|FAIL|WARN> <title> <detail>
record() {
  local id="$1" st="$2" title="$3" detail="${4:-}"
  RESULTS+=("$id|$st|$title|$detail")
  case "$st" in
    PASS) PASS=$((PASS+1));;
    FAIL) FAIL=$((FAIL+1));;
    WARN) WARN=$((WARN+1));;
  esac
}

# sshd effective config value (prefers `sshd -T`, falls back to grepping config)
sshd_val() {
  local key="$1"
  if is_root && have sshd; then
    sshd -T 2>/dev/null | awk -v k="$(echo "$key" | tr 'A-Z' 'a-z')" 'tolower($1)==k{print $2; found=1} END{if(!found) exit 1}' && return 0
  fi
  grep -RhiE "^\s*${key}\s+" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
    | awk '{print $2}' | tail -1
}

# ---- controls ---------------------------------------------------------------

c_ssh_root() {
  local v; v="$(sshd_val PermitRootLogin)"
  if [ "$v" = "no" ] || [ "$v" = "prohibit-password" ]; then
    record 1.ssh-root PASS "SSH root login disabled" "PermitRootLogin=$v"
  elif [ -z "$v" ]; then
    record 1.ssh-root WARN "SSH root login" "could not determine (run as root)"
  else
    record 1.ssh-root FAIL "SSH root login disabled" "PermitRootLogin=$v"
  fi
}

c_ssh_passwordauth() {
  local v; v="$(sshd_val PasswordAuthentication)"
  if [ "$v" = "no" ]; then
    record 2.ssh-passauth PASS "SSH password auth disabled (keys only)" ""
  elif [ -z "$v" ]; then
    record 2.ssh-passauth WARN "SSH password auth" "could not determine"
  else
    record 2.ssh-passauth WARN "SSH password auth disabled (keys only)" "PasswordAuthentication=$v — key-only recommended"
  fi
}

c_ssh_maxauth() {
  local v; v="$(sshd_val MaxAuthTries)"
  if [ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null; then
    record 3.ssh-maxauth PASS "SSH MaxAuthTries <= 4" "MaxAuthTries=$v"
  else
    record 3.ssh-maxauth WARN "SSH MaxAuthTries <= 4" "MaxAuthTries=${v:-default(6)}"
  fi
}

c_firewall() {
  if have ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
    record 4.firewall PASS "Host firewall active (ufw)" ""
  elif have nft && nft list ruleset 2>/dev/null | grep -q "chain input"; then
    record 4.firewall PASS "Host firewall active (nftables)" ""
  else
    record 4.firewall FAIL "Host firewall active" "ufw inactive / no nftables input chain"
  fi
}

c_autoupdates() {
  if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed" \
     && grep -qsr "Unattended-Upgrade.*1\|APT::Periodic::Unattended-Upgrade.*1" /etc/apt/apt.conf.d/ 2>/dev/null; then
    record 5.autoupdate PASS "Automatic security updates enabled" "unattended-upgrades"
  elif dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
    record 5.autoupdate WARN "Automatic security updates enabled" "installed but periodic flag not confirmed"
  else
    record 5.autoupdate FAIL "Automatic security updates enabled" "unattended-upgrades not installed"
  fi
}

c_empty_passwords() {
  if is_root; then
    if awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | grep -q .; then
      record 6.empty-pw FAIL "No accounts with empty passwords" "found empty-password account(s)"
    else
      record 6.empty-pw PASS "No accounts with empty passwords" ""
    fi
  else
    record 6.empty-pw WARN "No accounts with empty passwords" "need root to read /etc/shadow"
  fi
}

c_timesync() {
  if timedatectl show 2>/dev/null | grep -q "NTPSynchronized=yes" \
     || systemctl is-active --quiet systemd-timesyncd 2>/dev/null \
     || systemctl is-active --quiet chrony 2>/dev/null; then
    record 7.timesync PASS "Time synchronization enabled" ""
  else
    record 7.timesync WARN "Time synchronization enabled" "no active timesync detected"
  fi
}

c_apparmor() {
  if have aa-status && aa-status --enabled 2>/dev/null; then
    record 8.apparmor PASS "AppArmor enabled" ""
  elif have aa-status; then
    record 8.apparmor WARN "AppArmor enabled" "installed but not enabled"
  else
    record 8.apparmor FAIL "AppArmor enabled" "apparmor not installed"
  fi
}

c_auditd() {
  if systemctl is-active --quiet auditd 2>/dev/null; then
    record 9.auditd PASS "Audit daemon running (auditd)" ""
  else
    record 9.auditd WARN "Audit daemon running (auditd)" "auditd not active (optional but recommended)"
  fi
}

c_core_dumps() {
  if grep -qsrE "hard\s+core\s+0" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null \
     || sysctl fs.suid_dumpable 2>/dev/null | grep -q "= 0"; then
    record 10.coredump PASS "Core dumps restricted" ""
  else
    record 10.coredump WARN "Core dumps restricted" "no hard core limit / suid_dumpable!=0"
  fi
}

c_password_quality() {
  if dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
    record 11.pwquality PASS "Password quality enforced (pam_pwquality)" ""
  else
    record 11.pwquality WARN "Password quality enforced (pam_pwquality)" "libpam-pwquality not installed"
  fi
}

c_docker_present() {
  # NetMon runs in Docker; the gate confirms the runtime is present + the daemon
  # isn't exposing a TCP socket (a classic misconfig).
  if have docker; then
    if grep -qsrE -- "-H\s+tcp://0\.0\.0\.0" /lib/systemd/system/docker.service /etc/docker/daemon.json 2>/dev/null; then
      record 12.docker FAIL "Docker daemon not exposed on TCP" "docker listening on tcp://0.0.0.0 — lock to local socket"
    else
      record 12.docker PASS "Docker present, no exposed TCP socket" ""
    fi
  else
    record 12.docker WARN "Docker present" "docker not found (installer will add it)"
  fi
}

run_all() {
  c_ssh_root; c_ssh_passwordauth; c_ssh_maxauth; c_firewall; c_autoupdates
  c_empty_passwords; c_timesync; c_apparmor; c_auditd; c_core_dumps
  c_password_quality; c_docker_present
}

run_all

if [ "$JSON" = "1" ]; then
  printf '{"pass":%d,"fail":%d,"warn":%d,"controls":[' "$PASS" "$FAIL" "$WARN"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id st title detail <<< "$r"
    [ $first -eq 1 ] || printf ','
    first=0
    # escape double quotes in detail
    detail=${detail//\"/\\\"}
    printf '{"id":"%s","status":"%s","title":"%s","detail":"%s"}' "$id" "$st" "$title" "$detail"
  done
  printf ']}\n'
else
  echo "NetMon sensor hardening report (report-only — nothing changed)"
  echo "================================================================"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id st title detail <<< "$r"
    printf '  [%-4s] %-44s %s\n' "$st" "$title" "${detail:+— $detail}"
  done
  echo "----------------------------------------------------------------"
  printf '  PASS=%d  FAIL=%d  WARN=%d\n' "$PASS" "$FAIL" "$WARN"
  if [ "$FAIL" -gt 0 ]; then
    echo "  Note: FAILs are advisory in this report-only gate. Review before enrolling."
  fi
fi

# Report-only: ALWAYS succeed so the installer flow is never blocked by the gate.
exit 0
