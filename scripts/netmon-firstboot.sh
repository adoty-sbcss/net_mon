# /etc/profile.d/netmon-firstboot.sh
#
# Installed by setup.sh. On an interactive login (console or SSH), if the
# wizard hasn't been run yet, offer to launch it. Silent for non-interactive
# sessions (cron, scp, sftp), root logins, and users without docker access.

# Guard against double-sourcing.
[ -n "${_NETMON_FIRSTBOOT_LOADED:-}" ] && return 0
_NETMON_FIRSTBOOT_LOADED=1

# Only proceed on interactive shells with a tty on stdin AND stdout.
case $- in *i*) ;; *) return 0 ;; esac
[ -t 0 ] || return 0
[ -t 1 ] || return 0

# Wizard sentinel — created by netmon-wizard after a successful full run.
_NETMON_SENTINEL="/var/lib/netmon/.wizard-done"
[ -f "$_NETMON_SENTINEL" ] && return 0

# Only prompt if netmon-wizard is actually installed.
command -v netmon-wizard >/dev/null 2>&1 || return 0

# Skip when ssh is being used for scp/sftp/forced-command (no normal shell).
[ -n "${SSH_ORIGINAL_COMMAND:-}" ] && return 0

printf '\n'
printf '\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[1;36m║   NetMon — first-boot wizard has not been run on this box.   ║\033[0m\n'
printf '\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n'
printf '\n'
printf '  Run it now to configure SFTP destination, identity, and SNMP:\n'
printf '      sudo netmon-wizard\n'
printf '\n'
printf '  Or run later — this prompt will keep appearing until the wizard\n'
printf '  completes successfully.\n'
printf '\n'

# Don't auto-execute. We tell the operator the command and let them decide.
# Auto-running fights with provisioning automation, breaks scp pipelines,
# and surprises users in unexpected ways.
unset _NETMON_SENTINEL
