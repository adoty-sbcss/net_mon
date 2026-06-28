# NetMon sensor hardening — what we harden, and what we deliberately don't

A NetMon sensor is a single-purpose appliance, but it is **not** a normal server:
it needs a privileged, host-networked container, raw packet capture, VLAN
sub-interfaces, and unrestricted outbound access to do its job. So we apply a
**reviewed subset** of the CIS Ubuntu Benchmark, not the whole thing.

- **Report:** `scripts/cis-check.sh` (read-only; never changes anything).
- **Apply:** `scripts/cis-apply.sh --apply` (the safe subset below; backs up every
  change; `--revert` undoes it). Opt-in per deploy via `NETMON_CIS_HARDEN=true`
  (the dashboard installer's "CIS hardened" checkbox, on by default).
- **Apply (SSH, opt-in):** `scripts/cis-apply.sh --ssh-harden` — key-only SSH, a
  **separate** step from `--apply` (which never touches SSH). Lockout-guarded,
  validated with `sshd -t`, reload-not-restart, reverted by `--ssh-revert` (which
  undoes ONLY SSH, not the safe subset). Off by default; enable per deploy via
  `NETMON_CIS_SSH_HARDEN=true`. See "Opt-in" below.

> **This file is the contract.** Before adding a feature that needs a host
> capability, check the "Never apply" list. If your feature needs something here
> loosened or a new exception, update this file in the same change.

## ✅ Applied (reviewed safe)

| Control | What we do | Why it's safe |
|---|---|---|
| Host firewall (ufw) | `allow 22/tcp` **first**, then default **deny inbound / allow outbound**, enable | Sensor accepts no inbound except SSH; **outbound is never filtered**, so scanning + check-in (443) + SFTP (22) + SNMP (161) keep working |
| Automatic security updates | install `unattended-upgrades`, enable, **auto-reboot OFF** | Patches land; the box never reboots itself mid-day |
| Time sync | enable `systemd-timesyncd` | Accurate scan/SNMP timestamps |
| auditd | install + enable | Logging only |
| AppArmor | ensure enabled, **docker-default profile only** | No strict profile over the collector |
| Core dumps | `fs.suid_dumpable=0` + `hard core 0` | No functional impact |
| Password quality | install `libpam-pwquality` (present, **not** strict-enforced) | Avoids locking the admin out |

## 🚫 Never applied (would break NetMon or lock us out)

| Control | Why it's excluded |
|---|---|
| **SSH** — disable root login / password auth / lower MaxAuthTries | The **safe subset (`--apply`) never touches SSH**, so ticking "CIS hardened" can't break field access. Key-only SSH is now available as a **separate, opt-in, lockout-guarded** step — see "Opt-in" below. |
| **Docker** — forbid `privileged` / `network_mode: host` / `NET_ADMIN`+`NET_RAW` | The collector **requires** all three for capture + ARP + interface work |
| **Kernel modules** — disable "unused" modules, esp. **`8021q`** | `8021q` is mandatory for VLAN sub-interface monitoring (`lib/trunk.sh`); others are needed for capture/bridging |
| **Egress firewall filtering** | Breaks active scanning and all outbound (check-in, SFTP, broker dial-out) |
| **Strict reverse-path filtering** (`rp_filter=1`) | Drops packets on VLAN sub-interfaces / asymmetric monitoring paths |
| **Promiscuous-mode / raw-socket restrictions** | Breaks `tshark`/`arp-scan` capture entirely |
| **Unattended auto-reboot** | A sensor silently rebooting takes monitoring offline |

## 🔐 Opt-in (off by default) — key-only SSH

`scripts/cis-apply.sh --ssh-harden` writes `/etc/ssh/sshd_config.d/60-netmon-ssh-harden.conf`:

| Setting | Effect |
|---|---|
| `PasswordAuthentication no` | password logins refused — keys only |
| `KbdInteractiveAuthentication no` / `ChallengeResponseAuthentication no` | closes the keyboard-interactive/PAM password path |
| `PermitRootLogin prohibit-password` | root may log in **only** with a key |
| `PermitEmptyPasswords no` | belt-and-suspenders |
| `MaxAuthTries 3` | fewer guesses per connection |

Why it's safe to offer (it can't lock you out):

- **Lockout guard** — refuses (exit 3, SSH unchanged) unless a usable SSH public
  key already exists in `/root/.ssh/authorized_keys` or `/home/*/.ssh/authorized_keys`.
- **Validated before commit** — `sshd -t` must pass with the drop-in in place; if
  not, the drop-in is removed and SSH is left exactly as it was (exit 4).
- **Reload, not restart** — `systemctl reload ssh`, so the operator's current
  session is never dropped.
- **Reversible + independent** — `--ssh-revert` removes the drop-in and reloads
  (restores password login). It undoes ONLY SSH; the safe subset has its own
  `--revert`, so neither teardown silently affects the other. The drop-in is
  additive, so revert needs no file backup.
- **Off by default** — only runs when `NETMON_CIS_SSH_HARDEN=true` (separate from
  the `NETMON_CIS_HARDEN` safe-subset flag), so the normal "CIS hardened" checkbox
  never changes SSH.

Enable it only on boxes where you reach the admin user by key (the office test
boxes, or any sensor after you've installed your key). For a locked-down box whose
only access is a password, install a key first or leave SSH hardening off.

## Scope / status

- **New installs only** for now (the installer checkbox). A fleet-wide apply path
  for already-deployed boxes is a deliberate later step (after deeper testing).
- `cis-apply.sh` is idempotent and reversible (`--revert` restores the latest
  backup under `/var/lib/netmon/cis-backups/` and removes the drop-ins it wrote;
  installed packages are left in place).
