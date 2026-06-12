# NetMon sensor hardening — what we harden, and what we deliberately don't

A NetMon sensor is a single-purpose appliance, but it is **not** a normal server:
it needs a privileged, host-networked container, raw packet capture, VLAN
sub-interfaces, and unrestricted outbound access to do its job. So we apply a
**reviewed subset** of the CIS Ubuntu Benchmark, not the whole thing.

- **Report:** `scripts/cis-check.sh` (read-only; never changes anything).
- **Apply:** `scripts/cis-apply.sh --apply` (the safe subset below; backs up every
  change; `--revert` undoes it). Opt-in per deploy via `NETMON_CIS_HARDEN=true`
  (the dashboard installer's "CIS hardened" checkbox, on by default).

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
| **SSH** — disable root login / password auth / lower MaxAuthTries | Left **completely untouched** for now: field access to fix boxes during testing/deploy. (Tighten to key-only root + no password auth once the deploy push is done — temporary exception.) |
| **Docker** — forbid `privileged` / `network_mode: host` / `NET_ADMIN`+`NET_RAW` | The collector **requires** all three for capture + ARP + interface work |
| **Kernel modules** — disable "unused" modules, esp. **`8021q`** | `8021q` is mandatory for VLAN sub-interface monitoring (`lib/trunk.sh`); others are needed for capture/bridging |
| **Egress firewall filtering** | Breaks active scanning and all outbound (check-in, SFTP, broker dial-out) |
| **Strict reverse-path filtering** (`rp_filter=1`) | Drops packets on VLAN sub-interfaces / asymmetric monitoring paths |
| **Promiscuous-mode / raw-socket restrictions** | Breaks `tshark`/`arp-scan` capture entirely |
| **Unattended auto-reboot** | A sensor silently rebooting takes monitoring offline |

## Scope / status

- **New installs only** for now (the installer checkbox). A fleet-wide apply path
  for already-deployed boxes is a deliberate later step (after deeper testing).
- `cis-apply.sh` is idempotent and reversible (`--revert` restores the latest
  backup under `/var/lib/netmon/cis-backups/` and removes the drop-ins it wrote;
  installed packages are left in place).
