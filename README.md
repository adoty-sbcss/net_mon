# NetMon — quick start

Plug an Ubuntu box into a network, collect everything about it, ship the data to your SFTP server every hour. Upload the ZIPs to Claude for analysis.

---

## Where things live

After `./setup.sh` runs, the canonical paths on the box are:

| Path | Contents |
|---|---|
| `/etc/netmon/netmon.env` | All configuration (SFTP creds, SNMP, identity). `chmod 600`. |
| `/etc/netmon/snmp.yaml` | Optional per-device SNMP overrides. |
| `/var/lib/netmon/bundles/` | Hourly ZIPs awaiting upload + recent uploads. |
| `/var/log/netmon/` | `collector.log` + `audit.log`, rotated nightly. |
| *this repo* | Code only — no state. Safe to `rm -rf` and re-clone. |

Boxes provisioned before this layout existed get **auto-migrated** on the next `./setup.sh` or nightly auto-update. The old in-repo `.env`, `bundles/`, `logs/`, and `config/snmp.yaml` are moved into place atomically. See [lib/paths.sh](lib/paths.sh).

---

## 1. One-time setup on a fresh Ubuntu box

Copy-paste this. `setup.sh` does all the heavy lifting — installs Docker + the Compose plugin, resolves any package conflicts, adds you to the docker group, creates `/etc/netmon` + `/var/lib/netmon`, installs the `netmon-wizard` command, then launches the wizard for your inputs.

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/adoty-sbcss/net_mon.git NetMon
cd NetMon
./setup.sh
```

That's it. `setup.sh` is **safe to re-run** any time — it skips steps that are already done, so it's also how you reinstall things.

### The first-boot wizard

`setup.sh` invokes `netmon-wizard` which walks you through:

**Essentials** (always asked):
- **Identity** — district, school, and device/location label (e.g. "Library IDF"). These tag every scan and organize uploads on the SFTP server into `<district>/<school>/<device>/` folders.
- **SFTP destination** — host, port, user, password (silent), remote path.

**Then** the wizard asks "Set up advanced options now?" — say yes only if you want to override defaults for:
- SNMP communities (if you have read strings for switches/routers)
- Scan mode (`field` vs `monitor`)
- Capture cadence / log level

After the wizard, `setup.sh` builds the containers, starts them, and offers to test the SFTP connection.

### Re-running the wizard later

```bash
sudo netmon-wizard               # full re-run (current values shown as defaults)
sudo netmon-wizard identity      # just district / school / device
sudo netmon-wizard sftp          # just SFTP destination
sudo netmon-wizard snmp          # just SNMP communities
sudo netmon-wizard advanced      # mode / cadence / log level
```

You can also reach all of those from `./netmon` → **Configure** submenu.

### First-boot login hint

A `/etc/profile.d/` snippet posts a reminder on the first interactive login that the wizard hasn't been run yet. The reminder goes away once the wizard completes successfully (sentinel at `/var/lib/netmon/.wizard-done`).

> **Updating later?** `./netmon update` — or wait for the nightly timer (~03:00).

---

## 2. What happens automatically

| Trigger | What it does |
|---|---|
| Plug in a network cable | Detects new IP within 30s, runs a ~1-minute scan |
| Top of every hour | Bundles all scans from the past hour into one ZIP, uploads to your SFTP server |

Upload filename format: `<deviceName>_YYYY_MM_DD_HH.zip` (hour is the just-completed hour in local time). If no scans happened in the hour, no file is uploaded.

---

## 3. Don't want to wait an hour? Force an upload now

```bash
cd ~/NetMon
docker compose exec collector python -m collector upload-now
```

This bundles every scan from the most recent completed hour and uploads it immediately. Useful right after deployment to confirm the pipeline works.

---

## 4. Manual scan (if you don't want to wait for auto-detect)

Find your network interface name:

```bash
ip -br addr
```

Then trigger a scan on it:

```bash
docker compose exec collector python -m collector scan eth0
```

Wait ~90 seconds, then either wait for the hourly upload or run `upload-now`.

---

## 5. Common commands — the `./netmon` console

Run with no args for the interactive menu, or with a subcommand for one-shot use.

The menu is **main + 3 submenus**:

```
NetMon — Operations
  1) Status overview            5) Manual scan
  2) Tail live logs             6) Force upload now
  3) Audit log                  7) Test SFTP connection
  4) Recent scans               8) Restart containers

  c) Configure ▶   s) System ▶   d) Diagnostics ▶   q) Quit
```

- **Configure ▶** — Identity / SFTP / SNMP / scan mode / cadence / log level / show config / re-run full wizard. (All delegate to `netmon-wizard`.)
- **System ▶** — Bundle history / update timer schedule / run update now / version info / reboot.
- **Diagnostics ▶** — Ping / DNS lookup / collector self-test (from inside the collector container).

Frequently-used one-shots:

```bash
./netmon status         # container/identity/scan/upload/disk overview
./netmon logs           # tail collector logs
./netmon audit          # high-signal event log
./netmon scan eth0      # manual scan
./netmon upload-now     # force-build + ship the current bundle
./netmon upload-test    # SFTP connection check
./netmon wizard         # alias for sudo netmon-wizard
./netmon sftp           # alias for sudo netmon-wizard sftp
./netmon version        # git SHA + image + wizard status
./netmon help           # full list
```

Underneath it's still `docker compose ...` — see `netmon` for the exact commands if you want to call them directly.

---

## 6. Two settings you might want to change

The two that matter most are scan mode and capture window. Both are reached from `./netmon` → **Configure ▶** → option 4 (mode) and option 5 (cadence). Or one-shot:

```bash
sudo netmon-wizard mode       # field (one-shot per network) vs monitor (continuous)
sudo netmon-wizard cadence    # capture seconds / poll interval / cooldown
```

After changing, the menu reminds you to restart (`./netmon restart`) to apply.

To disable hourly uploads without removing the SFTP creds, edit `/etc/netmon/netmon.env` and set `NETMON_SFTP_ENABLED=false` (or rerun `sudo netmon-wizard sftp` and pick a fresh path — the wizard always re-enables on save).

**Prefer to hand-edit anyway?** `sudo nano /etc/netmon/netmon.env`, then `./netmon restart`.

---

## 7. Recovery & self-healing

NetMon runs three background timers to keep itself current and durable:

| Timer | Cadence | What it does |
|---|---|---|
| `netmon-update` | nightly ~03:00 | `git pull` + rebuild + `up -d`. **Pre-update**: `pg_dump` snapshot + tag current image as `:previous`. **Post-update**: 2-min healthcheck → auto-rollback if it fails. |
| `netmon-watchdog` | every 15 min | Prunes bundles + logs >7 days; emergency cleanup if disk >85%; restarts collector if no upload in 6h; restarts postgres if unreachable >5min. |
| `netmon-config-backup` | nightly ~02:30 | Uploads `/etc/netmon/netmon.env` + `snmp.yaml` as a small ZIP to `<sftp>/_config/<district>/<school>/<device>/config_YYYY-MM-DD.zip`. |

Check them with:
```bash
systemctl list-timers 'netmon-*.timer'
journalctl -u netmon-watchdog.service -n 20
journalctl -u netmon-update.service -n 50
```

### Recovery scenarios

| Symptom | What to do |
|---|---|
| **Nightly auto-update broke the collector** | Auto-rollback should have already fired. Verify with `journalctl -u netmon-update.service -n 50`. To force a manual rollback: `./netmon rollback`. |
| **Collector container is in a weird state but data is fine** | `./netmon quick-rebuild` — wipes the image, rebuilds from current source, keeps DB + config. |
| **Box is misconfigured beyond repair** | `./netmon factory-reset` — wipes DB + config + logs. Re-run the wizard to start over. If you have a config backup on SFTP, `sudo netmon-config-restore` restores it after the wizard. |
| **Walked up to a factory-reset box** | 1) `./setup.sh` (installs deps + runs the wizard). 2) `sudo netmon-config-restore --list` (see backups). 3) `sudo netmon-config-restore` (pulls the most recent). |
| **DB snapshots filling disk** | Watchdog prunes >7 days. Override with `NETMON_RETENTION_DAYS=N` env var on the watchdog service. |

All three recovery levels are also in the operator menu: `./netmon` → **System ▶** → options 6 (rollback) / 7 (quick rebuild) / 8 (factory reset) / 9 (restore from SFTP backup).

---

## 8. Troubleshooting

**"docker: permission denied" after install**
`setup.sh` added you to the docker group, but the current shell hasn't picked it up yet. Log out and back in (or run `newgrp docker`), then try again. While you're in the current shell, you can also just prefix commands with `sudo`.

**Install fails partway through and apt-get complains about conflicts**
Re-run `./setup.sh` — it's idempotent and will detect what's already installed, skip those steps, and resolve common conflicts (e.g. removing a stray `docker-ce` if `docker.io` is also present).

**`upload-test` says "connection failed"**
Check the SFTP server is reachable from this box: `nc -zv <sftp-host> 22`. If that works, your credentials or remote path are wrong — re-run `./setup.sh`.

**No scans appearing**
```bash
docker compose logs --tail 50 collector
```
Make sure your network cable is plugged in and the box has an IP (`ip -br addr` should show one).

**"interface not found" when running a manual scan**
Use `ip -br addr` to find the right interface name on this box (it might be `enp3s0`, not `eth0`).

**Nothing uploaded at the top of the hour**
The uploader skips empty hours. If you went a full hour with no link-up events and didn't run a manual scan, no file gets uploaded — that's intentional. Run a manual `scan` or `upload-now` to verify.

**Want to start completely over**
```bash
docker compose down -v                              # WARNING: deletes all collected scans
sudo rm -rf /etc/netmon /var/lib/netmon /var/log/netmon   # also wipes all config
./setup.sh
```

---

## What's in each ZIP

Each hourly ZIP contains:

- `README.md` — the prompt to paste into Claude
- `HOURLY_SUMMARY.md` — table of scans in this hour
- `scans/scan_<id>/` — one folder per scan with `summary.md`, `topology.json`, `devices.csv`, `metrics.json`, `timeline.json`, `findings.json`, and `raw/` tool outputs

Drop the ZIP into a Claude chat, paste the prompt from inside, and Claude tells you what's going on with the network — loops, broadcast storms, rogue DHCP servers, duplicate IPs, unusual devices.

---

## Notes

- Only run scans on networks you're authorized to assess. NetMon does light active probing (ARP scan, ping sweep), not port scans, but it still puts packets on the wire.
- SFTP password lives in `.env` (chmod 600). No keys, no MFA — v1 demo simplicity.
- All collected data stays on this box (and the configured SFTP server). Nothing reaches Claude until you manually upload a ZIP.
- Built from free, open-source tools: `lldpd`, `arp-scan`, `nmap`, `tshark`, `paramiko`, `postgres`.
