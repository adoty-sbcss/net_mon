# NetMon — quick start

Plug an Ubuntu box into a network, collect everything about it, ship the data to your SFTP server every hour. Upload the ZIPs to Claude for analysis.

> **New here?** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the whole-system picture — sensor → SFTP → dashboard ingest/analysis, the provisioning flow, and the remote-console broker — as diagrams.

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

### Minimal-touch enrollment (recommended for a fleet)

The dashboard URL and the shared enrollment **bootstrap key** are identical on every box, so you can bake them in and let the technician type *only the site identity*. Before running `setup.sh`, drop a provisioning file in the cloned repo:

```bash
cp config/provisioning.env.example config/provisioning.env
# paste the URL + key the dashboard shows under
#   Settings → SFTP ingestion → Sensor auto-enrollment
$EDITOR config/provisioning.env
```

On first run the wizard pre-fills the dashboard URL and bootstrap key from this file, so the tech just presses **Enter** to accept them. The box then **self-enrolls** on its first check-in (presenting the key + its identity), is issued its own per-sensor token, and appears under **Sensors** in the dashboard — no token copying. The dashboard's enrollment page generates this exact snippet for you.

> **Security:** the bootstrap key is a shared secret and this repo is public, so `config/provisioning.env` is git-ignored — never commit it. Distribute it out-of-band (config-management, a golden image, or your own secure channel), and rotate it from the dashboard if it leaks. See [lib/provisioning.sh](lib/provisioning.sh).

### The first-boot wizard

`setup.sh` invokes `netmon-wizard` which walks you through:

**Essentials**:
- **Identity** (always asked) — district, school, and device/location label (e.g. "Library IDF"). These tag every scan and organize uploads on the SFTP server into `<district>/<school>/<device>/` folders.
- **SFTP destination** — host, port, user, password (silent), remote path. **Skipped automatically when it's already provisioned** (host + user + password from `config/provisioning.env`); only prompted on a box without provisioned SFTP creds.

**Dashboard enrollment**:
- **Dashboard URL** and **bootstrap key** — **skipped automatically when provisioned** (URL + key from `config/provisioning.env`); the box auto-enrolls on its first check-in. Only prompted on a box without provisioned enrollment values (leave the URL blank there to run an SFTP-only box with no dashboard).

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
sudo netmon-wizard dashboard     # just dashboard URL + enrollment bootstrap key
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

## 6. How monitoring works (continuous, multi-interface)

NetMon continuously monitors **every active network interface** — the wired uplink, an associated Wi-Fi NIC, and (later) VLAN sub-interfaces. There's no "field" vs "monitor" mode anymore; the box always runs continuously.

Each network is re-scanned on the **rescan interval** (default hourly), so there's fresh data to bundle and upload every hour. A newly plugged-in network is scanned within ~30s of link-up; a stable network is re-scanned once the interval elapses.

```bash
sudo netmon-wizard cadence    # rescan interval / capture seconds / poll tick
```

`NETMON_RESCAN_INTERVAL=3600` (hourly) is the knob that controls how often each network produces a fresh scan. Lower it for near-continuous monitoring while troubleshooting; raise it to reduce load.

### Primary uplink vs secondary connections

The interface that owns the **default route** is the box's **primary uplink** — it's how the box reaches the SFTP server. It's auto-detected (no config). Everything else is a **secondary monitored** connection. See them all:

```bash
./netmon interfaces
```

```
== Monitored interfaces ==
  enp0s31f6      10.6.0.12/22         PRIMARY uplink
  wlan0          192.168.50.40/24     secondary (monitored)

  Default gateway: 10.6.0.1 via enp0s31f6
```

Each scan is tagged primary/secondary in its bundle so the analysis knows which network is the box's own vs. one it's watching.

### Adding a Wi-Fi network as a second connection

NetMon doesn't manage the Wi-Fi association itself — you connect `wlan0` at the OS level and NetMon auto-detects it and starts scanning it like any wired interface:

```bash
# Connect the Wi-Fi NIC to a network (persists across reboots)
sudo nmcli device wifi connect "SSID-NAME" password "wifi-password"

# Confirm it picked up an IP
ip -br addr show wlan0

# NetMon sees it on the next poll tick — verify:
./netmon interfaces
```

That's it — no NetMon config needed. The new network shows up as a secondary monitored connection and gets scanned + bundled + uploaded on the same cadence as the wired uplink.

### Monitoring many VLANs over one trunk port

Plug the sensor into a switch **trunk** port (802.1Q) and monitor every VLAN on it from one box. NetMon adds a VLAN sub-interface per VLAN; the poller then scans each like any NIC and tags the data with its VLAN.

```bash
sudo netmon-wizard trunk      # or ./netmon trunk, or Configure ▶ → VLAN trunk setup
```

The wizard:
- **detects** the VLANs present on the trunk (sniffs 802.1Q tags for a few seconds), proposes them, and lets you add/remove;
- gives each VLAN an IP by **DHCP** (or a **static** you provide for VLANs without DHCP) — but with **no routes**, so a monitored VLAN can never hijack the box's real uplink;
- writes a persistent netplan file (`/etc/netplan/60-netmon-vlans.yaml`) and applies it.

The switch port must already be a trunk that allows those VLANs — the sensor can't reconfigure the switch. Each VLAN's scans are tagged with `vlan_id` + `parent_interface` in the bundle. Drop noisy VLANs from auto-scanning with `NETMON_EXCLUDE_VLANS=900,999` (a manual `./netmon scan eth0.900` still works). Confirm the sub-interfaces with `./netmon interfaces`.

**Field notes:** trunk monitoring needs **systemd-networkd** (the Ubuntu Server default) — on a NetworkManager box the wizard warns and the VLANs may not attach. The apply uses `netplan try` (auto-reverts in 120s if it can't reach the network), so a bad VLAN change can't strand the box. If **detection sees no VLANs on a known-good trunk**, the NIC may be stripping 802.1Q tags in hardware before capture — turn that off with `sudo ethtool -K <parent> rxvlan off` and re-run, or just enter the VLANs manually (detection is only a convenience; the sub-interfaces work regardless).

To disable hourly uploads without removing the SFTP creds, set `NETMON_SFTP_ENABLED=false` in `/etc/netmon/netmon.env` and `./netmon restart`.

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
- `inventory.csv` / `inventory.json` — the box's **persistent** device inventory across all scans (per MAC: first/last seen, times seen, last known IP / hostname / vendor / device-class / location). Lets the analysis tell brand-new devices from long-known ones.
- `scans/scan_<id>/` — one folder per scan with `summary.md`, `topology.json`, `devices.csv`, `metrics.json`, `timeline.json`, `findings.json`, `service_discovery.json` (mDNS/SSDP), and `raw/` tool outputs

Drop the ZIP into a Claude chat, paste the prompt from inside, and Claude tells you what's going on with the network — loops, broadcast storms, rogue DHCP servers, duplicate IPs, unusual devices.

---

## Notes

- Only run scans on networks you're authorized to assess. NetMon does light active probing (ARP scan, ping sweep), not port scans, but it still puts packets on the wire.
- SFTP password lives in `.env` (chmod 600). No keys, no MFA — v1 demo simplicity.
- All collected data stays on this box (and the configured SFTP server). Nothing reaches Claude until you manually upload a ZIP.
- Built from free, open-source tools: `lldpd`, `arp-scan`, `nmap`, `tshark`, `paramiko`, `postgres`.
