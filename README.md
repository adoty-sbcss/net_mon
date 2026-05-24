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

Copy-paste this. `setup.sh` does all the heavy lifting — installs Docker, installs the Compose plugin, resolves any package conflicts, adds you to the docker group, creates `/etc/netmon` + `/var/lib/netmon`, builds and starts the containers, then asks for SFTP details.

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/adoty-sbcss/net_mon.git NetMon
cd NetMon
./setup.sh
```

That's it. `setup.sh` is **safe to re-run** any time — it skips steps that are already done, so it's also how you change settings later.

`setup.sh` asks you:

- **Device name** — used in upload filenames. Defaults to the box's hostname.
- **SFTP server hostname or IP**
- **SFTP port** (default `22`)
- **SFTP username**
- **SFTP password** (typed silently)
- **Remote directory** (default `/`)
- **SNMP polling** — optional; if enabled, asks for community strings.

After the SFTP prompts, it builds the containers, starts them, and offers to test the SFTP connection. Say yes when prompted.

> **Updating later?** `cd ~/NetMon && git pull && docker compose build && docker compose up -d`
>
> Or just run `./netmon update` — the nightly timer does the same thing automatically at ~03:00.

> **Changing settings later?** Re-run `./setup.sh` — it keeps your current values and shows them in brackets so you can press Enter to keep them. The expanded operator menu (Phase 2) will offer per-setting submenus too.

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

## 5. Common commands

The fastest path is the **`./netmon`** console — run it with no args for an interactive menu, or with a subcommand for one-shot use.

```bash
./netmon                # interactive menu with the top 14 operations
./netmon status         # container/scan/upload/disk overview
./netmon logs           # tail collector logs
./netmon audit          # high-signal event log
./netmon scan eth0      # manual scan
./netmon upload-now     # force-build + ship the current bundle
./netmon upload-test    # SFTP connection check
./netmon bundles        # local files + upload state
./netmon timers         # update timer schedule + last run
./netmon update         # run auto-update.sh manually
./netmon selftest       # collector self-checks
./netmon help           # full list
```

Underneath it's still `docker compose ...` — see `netmon` for the exact commands if you want to call them directly.

---

## 6. Two settings you might want to change

Edit `/etc/netmon/netmon.env` (needs `sudo`) to change behavior. The two that matter most:

```bash
# field   = scan once per network, then idle (good for site visits)
# monitor = keep scanning every time something changes
NETMON_MODE=field

# How long each scan listens for traffic (seconds). Longer = catches more.
NETMON_CAPTURE_SECONDS=60
```

After editing, restart: `./netmon restart` (or `sudo docker compose down && sudo docker compose up -d`).

To disable hourly uploads without removing the config, set `NETMON_SFTP_ENABLED=false`.

**Prefer not to hand-edit?** Re-run `./setup.sh` and press Enter past every prompt you don't want to change — it'll edit `/etc/netmon/netmon.env` for you and restart the containers.

---

## 7. Troubleshooting

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
