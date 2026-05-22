# App_Mon — quick start

Plug an Ubuntu box into a network, collect everything about it, ship the data to your SFTP server every hour. Upload the ZIPs to Claude for analysis.

---

## 1. One-time setup on a fresh Ubuntu box

Copy and paste this whole block into a terminal. It installs Docker, downloads App_Mon, runs the interactive setup, and starts everything.

```bash
# Install Docker + Compose plugin + git (works on every Ubuntu version)
sudo apt-get update
sudo apt-get install -y git openssl ca-certificates curl
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Quick sanity check — both lines should print versions, not errors
docker --version
docker compose version

# Get App_Mon
git clone https://github.com/adoty-sbcss/net_mon.git App_Mon
cd App_Mon

# Make directories the containers need
mkdir -p bundles config

# Interactive setup — asks for SFTP URL, user, password
./setup.sh
```

`setup.sh` asks you:

- **Device name** — used in upload filenames. Defaults to the box's hostname.
- **SFTP server hostname or IP**
- **SFTP port** (default `22`)
- **SFTP username**
- **SFTP password** (typed silently)
- **Remote directory** (default `/`)

At the end it offers to start the containers and test the SFTP connection. Say yes.

> **Updating later?** `cd ~/App_Mon && git pull && docker compose build && docker compose up -d`

> **Changing settings later?** Just re-run `./setup.sh` — it keeps your current values and shows them in brackets so you can press Enter to keep them.

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
cd ~/App_Mon
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

| What you want | Command |
|---|---|
| Test SFTP connection | `docker compose exec collector python -m collector upload-test` |
| Force upload right now | `docker compose exec collector python -m collector upload-now` |
| See live activity | `docker compose logs -f collector` |
| List all scans | `docker compose exec collector python -m collector list` |
| Export a single scan locally | `docker compose exec collector python -m collector bundle <id>` |
| Restart containers | `docker compose restart` |
| Stop everything | `docker compose down` |
| Start it again later | `docker compose up -d` |
| Apply a new `.env` | `docker compose down && docker compose up -d` |
| Reconfigure settings | `./setup.sh` |
| Wipe all data and start fresh | `docker compose down -v` |

---

## 6. Two settings you might want to change

Edit `.env` to change behavior. The two that matter most:

```bash
# field   = scan once per network, then idle (good for site visits)
# monitor = keep scanning every time something changes
APPMON_MODE=field

# How long each scan listens for traffic (seconds). Longer = catches more.
APPMON_CAPTURE_SECONDS=60
```

After editing `.env`, restart: `docker compose down && docker compose up -d`.

To disable hourly uploads without removing the config, set `APPMON_SFTP_ENABLED=false`.

---

## 7. Troubleshooting

**"docker: permission denied" after install**
Log out and back in (or run `newgrp docker`), then try again.

**`unknown shorthand flag: 'd' in -d` when setup.sh tries to start containers**
The Docker Compose v2 plugin isn't installed — `docker compose` doesn't exist on this box. Fix it:
```bash
sudo apt-get install -y docker-compose-v2
# or, if that package can't be found:
curl -fsSL https://get.docker.com | sudo sh
```
Then continue: `cd ~/App_Mon && docker compose up -d && docker compose exec collector python -m collector upload-test`

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
docker compose down -v   # WARNING: deletes all collected scans
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

- Only run scans on networks you're authorized to assess. App_Mon does light active probing (ARP scan, ping sweep), not port scans, but it still puts packets on the wire.
- SFTP password lives in `.env` (chmod 600). No keys, no MFA — v1 demo simplicity.
- All collected data stays on this box (and the configured SFTP server). Nothing reaches Claude until you manually upload a ZIP.
- Built from free, open-source tools: `lldpd`, `arp-scan`, `nmap`, `tshark`, `paramiko`, `postgres`.
