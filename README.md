# App_Mon — quick start

Plug an Ubuntu box into a network, collect everything about it, upload the result to Claude for analysis. That's the whole tool.

---

## 1. One-time setup on a fresh Ubuntu box

Copy and paste this whole block into a terminal. It installs Docker, downloads App_Mon, and starts it.

```bash
# Install Docker (Ubuntu 22.04 / 24.04)
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin git
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

# Get App_Mon
git clone https://github.com/adoty-sbcss/net_mon.git App_Mon
cd App_Mon

# Configure (just sets a password — accept defaults for the rest)
cp .env.example .env
sed -i "s/change-me-please/$(openssl rand -hex 16)/" .env

# Build and start
mkdir -p bundles config
docker compose build
docker compose up -d
```

That's it. App_Mon is running.

> **Updating later?** From inside the `App_Mon` folder, run `git pull && docker compose build && docker compose up -d`.

---

## 2. Daily use — collect data from a network

### Step 1. Plug the Ubuntu box into the network you want to look at

When the network cable is connected and the box gets an IP, App_Mon **automatically starts a scan**. It runs for about 1 minute.

### Step 2. Wait about 90 seconds, then see what you got

```bash
cd ~/App_Mon
docker compose exec collector python -m collector list
```

You'll see a table like:

```
  id  started                    iface       cidr                  gw                reason
   1  2026-05-22 13:42:11+0000   eth0        10.20.30.5/24         10.20.30.1        link_up
```

The number in the first column is your scan ID.

### Step 3. Export the scan as a ZIP

Replace `1` with your scan ID:

```bash
docker compose exec collector python -m collector bundle 1
```

The ZIP lands in `./bundles/` on the Ubuntu box. Filename looks like:

```
bundles/network-scan-myhostname-20260522-134211.zip
```

### Step 4. Get the ZIP off the box and upload it to Claude

From your laptop, copy it down:

```bash
scp user@ubuntu-box:~/App_Mon/bundles/network-scan-*.zip .
```

Open [claude.ai](https://claude.ai) → new chat → drag the ZIP in → paste the prompt that's inside the ZIP's `README.md` → send.

Claude reads the bundle and tells you what's going on with the network — loops, broadcast storms, rogue DHCP servers, duplicate IPs, unusual devices, etc.

---

## 3. Manual scan (if you don't want to wait for auto-detect)

Find your network interface name (usually `eth0`, `enp0s3`, `eno1`, etc.):

```bash
ip -br addr
```

Then trigger a scan on it:

```bash
docker compose exec collector python -m collector scan eth0
```

Wait ~90 seconds, then bundle it as in step 3 above.

---

## 4. Common commands

| What you want | Command |
|---|---|
| See live activity | `docker compose logs -f collector` |
| List all scans | `docker compose exec collector python -m collector list` |
| Export a specific scan | `docker compose exec collector python -m collector bundle <id>` |
| Stop everything | `docker compose down` |
| Start it again later | `docker compose up -d` |
| Apply a new config | `docker compose down && docker compose up -d` |
| Wipe all data and start fresh | `docker compose down -v` |

---

## 5. Two settings you might want to change

Edit `.env` to change behavior. The two that matter most:

```bash
# field   = scan once per network, then idle (good for site visits)
# monitor = keep scanning every time something changes
APPMON_MODE=field

# How long each scan listens for traffic (seconds). Longer = catches more.
APPMON_CAPTURE_SECONDS=60
```

After editing `.env`, restart:

```bash
docker compose down && docker compose up -d
```

---

## 6. Troubleshooting

**"docker: permission denied" after install**
Log out and back in (or run `newgrp docker`), then try again.

**No scans appearing**
Check the logs:
```bash
docker compose logs --tail 50 collector
```
Make sure your network cable is plugged in and the box has an IP (`ip -br addr` should show one).

**"interface not found" when running a manual scan**
You used the wrong interface name. Run `ip -br addr` and use a name from that list (not `eth0` if your box names it `enp3s0`).

**Bundle is empty or tiny**
The scan probably didn't capture much. Make sure the network cable is plugged in on the *correct* interface, and that the box actually got an IP. Try increasing `APPMON_CAPTURE_SECONDS` in `.env` to 120 or 180.

**Want to start completely over**
```bash
docker compose down -v   # WARNING: deletes all collected scans
docker compose up -d
```

---

## What's in the ZIP you upload to Claude

You don't really need to read these — Claude does. But just so you know:

- `README.md` — the prompt to paste into Claude
- `summary.md` — a human-readable overview of the scan
- `findings.json`, `topology.json`, `metrics.json`, `timeline.json` — structured data
- `devices.csv` — flat list of every device found
- `raw/` — the underlying tool outputs (LLDP neighbors, ARP table, DHCP messages, STP events, etc.)

---

## Notes

- Only run scans on networks you're authorized to assess. App_Mon does light active probing (ARP scan, ping sweep), not port scans, but it still puts packets on the wire.
- All data stays on your Ubuntu box until you manually upload a ZIP to Claude.
- Built from free, open-source tools: `lldpd`, `arp-scan`, `nmap`, `tshark`, `postgres`.
