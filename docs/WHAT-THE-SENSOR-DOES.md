# What the sensor does on your network

Read this before you put a NetMon sensor on a network you are responsible for. It
lists what the box sends, where it connects, what it stores, what it uploads, and
what the dashboard it is enrolled to can make it do. Every statement here is
checked against the code in this repository; the file named in each section is
where to look.

The short version:

- The sensor **actively probes** the networks it is plugged into. It does not port
  scan, and it never stores packet payloads.
- It makes **outbound connections only**. NetMon opens no listening network port.
- The dashboard it is enrolled to is a **full control plane**: it can push
  configuration, queue commands, update the code, and — for a dashboard
  superadmin — open a root shell on the box. **Trust in a sensor is trust in
  whoever operates its dashboard.**
- It **updates itself unattended** every night from this repository unless you pin
  or hold it.

## 1. Traffic the sensor originates on your LAN

On by default, on every monitored interface (the wired uplink, an associated
Wi-Fi NIC, and any VLAN sub-interface you configure):

| What | Detail | Code | Turn off with |
|---|---|---|---|
| Passive capture | `tshark` in promiscuous mode for 60 s per scan, plus a light pass every 15 min. Only STP, CDP, LLDP, DHCP, ARP, broadcast and multicast frames are parsed. Parsed fields are kept; **no pcap and no payload is stored or uploaded.** | `discovery/tshark.py` | `NETMON_CAPTURE_SECONDS`, `NETMON_CAPTURE_INTERVAL` |
| LLDP / CDP transmit | `lldpd` advertises the sensor to the switch (hostname, port, OS description, management address). CDP and similar vendor protocols are sent only once a neighbor speaking them is heard. | `collector/entrypoint.sh` | no setting |
| ARP sweep | `arp-scan --localnet` on each scan. | `discovery/arp.py` | no setting |
| Ping sweep | `nmap -sn -PE -PR` — ICMP echo, ARP and reverse-DNS lookups. **No port scan.** | `discovery/nmap.py` | no setting |
| DHCP probe | One DHCPDISCOVER per full scan from the interface's own MAC. It never sends a REQUEST, so no lease is taken. Visible in DHCP and NAC logs. | `discovery/dhcp_probe.py` | `NETMON_DHCP_PROBE_ENABLED` |
| mDNS / SSDP | Service-discovery queries to `224.0.0.251:5353` and `239.255.255.250:1900`. | `discovery/mdns_ssdp.py` | `NETMON_MDNS_ENABLED` |
| IGMP | Passive listen, plus one join/leave of a random `239.255.x.y` group as a positive control. | `discovery/igmp.py` | `NETMON_IGMP_ENABLED` |
| Reachability | `ping` and a 10-hop `traceroute` to the gateway and discovered network devices (up to 256). | `discovery/reachability.py` | `NETMON_REACHABILITY_ENABLED` |
| Reverse DNS | `dig -x` for devices with no hostname (up to 512). | `discovery/rdns.py` | `NETMON_RDNS_ENABLED` |
| Wi-Fi survey | If the box has a radio: an active scan every 15 min listing visible SSIDs/BSSIDs. It does not associate. | `scripts/netmon-wifi-survey.sh` | `NETMON_WIFI_SURVEY_ENABLED` |

**SNMP** is armed by default but does nothing until a read community is
configured (locally or pushed from the dashboard). Once one is:

- It polls SNMP v2c on UDP/161 against the default gateway, switch management
  addresses learned from LLDP, and any discovered host whose vendor looks like
  network equipment. It reads system description/name/location/contact, interface
  tables, the ARP cache, the bridge forwarding (MAC) tables, spanning-tree state,
  and hardware inventory including serial numbers (`discovery/snmp.py`).
- The **topology crawl** then follows LLDP/CDP neighbors from switch to switch.
  It is bounded (5 hops, 600 devices, a 60 s time budget on a standard install,
  once a week by default) and defaults
  to the path toward the gateway, but it is **not confined to the sensor's own
  subnet or site**: it will query any management address a neighbor table
  reveals, wherever the community string is accepted
  (`discovery/snmp_topology.py`). If one community is valid district-wide, a
  sensor at one school can walk the district. Limit it with
  `NETMON_SNMP_TOPOLOGY_ENABLED`, `NETMON_SNMP_TOPOLOGY_MAX_DEPTH`,
  `NETMON_SNMP_TOPOLOGY_MAX_NODES`, `NETMON_SNMP_EXCLUDE`, or a per-site community.
- `NETMON_SNMP_ENABLED=false` disables all of it.

Off by default; each needs credentials or targets that only the dashboard
operator (or you, locally) can supply:

| Feature | What it does when enabled | Code |
|---|---|---|
| Windows DHCP server intelligence | Connects to the DHCP servers you list over WinRM (5985/5986), falling back to MS-RPC (135 + dynamic port), with a domain account you provide. Reads scopes, utilization, leases, reservations, options and failover. **The WinRM TLS certificate is not validated.** Use a read-only account (the built-in "DHCP Users" group is sufficient). | `discovery/dhcp_server.py`, `discovery/dhcp_rpc.py` |
| Switch configuration backup | SSH to the switches you list, with credentials you provide, and runs `show running-config` / `show startup-config`. Secrets are redacted on the box before storage. | `discovery/device_config.py` |
| Wi-Fi client-experience test | Joins the SSIDs you list (open, PSK or 802.1X) on a dedicated radio, measures DHCP, DNS, captive portal, throughput and client isolation, then leaves. If you turn on auto-accept for a profile it will submit that captive portal's accept form. **802.1X joins do not validate the RADIUS server certificate.** Runs as root. | `scripts/netmon-wifi-experience.sh`, `lib/wifi.sh` |
| VLAN trunk monitoring | Creates one VLAN sub-interface per VLAN you choose, with no routes. | `lib/trunk.sh` |
| iperf3 | Throughput tests to an iperf server you name. | `iperf.py` |
| Web performance | Timed `curl` fetches of URLs you list. | `webperf.py` |
| Watch list | Pings up to 200 addresses you mark as core devices at every check-in. | `watch.py` |

## 2. Outbound connections off your LAN

The sensor needs outbound access to these. Nothing else is contacted by default.

| Destination | Why | Cadence |
|---|---|---|
| Your NetMon dashboard (HTTPS) | Enrollment, check-in, command results, measurement results. Authenticated with a per-sensor bearer token. | Check-in every 3 min; console poll every 30 s |
| Azure Blob Storage (HTTPS) | The hourly bundle is uploaded to a short-lived, write-only URL the dashboard issues for that one file. | Hourly |
| The dashboard's console broker (WebSocket) | Only while a dashboard operator has a remote console session open. | On demand |
| `github.com` | Nightly code update from this repository. | 03:00 nightly, plus a weekly refresh |
| `ghcr.io` | The prebuilt collector image. | With each update |
| Docker Hub, Debian mirrors, PyPI, `wireshark.org` | Base images and packages when the image is built locally — the weekly refresh, and the fallback when the prebuilt image cannot be pulled. | Weekly |
| Ubuntu package mirrors | OS packages at install; unattended security updates afterwards. | Ongoing |
| `1.1.1.1`, `8.8.8.8` (ICMP) | Internet latency and loss. A 5-second voice-quality stream marked DSCP EF also goes to the gateway and `1.1.1.1`. | Every check-in |
| `1.1.1.1`, `8.8.8.8`, `9.9.9.9` (DNS) | DNS health: a few public names and one deliberately non-existent name. | Every scan |
| `1.1.1.1`, `1.0.0.1`, `www.cloudflare.com` (HTTPS) | Learns the site's public IP address and reports it to the dashboard, so a WAN failover shows up as an address change. The dashboard uses that address to look up the site's externally visible exposure in a third-party index (Shodan InternetDB). | Every 15 min |
| `speed.cloudflare.com` (HTTPS) | Download/upload speed test. | Every 6 h |
| `1.1.1.1`, `8.8.8.8` (traceroute, ICMP and TCP/443) | WAN path trace when check-in fails or recovers, and a daily baseline. | On event; daily |

An intrusion-detection system will see the 3-minute cadence as beaconing; it is
expected. The latency, voice, speed-test, DNS and WAN-path probes each have a
switch (`NETMON_LATENCY_ENABLED`, `NETMON_VOICE_ENABLED`,
`NETMON_SPEEDTEST_ENABLED`, `NETMON_DNS_ENABLED`, `NETMON_WAN_PATH_ENABLED`). The
public-IP report has no switch today.

## 3. Inbound

NetMon opens **no listening TCP or UDP port**. Postgres is bound to `127.0.0.1`
only. The remote console is an outbound connection relayed to a local Unix
socket. The host's own SSH daemon is untouched by default; the optional CIS hardening
step firewalls everything inbound except SSH, and its separate opt-in key-only
step adds an `sshd` configuration drop-in.

## 4. What the dashboard can make a sensor do

An enrolled sensor polls its dashboard and acts on what it is given. That is how
configuration, credentials and commands reach a box that accepts no inbound
connections — and it means **the dashboard operator has administrative control
of the sensor.**

- **Push configuration.** Most settings in sections 1 and 2, including SNMP
  communities, DHCP-server and switch credentials, Wi-Fi profiles, probe targets,
  scan cadence, and the update channel. The dashboard rewrites the settings it
  manages whenever its configuration for the sensor changes, so a local edit to
  `/etc/netmon/netmon.env` for a managed setting is not durable — change it in
  the dashboard. A few switches are local-only and stay as you set them: mDNS,
  reachability, reverse DNS, DNS health and WAN path.
- **Queue commands.** Run a scan, upload now, run a speed or iperf test, collect
  logs, a fixed list of read-only diagnostics, flush the ARP cache, test a switch
  SSH login, back up switch configs, and update the sensor's code.
- **Queue host actions.** Restart or rebuild the containers, reboot the box, roll
  back to the previous version, apply VLAN sub-interfaces, join or leave a Wi-Fi
  network, and apply or revert the CIS hardening subset
  (`scripts/host-action.sh`).
- **Open a remote console.** The default is a restricted console limited to a
  fixed list of diagnostic commands. The dashboard can also request a **full
  shell, which is an interactive root shell on the host**
  (see [HARDENING.md](HARDENING.md)).

What limits this, and where the limit is enforced:

- *On the sensor:* every pushed value is validated (types, bounds, characters);
  commands are a fixed allow-list, not free-form — the iperf and speed-test
  commands take a target host, port and duration from the dashboard, passed as
  arguments and never through a shell; a full-shell session is bound
  to a one-time nonce and killed after at most 61 minutes.
- *On the dashboard:* who may do any of the above — role checks, the one-time
  code required before a full shell, session recording, the kill switch. The
  sensor cannot verify these. It carries out a request that arrives with its
  valid token.

So: a compromise of the dashboard, or of an account with sufficient rights on
it, is a compromise of every sensor enrolled to it. Ask your dashboard operator
how those controls are configured and who holds those rights.

A sensor with no dashboard URL configured has no control plane at all: it scans
and bundles locally, uploads nothing, and skips the check-in probes (latency,
voice, speed test, public-IP report, WAN path). It still makes the DNS-health
queries to public resolvers on each scan, and the update and refresh timers
still reach GitHub, the image registries and package mirrors.

## 5. Privileges on the box

- The collector container runs **privileged, on the host network**, with
  `NET_ADMIN`, `NET_RAW` and `SYS_PTRACE`. Packet capture, ARP scanning and VLAN
  sub-interfaces require host networking and raw sockets. Treat the container as
  equivalent to root on the host.
- The installer grants the installing user **passwordless sudo for all commands**
  (`/etc/sudoers.d/netmon-update`) so the scheduled update, watchdog and host
  actions can run unattended. `setup.sh` asks whether to install the scheduled
  jobs (the grant comes with a yes); the one-line installer does not ask.
  `scripts/install-auto-update.sh --uninstall` removes the grant together with
  all seven timers — including check-in, so the sensor then stops reporting to
  the dashboard, taking commands and updating itself. It keeps scanning.
- That user is added to the `docker` group.
- `setup.sh` enables Ubuntu `unattended-upgrades`, installs a login banner, and
  installs seven systemd timers: check-in (3 min), console poll (30 s), watchdog
  (15 min), Wi-Fi survey (15 min), Wi-Fi experience (15 min tick, idle unless
  enabled), nightly update, weekly refresh.

Dedicate a machine to the sensor. Do not install it on a box that does anything else.

## 6. Credentials the sensor holds

| Credential | Where it lives on the box | Leaves the box? |
|---|---|---|
| Per-sensor enrollment token | `/var/lib/netmon/enroll-token`, mode 0600 | Sent to the dashboard as the bearer token on each request |
| Shared bootstrap key | `/etc/netmon/netmon.env`, mode 0600 | Sent at enrollment, and again if the sensor has to re-enroll |
| SNMP read communities | `netmon.env` (0600) and the local database | **Yes.** The community that worked for each device is included in the hourly bundle, and the configured list is reported at check-in, so the dashboard can show which credential works where. Use read-only communities. |
| DHCP-server (WinRM) account | `/var/lib/netmon/dhcp-targets.json`, 0600 | The password never does. If a login fails, the error text in the bundle may name the account. |
| Switch SSH credentials | `/var/lib/netmon/device-config-targets.json`, 0600 | No |
| Wi-Fi PSK / 802.1X credentials | `netmon.env`, a 0600 profile file, and a 0600 NetworkManager keyfile | No |
| Secrets inside backed-up switch configs | Replaced on the box by a keyed hash before storage; the key never leaves the box | No — only the redacted config is uploaded |

All of these except the bootstrap key normally originate from the dashboard, so
the dashboard also stores them.

## 7. What is collected and uploaded

Each hourly bundle is a ZIP of that hour's scans. It contains:

- **Device inventory:** IP address, MAC address, hostname, vendor and device
  class for everything seen. The inventory is cumulative and is kept on the box
  for the life of the install.
- **DHCP observations:** client MAC, offered address, and the **client-supplied
  hostname** (DHCP option 12 — often a person's device name) and fingerprint.
- **Service discovery:** mDNS and SSDP announcements, including TXT records as sent.
- **Switch data (when SNMP is configured):** MAC-to-port tables, ARP tables,
  interface and PoE state, serial numbers, `sysContact` / `sysLocation`, and
  LLDP/CDP topology.
- **Measurements:** DNS answers and timings, traceroute paths, latency, speed
  tests, IGMP and DHCP-server findings.
- **Wi-Fi (when a radio is present):** every visible SSID and BSSID — including
  neighbors' networks, not only yours — with channel, signal and security mode.
- **When enabled:** Windows DHCP scopes, leases and reservations; redacted switch
  configurations.

It contains **no packet payloads**, no browsing history, and no content of any
user's traffic.

Local retention: scans 14 days, bulk SNMP detail 3 days, uploaded bundles 7 days, nightly
database snapshots 7 days. Retention after upload is governed by the dashboard.

Device names and MAC addresses can identify individuals. Check this list against
your own data-classification and student-privacy obligations.

## 8. Updates

- Every night at about 03:00 the sensor fetches this repository's `main` branch,
  resets its checkout to it, pulls the matching prebuilt image from `ghcr.io`,
  and restarts. It snapshots the database first, runs a 2-minute health check
  afterwards, and rolls back automatically if the check fails
  (`scripts/auto-update.sh`).
- Images are built by this repository's GitHub Actions after CI passes. They are
  **not cryptographically signed**.
- To control it, set the update channel:
  - `NETMON_UPDATE_CHANNEL=hold` — pause updates.
  - `NETMON_UPDATE_CHANNEL=stable` with `NETMON_UPDATE_REF=<commit>` — stay on a
    commit you have reviewed. The commit must be on `main`. If the ref cannot
    be resolved, or is not on `main`, the box **stays on the commit it is running** and does not
    update; the reason is reported to the dashboard as a failed update and
    logged (`journalctl -u netmon-update`). It never falls back to `main`.

  The channel is a dashboard-managed setting, so set it there; the dashboard
  operator can change it. The weekly refresh (`scripts/weekly-deep-refresh.sh`)
  honours the channel: on `hold`, or with a pinned commit, it rebuilds the
  commit already checked out (fresh OS and Python packages, same sensor code)
  and does not pull `main`.
- `scripts/install-auto-update.sh --uninstall` removes all scheduled jobs.

## 9. Reducing the footprint

For a conservative first deployment:

1. Give the sensor its own access port on a management or test VLAN.
2. Use a dedicated read-only SNMP community, or leave SNMP unconfigured to start.
3. Leave the opt-in features in section 1 off until you need them.
4. Hold or pin the update channel while you evaluate.
5. Apply the CIS hardening subset and key-only SSH ([HARDENING.md](HARDENING.md)).
6. Ask your dashboard operator who can push configuration, queue host actions and
   open a full shell on your sensors, and how those sessions are logged.
