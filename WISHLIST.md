# NetMon wishlist

Brain-dump of features and ideas. Each item is one checkbox plus a short "why" so future-me remembers what was interesting. Move items to GitHub Issues (or a project board) when you're ready to actually build them.

Items tagged `(suggested)` were added during the wishlist drafting session and aren't yet committed-to — delete any that don't fit.

---

## Multi-network & VLAN

- [ ] **Multiple networks on one trunk cable**
  Today the poller scans each Linux interface independently — multi-NIC already works ([poller.py:52](collector/src/collector/poller.py:52)). Trunks don't: the kernel only exposes the untagged VLAN. Path: config-driven VLAN sub-interfaces (`ip link add link eth0 ... type vlan id N`), each one DHCP'd, picked up automatically by the existing poller. LLDP already extracts `vlan_id` per neighbor ([discovery/lldp.py:79](collector/src/collector/discovery/lldp.py:79)).

- [ ] **VLAN-aware passive capture on raw trunk** (suggested)
  Alternative to sub-interfaces: capture once on `eth0`, decode 802.1Q tags inline. Lets you see tagged frames on access ports (which the Claude prompt already calls out as suspicious in [prompts.py:46](collector/src/collector/prompts.py:46)).

## Wireless

- [ ] **Wireless connectivity** — associate to an SSID and scan it like any other LAN
  Once `wlan0` has an IP, the existing poller treats it like any wired interface. Need wpa_supplicant config + credentials managed from the operator menu.

- [ ] **Wifi monitoring** — AP / spectrum survey
  `iw dev wlanX scan` to enumerate nearby SSIDs, channels, RSSI, encryption, channel overlap. One new `discovery/wifi.py`. Works on any Wi-Fi NIC; no monitor mode required.

- [ ] **Passive 802.11 sniffing** (suggested)
  Monitor mode + tshark for beacons, probe req/resp, retransmit rate, deauths, hidden SSIDs, rogue APs. Needs a known-good monitor-mode USB adapter (AR9271, MT76xx, RTL8812AU) and a separate scan flow because monitor mode disconnects from the network.

## Discovery & inventory

- [ ] **Persistent device inventory** — printers, IoT, AV, computers, etc.
  Cross-scan persistence keyed on MAC: vendor (OUI), device class, first seen, last seen, where seen. Foundation for the items below.

- [ ] **mDNS / Bonjour + SSDP / UPnP discovery** (suggested)
  Catches Apple printers, AirPlay receivers, Chromecasts, Sonos, IP cameras — most of which barely show up in ARP/nmap. Huge in K-12.

- [ ] **DHCP fingerprinting (option 55)** (suggested)
  Already capturing DHCP via tshark — extract option 55 and match against a Fingerbank-style DB. Identifies OS and device class even when OUI is generic.

- [ ] **IPv6 discovery** (suggested)
  ND / RA capture + IPv6 host enumeration. Today's collector is IPv4-only.

- [ ] **Change detection per switch port** (suggested)
  "Port Gi1/0/12 had MAC A last week, has MAC B today." Combines LLDP + persistent inventory. Useful for desk moves and theft.

- [ ] **AD / LDAP cross-reference** (suggested)
  Compare discovered hostnames against AD computer accounts: flag domain-joined devices that aren't on the wire (decommissioned?) and devices on the wire that aren't in AD (BYOD / rogue).

- [ ] **Crawling outside Layer 3 gateways**
  Use SNMP on the gateway to walk routing tables (ipRouteTable / ipCidrRouteTable) and ARP caches (ipNetToMediaTable) → discover other subnets the box can't reach directly. Hop from there to the next router by walking its tables. Builds an org-wide picture from one collector. Needs read-only SNMP on the routers. Pairs with the visual map below.

- [ ] **Full network map (visual)**
  The payoff item for the cross-segment crawl. Render the discovered topology as a real visual: nodes = switches / routers / endpoints, edges = LLDP/CDP-discovered links + SNMP-walked routes, color-coded by VLAN / subnet / site, click-to-drill-down on a device. Two output flavors worth shipping side-by-side:
  - **HTML** (D3 / vis.js / Cytoscape) — interactive, included in the hourly bundle, opens in any browser without a server.
  - **Static SVG / Mermaid** — for the bundle README and PDF reports.
  Today the LLDP graph is already extracted ([discovery/lldp.py](collector/src/collector/discovery/lldp.py)) and the bundle is structured for it ([bundle.py](collector/src/collector/bundle.py)) — visualization is mostly a rendering layer on top of data we already have.

## Security & vulnerability

- [ ] **Notify on known vulnerabilities** — CVE match for discovered devices/firmware
  Match SNMP sysDescr, HTTP banners, SSH banners, etc. against CVE feeds (NVD JSON, vulners). Auto-flag at scan time; surface in bundle summary.

- [ ] **Default-credential check on web admin pages** (suggested)
  Probe :80 / :443 / :8080 with the common defaults (admin/admin, root/root, etc.) — only on devices the operator marks "ok to test." K-12 is full of printers and cameras with default creds.

- [ ] **TLS cert health + weak cipher / SMBv1 / EOL OS detection** (suggested)
  Cheap scans on responding services. Maps directly to compliance reporting.

- [ ] **Threat-intel match** (suggested)
  Check active flows against IP/domain reputation feeds. Catches infected hosts beaconing out.

## Diagnostics & performance

- [ ] **Off-network performance testing**
  Path quality (jitter, loss, MTR-style hop-by-hop) to a configurable list of targets — ISP gateway, district HQ, Google, Microsoft 365, instructional platforms.

- [ ] **DNS resolution health** (suggested)
  Latency, recursion behavior, server availability, NXDOMAIN rate. Common K-12 complaint — "internet is slow" usually means DNS.

- [ ] **VoIP / multicast path quality** (suggested)
  Synthetic jitter/loss test + IGMP membership / multicast routing check. Schools care: phones over IP, PA systems, streaming bell schedules.

- [ ] **Speed / duplex mismatch detection** (suggested)
  `ethtool` on the active interface + compare against LLDP neighbor's advertised settings. Cheap fix for a common silent performance killer.

- [ ] **Site-to-site bandwidth via iperf3** (suggested)
  Two NetMon boxes can iperf each other. Lets you measure WAN throughput between schools without buying a separate tool.

## Deployment, hardening & operator UX

- [ ] **Automated Ubuntu deployment**
  Autoinstall ISO (cloud-init) + late-commands that clone the repo and run setup. Optional qcow2 image for VM deployments. Decisions still open: full-disk encryption (LUKS), remote-support channel (Tailscale / reverse-SSH / none), hardware target.

- [ ] **OS hardening pass** — separate from the collector container
  CIS Level 1-ish: SSH keys only, ufw default-deny, fail2ban, sysctl hardening, auditd, AppArmor enforcing, lynis baseline report. Hardened MOTD with status info.

- [ ] **Collector container hardening**
  Today the container runs `privileged: true` ([docker-compose.yml](docker-compose.yml)). See if `cap_add: NET_ADMIN, NET_RAW, SYS_PTRACE` alone is enough; drop to non-root user inside the container; tighter seccomp profile.

- [ ] **Expanded operator menu** — write-capable, not just read-only
  Today's `./netmon` is mostly read-only. Add a Configure submenu (SFTP / SNMP communities / known networks / cadence / log level / device name / scan mode) and a System submenu (network settings / SSH keys / firewall / disk cleanup / reboot / factory reset / export-import config). Every write goes through the same `set_value` + `chmod 600` pattern from [setup.sh:218](setup.sh:218).

- [ ] **Self-diagnostic wizard** (suggested)
  "I think DHCP is broken / I can't upload / no scans" → menu option that runs the right checks and prints what's wrong. Saves call-backs to the operator.

- [ ] **Support bundle export** (suggested)
  One menu item → ZIP of redacted logs + config + lynis report. Tech in the field emails it back without piping through SSH.

- [ ] **Scheduled scans + quiet hours** (suggested)
  "Scan every Monday 8am" / "no scanning during state testing days." Cron-style entries managed from the menu, not by editing systemd.

- [ ] **Read-only root filesystem option** (suggested)
  For permanently-deployed sensors. Survives power-cuts without fsck pain. State on tmpfs + writable volumes for `./bundles` and `./logs`.

- [ ] **Raspberry Pi target** (suggested)
  ARM64 image so you can drop a $75 sensor in every wiring closet instead of repurposing PCs.

## Fleet & central platform (Azure)

> This is the big one — central collector + dashboard on Azure. Items below are seeds; expand as you scope the platform.

- [ ] **Central collector + dashboard**
  Aggregate bundles from every deployed NetMon box; org-wide topology, inventory, alerts.

- [ ] **Heartbeat per box** (suggested)
  Each box drops `<device>_heartbeat.txt` in the SFTP path every 15min. Dashboard shows green/yellow/red per site without needing inbound connectivity to the box.

- [ ] **Remote config push** (suggested)
  Central UI to update an `.env` for one or all boxes; box pulls and applies on the next maintenance window. Avoids site visits for routine changes.

- [ ] **Cross-site device correlation** (suggested)
  Same MAC seen at School A then School B → loaned-out / stolen / BYOD pattern.

- [ ] **Per-box version + health view** (suggested)
  Which boxes are on which git SHA, last successful upload, last reboot, lynis score trend.

- [ ] **Org-wide search and reporting** (suggested)
  "Find every printer in the district" / "every device on EOL Windows" / "every site missing a heartbeat >24h."

## Integrations & extensibility

- [ ] **Syslog forwarding** (suggested)
  Forward collector + audit logs to a central SIEM. Trivial; high value for incident response.

- [ ] **Prometheus metrics + REST API** (suggested)
  `/metrics` endpoint for scrape; `/api` for other tools to query last scan / device list.

- [ ] **Webhook output** (suggested)
  POST findings to Splunk HEC / generic webhook / Teams channel. "Rogue DHCP found on School-A" arrives in chat.

- [ ] **SNMP trap receiver** (suggested)
  Let switches/routers send link-state / authentication-failure / temperature traps to the box; bundle them with the rest of the scan data.

- [ ] **NetFlow / sFlow collector** (suggested)
  Big upgrade for sites that have flow-capable gear but no collector. Top talkers / top destinations stored summarized in Postgres, not raw flows.

- [ ] **Small local web UI** (suggested)
  Read-only dashboard on `http://<box>:8080` for ops who don't want to SSH. Separate from the Azure central dashboard.

## Nice-to-haves / future

- [ ] **On-box LLM for instant analysis** (suggested)
  Small local model (Llama-3.1-8B-class or smaller) runs the same prompt the bundle ZIP shows today, on the box itself. Matches the air-gapped preference — no data leaves, analysis is instant, and useful at sites with no upload connectivity.

- [ ] **Bundle signing** (suggested)
  Sign the hourly ZIP with a per-box key. Lets the central platform verify origin and detect tampering.
