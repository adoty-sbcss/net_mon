from __future__ import annotations

CLAUDE_BUNDLE_README = """\
# NetMon Evidence Bundle

This ZIP contains the output of a single network scan. Drag-and-drop the
files into a Claude conversation, then send the prompt below.

## What's in here

- **summary.md** — Read first. Human-readable overview of the scan and
  high-level counts.
- **findings.json** — Structured detections from the on-box analyzer. May
  be empty on this MVP build — that's expected; you're relying on Claude
  for analysis.
- **topology.json** — Devices and L2/L3 edges built from LLDP, ARP, and
  routing data.
- **devices.csv** — Flat inventory of everything seen (IP, MAC, vendor,
  hostname, source).
- **metrics.json** — Interface counter deltas and broadcast/multicast
  rates over the capture window.
- **timeline.json** — Ordered events captured during the scan.
- **dns_health.json** — Per-resolver DNS probe results: status, latency,
  answers. Includes a unique NXDOMAIN probe to detect resolvers that
  rewrite bogus names to an ad/filter page.
- **raw/** — Underlying tool outputs (lldp neighbors, arp table, dhcp
  observations, stp events, snmp polls, dns probes, interface state).

## Prompt — paste this into Claude

> I'm uploading a network scan bundle from a passive + light-active
> capture taken on a single Ethernet segment. I need you to analyze it
> and tell me what's going on.
>
> Please:
>
> 1. Summarize the network's identity (subnet, gateway, vendor mix,
>    apparent device roles).
> 2. Map the topology to the extent the data supports. Identify the
>    upstream switch from LLDP/CDP if present, and the access port the
>    box is plugged into.
> 3. Look for and call out evidence of:
>    - **Layer-2 loops** (multiple roots in STP, frequent topology
>      changes, MACs flapping)
>    - **Broadcast/multicast storms** (rates relative to total packets,
>      anomalous senders)
>    - **Duplicate IPs** (same IP, different MACs in the ARP table)
>    - **Rogue DHCP** (DHCP offers from unexpected MACs or IPs)
>    - **VLAN issues** (tagged frames showing up on what should be an
>      access port, mismatched native VLAN)
>    - **Unusual hosts** (vendor OUI mismatches, unexpected device types,
>      management addresses that shouldn't be on this VLAN)
>    - **Interface health** (high error/drop rates, asymmetric traffic)
> 4. If `snmp_topology.json` is non-empty, walk it:
>    - Sketch the L2 fabric from the `edges` array (which switch ports
>      connect to which). Identify the apparent core/distribution/access
>      tiers if you can.
>    - Flag any node whose `system_description` indicates **EOL firmware,
>      management on an unexpected subnet, or a vendor that shouldn't be
>      in this network** (e.g., a consumer switch in a school MDF).
>    - Note any **switches that LLDP says exist but SNMP couldn't reach**
>      (present in `topology_nodes` with `source: 'lldp'` but no mgmt_ips
>      that responded to a community). These are visibility gaps worth
>      fixing.
> 5. Walk `dns_health.json` if present:
>    - Per `by_resolver`, compare mean latency between `public` and
>      `dhcp` resolvers — a DHCP-assigned resolver that's much slower
>      than the public ones is a likely user-pain culprit.
>    - Flag any `nxdomain_rewrite: true` resolver — that's the ISP/DNS
>      filter rewriting NXDOMAIN to an ad/portal page.
>    - Diff the `answers_text` for the same `query_name` across
>      resolvers. Disagreement is split-horizon DNS, hijacking, or a
>      misconfigured internal zone.
>    - Surface high `errors` counts (SERVFAIL/TIMEOUT) per resolver
>      and call out which.
> 6. Rank findings by severity and confidence. Tell me which are
>    *definite* from the evidence and which are *suggestive*.
> 7. For each finding, cite the file and field in the bundle that
>    supports it.
> 8. End with a short list of follow-up checks I should run on the
>    physical network or with elevated tooling (SNMP, switch CLI, packet
>    capture targets).
>
> If anything is missing that you'd need to be more confident, say so —
> I can re-run the collection with different parameters.

## Notes on data quality

- Captures are bounded to a configurable window (default 60s). Storms
  with sub-second peaks may be missed; sustained issues will show.
- nmap was run with `-sn -PE -PR` only — no port scanning. Hostnames
  come from PTR records if upstream DNS provided any.
- SNMP polling is off by default and only runs when configured with
  community strings.
"""


CLAUDE_BUNDLE_README_HOURLY = """\
# NetMon Hourly Evidence Bundle

This ZIP rolls up every network scan that completed during one hour on a
single Ubuntu collector box. It was generated automatically and uploaded
to the configured SFTP server at the top of the hour.

## What's in here

- **HOURLY_SUMMARY.md** — Read first. Lists every scan in the window,
  plus aggregate counts and notable changes between scans.
- **README.md** — This file. Use the prompt below.
- **inventory.csv / inventory.json** — The box's *persistent* device
  inventory across all scans (not just this hour): per MAC, the first/last
  time it was ever seen, how many scans it has appeared in, and its last
  known IP / hostname / vendor / device-class / location. Use this to tell
  brand-new devices from long-known ones.
- **scans/scan_<id>/** — Per-scan data. Each folder contains:
  - `summary.md`, `findings.json`, `topology.json`, `devices.csv`,
    `metrics.json`, `timeline.json`, `dns_health.json`,
    `service_discovery.json`
  - `raw/` — underlying tool outputs (LLDP, ARP, DHCP, STP, SNMP,
    nmap, DNS probes, mDNS/SSDP service discovery, interface state)

## Prompt — paste this into Claude

> I'm uploading an hourly rollup of network scans from an NetMon
> collector. The box does a 60-second passive + light-active capture
> per scan, triggered by link-up or run manually. This ZIP contains
> every scan that completed in one hour on one box.
>
> Please:
>
> 1. Read `HOURLY_SUMMARY.md` first to understand what's in the bundle.
> 2. For each scan, summarize the network identity (subnet, gateway,
>    vendor mix, apparent device roles).
> 3. Cross-reference `inventory.csv` (the box's lifetime device list).
>    Call out devices first seen in the last 24h (`first_seen_at`), and
>    note any whose `vendor` / `device_class` looks out of place for the
>    network they're on (`last_network_id`). Also check each scan's
>    `service_discovery.json` (mDNS/SSDP): these are AirPrint printers,
>    Apple TV/AirPlay, Chromecasts, Sonos, Rokus, cameras and UPnP media
>    devices — flag any `device_hint` that's unexpected for the segment
>    (e.g. a Chromecast/camera on a staff or server VLAN).
> 4. Compare scans across the hour. Flag anything that changed:
>    - Devices appearing or disappearing
>    - MAC/IP bindings shifting
>    - DHCP server changing or multiple servers seen
>    - STP root changing, topology change flag flapping
>    - Broadcast / multicast rate spikes
> 5. Across the hour, look for and call out evidence of:
>    - **Layer-2 loops** (root churn, frequent topology changes, MAC
>      flapping, TTL anomalies)
>    - **Broadcast/multicast storms** (rates relative to total packets,
>      anomalous senders)
>    - **Duplicate IPs** (same IP claimed by different MACs)
>    - **Rogue DHCP** (offers from unexpected MAC or IP)
>    - **VLAN issues** (tagged frames on access ports, mismatched
>      native VLAN)
>    - **Unusual hosts** (vendor OUI mismatches, unexpected devices)
>    - **Interface health** (high error/drop counts, asymmetric flow)
> 6. Walk each scan's `dns_health.json`:
>    - Compare per-resolver mean latency. Flag DHCP-assigned resolvers
>      noticeably slower than the public ones (1.1.1.1/8.8.8.8/9.9.9.9).
>    - Flag `nxdomain_rewrite: true` — ISP/filter is rewriting NXDOMAIN.
>    - Diff `answers_text` for the same `query_name` across resolvers;
>      disagreement is split-horizon or hijacking.
>    - Track DNS error rates across the hour. A resolver going from
>      clean to SERVFAIL/TIMEOUT mid-hour is a real incident.
> 7. Rank findings by severity and confidence (definite vs.
>    suggestive). Cite the scan id and file that supports each finding.
> 8. End with a short list of follow-up checks (SNMP polls, switch
>    CLI, longer captures, specific MACs to track).
>
> If a scan is missing data or looks truncated, say so.
"""


def get_bundle_readme() -> str:
    return CLAUDE_BUNDLE_README


def get_bundle_readme_hourly() -> str:
    return CLAUDE_BUNDLE_README_HOURLY
