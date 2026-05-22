from __future__ import annotations

CLAUDE_BUNDLE_README = """\
# App_Mon Evidence Bundle

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
- **raw/** — Underlying tool outputs (lldp neighbors, arp table, dhcp
  observations, stp events, snmp polls, interface state).

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
> 4. Rank findings by severity and confidence. Tell me which are
>    *definite* from the evidence and which are *suggestive*.
> 5. For each finding, cite the file and field in the bundle that
>    supports it.
> 6. End with a short list of follow-up checks I should run on the
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


def get_bundle_readme() -> str:
    return CLAUDE_BUNDLE_README
