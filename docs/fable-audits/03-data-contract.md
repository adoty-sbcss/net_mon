# Audit 3 — Data-contract completeness (collected → stored → shown → exposed-to-AI)

**Run:** Claude Fable 5 deep hunt → verified/curated on Opus 4.8, 2026-07-02.
**Question:** for every data type the collector produces, does it make it all the way through the pipeline, and where are the gaps? Per the project strategy ("dashboard = visibility, AI = insights: expose new fields to the AI tools"), **AI-exposure gaps are first-class findings.**
**Complements Audit 1** (which covered silent *loss*): this is the completeness matrix + partial-field drops + config-knob coverage.

## Verification status (Opus)

Re-confirmed against source: **Gap 1** (`grep src/lib/ai` for fleet-health tables → empty), **Gap 4** (`ingest.ts` comment "traffic_stats: no longer stored… never read"; `trafficStats` written only by `seed-demo.ts`), **Gap 5 / B1** (`checkin.py:1146-1150` reports `snmp_exclude` + 4 `snmp_topology_*`; `route.ts:119-132` persists only the snmp-enabled/communities/sftp subset), **Gap 6** (no inventory reader in `bundle.ts`). Fable also independently re-found the `saveSensorConfigAction` replace-not-merge bug (Audit 1 #6) — corroborated. Remaining rows carry Fable's CONFIRMED marking with accurate anchors.

## A. Completeness matrix

✅ wired · ◐ partial · ✗ missing. "Analysis ctx" = `src/lib/ai/context.ts` (scheduled findings run); "Chat" = `src/lib/ai/chat-tools.ts`; "Topo AI" = `topology-context.ts`.

| # | Data type | Collected | Stored | Shown (UI) | In-AI |
|---|---|---|---|---|---|
| 1 | Device discovery (ARP/nmap/rDNS/DHCP-name) | `discovery/{arp,nmap,rdns}.py`, `scan.py:_persist` | ✅ `devices` + `entities_host` | ✅ hosts pages | ✅ `search_devices`/`device_counts`/`devices_in_scan` + ctx breakdown |
| 2 | LLDP/CDP neighbors | `discovery/lldp.py` | ✅ `neighbors` + `entities_switch` | ✅ neighbors/switches | ◐ `search_switches`, Topo AI links; port-level detail not AI-visible |
| 3 | DHCP obs + fingerprint (opts 60/55/12) | `tshark.py:_parse_dhcp` | ✅ `dhcp_observations` | ✅ dhcp page, host detail | ✅ ctx `getDhcpAnalysis` |
| 4 | STP events | `tshark.py:_parse_stp` | ✅ `stp_events` | ◐ count-only (rollup number) | ✅ ctx `listStpForSchool` + `rules/stp.ts` |
| 5 | **Traffic stats** (bcast/mcast/pps, rx err/drop) | `interfaces.py` + tshark | **✗ dropped at ingest** (`ingest.ts:1216`); dead `trafficStats` table | ✗ | ✗ |
| 6 | SNMP polls (identity, ENTITY/HR/Printer-MIB) | `discovery/snmp.py` | ✅ curated `snmp_polls`; serial/model → `entities_switch.attributes` | ✅ switch/host SNMP cards | ◐ only via classification; ENTITY-MIB serial/clean-model not in AI |
| 7 | Host↔switch-port (FDB) | derived from #6 | ✅ `host_switch_ports` | ✅ host pages | ✅ `search_devices.switch_port` |
| 8 | SNMP fabric topology crawl | `snmp_topology.py` | ✅ `topology_snapshots` + edges; **crawl `stats` dropped** | ✅ map (MAP-3/4) | ◐ Topo AI has nodes/links; per-port health/blocked/PoE not exposed; none in Chat |
| 9 | Uplink octet samples (PERF-3) | `snmp_topology` `extra.uplink` | ✅ `uplink_samples` | ✅ Speed & Bandwidth | ✗ (known perf gap) |
| 10 | DNS health probes | `dns_health.py` | ✅ `dns_resolver_health` + `dns_probes` | ✅ dns page | ✅ ctx `dnsResolvers` |
| 11 | Reachability (ping/traceroute/SNMP-responded) | `reachability.py` | ✅ `network_reachability` incl. traceroute | ✅ switches rollup + detail | ◐ Topo AI gets derived gaps only; **no Chat tool** |
| 12 | mDNS/SSDP service discovery | `mdns_ssdp.py` | ◐ no table; hint+types → `entities_host.attributes`; `details` dropped | ✅ host detail | ◐ classification only |
| 13 | Wi-Fi RF/AP survey (WIFI-2) | `discovery/wifi.py` | ✅ `wifi_surveys` (all 20 fields) | ✅ wireless page | ✅ `wireless_posture`; **✗ absent from analysis ctx** |
| 14 | Wi-Fi client-experience (WIFI-3/6) | `wifi_experience.py` | ✅ `wifi_experience` + wifi-tagged perf | ✅ wireless page | ✅ `wifi_experience` (richest tool); omits RSSI/ip/gateway/captive; **✗ absent from analysis ctx** |
| 15 | Collector findings | scan rules → `findings.json` | ✅ `findings` | ✅ findings pages | ✅ `site_findings` + ctx |
| 16 | **Persistent inventory** (`inventory.json`: device_class, times_seen, first/last-seen, last_network_id) | `db.list_inventory` → bundle root | **✗ never read** (`bundle.ts` has no reader) | ✗ | ✗ |
| 17 | SNMP credential cache | bundle `snmp_credentials.json` | ✅ `snmp_device_credentials` (drops `last_attempt_at`) | ✅ device "working community" | ✗ (deliberate — creds) |
| 18 | Scan-run metadata (VLAN/trigger/duration/error) | `scan.py:insert_scan_run` | ✅ `scan_runs` | ✅ scan filters; VLAN status | ◐ `list_scans` returns id/sensor/date only — no VLAN/iface/error anywhere in AI |
| 19 | Sensor host metrics (CPU/RAM/disk/OS/uptime/temp) | `host_metrics.py` via check-in | ✅ `sensors.reportedHostMetrics` jsonb | ✅ sensor detail + fleet flags | **✗ no AI surface** |
| 20 | Live interface list (mac, wireless flag) | `checkin.py:_interfaces` | ✅ `sensors.reportedInterfaces` jsonb | ✅ per-VLAN status, radio MAC | ✗ |
| 21 | Reported ground-truth config | `checkin.py:1143-1155` (incl. snmp_exclude + 4 topo fields) | **◐ route persists only snmp_enabled/communities/sftp_*** — exclude + topology fields dropped | ◐ shows stored subset | ✗ |
| 22 | Update/host-action telemetry | `checkin.py:989-1023` | ✅ sensors columns | ✅ sensor + releases | ✗ |
| 23 | iperf3 results | `iperf.py` → route | ✅ `iperf_results` | ✅ Speed & Bandwidth | ✗ (known) |
| 24 | Speedtest (wired) | `speedtest.py` → route | ✅ `speedtest_results` | ✅ Speed & Bandwidth | ✗ wired (wifi rows exposed via `wifi_experience`) |
| 25 | Latency/jitter/loss (PERF-4) | `latency.py` → route | ✅ `latency_results` | ✅ Speed & Bandwidth | ✗ (known) |
| 26 | Webperf waterfalls (wired, PERF-5) | `webperf.py` → route | ✅ `webperf_results` | ✅ Speed & Bandwidth | ✗ wired (wifi rows exposed) |
| 27 | Config backups | `config_backup.py` → SFTP | ✅ `config_backups` | ✅ sensor download | ✗ (fine — secrets) |
| 28 | Diag/command results | `checkin.py` `_DIAG_COMMANDS` | ✅ `command_results` jsonb | ✅ console/VLAN wizard | ✗ |
| 29 | Bundle metrics/timeline/summary MDs | `bundle.py:154-171` | ✗ not read (derived dupes of #3/4/5) | — | — |

## B. Ranked highest-value gaps

**1. Sensor fleet health is invisible to the AI · CONFIRMED (Opus-verified).** "Which sensors are unhealthy / offline / failed their update / low on disk?" is the most basic fleet question; the data is all stored (`sensors.reportedHostMetrics`, `lastCheckinAt`, `lastUpdateStatus`, `lastHostAction`, `reportedSha`) and rendered by `lib/sensor-health.ts`, but no chat tool or analysis context reads it. Evidence: `chat-tools.ts:54-161` (no sensor tool); `context.ts:70-82` (no sensor query). **Fix:** add a `sensor_health` chat tool wrapping `listSensorsForSchool` + `sensorHealthFlags`, and a `sensors:[…]` block in `buildSchoolContext`. *(This is the single best AI-exposure win — smallest change, biggest operational value.)*

**2. Wireless posture/experience is chat-only — scheduled AI findings can't see it · CONFIRMED.** An open district SSID, WEP AP, failed captive portal, or a guest network reaching internal hosts (`isolationReachable=true`) never appears in the scheduled analysis/notification pipeline — only if a human asks chat. Evidence: `context.ts:64-127` has no wifi query; `wireless_posture`/`wifi_experience` live only in `chat-tools.ts`; no wifi rule in `lib/rules/`. **Fix:** add compact `wifiPosture` (counts by auth; open/WEP/TKIP APs) + latest experience failures (assoc fail, isolation breach, captive fail) to `buildSchoolContext`.

**3. Reachability / SNMP-gap has no chat tool · CONFIRMED.** `network_reachability` is a flagship dataset with a full UI, but chat can't answer "which switches at X don't answer SNMP" — only the topology design review sees a derived gap count. **Fix:** `snmp_coverage` chat tool over the existing school reachability query.

**4. Traffic stats dropped end-to-end · CONFIRMED (deliberate, now contradicts the strategy).** Broadcast/multicast %/pps + RX errors/drops are the collector's only broadcast-storm/loop-corroboration signal; ingest deletes them ("pure dead weight"), and STP rules fire with no traffic corroboration. Evidence: collected `scan.py:643-659`, bundled `bundle.py:167,192`, discarded `ingest.ts:1216-1218`; `trafficStats` table written only by `seed-demo.ts`. **Fix:** either re-store one row/scan (tiny) and add `broadcast_pct`/`rx_errors` to the analysis context, or delete the dead table + parse to make the drop honest.

**5. Reported ground-truth config partially dropped at check-in · CONFIRMED (Opus-verified).** The collector reports `snmp_exclude` + `snmp_topology_{enabled,scope,max_depth,interval}` so the dashboard can show ground truth vs pushed config; the route silently discards them, so topology-crawl drift (box stuck on `full` scope, exclusion not applied) is undetectable — the exact failure the exclude feature was built to catch. Evidence: sent `checkin.py:1146-1150`; persisted subset `route.ts:119-132`. **Fix:** widen the route type + add `reportedSnmpExclude`/`reportedTopo*` columns (or a single `reportedConfig` jsonb like `reportedHostMetrics`).

**6. Persistent inventory artifact never ingested · CONFIRMED (Opus-verified).** `inventory.json`/`.csv` (MAC-keyed lifetime view: `times_seen`, collector-side `device_class`, `last_network_id`, per-box first/last-seen) ships in every hourly bundle; `bundle.ts` has no reader. `entities_host` re-derives most of it, but `times_seen` and per-box network/VLAN attribution are lost, and collector/dashboard classifications can silently disagree. Evidence: written `bundle.py:96-99`; absent from `bundle.ts:528-598`. **Fix:** ingest it into `entities_host.attributes`, or stop bundling it and document `entities_host` as canonical.

**7. Per-port switch health is on the map but invisible to AI · CONFIRMED.** Per-ifIndex oper/admin status, errors, duplex, PoE, STP-blocked links, link speed drive the map UI, but the topology design review only sees node names + edge kinds. Evidence: stored `ingest.ts:463-506`; `topology-context.ts:53-73` maps only name/type/ip/model/kind. **Fix:** extend `infraLinks` with `stp_blocked`/`speed_mbps`; add per-switch `portsWithErrors`/`poeFaults` rollups.

**8. The VLAN dimension is absent from every AI surface · CONFIRMED.** PROV-4/5 built VLAN-tagged scans, per-VLAN interfaces, a VLAN-aware map — but `list_scans` returns no interface/VLAN, no tool filters by VLAN, and the logical graph is never given to AI. "What's on VLAN 40" / "is the trunk VLAN 12 scan failing" can't be answered. **Fix:** return `interface`/`vlan_id`/`error` from `list_scans`; optionally add the logical graph to design-review context.

## C. Partial-field drops

1. **`currentConfig.snmp_exclude` + `snmp_topology_*` dropped by check-in route** — see Gap 5. CONFIRMED (Opus-verified).
2. **Traffic dataset parsed then discarded; dead `trafficStats` table** — see Gap 4. CONFIRMED (Opus-verified).
3. **`service_discovery.details` never stored** (mDNS TXT / SSDP headers incl. printer model strings) — only hint + service-type list survive; no `service_discovery` table exists. Evidence: `mdns_ssdp.py:106-115`, `bundle.ts:264-271`, `ingest.ts:1149-1161`. CONFIRMED.
4. **SNMP crawl `stats` dropped** (`visited_ips`, `elapsed_sec`, `budget_exhausted`) — a budget-exhausted crawl ships a truncated fabric; the dashboard can't distinguish "small network" from "crawl gave up." Evidence: `snmp_topology.py:542-546`; `bundle.ts:257-260` has no `stats`. CONFIRMED.
5. **`devices.csv` fallback drops the collector's `extra`** — fixed fieldnames in `_devices_csv` (`bundle.py:605-612`) mean ingest's `d.extra` fallback (`ingest.ts:1368-1372`) can never fire. Harmless today, a trap. CONFIRMED.
6. **`snmp_credentials.last_attempt_at` dropped at ingest** (`bundle.ts:297` vs `ingest.ts:536-541`) — backoff state invisible. CONFIRMED, minor.
7. **Stored-but-not-in-AI fields:** `wifi_experience.signal/ip/gateway/captiveHttpCode/captiveRedirect`; `entities_switch.attributes.serial/model` (`search_switches` returns raw sysDescr); `network_reachability.traceroutePath`; `dns_probes.answers_text` (hijack evidence). CONFIRMED.
8. **Stored-but-never-shown (dead columns):** `trafficStats.*`; `scan_runs.notes`; `neighbors.extra` (always `{}`); `lastUpdate.channel` (redundant with `reportedChannel`). CONFIRMED. `dhcpObservations.serverMac` — PLAUSIBLE.

## D. Config-knob coverage (`config.py` vs dashboard controls)

**Collector knobs with NO dashboard control (SSH/env-only), ranked by operational value:**
1. **`NETMON_EXCLUDE_VLANS`** (`config.py:41`) — the only way to stop auto-scanning a noisy trunk VLAN; complements the trunk wizard, yet SSH-only. CONFIRMED.
2. **`NETMON_SNMP_POLL_ALL_HOSTS`** (`config.py:52`) — flips SNMP classification of printers/PCs/IoT fleet-wide. CONFIRMED.
3. **`NETMON_LATENCY_TARGETS`** (`config.py:246`) — `_apply_config` accepts it (`checkin.py:201-202`) but `speedtest-actions.ts:76-80` pushes only `latency_enabled`; targets frozen at 1.1.1.1/8.8.8.8. **Cheapest fix in this list.** CONFIRMED.
4. **`NETMON_WEBPERF_SCHEDULE_SEC`** (`config.py:253`) — `_apply_config` supports it; `webperf-actions.ts` never sends it (cadence stuck at 15 min). CONFIRMED.
5. **`NETMON_WIFI_JOIN_QUIET`** (quiet hours) + **`NETMON_WIFI_JOIN_IFACE`** — `_apply_config` supports (`checkin.py:234-254`); dashboard never pushes. The WIFI-6 scheduler UI exists but its quiet-hours guardrail doesn't. CONFIRMED.
6. **`NETMON_DNS_{ENABLED,PUBLIC_RESOLVERS,TEST_NAMES,TIMEOUT_SEC,INCLUDE_NXDOMAIN_PROBE}`** — districts can't test their own domains (e.g. the SIS URL) in DNS health. CONFIRMED.
7. **Tuning/kill-switches (SSH-only AND not applied by `_apply_config` at all):** `NETMON_CAPTURE_SECONDS`, `NETMON_COOLDOWN_SECONDS`, `NETMON_POLL_INTERVAL`, `NETMON_LOCAL_RETENTION_DAYS`, `NETMON_SNMP_BULK_INTERVAL`, `NETMON_EXCLUDE_IFACES`, `NETMON_RDNS_*`, `NETMON_INVENTORY_ENABLED`, `NETMON_MDNS_ENABLED/_SECONDS`, `NETMON_SSDP_SECONDS`, `NETMON_REACHABILITY_*`, `NETMON_WIFI_SURVEY_MAX_AGE`. CONFIRMED.

**Dashboard→collector keys the collector ignores:** none found (`speedtest_providers` is vestigial — collector normalizes to "cloudflare"; `trunk_*` consumed host-side by `lib/trunk.sh`, intentional). CONFIRMED.

**Config-integrity bug (re-found from Audit 1 #6):** `saveSensorConfigAction` (`sensor-actions.ts:242-263`) **replaces** the whole `desired_config.config` object with only snmp/rescan/topo/sftp keys, while webperf/wifi-join/iperf actions jsonb-merge. Saving the SNMP form wipes `webperf_urls`, `wifi_join_profiles`, `iperf_*`, `latency_enabled`, `trunk_*` from the record; the box keeps env values (`_apply_config` only applies present keys) but the dashboard's record of what it pushed is destroyed. CONFIRMED (code); runtime effect PLAUSIBLE.

## Fully wired end-to-end (coverage — these are the model to copy)

Device/host discovery + classification · DHCP + fingerprints · DNS health · LLDP/switch entities · host↔switch-port · collector findings · Wi-Fi RF survey · **Wi-Fi experience battery** (the exemplar of "expose to AI") · physical topology (design review) · STP (AI-ahead-of-UI: rules see it, UI is count-only).

## Suggested action order

1. **Gap 1 (`sensor_health` tool + context block)** — smallest change, biggest operational win, dead-on the AI-insights strategy.
2. **Gap 2 + Gap 3 (wifi posture into analysis ctx; reachability/SNMP-gap chat tool)** — turn two flagship datasets into insights.
3. **Gap 5 + config-knob #3/#4 (persist reported topo/exclude config; push latency targets + webperf cadence)** — cheap, close ground-truth blind spots.
4. **Gap 6, Gap 4 (inventory; traffic stats)** — decide ingest-or-drop; don't leave data shipped-but-discarded.
5. **Config-integrity bug** — shared with Audit 1 #6; fix the replace→merge once.
