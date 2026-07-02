# Audit 1 — Silent data-loss hunt (collector → dashboard delivery seam)

**Run:** Claude Fable 5 deep hunt → verified/curated on Opus 4.8, 2026-07-02.
**Scope:** cases where a healthy-looking sensor produces data that never lands in the dashboard DB (or never reaches the AI layer) while every green check still passes.
**Repos:** collector = `net_mon` (`collector/src/collector/...`); dashboard = `netmon-dashboard` at `C:/Users/Adam.Doty/netmon-ux/`.

## Verification status (Opus)

Line references were spot-checked against live code and landed exactly. Independently re-confirmed against source: **#1** (`db.py:371-377`, `ingest.ts:986`, `checkin.py:516-529`), **#4** (`grep src/lib/ai` → zero perf-table refs), plus supporting evidence for **#2** (`list_pending_bundles` retries only built bundles) and **#5** (`_current_token` never self-heals a revoked token). The remaining findings carry Fable's CONFIRMED marking with accurate line anchors; treat PLAUSIBLE items as "verify at runtime before acting."

## Findings (ranked by field-impact × confidence)

| # | Finding | Severity | Confidence | Fix lands in |
|---|---------|----------|-----------|--------------|
| 1 | Same-hour bundle rebuild silently skipped by ingest → scans vanish | **Critical** | CONFIRMED (Opus-verified) | dashboard ingest + collector uploader |
| 2 | No backfill: downtime spanning top-of-hour orphans scans permanently | High | CONFIRMED | collector uploader |
| 3 | Scheduled perf results are fire-once, no retry; ledger marks done on failed POST | High | CONFIRMED | collector checkin (+ dashboard routes) |
| 4 | Entire performance dataset never reaches the AI layer | High* | CONFIRMED (Opus-verified) | dashboard `src/lib/ai` |
| 5 | Enrollment-token collision silently 401-discards one box forever | Med-High | CONFIRMED mech / PLAUSIBLE trigger | collector + dashboard enroll |
| 6 | `saveSensorConfigAction` replaces (not merges) desired config — dormant | Medium | CONFIRMED (dead code today) | dashboard sensor-actions |
| 7 | Out-of-order bundle re-ingest drops uplink samples & regresses Wi-Fi survey | Medium | CONFIRMED | dashboard ingest |
| 8 | Command results: crash → stuck `sent` forever; `scheduled` coerced to `done` | Med-Low | CONFIRMED | dashboard routes + maintenance |
| 9 | Legacy/pre-identity boxes: config backups never stored; scans → district "unknown" | Low | CONFIRMED | dashboard config-backup/ingest |
| 10 | Bundle reader swallows corrupt artifacts as empty; bundle still marked `parsed` | Low | CONFIRMED | dashboard bundle reader |

\* High relative to the project's own "dashboard = visibility, AI = insights" policy.

---

### 1. Same-hour bundle rebuild is silently skipped by ingest — scans permanently vanish · Critical · CONFIRMED

**Mechanism.** The collector deliberately rebuilds and re-uploads a bundle for an hour it already shipped, but the dashboard's idempotency ledger keys on **filename only** and refuses to re-parse it. Everything added to that hour after the first upload is discarded.

- Collector rebuild is by design — `collector/src/collector/db.py:361-380`: `ON CONFLICT (filename) DO UPDATE SET built_at = NOW(), uploaded_at = NULL, remote_path = NULL` ("If we're rebuilding, the prior upload is stale"). The rebuilt ZIP (same filename `<device_slug>_YYYY_MM_DD_HH.zip`, `uploader.py:63-78`) overwrites the remote file.
- Dashboard ignores the rebuild — `src/ingest/ingest.ts:986-988`: `if (existing && existing.parseStatus === "parsed" && !ov.force) return { skipped: true }`; `src/ingest/sync-core.ts:108-124` also skips downloading an already-`parsed` filename.

**Trigger (common).** `upload-now` is a first-class operator action (command queue / live console / standard support move) and ships a **partial** hour — `checkin.py:516-529`: `window_end = last_completed_scan_hour + 1h`. Sequence: 10:20 operator Upload-now → `dev_..._10.zip` ships with the 10:05 scan, ingested + marked `parsed`; 10:30 & 10:45 more scans complete; 11:00 hourly tick rebuilds the same filename with all hour-10 scans, re-uploads; next sync logs `... already parsed (skipped)` and the 10:30/10:45 scans never reach the dashboard (local copy purged after 14 days, `config.py:32`). Second trigger: **DST fall-back** — box-local filename means the repeated 1 a.m. hour collides once a year, fleet-wide.

**Why green.** Collector logs `bundle_uploaded`; dashboard sync shows `skipped` (reads as healthy dedup); ingest exits 0; sensor page shows fresh check-ins.

**Fix.** Make idempotency content-aware. Store `builtAt` (already parsed at `ingest.ts:966-969`) or a zip hash/size on `ingested_bundles`; in `ingestBundle` treat `existing.parsed && incoming.builtAt > existing.builtAt` as a re-ingest (the transactional delete-and-rebuild path at `ingest.ts:1001-1008` already exists). Mirror in `sync-core.ts` by comparing remote mtime/size before skipping. Collector alternative: never reuse a shipped hour's filename (append `-r2`).

### 2. No backfill: downtime spanning a top-of-hour orphans scans permanently · High · CONFIRMED

**Mechanism.** Only the scheduler tick *at* an hour boundary bundles that hour — `uploader.py:363-388` sets `target = _next_hour_boundary()` each loop/start, so hours whose boundary passed while the process was down are never built. The retry ledger (`list_pending_bundles`, `db.py:414-427`, `WHERE uploaded_at IS NULL`) only retries **built-but-unuploaded** bundles; never-built hours have no row. Scans sit in local Postgres and purge after 14 days.

The collector restarts more than it looks: every dashboard config push → `docker compose up -d --force-recreate` (`scripts/netmon-checkin.sh:35-46` on exit 10/11/12), district actions push to every sensor (`src/lib/webperf-actions.ts:55-81`), plus nightly auto-update, host reboot/rebuild, and school power-downs. Worse variant — the tail of the known SFTP enable-flag incident: with `NETMON_SFTP_ENABLED=false` the scheduler never starts (`uploader.py:363-366,390-398`), so nothing is built during the disabled window; flipping the flag on ships only *future* hours. **Healing the flag does not heal the gap.**

**Fix.** At scheduler start and each tick, query scan hours in the last N days with no matching `bundle_uploads` row and build/upload them. Fully local to the collector.

### 3. Scheduled perf results are fire-once, no retry; ledger marks done on failed POST · High · CONFIRMED

**Mechanism.** All result reporting rides `checkin.py:_post` (`checkin.py:70-84`), which swallows every failure (→ `log.warning`, return None) and nobody checks the return:
- iperf: `_maybe_scheduled_iperf` marks `slots[slot_key] = today` unconditionally (`checkin.py:763-771`) → a failed POST loses that day's slot.
- speedtest: `SPEEDTEST_LAST_FILE` written regardless (`checkin.py:843-849`).
- webperf/latency: same (`checkin.py:940-945`; latency = one POST per target).

Dashboard result routes (`src/app/api/sensor/{iperf,speedtest,latency,webperf}-result/route.ts`) have **no try/catch around `db.insert`** → a transient DB error (pool exhaustion, deploy restart, migration lock) is a 500, swallowed identically. The dashboard restarts the web app on every push to main → every deploy is a loss window for every sensor mid-report.

**Fix (collector suffices).** Make `_post` return success/failure; only write the slot/last-run ledger on confirmed 2xx; spool failed payloads to `/var/lib/netmon/result-spool/` and drain at next check-in. Dashboard: wrap route inserts, return 503 vs 500 for retryable cases.

### 4. Entire performance dataset never reaches the AI layer · High (policy) · CONFIRMED (Opus-verified)

**Mechanism.** `speedtest_results`, `iperf_results`, `latency_results`, `webperf_results`, `uplink_samples` have **zero references under `src/lib/ai/`** (verified — grep for both Drizzle identifiers and snake_case names returns empty). The chat tool catalog (`src/lib/ai/chat-tools.ts`) exposes `list_sites, device_counts, search_devices, search_switches, list_scans, devices_in_scan, site_findings, wireless_posture, wifi_experience` — nothing perf-related; the scheduled-analysis context (`src/lib/ai/context.ts`) likewise. The data lands in the DB and raw pages but the layer meant to produce insights/alerts is blind to it: a WAN speed collapse or 20% gateway packet loss can never surface in an AI finding, and "what's our internet speed at X?" has no tool to answer it.

**Fix (best quick win — aligns with the project's stated AI-insights direction).** Add a `perf_summary` tool (latest + 7-day trend per sensor for speedtest/latency/webperf/iperf, plus uplink utilization vs `school_committed_rate`) to `chat-tools.ts`, and fold aggregates into `context.ts`.

### 5. Enrollment-token collision silently 401-discards one box forever · Med-High · CONFIRMED mech / PLAUSIBLE trigger

**Mechanism.** `/api/sensor/enroll` revokes **all** existing tokens for the sensor on every enroll (`src/app/api/sensor/enroll/route.ts:95-101`). Two boxes sharing identity slugs resolve to the same `sensorId` (`getOrCreateSensorId`); the second enroll kills the first box's token. The loser then 401s on every check-in and result POST — all swallowed (`checkin.py:80-84`) — and never recovers: `_current_token` (`checkin.py:550-557`) returns the stored token, and auto-enroll only runs when the token is *empty* (`checkin.py:1106-1111`), so the revoked token is retried forever. Its SFTP bundles still ingest (SFTP path is token-less), making the picture look healthier while check-in-borne data (perf, host metrics, interface truth) is the winner's only.

**Fix.** Collector: on a 401 with a stored token, delete `TOKEN_FILE` and re-enroll next cycle. Dashboard: on enroll for a sensor with a recent `lastCheckinAt`, raise a security event / require confirm.

### 6. `saveSensorConfigAction` replaces desired config instead of merging — dormant but a loaded gun · Medium · CONFIRMED (dead code today)

`src/lib/admin/sensor-actions.ts:240-260` writes `set: { ..., config, ... }` containing only the SNMP/topo/SFTP form keys — a whole-document replace, while every sibling writer merges (`{...existing, ...patch}`, e.g. lines 425/503/664/724; `webperf-actions.ts:73` uses jsonb `||`). One call would silently delete `webperf_urls`, `iperf_*`, `speedtest_*`, `latency_*`, `wifi_join_*` from desired state; live boxes keep their env values so nothing changes visibly, but any re-imaged box then pulls the gutted config with perf features off. No call site exists today — flagged because it's exactly the class that ships in a UI refactor and passes every build. **Fix:** make it merge like its siblings, or delete it.

### 7. Out-of-order bundle re-ingest drops uplink samples & regresses Wi-Fi survey · Medium · CONFIRMED

Bundles process in SFTP listing order with no sort (`sync-core.ts:140-145,180-182`). A once-failed bundle is usually re-ingested after a newer hour landed; then `persistUplinkSamples` (`ingest.ts:816-818`) discards any sample `<= prev.sampledAt` ("keeps the series monotonic") → a permanent PERF-3 hole, and `persistWifiSurvey` (`ingest.ts:566-567`) is delete-and-replace with no timestamp guard → the older survey replaces the newer, regressing "current posture" until the next survey. **Fix:** sort `fresh` by the filename `YYYY_MM_DD_HH` stamp (`sync-core.ts`); guard the survey replace with `generated_at > existing.generatedAt`.

### 8. Command results: crash → stuck `sent` forever; `scheduled` coerced to `done` · Med-Low · CONFIRMED

Check-in marks commands `sent` on dispatch (`src/app/api/sensor/checkin/route.ts:156-161`); a mid-command crash or swallowed result POST leaves it `sent` forever (no timeout/re-dispatch), losing the requested scan/logs/diag. Separately `src/app/api/sensor/result/route.ts:29` coerces the collector's `"scheduled"` (host actions/updates, `checkin.py:489,1201`) to `done`, so a host action that later fails shows green `done`; the real outcome only lands in `sensors.lastHostAction` next check-in. **Fix:** accept `scheduled` in route+schema; add a sweep flipping stale `sent` → `expired`.

### 9. Legacy/pre-identity boxes: config backups never stored; scans → district "unknown" · Low · CONFIRMED

An identity-less box uploads config backups to `_config/<hostname>/` (`config_backup.py:42-52`), but `configSlugsFromPath` requires 3 slugs after `_config` (`src/ingest/config-backup.ts:28-37`) and returns null → `configBackupStored` returns **true** ("don't bother downloading", `config-backup.ts:107-110`) → skipped forever, no log. Slug-less `scan.json` routes bundles to district `unknown` (`ingest.ts:326-339`); `resolveIdentity` keys the whole bundle off `scans[0]`, so a bundle straddling identity-config files all scans under the pre-identity tenancy. **Fix:** log unparsed `_config` paths; resolve identity per-scan (or prefer newest scan's slugs).

### 10. Bundle reader swallows corrupt artifacts as empty; bundle still marked `parsed` · Low · CONFIRMED

`readJson` returns the fallback on any parse error (`src/ingest/bundle.ts:510-517`); a truncated `findings.json`/`dhcp-observed.json`/`scan.json` ingests as `[]`/`{}` with `parseStatus='parsed'`, `parseError=null`, counts just lower. A collector serialization regression could zero one data type fleet-wide with a fully green pipeline (same shape as the Cloudflare-UA incident, on the bundle path). **Fix:** count parse-fallback hits into `ingested_bundles.parse_warnings`; alert when a bundle has scans but zero devices/dhcp/snmp.

---

## Seams checked and found SOUND (coverage — don't re-audit these blind)

- **Edge allowlist** (`src/proxy.ts:38-45`): all 8 collector POST targets present, exact-match.
- **Result-POST field contracts end-to-end**: every key in `_report_{speedtest,iperf,latency,webperf}` matches its route reader (`coerceNum/Int/Str`, `parseStartedAt` in `src/lib/sensor/payload.ts`) and a real Drizzle column; `ok` semantics match (`b.ok !== false` vs `res.get("ok", False)`).
- **Date/type handling on delivery paths**: collector DB is `TIMESTAMPTZ`; bundle export tags UTC; result routes hand real `Date` objects to the drizzle codec — the known drizzle+postgres.js raw-SQL date trap is **not** present on any traced write path.
- **SFTP upload retry ledger**: failed uploads retry every tick incl. after restarts; ingest failures roll back the whole transaction and retry next sync (`sync-core.ts:212-216`).
- **WIFI-6 dedup**: `uq_speedtest_wifi_run` / `uq_webperf_wifi_run` / wifi_experience unique targets exactly match the `onConflictDoNothing` targets; wired rows (ssid NULL) can't collide.
- **Check-in ground-truth roundtrip**: `currentConfig`/`hostMetrics`/`interfaces`/`lastUpdate`/`lastHostAction` all map to real `sensors` columns.
- **Webperf push** always materializes a non-empty URL list (`DEFAULT_WEBPERF_URLS`), so an enabled district can't be stranded.

## Needs runtime verification (worklist)

- **#2 field rate — do this first, it quantifies the bleed:** on Monitor1, diff `scan_runs.completed_at` hours vs `bundle_uploads.filename` hours over the last 30 days to count already-orphaned hours.
- **#1:** reproduce upload-now → later scan → hourly tick → sync `skipped` on Monitor1 (~5 min; confirms the log line).
- **#5:** on a lab box, confirm a revoked-token box never self-heals and the dashboard shows no anomaly while two boxes share slugs.
- **#6:** confirm no route reaches `saveSensorConfigAction` in the built app (static grep says dead).
- SFTP listing order (affects #7 frequency only); sanity-check one stored `started_at` for microsecond precision.

## Suggested action order

1. **#1 + #2 together** (both live in the collector uploader + one dashboard idempotency change) — this is the actual "sensor looks healthy, data missing" bleed, and #2's runtime diff tells you how bad it already is.
2. **#4** — cheapest high-value win and directly on-strategy (AI = insights); one new chat tool + context aggregate.
3. **#3, #5** — resilience against the routine restart/deploy/enroll churn.
4. **#6–#10** — hardening; #6 is a pre-emptive guard against a future refactor.
