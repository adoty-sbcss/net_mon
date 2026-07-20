# NetMon Fable Audit Program

Deep cross-repo audits run on **Claude Fable 5** (Anthropic's most capable model) during a
time-boxed free-credit window. The goal: spend premium reasoning on the exhaustive,
breadth-first work that is normally too expensive to justify, and leave behind **durable
artifacts every future Opus chat can act on**.

**Repos in scope**
- Collector / sensor: `net_mon` (this repo) — `github.com/adoty-sbcss/net_mon`
- Dashboard: `netmon-dashboard` at `C:/Users/Adam.Doty/netmon-ux` — `github.com/adoty-sbcss/netmon-dashboard`

## How the program is run (so it can be repeated cheaply)

1. **Orientation on Opus (cheap):** map the relevant files in both repos, hand the model a precise target list.
2. **Deep hunt on Fable (expensive):** one strongly-scoped Fable agent per audit returns ranked, evidence-backed findings (file:line + mechanism + repro + fix sketch).
3. **Verify + write-up on Opus (cheap):** confirm the top findings against the code, discard the speculative ones, write the report here.
4. **Checkpoint before moving on:** each report is committed and a one-line memory pointer is added to `MEMORY.md` so the finding survives even if the credit window closes mid-program.

Audits run **sequentially, highest-value first**, so a partial run still banks the most important results.

## Status

| # | Audit | Report | Status |
|---|-------|--------|--------|
| 1 | Silent data-loss hunt (collector → dashboard delivery seam) | [01-silent-data-loss.md](01-silent-data-loss.md) | ✅ done — 10 findings (1 Critical, 3 High) |
| 2 | Deploy / infra safety (bicep drift, blind-apply blast radius, pipeline fragility) | [02-deploy-safety.md](02-deploy-safety.md) | ✅ done — 13 findings (2 Critical, 4 High) + blast-radius table |
| 3 | Data-contract audit (fields collected → ingested → exposed to AI) | [03-data-contract.md](03-data-contract.md) | ✅ done — 29-row matrix, 8 AI-exposure gaps + config-knob coverage |
| 4 | Test / failure-path gap map (test-bootstrap plan) | [04-test-gaps.md](04-test-gaps.md) | ✅ done — harness + 17 ranked tests + phase split |

**Program complete (2026-07-02):** all four audits run on Fable, verified on Opus, committed.

## Top priorities across the program (synthesis)

If you act on nothing else, act on these — ranked by field impact:

1. **[A1 #1, Critical] Bundle idempotency loses mid-hour scans.** `upload-now` ships a partial hour; the hourly rebuild reuses the filename; the dashboard's filename-only ingest guard (`ingest.ts:986`) refuses to re-parse → scans added mid-hour vanish. Fix = content-aware re-ingest on newer `builtAt`. Pair with A1 #2 (no backfill) — together they are the "sensor looks healthy, data missing" bleed. Quantify first on Monitor1 (diff `scan_runs` hours vs `bundle_uploads` hours).
2. **[A2 #1/#2, Critical] A full `main.bicep` apply still breaks prod.** The env/secrets arrays only declare a subset, so an apply drops OIDC/email/SFTP-provisioning env; a re-apply that regenerates `AUTH_SECRET` makes the in-DB SFTP config undecryptable. Fix = reconcile the full live env/secrets into bicep (like the domain binding already got); read the two secrets from Key Vault on re-apply. Until then, follow the safe-deploy checklist in `02`.
3. **[A4 Phase 1] Stand up the test harness (~1 day).** Reuses the codebase's own text-parse drift-guard idiom. Catches, structurally: the proxy.ts build-breaker, un-allowlisted sensor routes, collector↔dashboard contract drift, the bicep env-wipe class, and surfaces two live bugs as red tests. This is the highest-leverage follow-up the whole program points to.
4. **[A3 gap 1, best AI win] Sensor fleet health is invisible to the AI.** Add a `sensor_health` chat tool + analysis-context block so "which sensors are unhealthy/failed update" can become an insight. Smallest change, on-strategy.

## Remediation ledger

Kept current so the reports stay a WORKLIST, not a museum — check here before
re-fixing something. Dashboard PRs #127–#132 were built the night of
**2026-07-19/20** with GitHub Actions billing-blocked, so they carry local-gate
proof and merge when Actions is restored ("open" below = ready, unmerged).

| Finding | Status | Where |
|---|---|---|
| A1 #1 bundle idempotency (Critical) | **fix open** | dashboard #127 — builtAt-aware re-ingest + mtime-aware re-download, validator-pinned (`ingest:check`) |
| A1 #2 backfill for missed hours | **✅ fixed** | collector `_catch_up_missed_hours` (+ `test_uploader_catchup.py`) |
| A1 #3 perf results lost on failed POST | **✅ fixed** | collector result spool + drain (`test_result_spool.py`) |
| A1 #4 perf invisible to AI | **partial** | `throughput_history` (speedtest+iperf) + `wifi_experience` (webperf) shipped; `latency_results` + `uplink_samples` still unexposed |
| A1 #5 revoked token never self-heals | **fix open** | collector [#51](https://github.com/adoty-sbcss/net_mon/pull/51) — 3×401 → clear file token + re-enroll; enroll-refusal backoff. Deliberately NOT self-merged (enroll path → fleet) |
| A1 #6 / A3 §D `saveSensorConfigAction` replace-not-merge | **fix open** | dashboard #129 — merges like its siblings (still dead code, now defused) |
| A1 #7 out-of-order ingest (uplink drop, survey regress) | **fix open** | dashboard #127 — hour-order sort + survey generated_at guard |
| A1 #8 commands stuck `sent` / `scheduled` coerced | **fix open** | dashboard #132 — `scheduled`+`expired` states, route honesty, 24h maintenance sweep |
| A1 #9 pre-identity boxes | open | unchanged |
| A1 #10 corrupt artifacts swallowed | **✅ fixed** | dashboard F-DASH-8 (`parseErrors` → durable `parse_error` + loud log) |
| A2 #1/#2 bicep env-wipe + AUTH_SECRET rotation | **✅ fixed (2026-07-02/03)** | `env:check` drift validator (dashboard #29) + the FULL bicep reconciliation: dashboard #31 (8 out-of-band env + 3 KV secret refs into the web app; AUTH_SECRET/DATABASE_URL can no longer rotate on apply), #32/#33 (job/CAE field reconcile) — all `az what-if`-verified; see `infra/WHATIF.md`. A full apply is now a no-op modulo documented benign what-if artifacts |
| A2 #3/#6 deploy.yml has no gate | **fix open** | dashboard #128 — pre-deploy `check` job + `needs:` + deploy concurrency queue |
| A3 gap 1 sensor fleet health invisible to AI | **fix open** | dashboard #130 — `sensor_health` tool (same flags as /sensors page) + prompt routing |
| A3 gap 5 check-in drops 5 config keys | **fix open** | dashboard #129 — whole `currentConfig` persisted verbatim (`reported_config` jsonb) + shown on the sensor page |
| A4 collector pytest harness | **✅ done** | `collector/tests/` (13 files, incl. #15 self-heal tests shipping with A1 #5) + CI |
| A4 dashboard harness | **partial** | tsx-validator idiom extended (`ingest:check`, `env:check`) + tsc/`next build` CI gates in #128; vitest skeleton still open |

**Cross-cutting themes:** (a) *silent-because-swallowed* — `_post` and several ingest paths log-and-continue, so failures never surface (A1 #3, #10); (b) *shipped-but-unconsumed* — perf data, traffic stats, `inventory.json`, reported topology config are collected but dropped before AI/DB (A3); (c) *no safety net* — no tests, no post-deploy healthcheck, a no-op DB rollback (A2 #3/#5, A4). Recurring root cause: green checks that verify a *different* condition than the one that matters.

Two findings were independently re-discovered by more than one audit (the `saveSensorConfigAction` replace-not-merge bug: A1 #6 = A3 §D; the perf→AI gap: A1 #4 ⊂ A3) — corroboration, not duplication.

## How to read a report

Each report ranks findings by **field impact × confidence**. Every finding carries:
the exact mechanism (why it passes green checks but still loses data), file:line anchors in
**both** repos, a concrete trigger/repro, and a fix sketch. Confidence is marked
CONFIRMED (traced in code) vs PLAUSIBLE (needs a runtime check).

Findings are **not auto-applied** — they are a worklist for a human + a normal Opus session.
