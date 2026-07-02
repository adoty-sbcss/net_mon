# Audit 4 — Test-bootstrap plan

**Run:** Claude Fable 5 (grounded in audits 01–03 + the four known incidents) → verified/curated on Opus 4.8, 2026-07-02.
**Framing:** NetMon has **no automated test suite**. Collector CI = ruff + mypy + compileall + import-smoke + console-allowlist drift check (no pytest, no `tests/`); dashboard CI = `console:check` + `topology:check` only (no tsc, no `next build`, no test runner). So this is not a coverage report — it's the minimal harness + the specific first tests that would have caught the failures that actually shipped or nearly shipped.

## Verification status (Opus)

Keystone harness claims re-confirmed: `src/db/index.ts:42` is a lazy `Proxy` (materializes Drizzle on first access) → imports are side-effect-free, so unit tests and `next build` need no live DB; 48 dashboard files import `server-only` (validates the vitest stub recommendation); both `console-allowlist.validate.ts` + `graph.validate.ts` drift-guards exist (the proven text-parse idiom this plan extends). The "FAIL today" tests map to already-verified audit findings (check-in drop, bicep env, ledgers, idempotency, merge). Plan is sound.

**Key insight:** this codebase already has a proven, org-accepted test idiom — the **text-parsing drift guard** (`console-allowlist.validate.ts` parses `broker/index.js` as text; a collector CI step checks a committed manifest). The highest-ROI tests below reuse that idiom for every cross-repo contract: no DB, no Next runtime, no `server-only` workarounds, already has buy-in.

---

## 1. Harness setup

### Collector — pytest
Layout `collector/tests/{conftest,test_contracts,test_ledgers,test_apply_config,test_db_ledger}.py` + `collector/contracts/sensor-api.json`. Add `"pytest>=8"` to the `dev` extra in `collector/pyproject.toml:31-34` (CI already `pip install -e "collector[dev]"`).

Verified fixture facts:
- `Settings` is pydantic-settings with `env_file=None, extra="ignore"` (`config.py:9-10`) — build via `monkeypatch.setenv`; reset the singleton with `monkeypatch.setattr(collector.config, "_settings", None)` (`config.py:312-318`).
- Ledger paths are module constants (`checkin.py:585-591`) — monkeypatch to `tmp_path`.
- **`_post` (`checkin.py:70-84`) is the single network chokepoint for every dashboard POST** — monkeypatch once to capture `(url, body)` or simulate failure (`return None`). Makes almost the whole check-in surface testable with zero network.
- Unix-only imports are already lazy (existing lesson) so import works on Windows; CI is Linux regardless.
- DB tests: mark `@pytest.mark.db`, skip unless `POSTGRES_HOST` set; CI provides a `postgres:16` service.

CI edit (collector `ci.yml`, after import-smoke): `pytest collector/tests -q -m "not db"`. Phase 2 adds a `postgres:16` service job running `-m db`.

### Dashboard — vitest (recommended over node:test)
Why vitest: 48 lib modules import `server-only` (throws outside the `react-server` condition) — vitest solves it with one `resolve.alias` (`server-only` → empty stub); node:test would need `--conditions` + a tsx loader + manual `@/` alias threading through every call. tsconfig `@/` paths resolve via config. drizzle+postgres.js are runtime-neutral and `src/db/index.ts` is a **lazy proxy** — tests import anything DB-adjacent and never connect unless a query runs. **Constraint: no React component tests** (React 19.2 + Next 16 under vitest is the pain zone) — everything here is node-env server logic, text parsing, or DB integration.

Files: `vitest.config.ts` (`environment:'node'`, alias `@`→`./src`, alias `server-only`→`tests/stubs/empty.ts`) + `tests/{contracts,unit,integration,fixtures}/` + `contracts/sensor-api.json`.
`package.json` scripts: `"typecheck": "tsc --noEmit"`, `"test": "vitest run --exclude \"tests/integration/**\""`, `"test:integration": "vitest run tests/integration"`. Dev dep: `vitest`.

CI edit (dashboard `ci.yml`, after `topology:check`):
```yaml
      - name: Type check
        run: npm run typecheck
      - name: Unit + contract tests
        run: npm test
      - name: Production build          # THE proxy.ts/middleware.ts gate (SEC-4)
        run: npm run build              # buildable without env — db client is lazy
```
Phase 2: an `integration` job with `postgres:16` + `db:migrate` + `test:integration`.

Also (audit 2 #3/#6): `deploy.yml` doesn't depend on CI. Cheapest fix — add a first `check` job in `deploy.yml` running `npm ci && npm run typecheck && npm test` and make `deploy` `needs: check`. Converts the mid-deploy `az acr build` failure (lost cycle) into a pre-deploy failure.

### Cross-repo contract seam
Reuse the committed-manifest pattern: `contracts/sensor-api.json` describes the 8 sensor endpoints, each result payload's key set, the check-in `currentConfig` keys, and desired-config keys the dashboard pushes. Collector pytest asserts collector code matches; dashboard vitest asserts routes/schema match. Since **net_mon is public**, dashboard CI can optionally fetch the collector's manifest from raw.githubusercontent and diff (fall back to local copy on fetch failure) — closes the "two mirrors drift" hole `console:check` tolerates.

---

## 2. Ranked test list

**FAIL today** = doubles as a confirmed-bug worklist item. Effort: S ≈ <1h, M ≈ half-day, L ≈ day+.

| # | Test | Asserts | Guards | Today | Effort |
|---|------|---------|--------|-------|--------|
| 1 | Dashboard CI build gate (`tsc --noEmit` + `next build`) | app type-checks + builds | Audit 2 #6; proxy.ts (SEC-4) | PASS | **S** |
| 2 | `proxy-allowlist.test.ts` | every bearer-auth sensor route is Edge-exempted | allowlist-307 lesson; A1 seam | PASS | **S** |
| 3 | `checkin-groundtruth.test.ts` | every `currentConfig` key persisted | A3 gap 5 | **FAIL** | **S** |
| 4 | `sensor-payload.test.ts` + collector `test_contracts.py` | payload keys ⇄ route readers ⇄ columns | A3 class; A1 seam | PASS | **M** |
| 5 | `migration-safety.test.ts` | no destructive DDL / bare unique index | A2 #13 | PASS (baselined) | **S** |
| 6 | `bicep-env.test.ts` | every `process.env.X` declared in bicep or baselined | A2 #1 | **FAIL (strict)** | **S** |
| 7 | Collector `test_ledgers.py` | scheduled-run ledgers advance only on 2xx | A1 #3 | **FAIL** | **S** |
| 8 | `ingest-idempotency.test.ts` | rebuilt same-filename bundle w/ newer `builtAt` re-ingests | A1 #1 (Critical) | **FAIL** | **M** (PG) |
| 9 | `test_apply_config.py` + `deploy-sensor-env.test.ts` | sftp_enabled flag round-trips; install flow flips it | SFTP-flag lesson | PASS (pins) | **S** |
| 10 | `date-roundtrip.test.ts` + static `sql<Date>` guard | dates survive write→read as real `Date`s | drizzle date-trap lesson | PASS (pins) | **M** (PG) |
| 11 | `bundle-reader.test.ts` (corrupt artifact) | truncated JSON → parse warning, not silent `[]` | A1 #10 | **FAIL** | **M** |
| 12 | `sync-order.test.ts` | bundles ingest in filename-hour order | A1 #7 | **FAIL** | **S–M** |
| 13 | `desired-config-merge.test.ts` | config writers merge, never replace | A1 #6 / A3 §D | **FAIL** | **M** (PG) |
| 14 | Collector `test_db_ledger.py` | `record_bundle_built` resets `uploaded_at` on rebuild | A1 #1 collector half | PASS | **S** (PG) |
| 15 | `test_enroll_selfheal.py` | 401 w/ stored token → cleared, re-enroll next cycle | A1 #5 | **FAIL** (feature absent) | **M** |
| 16 | `test_backfill.py` | scan-hours w/ no `bundle_uploads` row get built at scheduler start | A1 #2 | **FAIL** (feature absent) | **L** |
| 17 | Desired-config knob contract | every dashboard-pushed key handled by `_apply_config` | A3 §D drift class | PASS | **M** |

### Notable sketches

- **#1 build gate** — the *only* thing that catches `src/middleware.ts` vs `src/proxy.ts` (tsc + eslint verifiably miss it; cost a deploy cycle). Add the three CI steps + a 3-line vitest canary `expect(existsSync("src/middleware.ts")).toBe(false)`.
- **#2 allowlist coverage** — glob `src/app/api/sensor/**/route.ts`, keep those containing `resolveSensorFromBearer` (the self-auth marker — all 8 today), assert each path appears in `proxy.ts:37-48`'s exemption block (regex-extract literals, like `console-allowlist.validate.ts`). Collector-side pytest asserts `checkin.py`'s POST targets equal the manifest. Fails in the same PR that adds an un-allowlisted route.
- **#3 check-in ground-truth** — manifest = 11 `currentConfig` keys (`checkin.py:1143-1155`); assert `route.ts:119-132` reads+maps each. **FAILS today on exactly 5 keys** (`snmp_exclude`, `snmp_topology_{enabled,scope,max_depth,interval}`) — A3 gap 5 verbatim. Ship red→green with the route fix.
- **#5 migration-safety** — read `drizzle/*.sql`; for non-baselined files fail on `DROP …`, `SET NOT NULL`, `ALTER … TYPE`, `RENAME`, `CREATE UNIQUE INDEX` unless a preceding dedup exists in the same file. Grandfather `0037`, `0059`. Mechanizes the A2 checklist line ("dedup first, same file").
- **#6 bicep env completeness** — grep `process.env.([A-Z0-9_]+)` (inventory: AUTH_SECRET, DATABASE_URL, APP_ORIGIN, AUTH_MICROSOFT_ENTRA_ID_*, AUTH_GOOGLE_*, ACS_CONNECTION_STRING, EMAIL_FROM, AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_MANAGED_IDENTITY_CLIENT_ID, DEPOT_SFTP_*, BROKER_WSS_URL, SFTP_*), parse `main.bicep`'s env array (~466-471 + aiEnv 222-234), assert each is in bicep or in a committed `infra/env-out-of-band.json` with a justification. FAILS today on ~11 vars = A2 #1's wipe list. Ship with the baseline populated (the baseline *is* the reconciliation worklist); any *new* var then fails CI until declared. When A2 action-1 lands, the baseline shrinks to `[]` and the env-wipe class becomes structurally impossible to reintroduce silently.
- **#7 ledger-vs-POST** — monkeypatch `_post`→`None`, run `_maybe_scheduled_iperf`/`_maybe_scheduled_speedtest`/`_maybe_webperf`, assert the ledger did **not** advance; then `_post`→`{"ok":true}` and assert it does. **FAILS today** (`slots[...] = today` unconditional, `checkin.py:763-771`; `SPEEDTEST_LAST_FILE` written regardless, 843-849) — A1 #3.
- **#8 bundle idempotency** (PG) — ingest fixture dir A (scan 10:05), then A′ (same filename, scans 10:05+10:30, newer `builtAt`); assert 2nd call is not `{skipped:true}` and `scan_runs` has 2 rows. **FAILS today** at `ingest.ts:986-988` — A1 #1 Critical. The delete-and-rebuild path it needs already exists (`ingest.ts:1001-1008`).
- **#13 merge invariant** (PG) — seed `desired_config` with `webperf_urls`+`iperf_*`, invoke `saveSensorConfigAction`'s write (`sensor-actions.ts:240-263`), assert untouched keys survive. **FAILS today** — replace-not-merge, re-found by two audits.

(Full per-test detail for #4, #9, #10, #11, #12, #14, #15, #16, #17 is in the audit transcript; the table + guards above are the actionable core.)

---

## 3. Phase split

**Phase 1 — first ~6, all cheap, no DB, biggest class coverage** (build order):
1. **CI gates (#1):** tsc + `next build` in dashboard `ci.yml`; `deploy.yml` pre-deploy `check` job. *(Highest-leverage change in this plan.)*
2. **vitest + pytest skeletons** with one trivial passing test each, wired into both `ci.yml`s — the harness itself is the deliverable.
3. **Allowlist coverage (#2).**
4. **Check-in ground-truth (#3)** — lands RED; fix in the same/next PR.
5. **Migration-safety guard (#5).**
6. **Bicep env completeness (#6)** with the out-of-band baseline, + **scheduled-result ledger (#7)** on the collector.

Phase 1 nets: the two repeat build/deploy incident classes gated; the collector↔dashboard seam frozen at its three drift points (routes, payloads, check-in config); one Critical audit finding (deploy env-wipe) fenced; two confirmed bugs (dropped config keys, lossy ledgers) surfaced as red tests.

**Phase 2** (in order): result-payload contract (#4) → PG integration rig (service containers both repos) → bundle idempotency #8 + collector ledger #14 (ship with the A1 #1 fix) → SFTP-flag trio #9 → date round-trip #10 → corrupt-artifact #11 + sync order #12 → merge invariant #13 → knob contract #17 → self-heal #15 / backfill #16 with their features.

## 4. Cheap parse/unit vs real environment

- **Cheap (no DB/network — the majority):** #1, 2, 3, 5, 6, 9b/9c, 10-static, 12 (text-parse/glob, the `console:check` idiom); #4, 7, 9a (pytest + monkeypatched `_post` + tmp files); #11 (pure fs fixtures — `readBundleDir` takes a directory).
- **Real Postgres (GitHub Actions `postgres:16` service — no Azure, no SFTP):** #8, 10-integration, 13, 14, later 15/16. Dashboard: service + `drizzle-kit migrate` + vitest integration (lazy proxy means just export `DATABASE_URL`). **Don't** use testcontainers/docker-in-docker — service containers match how these apps run.
- **Genuinely live infra (out of scope — keep as runbook checks):** real SFTP round-trip, bicep `what-if`, Monitor1 canary, anything touching the enrolled fleet. None of the 17 tests depend on these.
- **README caveat:** vitest must alias `server-only`→empty stub; integration tests import route *handlers*, never `src/app/**` pages.

## Bottom line

Do **Phase 1** and you have caught, structurally: the proxy.ts build-breaker, a new un-allowlisted sensor route, the collector↔dashboard contract drift at all three seams, the full-`main.bicep`-apply env-wipe class, and two live bugs — for roughly a day of work, using an idiom the codebase already trusts. That is the highest-leverage engineering follow-up the whole audit program points to.
