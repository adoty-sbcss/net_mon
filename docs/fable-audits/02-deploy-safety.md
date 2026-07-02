# Audit 2 — Deploy & infra safety ("a deploy or infra apply breaks prod or the fleet")

**Run:** Claude Fable 5 deep hunt → verified/curated on Opus 4.8, 2026-07-02. Static code/config audit only — **no `az` commands were run**.
**Repos:** dashboard/Azure = `netmon-dashboard` at `C:/Users/Adam.Doty/netmon-ux/`; collector = `net_mon` (this repo).

## Verification status (Opus)

Independently re-confirmed against source (line refs landed exactly): **#1** (`main.bicep` secrets/env arrays + the self-admitting comment at ~L99), **#2** (`main.bicepparam:13-14` `readEnvironmentVariable` + the "generate a NEW one" comment + `AUTH_SECRET` decrypts in-DB SFTP creds), **#5** (`db-snapshot.sh` dumps without `--clean`; `rollback.sh` pipes into the existing DB with `ON_ERROR_STOP=1` → aborts; comment describes non-existent code), **#6** (dashboard `ci.yml` runs only `console:check`/`topology:check`, no `next build`/tsc), **#12** (headless VLAN apply IS backend-aware at `trunk.sh:212-218`; only the interactive wizard `trunk.sh:~355` leaks the file). The rest carry Fable's CONFIRMED marking with accurate anchors; PLAUSIBLE items need a live `az what-if`.

> **Memory note:** the `MEMORY.md` index line for VLAN/netplan read "fix not yet built" — stale. The underlying `lesson_vlan_networkmanager_netplan` memory is current (fix shipped `541cd3b`, 2026-06-24; headless path is backend-aware) and already lists the interactive-wizard gap as a known minor followup. #12 re-confirms that followup against current code; the stale index line was corrected.

## Findings (ranked by blast-radius × likelihood)

| # | Finding | Severity | Confidence |
|---|---------|----------|-----------|
| 1 | Full `main.bicep` apply wipes web-app out-of-band env/secrets (OIDC, email, SFTP-provision, AI keys) | **Critical** | CONFIRMED (Opus-verified) |
| 2 | `AUTH_SECRET`/`PG_ADMIN_PASSWORD` re-read from shell env → apply rotates session-signing + SFTP-decryption key / resets DB pw | **Critical** | CONFIRMED (Opus-verified) |
| 3 | Pipeline re-points all jobs to new code *before* the migration gate; no post-roll healthcheck/rollback | High | CONFIRMED |
| 4 | Collector `:stable` publishes on every main push, ungated by CI → one bad merge hits whole fleet that night | High | CONFIRMED |
| 5 | Collector rollback's DB restore is a guaranteed no-op — "3-component rollback" is really 2 | High | CONFIRMED (Opus-verified) |
| 6 | Dashboard CI runs no `next build`/tsc/eslint — proxy/middleware build-breaker class has zero coverage | High | CONFIRMED (Opus-verified) |
| 7 | Two unattended prod deploy paths (weekly rebuild) migrate + roll with un-pinned base images, no health gate | Med-High | CONFIRMED |
| 8 | Postgres block pins day-one SKU/storage/backup → apply reverts live scaling or fails mid-flight | High | PLAUSIBLE (needs what-if) |
| 9 | Migration gate: execution-name race, 15-min poll vs 30-min job timeout, `enrich` bundled into the gate | Medium | CONFIRMED |
| 10 | `\|\| echo` guards on job/broker re-points swallow real failures → silent stale code in prod | Medium | CONFIRMED |
| 11 | No `concurrency:` on `deploy.yml` → two rapid pushes interleave | Medium | CONFIRMED |
| 12 | Interactive VLAN wizard writes/leaves a poisoned netplan file on NetworkManager boxes | Medium | CONFIRMED (Opus-verified) |
| 13 | Migration content risk low today, but the two guardrails (backup, pre-index dedup) are implicit | Medium | CONFIRMED (pattern) |

---

### 1. Full `main.bicep` apply wipes the web app's out-of-band env + secrets · Critical · CONFIRMED
Same class as the custom-domain near-miss, **still live**. The domain binding was reconciled into bicep after the incident (`main.bicep:102-112`), but the container app's `secrets` and `env` arrays were not. Bicep declares only `auth-secret`/`database-url`(+AI) as secrets (`main.bicep:443-454`) and only `AUTH_SECRET/DATABASE_URL/NODE_ENV/APP_ORIGIN`(+aiEnv) as env (`main.bicep:465-472`). The live app also carries — applied via `az containerapp update` (docs/DEPLOY.md:316-331) — `AUTH_MICROSOFT_ENTRA_ID_*`, `AUTH_GOOGLE_*`, `ms-secret`/`google-secret`, `ACS_CONNECTION_STRING`, `EMAIL_FROM`, `AZURE_SUBSCRIPTION_ID`, `AZURE_MANAGED_IDENTITY_CLIENT_ID`, `DEPOT_SFTP_*`, `BROKER_WSS_URL`. An ARM PUT replaces both arrays wholesale. `main.bicep:99` admits it: *"a full bicep redeploy reapplies APP_ORIGIN but you must re-add those auth env vars."*
**Blast radius:** Microsoft/Google sign-in breaks for every district user (only break-glass local login survives); notification email dies; per-district SFTP user minting dies; AI features die if `anthropicApiKey` param not re-supplied (default `''`).
**Trigger:** any `az deployment group create -f infra/main.bicep` in default Incremental mode — even a "successful" one.
**Fix:** reconcile the full live env/secret set into `main.bicep` (non-secret IDs as params w/ live defaults, secrets as KV refs — same treatment the domain got) so an apply is a no-op. Until then, snapshot the live env + secrets before/after any apply.

### 2. `AUTH_SECRET`/`PG_ADMIN_PASSWORD` re-read from shell env on every apply · Critical · CONFIRMED
`main.bicepparam:13-14`: both `readEnvironmentVariable(...)`. An apply writes them as **new KV secret versions** (`main.bicep:350-360`) and sets the Postgres admin password (`main.bicep:835`); the app uses versionless KV URIs (latest wins). `AUTH_SECRET` is not just session signing — it **decrypts the in-app SFTP ingest config stored encrypted in the DB** (confirmed: maintenance-job comment "AUTH_SECRET decrypts the SFTP creds"). The bicepparam comment itself says "generate a NEW one for prod" — fine from-scratch, catastrophic on **re-apply**: supply a fresh value and all sessions invalidate **and every encrypted SFTP credential in the DB becomes undecryptable → fleet ingestion silently stops with no error at apply time**. (Recovery: an admin re-saves the SFTP config in Settings → re-encrypts under the new key — so it's recoverable, but only once someone notices ingestion died.) A wrong `PG_ADMIN_PASSWORD` resets the server login and rewrites `DATABASE-URL`.
**Fix:** on re-apply, read current values *from Key Vault* (checklist below); add a loud `main.bicepparam` comment that on re-apply these MUST be the live values, never regenerated.

### 3. Jobs re-pointed to new code *before* the migration gate; no post-roll healthcheck · High · CONFIRMED
`deploy.yml` order: build → re-point ingest(103)/AI(112)/enrich(122)/maintenance(132) → *then* migrate+wait(143-171) → roll web(173) → roll broker(186). A failed migration correctly blocks the web roll (`deploy.yml:167`), but four scheduled jobs already run new code against the old schema until someone notices. After a *successful* roll there is no smoke test / health probe / revision rollback (`activeRevisionsMode: 'Single'`, `main.bicep:419`) — a runtime-only bug ships and stays.
**Fix:** move the four `job update` steps *after* the migration gate; add a post-roll health curl with `az containerapp revision` rollback on failure.

### 4. Collector `:stable` = every push to main, ungated by CI · High · CONFIRMED
`build-collector.yml:10-13` publishes `:stable` on every main push, in **parallel** with `ci.yml` (no `needs:`/cross-workflow gate) — an image can ship to `:stable` while CI is red on that commit. Every default-channel box pulls `:stable` at 03:00 (+≤30 min jitter) with no staged rollout. The net is each box's 120 s selftest + auto-rollback (`auto-update.sh:392-424`), but selftest checks DB/tools/disk/interfaces/capabilities/control-plane (`selftest.py:32-41`) — a bug that scans wrong / uploads garbage / corrupts data passes it, degrading the fleet by morning.
**Fix:** gate the publish on CI success (single workflow with `needs:`, or `workflow_run` on CI success). Better: `:canary` on main, promote `:stable` only after Monitor1 (canary channel) survives a night — the channel plumbing exists (`auto-update.sh:230-261`).

### 5. Collector rollback's DB restore is a guaranteed no-op · High · CONFIRMED
`db-snapshot.sh:60-62` dumps with `pg_dump --no-owner --no-privileges` (no `--clean/--if-exists/--create`). `rollback.sh:109-110` pipes that into the **existing, non-empty** `netmon` DB with `-v ON_ERROR_STOP=1` → the first `CREATE TYPE`/`CREATE TABLE` collision aborts, hitting "WARN: snapshot restore reported errors — proceeding to container restart anyway" **every time**. After an auto-rollback: old code runs against the *new* migrated schema, and the operator believes DB state was restored. The comment "Drop + recreate the db, then load" describes code that doesn't exist. (Also: `db-snapshot.sh:9-10` claims auto-update aborts on snapshot failure, but `auto-update.sh:311-313` only WARNs and continues.)
**Fix:** dump with `--clean --if-exists` (or restore via `dropdb/createdb`); make auto-update actually abort on snapshot failure (or fix the comment).

### 6. Dashboard CI runs no `next build`/tsc/eslint · High · CONFIRMED
`ci.yml` runs exactly two tsx harnesses — `console:check` (38) and `topology:check` (43). Nothing type-checks or builds the app, and `deploy.yml` doesn't depend on CI. The first `next build` runs inside `az acr build` mid-deploy (`deploy.yml:47-53`) — the exact trap that cost a cycle with `src/middleware.ts` vs `src/proxy.ts` (SEC-4). Failure = lost deploy cycle (build fails before mutating), but combined with #3, anything that *builds* but breaks at runtime ships unchecked.
**Fix:** add `tsc --noEmit` + `next build` to `ci.yml`; optionally `deploy.yml` `needs:` a build check on the same SHA.

### 7. Two unattended prod deploy paths migrate + roll with un-pinned base images · Med-High · CONFIRMED
`deploy.yml:15-16` weekly rebuild (Mon 11:00 UTC ≈ 3–4 am PT) rebuilds all five images from main HEAD, re-runs migrations, rolls web+broker (designed to always roll, `deploy.yml:173-184`). Base images are un-pinned `node:24-alpine` (Dockerfile:4,10,61) — a broken upstream base lands on prod Monday morning unattended, no health gate (#3). (`refresh-data.yml`'s bot commit does **not** recursively trigger deploy — that part is fine.)
**Fix:** keep the weekly patch cadence but add the post-roll smoke test; pin base-image digests and let the weekly job be the only thing that bumps them.

### 8. Postgres block pins day-one SKU/storage/backup · High · PLAUSIBLE (needs what-if)
`main.bicep:825-850`: `Standard_B1ms`, `storageSizeGB: 32`, `backupRetentionDays: 7`, `version: '16'` + the admin-pw reset (#2). If live storage ever grew, an apply attempts a shrink — Azure rejects it, **failing the deployment after earlier resources (incl. the #1 env wipe) already PUT** (ARM group deploys are not atomic). Also `main.bicepparam:17-19`: with default `ASSIGN_ROLES=true`, a re-apply is *expected* to fail on `RoleAssignmentExists` — the documented default re-apply path is a guaranteed partial deployment.
**Fix:** what-if first; `ASSIGN_ROLES=false` for re-applies; reconcile SKU/storage to live.

### 9. Migration-gate fragility · Medium · CONFIRMED
(a) `deploy.yml:155-159`: `job start`, `sleep 8`, then pick the latest execution by startTime — if the new execution hasn't registered in 8 s the poll can latch onto the *previous* (Succeeded) one and report "Migrations applied." while the real one later fails; the roll proceeds on the wrong signal. `az containerapp job start` returns the execution name — use it. (b) Poll gives up at 90×10 s = 15 min while `replicaTimeout` is 1800 s (`main.bicep:505`) — a slow-but-successful migration aborts the deploy (jobs already re-pointed, #3). (c) Migrator CMD is `db:migrate && auth:seed && enrich` (Dockerfile:29) — an enrichment slowdown fails the "migration" gate though schema applied fine.
**Fix:** use the returned execution name; align poll window with `replicaTimeout`; move `enrich` out of the migrate CMD (nightly enrich job exists).

### 10. `|| echo` guards swallow real failures · Medium · CONFIRMED
`deploy.yml:130,141,195`: enrich/maintenance/broker update steps end with `|| echo "... not provisioned yet"`. All three resources now exist, so a genuine failure (ACR auth blip, bad image ref) prints a friendly message and the deploy goes green while that component runs old code. Worst: a console-allowlist change shipping to the dashboard but not the broker is exactly the drift `console:check` guards against.
**Fix:** remove the guards (all resources exist) or replace with an existence check that fails on any other error.

### 11. No `concurrency:` on `deploy.yml` · Medium · CONFIRMED
Two rapid pushes run two full pipelines in parallel; job re-points, migrate, and `containerapp update` calls interleave — an older SHA can win a later step, and two simultaneous migrate `job start`s worsen #9.
**Fix:** `concurrency: { group: deploy-prod, cancel-in-progress: false }` (queue, don't cancel).

### 12. Interactive VLAN wizard leaves a poisoned netplan file on NetworkManager boxes · Medium · CONFIRMED
The **headless** path is now backend-aware — `trunk.sh:212-218` routes NM boxes to `_apply_vlan_nmcli`, and the netplan path removes the file on validation failure + reverts on default-route loss (`trunk.sh:230-249`). The **interactive wizard** only warns on NM and proceeds: it writes `/etc/netplan/60-netmon-vlans.yaml`, and when `netplan generate` crashes on NM it warns and `return 0` **without removing the file** (`trunk.sh:~355`). The poisoned yaml persists, so any future `netplan generate/apply` (OS upgrade, cloud-init, other admin work) crashes — a delayed, hard-to-attribute landmine.
**Fix:** route the wizard through the backend check before writing (like headless), and mirror the headless `rm -f "$f"` on validation failure.

### 13. Migration content risk low today, guardrails implicit · Medium · CONFIRMED (pattern)
All 63 migrations: essentially no destructive DDL (one `DROP CONSTRAINT` in 0037 immediately replaced by a unique index; one idempotent backfill in 0061). The recurring risk pattern is **`CREATE UNIQUE INDEX` on existing data** (0037, 0059) — duplicate prod rows fail the migration mid-deploy (→ #3's mixed state). No backup step precedes migrate; the only net is the flexible server's 7-day PITR. drizzle-kit runs each migration transactionally (good — but blocks `CREATE INDEX CONCURRENTLY` if ever needed on a big table).
**Fix:** adopt the migration checklist (below); ship a dedup `DELETE`/`UPDATE` in the same migration *before* any unique index (0059 did not).

> **Security-adjacent (SEC-* chat owns it):** `install-auto-update.sh:144` grants the service user `NOPASSWD:ALL` — full root on every fleet box for whoever compromises that account; intersects the console threat model. Flagged for the security track, not fixed here.

---

## BLAST-RADIUS TABLE — `az deployment group create -f infra/main.bicep` (Incremental mode)

**Never use `--mode Complete`.** In Complete mode everything in the RG absent from `main.bicep` is DELETED: the broker container app (`broker.bicep`), the **SFTP depot storage `w2sbcssnetmondepot` incl. all sensor bundle data + SFTP local users** (`sftp-depot.bicep`), and any ACS/email or other out-of-band resources. Incremental-mode outcomes:

| Resource (main.bicep) | Apply outcome | Note |
|---|---|---|
| `logAnalytics` (242) | SAFE / REVERTS-DRIFT | Retention reconciled to 90; reverts only if tuned live |
| `vnet` (252) | REVERTS-DRIFT (risky) | `subnets` full-replace array — any out-of-band subnet/NSG association removed; in-use subnet change fails the deploy |
| `postgresPrivateDnsZone` + link (296) | SAFE | Static |
| `appIdentity`/`deployIdentity` (312) | SAFE | Name-only |
| `deployFederation` (323) | REVERTS-DRIFT | Subject pinned to `adoty-sbcss/netmon-dashboard:main`; re-pin breaks CI OIDC if repo slug changed. Verify live |
| `keyVault` (334) | SAFE | Purge protection on |
| `kvAuthSecret` (350) | **REVERTS/ROTATES — CRITICAL** | New version from `$AUTH_SECRET`; wrong value = sessions dead + encrypted SFTP configs unreadable (#2) |
| `kvDatabaseUrl` (356) | **REVERTS/ROTATES — CRITICAL** | Rebuilt from `$PG_ADMIN_PASSWORD`; must equal live |
| `storage` dash (363) | SAFE | Data untouched (Incremental never deletes data) |
| `acr` (376) | SAFE | Basic, admin off |
| `containerEnv` CAE (386) | SAFE-ish | Managed cert is a referenced child, not managed — untouched |
| `containerApp` web (407) | **REVERTS-DRIFT — CRITICAL** | Env+secrets arrays replaced → kills OIDC/email/SFTP-provision/broker/AI (#1). Image = whatever param you pass (passing non-live-`:sha` downgrades prod). Custom domain SAFE **only if** cert name still matches live (L111-112) |
| `migrateJob` (492) | REVERTS image | Pass live `:sha` or next deploy's `job update` fixes it |
| `ingest/maintenance/ai/enrich` Jobs (558/621/691/760) | REVERTS image + cron | Images from required params; crons reset to defaults |
| `postgres` (825) | **REVERTS-DRIFT — HIGH** | B1ms/32 GB/7-day/v16 + admin-pw reset. Storage-shrink attempt = deploy failure mid-flight; SKU change = restart |
| `postgresDb` netmon (852) | SAFE | Data untouched |
| 4× `roleAssignments` (862-901) | FAILS on re-apply | `RoleAssignmentExists` unless `ASSIGN_ROLES=false` — earlier resources already PUT (non-atomic) |
| Broker app | **ABSENT-FROM-BICEP** | Untouched Incremental; deleted in Complete |
| SFTP depot + users + **bundle data** | **ABSENT-FROM-BICEP** | Untouched Incremental; **deleted w/ all data in Complete** |
| Depot role assignments / custom role | **ABSENT-FROM-BICEP** | Extension resources; survive Incremental |
| Managed cert (CAE child) | ABSENT (referenced only) | Fine Incremental; must exist before `customDomainName` on a fresh env |
| ACS email, alerts, diagnostics, anything else in RG | ABSENT-FROM-BICEP | Inventory before ever considering a full apply |

## SAFE-DEPLOY CHECKLIST (would have caught the known incidents)

**Any bicep apply, in order:**
1. `az deployment group what-if -g <RG> -f <file> -p <params>` — read every `Modify`/`Delete` line. On `main.bicep`, treat ANY change under `w2-sbcss-netmon-web` `configuration.secrets`/`template.containers[0].env` or under `w2-sbcss-netmon-psql` as **stop-the-line**.
2. **Never `--mode Complete`.** Never apply `main.bicep` whole while #1/#2/#8 stand — add single resources via surgical files (the broker/sftp-depot pattern, with the what-if invocation in the file header).
3. Supply **live** secrets, never fresh: `AUTH_SECRET` = current `az keyvault secret show --vault-name <KV> -n AUTH-SECRET`; `PG_ADMIN_PASSWORD` = current live pw; `ASSIGN_ROLES=false` on every re-apply.
4. Pass the **live pinned images**: `az containerapp show -n w2-sbcss-netmon-web ... --query "properties.template.containers[0].image"` (and each job's) — never a placeholder against a live stack.
5. Pre-apply snapshot for diff/recovery: dump the web app's full env + secret names, job crons, postgres SKU/storage.

**Any migration-bearing push to main:** grep new `drizzle/*.sql` for `DROP`, `SET NOT NULL`, `ALTER ... TYPE`, `RENAME`, `CREATE UNIQUE INDEX` on existing tables (ship the dedup in the same file, before the index); confirm PITR (7-day) or take an on-demand backup first; know a failed migration leaves the four jobs on new code (#3) until fixed — roll forward fast.

**Any routing/build-config change:** run `next build` locally before pushing (the proxy.ts lesson) — the only pre-deploy gate until CI gains a build step.

**Collector risky change:** merge → verify on Monitor1 with `sudo bash scripts/auto-update.sh` the **same day**, before the 03:00 fleet wave; for scary changes pin the fleet (`NETMON_UPDATE_REF`) or set `hold` via dashboard first.

## SOUND / ALREADY-SAFE (coverage)

- Custom domain + managed cert reconciled into `main.bicep` (102-112); `APP_ORIGIN` defaults to the custom domain — the original near-miss is closed at the binding level.
- Image params are **required with no `:latest` defaults** — a full apply can't silently downgrade to a floating tag; CI publishes immutable `:<sha>` tags on both repos.
- Migration-before-roll ordering has a hard gate that stops the web roll on failure; drizzle applies each migration transactionally.
- Collector auto-update is defensively layered: dirty-tree refusal, ownership self-heal + `safe.directory` + validated re-clone with loop guard + path allowlist, pre-update SHA + pg_dump, channels (hold/canary/pin), 120 s healthcheck w/ auto-rollback to the immutable per-commit image, update-result reporting (the "network down" mis-report is fixed).
- Headless VLAN apply is backend-aware with a default-route revert guard (the NM/netplan crash is fixed on install.sh + dashboard-push paths; only the `MEMORY.md` index line was stale, not the fix).
- `seed-admin` is idempotent (never resets an existing admin without `--reset`).
- `refresh-data.yml`'s bot push can't recursively trigger a deploy; surgical bicep files carry the what-if invocation in their headers.

## NEEDS LIVE VERIFICATION (read-only `az`/portal)

1. `az deployment group what-if -f infra/main.bicep` with live params — authoritative confirmation of #1/#2/#8 (env/secrets diff, postgres SKU/storage diff, VNet subnet diff, cert-name match).
2. Live web-app env inventory vs docs (is `BROKER_WSS_URL`, `ACS_CONNECTION_STRING`, `EMAIL_FROM`, `AZURE_SUBSCRIPTION_ID`, `AZURE_MANAGED_IDENTITY_CLIENT_ID`, `DEPOT_SFTP_*` actually set live — several have code fallbacks).
3. Managed cert name still `netmon.sbcss.net-w2-sbcss-260603224931`; federated-credential subject matches the real repo slug.
4. Postgres live SKU/storage/version vs bicep's B1ms/32 GB/16.
5. Full RG resource inventory (ACS? alerts? anything out-of-band) to complete the Complete-mode delete list.
6. Fleet channel distribution (is 100% on default `:stable`?) and GHCR package visibility.

## Suggested action order

1. **#1 + #2 (reconcile env/secrets + Key-Vault-read the two secrets)** — this closes the still-live "same class as the domain near-miss" hole and makes a full apply genuinely a no-op.
2. **#6 (add `next build`/tsc to CI)** — cheapest guard against the repeat build-breaker.
3. **#3 + #9 (reorder job re-points after the gate; fix the execution-name race; add a post-roll health probe)** — de-risk the routine deploy.
4. **#4 + #5 (gate `:stable` on CI; fix the rollback DB restore)** — the fleet-wide collector risks.
5. **#7, #10, #11, #12, #13** — hardening.
