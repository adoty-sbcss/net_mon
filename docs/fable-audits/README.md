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
| 4 | Test / failure-path gap map | 04-test-gaps.md | ⏳ queued |

## How to read a report

Each report ranks findings by **field impact × confidence**. Every finding carries:
the exact mechanism (why it passes green checks but still loses data), file:line anchors in
**both** repos, a concrete trigger/repro, and a fix sketch. Confidence is marked
CONFIRMED (traced in code) vs PLAUSIBLE (needs a runtime check).

Findings are **not auto-applied** — they are a worklist for a human + a normal Opus session.
