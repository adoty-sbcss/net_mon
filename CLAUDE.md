# NetMon — collector (net_mon)

Ubuntu network-discovery **sensor**: scans the LAN and ships an hourly data **bundle** to the dashboard for analysis. Python package in `collector/` (3.12); host-side bash in `bin/ lib/ scripts/`. Code only, no state. Whole-system architecture lives in the dashboard repo's `docs/ARCHITECTURE.md`.

## Before pushing, mirror CI
CI runs on every push; the gate that matters is **mypy** — it catches the runtime-only bugs (bad attr/kwarg) that crash-loop a box.

```bash
pip install -e "collector[dev]"
ruff check collector/src/collector
mypy collector/src/collector --ignore-missing-imports --check-untyped-defs
cd collector && pytest tests -q
```

Shell scripts must pass `bash -n`.

## Gotchas
- **mypy on Windows** false-positives on Unix-only syscalls — keep those imports lazy. CI (Ubuntu) is authoritative.
- **Public repo** — no secrets. Box config lives in `/etc/netmon/` (0600); `config/provisioning.env` is git-ignored.

## Deploy
Push `main` → CI builds the image → fleet auto-updates nightly (`scripts/auto-update.sh`, health-check + rollback). Script-only changes ride the git pull.
