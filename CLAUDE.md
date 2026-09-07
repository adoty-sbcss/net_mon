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
- **pytest inside a git worktree tests the MAIN checkout.** The package is an editable install that points at the primary checkout, so a worktree's tests import code you did not change and stay green. Run `PYTHONPATH="$PWD/collector/src" python -m pytest collector/tests -q`. The tell is a traceback path outside the worktree.
- **Public repo** — no secrets, and no tenant identifiers (addresses, hostnames, district names). Box config lives in `/etc/netmon/` (0600); `config/provisioning.env` is git-ignored.

## Deploy
Push `main` → CI → `build-collector` publishes the `:stable` image → fleet auto-updates nightly (`scripts/auto-update.sh`: git pull, image pull, recreate, 120 s health check, rollback on failure). A failed build does not move `:stable`, so a broken build cannot reach the fleet. Script-only changes ride the git pull.

## Definition of done
A green CI run and a published `:stable` are not a deployed change, and this sensor's characteristic bug is something quietly doing nothing. Work is done when it has **run on the designated verification sensor** and the output has been read:

1. **Force the update** instead of waiting for the nightly: `sudo bash scripts/auto-update.sh` from the repo checkout on the box. Success is the log line `healthcheck passed; update complete at <sha>`; a rollback line means the change never landed.
2. **Run the changed thing.** `docker compose exec -T collector python -m collector selftest` for health. For a targeted probe, pipe a script into the running container (`echo <base64> | base64 -d | sudo docker compose exec -T collector python -`) rather than fighting SSH quoting; the package imports as `collector` from the container's default workdir.
3. **Cross-check the dashboard:** the next bundle landed, and the page that consumes the change shows it.

The verification box's address and credentials live in private notes, never here. Sensor IPs drift over DHCP — take the address from the dashboard's sensors page, not from memory. And "nothing found" needs a positive control: a source that refused and a clean result look identical, so report *unavailable*, not *clean*.

## Worth a second reader before merging
Adversarial review of the finished diff has, twice on this repo, found the fix reproducing the bug it existed to fix — after every gate was green. Shapes that earn one here:
- **Fallback chains in bash** (`auto-update.sh` ownership and clone handling, env-file writes): validate every candidate, not just the last one. A guard only at the end prefers a bad early answer over a good late one.
- **Anything that filters or redacts untrusted strings** (config-backup redaction, env-file line injection, SNMP values): tests written from the same blocklist share its blind spot, and net-snmp `-Oq` quotes every string.
- **Vendor and SNMP grammars, version parsing, and any change to what a field means** for the dashboard — enumerate every reader.
