# NetMon — collector (net_mon)

Ubuntu network-discovery **sensor**: scans the LAN and ships an hourly data **bundle** to the dashboard for analysis. Python package in `collector/` (3.12); host-side bash in `bin/ lib/ scripts/`. Code only, no state. Whole-system architecture lives in the dashboard repo's `docs/ARCHITECTURE.md`.

## Before pushing, mirror CI
CI runs on every push; the gate that matters is **mypy** — it catches the runtime-only bugs (bad attr/kwarg) that crash-loop a box.

```bash
pip install -e "collector[dev]"
ruff check collector/src/collector
mypy collector/src/collector --ignore-missing-imports --check-untyped-defs
python -c "import collector; print(collector.__file__)"   # must print a path INSIDE this checkout
cd collector && pytest tests -q
```

Shell scripts must pass `bash -n`.

## Gotchas
- **mypy on Windows** false-positives on Unix-only syscalls — keep those imports lazy. CI (Ubuntu) is authoritative.
- **pytest in a worktree tests whichever checkout last ran `pip install -e`**, not this one. Before running tests, `python -c "import collector; print(collector.__file__)"` must print a path inside this worktree. If it doesn't, run `PYTHONPATH="$(pwd -W)/collector/src" python -m pytest collector/tests -q` in Git Bash (`$(pwd -W)` survives `MSYS_NO_PATHCONV=1`; `$PWD` does not and imports the wrong checkout with no error) or `$env:PYTHONPATH="$PWD\collector\src"` in PowerShell, then re-check the import path. A green run is not a tell.
- **Public repo** — no secrets, and no tenant identifiers (addresses, hostnames, district names). Box config lives in `/etc/netmon/` (0600); `config/provisioning.env` is git-ignored.

## Deploy
Push `main` → CI → `build-collector` publishes the `:stable` image → fleet auto-updates nightly (`scripts/auto-update.sh`: git pull, image pull, recreate, 120 s health check, rollback on failure). A failed build does not move `:stable`, so a broken build cannot reach the fleet. Script-only changes ride the git pull.

## Definition of done
A green CI run and a published `:stable` are not a deployed change, and this sensor's characteristic bug is something quietly doing nothing. Work is done when it has **run on the designated verification sensor** and the output has been read:

1. **Force the update** instead of waiting for the nightly: `sudo bash scripts/auto-update.sh` from the repo checkout on the box. Success is the log line `healthcheck passed; update complete at <sha8>`; a rollback line means the change never landed. The running commit is `cat /var/lib/netmon/current-sha` (also reported at check-in); gate on `git merge-base --is-ancestor <your-merge-sha> <that>`, never on a tag.
2. **Run the changed thing.** `docker compose exec -T collector python -m collector healthcheck --verbose` for health — it exits non-zero on a real failure. `selftest` prints the same checks but **always exits 0**; never gate on it. For a targeted probe, pipe a script into the running container (`echo <base64> | base64 -d | sudo docker compose exec -T collector python -`) rather than fighting SSH quoting; the package imports as `collector` from the container's default workdir.
3. **Cross-check the dashboard:** the next bundle landed, and the page that consumes the change shows it.

The verification box's address and credentials live in private notes, never here. Sensor IPs drift over DHCP — take the address from the dashboard's sensors page, not from memory. And "nothing found" needs a positive control: a source that refused and a clean result look identical, so report *unavailable*, not *clean*.

## Worth a second reader before merging
Adversarial review of the finished diff has, twice on this repo, found the fix reproducing the bug it existed to fix — after every gate was green. Shapes that earn one here:
- **Fallback chains in bash** (`auto-update.sh` ownership and clone handling, env-file writes): validate every candidate, not just the last one. A guard only at the end prefers a bad early answer over a good late one.
- **Anything that filters or redacts untrusted strings** (config-backup redaction, env-file line injection, SNMP values): tests written from the same blocklist share its blind spot, and net-snmp `-Oq` quotes every string.
- **Vendor and SNMP grammars, version parsing, and any change to what a field means** for the dashboard — enumerate every reader.
