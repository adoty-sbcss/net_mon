#!/usr/bin/env python3
"""Guard against remote-console allow-list drift between this repo and the dashboard.

The sensor is the source of truth for which remote-console commands exist: the
union of checkin.py's ``_DIAG_COMMANDS`` + ``_CONTROL_COMMANDS`` + ``_LIVE_OPS``.
The dashboard repo (netmon-dashboard) hand-mirrors that set in two places — the
broker's ``ALLOWED_CMDS`` (defense-in-depth relay allow-list) and the offered
command set in ``console-config.ts`` — with no automated cross-repo drift check.
If they diverge, a command the dashboard offers is silently rejected at the
broker (an availability bug, not a security hole). See the CON-7 audit (2026-06-28).

This script pins the canonical answer in ``collector/console_broker_allowlist.json``
so drift becomes a CI failure on THIS side (the source of truth): editing the
registries without regenerating the manifest fails CI, and the failure message
reminds you to update the dashboard mirror.

Usage:
    python collector/scripts/check_console_allowlist.py            # --check (default)
    python collector/scripts/check_console_allowlist.py --check    # assert manifest matches registries
    python collector/scripts/check_console_allowlist.py --write    # regenerate the manifest

Exit code is non-zero on drift (so CI fails).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Resolve repo paths relative to this file so the script runs from anywhere
# (CI runs it from the repo root; a dev may run it from collector/).
_THIS = Path(__file__).resolve()
_COLLECTOR_DIR = _THIS.parent.parent  # collector/
_SRC = _COLLECTOR_DIR / "src"
_MANIFEST = _COLLECTOR_DIR / "console_broker_allowlist.json"

# Make `import collector` work even when the package isn't pip-installed.
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collector.checkin import (  # noqa: E402  (import after sys.path tweak)
    _CONTROL_COMMANDS,
    _DIAG_COMMANDS,
    _LIVE_OPS,
)


def _registry_union() -> set[str]:
    """Every remote-console command id the sensor knows about."""
    return set(_DIAG_COMMANDS) | set(_CONTROL_COMMANDS) | set(_LIVE_OPS)


def _load_manifest() -> dict:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def _expected_live(manifest: dict) -> list[str]:
    """The canonical live-broker list derived from the registries + manifest exceptions."""
    exceptions = set(manifest["queued_exceptions"]["ids"])
    return sorted(_registry_union() - exceptions)


def _render(manifest: dict) -> str:
    """Serialize the manifest with `live_broker_commands` regenerated from the registries."""
    manifest = json.loads(json.dumps(manifest))  # deep copy, preserve key order
    manifest["live_broker_commands"] = _expected_live(manifest)
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def _check() -> int:
    manifest = _load_manifest()
    union = _registry_union()
    errors: list[str] = []

    # 1. Every declared queued-exception must be a real registry id (a stale
    #    exception would silently shrink the expected live list).
    exceptions = set(manifest["queued_exceptions"]["ids"])
    unknown = sorted(exceptions - union)
    if unknown:
        errors.append(
            "queued_exceptions lists id(s) that are not in any registry "
            f"(stale?): {unknown}"
        )

    # 2. The committed live list must equal registries-minus-exceptions.
    expected = _expected_live(manifest)
    actual = manifest["live_broker_commands"]
    if actual != expected:
        missing = sorted(set(expected) - set(actual))   # in registries, absent from manifest
        extra = sorted(set(actual) - set(expected))     # in manifest, no longer in registries
        if missing:
            errors.append(f"manifest is MISSING (added to a registry?): {missing}")
        if extra:
            errors.append(f"manifest has EXTRA (removed from a registry?): {extra}")
        if not missing and not extra:
            errors.append(f"manifest order differs: expected {expected}, got {actual}")

    if errors:
        print("console allow-list DRIFT detected:\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nFix: regenerate the manifest with\n"
            "    python collector/scripts/check_console_allowlist.py --write\n"
            "then mirror `live_broker_commands` into the dashboard repo "
            "(broker/index.js ALLOWED_CMDS + src/lib/admin/console-config.ts).",
            file=sys.stderr,
        )
        return 1

    print(f"console allow-list OK - {len(expected)} live-broker commands, "
          f"exceptions {sorted(exceptions)}")
    return 0


def _write() -> int:
    manifest = _load_manifest()
    _MANIFEST.write_text(_render(manifest), encoding="utf-8")
    print(f"wrote {_MANIFEST.relative_to(_COLLECTOR_DIR.parent)} "
          f"({len(manifest['live_broker_commands'])} commands)")
    return 0


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "--check"
    if mode == "--write":
        return _write()
    if mode in ("--check", ""):
        return _check()
    print(f"unknown mode {mode!r}; use --check or --write", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
