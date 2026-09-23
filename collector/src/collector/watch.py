"""Active monitoring of core devices (NOTIF-8): ping a pushed list, report edges.

The dashboard hands each sensor a short list of core devices to watch (switches,
routers/firewalls, servers) in the check-in response's ``watch`` key — deliberately
NOT in ``desired_config``, because any config version bump makes the host wrapper
recreate the collector container, and the watch list changes on every ingest that
classifies a device. This module pings that list once per check-in, keeps state ON
THE BOX, and reports what changed — plus a full per-target SNAPSHOT, so the
dashboard reconciles from the box's current truth rather than trusting that every
edge arrived.

Rules that each exist because the alternative lies:

* **Positive control.** A target is only ever reported ``down`` if THIS sensor has
  seen it ``up`` at least once (``first_up_at``), and a new address for the same
  device must earn that again. A management VLAN the sensor can't route to, or a
  firewall that drops ICMP, is "never reached" — shown, never alerted.
* **Debounce (layer 1).** Down after 2 consecutive failed cycles (~6 min at the
  3-minute check-in); up after 1 success. One lost ping is not an event.
* **Blind cycles.** Nothing answered AND (our own gateway is dead, or — with no
  gateway reading — at least 3 targets all failed): the SENSOR has lost its view.
  That cycle advances no failure counters, and the change of visibility is itself
  an event (``blind`` / ``sighted``), so an outage-long blind stretch leaves a
  trace even when a healthy cycle comes last. A gateway that answers IS the
  positive control that our own network works: three dead switches under a live
  gateway are a site event, not lost visibility.
* **Unknown is not failed.** A target the time budget didn't reach is ``skipped``
  and its state does not move.
* **Untrusted input.** The pushed list becomes ``ping`` argv. Only IP literals are
  accepted (no hostnames: resolution happens before any deadline is armed; no IPv6
  scope text), IPv4-mapped IPv6 is normalised to IPv4, and special ranges
  (loopback, multicast, unspecified, link-local, reserved) are refused. Keys are a
  strict charset, labels are length-capped, and the list is capped. Public unicast
  IS allowed: school districts commonly run their own public blocks internally, and
  the worst a tampered list can do is make the box ping a host. An invalid list is
  refused whole — the old one is kept — and the refusal is reported with the
  version that was refused. The stored list is re-validated on every read.
* **Delivery.** The report is written BEFORE the state, so a kill between the two
  (the nightly container recreate, a power cut) can duplicate an edge but never
  lose one. Every event carries a per-box increasing ``seq`` so the dashboard can
  drop re-deliveries. The report is cleared only after a check-in the dashboard
  accepted.

State lives in ``/var/lib/netmon/watch-state.json``; the list in
``watch-targets.json``; the report the next check-in carries in
``watch-report.json``. All writes are atomic, fsynced, 0600.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

STATE_DIR = Path("/var/lib/netmon")
TARGETS_FILE = STATE_DIR / "watch-targets.json"
STATE_FILE = STATE_DIR / "watch-state.json"
REPORT_FILE = STATE_DIR / "watch-report.json"

MAX_TARGETS = 200
MAX_LABEL = 64
DOWN_AFTER_FAILS = 2
MAX_WORKERS = 16
# Wall-clock budget for one cycle. The check-in is the box's only control plane:
# 200 dead targets at ~3 s each over 16 threads is ~40 s, so beyond this we stop
# and report the rest as skipped rather than stretch the timer.
CYCLE_BUDGET_S = 40.0
# Events kept for delivery while the dashboard is unreachable (oldest dropped first,
# and the drop is COUNTED in the report so a gap is never silent — and the snapshot
# lets the dashboard recover the current truth anyway).
MAX_PENDING_EVENTS = 500

_KEY = re.compile(r"^[A-Za-z0-9:_-]{1,64}$")


# --- validation -------------------------------------------------------------------


def _clean_ip(ip: Any) -> tuple[str | None, str | None]:
    """(normalised ip, None) or (None, reason)."""
    if not isinstance(ip, str):
        return None, "no ip"
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip)
    except ValueError:
        return None, "ip is not an IP literal"
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.scope_id:
            return None, "ip carries an IPv6 scope"
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local or addr.is_reserved:
        return None, "ip is not a unicast host address"
    return str(addr), None


def validate_targets(raw: Any) -> tuple[list[dict], str | None]:
    """Return (targets, refusal). A refusal means the WHOLE list was rejected."""
    if not isinstance(raw, list):
        return [], "watch targets are not a list"
    if len(raw) > MAX_TARGETS:
        return [], f"watch list has {len(raw)} targets (max {MAX_TARGETS})"
    out: list[dict] = []
    seen: set[str] = set()
    for i, t in enumerate(raw):
        if not isinstance(t, dict):
            return [], f"target {i} is not an object"
        key, label = t.get("key"), t.get("label", "")
        if not isinstance(key, str) or not _KEY.match(key):
            return [], f"target {i} has an invalid key"
        ip, why = _clean_ip(t.get("ip"))
        if ip is None:
            return [], f"target {i} {why}"
        if not isinstance(label, str):
            return [], f"target {i} label is not text"
        if key in seen:
            continue
        seen.add(key)
        out.append({"key": key, "ip": ip, "label": label[:MAX_LABEL]})
    return out, None


# --- the pure state machine --------------------------------------------------------


def step(
    state: dict,
    targets: list[dict],
    results: dict[str, bool | None],
    now: float,
    gateway_ok: bool | None,
) -> tuple[dict, list[dict], dict]:
    """Advance the per-target state with one cycle's results.

    ``results[key]`` is True (answered), False (did not), or None / missing
    (skipped: the budget ran out). Returns (new_state, events, cycle_summary).
    Pure: no clock, no I/O. Events carry ``seq`` from the state's counter.
    """
    prev: dict = dict(state.get("targets") or {})
    seq = int(state.get("seq") or 0)
    was_blind = bool(state.get("blind"))
    keys = {t["key"] for t in targets}
    probed = [k for k in keys if results.get(k) is not None]
    answered = [k for k in probed if results[k]]
    blind = not answered and (gateway_ok is False or (gateway_ok is None and len(probed) >= 3))

    events: list[dict] = []

    def emit(ev: dict) -> None:
        nonlocal seq
        seq += 1
        events.append({"seq": seq, **ev})

    if blind != was_blind:
        emit({"edge": "blind" if blind else "sighted", "at": now, "gateway_ok": gateway_ok, "probed": len(probed)})

    new: dict = {}
    for t in targets:
        k = t["key"]
        fresh = {"state": "unknown", "fails": 0, "since": None, "first_up_at": None}
        s = dict(prev.get(k) or fresh)
        # A new address for the same device is a new target: the positive control
        # ("seen up from HERE") must be earned again. If it was down, close that out.
        if s.get("ip") not in (None, t["ip"]):
            if s.get("state") == "down":
                emit({"key": k, "ip": s.get("ip"), "edge": "cleared", "at": now, "reason": "address changed"})
            s = dict(fresh)
        s["ip"] = t["ip"]
        r = results.get(k)
        if r is None:
            new[k] = s  # skipped: nothing moves
            continue
        s["last_probed_at"] = now
        if r:
            if s.get("first_up_at") is None:
                s["first_up_at"] = now
            if s["state"] == "down":
                emit({"key": k, "ip": t["ip"], "edge": "up", "at": now, "down_since": s.get("since")})
            if s["state"] != "up":
                s["since"] = now
            s["state"], s["fails"] = "up", 0
        elif not blind:
            s["fails"] = int(s.get("fails") or 0) + 1
            if s.get("first_up_at") is None:
                s["state"] = "never"  # never seen up from here: a reachability gap
            elif s["state"] != "down" and s["fails"] >= DOWN_AFTER_FAILS:
                s["state"], s["since"] = "down", now
                emit({"key": k, "ip": t["ip"], "edge": "down", "at": now, "fails": s["fails"]})
        new[k] = s
    # Keys no longer on the list are dropped; the dashboard removed them itself.

    summary = {
        "at": now,
        "targets": len(targets),
        "probed": len(probed),
        "skipped": len(keys) - len(probed),
        "blind": blind,
        "gateway_ok": gateway_ok,
        "up": sum(1 for s in new.values() if s["state"] == "up"),
        "down": sum(1 for s in new.values() if s["state"] == "down"),
        "never": sum(1 for s in new.values() if s["state"] == "never"),
    }
    return {"targets": new, "seq": seq, "blind": blind}, events, summary


def snapshot(state: dict) -> dict:
    """The compact per-target truth the dashboard reconciles from."""
    return {
        k: {
            "state": s.get("state"),
            "since": s.get("since"),
            "ip": s.get("ip"),
            "first_up_at": s.get("first_up_at"),
            "last_probed_at": s.get("last_probed_at"),
        }
        for k, s in (state.get("targets") or {}).items()
    }


def merge_report(
    pending: dict | None,
    version: Any,
    summary: dict,
    events: list[dict],
    refused: str | None,
    refused_version: Any = None,
    states: dict | None = None,
) -> dict:
    """Fold one cycle into the report the next check-in carries."""
    rep = dict(pending or {"events": [], "dropped_events": 0, "blind_cycles": 0, "cycles": 0})
    all_events = list(rep.get("events") or []) + events
    dropped = int(rep.get("dropped_events") or 0)
    if len(all_events) > MAX_PENDING_EVENTS:
        dropped += len(all_events) - MAX_PENDING_EVENTS
        all_events = all_events[-MAX_PENDING_EVENTS:]
    rep.update(
        {
            "version": version,
            "last": summary,
            "events": all_events,
            "dropped_events": dropped,
            "cycles": int(rep.get("cycles") or 0) + 1,
            "blind_cycles": int(rep.get("blind_cycles") or 0) + (1 if summary.get("blind") else 0),
            "refused": refused,
            "refused_version": refused_version,
            "states": states or {},
        }
    )
    return rep


# --- I/O ------------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json_atomic(path: Path, data: Any) -> None:
    """Atomic, durable, 0600 from creation — same guarantees as checkin's writer,
    without its POSIX-only calls (the pure tests run on any OS)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / (path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data, separators=(",", ":")))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(str(tmp), str(path))
    try:
        from .checkin import _match_owner_to_parent_dir

        _match_owner_to_parent_dir(path)
    except Exception:  # noqa: BLE001 — ownership is a convention, never a failure
        pass


def accept_targets(watch: Any) -> None:
    """Store the list from the check-in response's ``watch`` key, if it changed.

    Shape: ``{"version": <content hash>, "targets": [...]}``. ``targets: []`` is an
    off-switch; a missing / null ``watch`` keeps the current list. A refused list is
    recorded as a refusal (with its version) and the previous targets are kept.
    """
    if not isinstance(watch, dict):
        return
    current = _read_json(TARGETS_FILE) or {}
    version = watch.get("version")
    if version is not None and current.get("version") == version and not current.get("refused"):
        return
    targets, refusal = validate_targets(watch.get("targets"))
    if refusal:
        _write_json_atomic(TARGETS_FILE, {**current, "refused": refusal, "refused_version": version})
        return
    _write_json_atomic(TARGETS_FILE, {"version": version, "targets": targets, "refused": None, "refused_version": None})


def pending_report() -> dict | None:
    rep = _read_json(REPORT_FILE)
    return rep if isinstance(rep, dict) else None


def clear_report() -> None:
    try:
        REPORT_FILE.unlink()
    except FileNotFoundError:
        pass


def _ping(ip: str) -> bool:
    # -w 3: a hard deadline for the whole ping. IP literals only, see above.
    try:
        res = subprocess.run(["ping", "-n", "-c", "2", "-W", "1", "-w", "3", ip], capture_output=True, text=True, timeout=6)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return res.returncode == 0


def probe_all(targets: list[dict], budget_s: float = CYCLE_BUDGET_S) -> dict[str, bool | None]:
    """Ping every target in parallel within ``budget_s``; unfinished → None (skipped).

    Not-started pings are cancelled at the deadline; the ≤16 in flight are each
    capped at 6 s by their own subprocess timeout, so the overrun is bounded.
    """
    results: dict[str, bool | None] = {t["key"]: None for t in targets}
    if not targets:
        return results
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets)))
    try:
        futs = {pool.submit(_ping, t["ip"]): t["key"] for t in targets}
        done, _not_done = wait(futs, timeout=budget_s)
        for f in done:
            try:
                results[futs[f]] = bool(f.result())
            except Exception:  # noqa: BLE001
                results[futs[f]] = None
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return results


def run_cycle(gateway_lookup: Callable[[], str | None]) -> dict | None:
    """One watch cycle: probe, advance state, fold into the pending report.

    Returns the updated report, or None when there is nothing to watch (then no
    file is touched and nothing is pinged — not even the gateway). Contained by the
    caller: nothing here may break the check-in.
    """
    tf = _read_json(TARGETS_FILE) or {}
    # Re-validated on every read: the file is a trust boundary like netmon.env.
    targets, stored_refusal = validate_targets(tf.get("targets") or [])
    refused = tf.get("refused") or stored_refusal
    if not targets and not refused:
        return None
    now = time.time()
    gateway = gateway_lookup()
    gateway_ok: bool | None = None
    if gateway:
        ip, _why = _clean_ip(gateway)
        gateway_ok = _ping(ip) if ip else None
    results = probe_all(targets)
    state = _read_json(STATE_FILE) or {}
    new_state, events, summary = step(state, targets, results, now, gateway_ok)
    rep = merge_report(pending_report(), tf.get("version"), summary, events, refused, tf.get("refused_version"), snapshot(new_state))
    # Report FIRST: a kill between these two writes may re-send an edge (the seq
    # lets the dashboard drop it) but can never lose one.
    _write_json_atomic(REPORT_FILE, rep)
    _write_json_atomic(STATE_FILE, new_state)
    return rep
