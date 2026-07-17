"""Remote console: the in-flight bounds on live operational commands (F-COL-15).

Pure unit tests: `_run_command` (the only thing that touches the box) is faked and
blocked on an Event so ops can be held "in flight" deterministically, and the
websocket is a list-backed stub.

Why this is worth pinning: every `cmd` frame used to spawn an unbounded daemon
thread, so a flood of `run-scan` frames launched N concurrent force scans — each
driving nmap + arp-scan + a multi-minute tshark capture — and could exhaust CPU /
memory / fds on a small field sensor.
"""
from __future__ import annotations

import json
import threading
import time

import pytest

from collector import remote_console as rc


class _FakeWS:
    """Collects the frames _send() would have put on the wire."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self._lock = threading.Lock()

    def send(self, raw: str) -> None:
        with self._lock:
            self.sent.append(json.loads(raw))

    def frames(self, ftype: str) -> list[dict]:
        with self._lock:
            return [f for f in self.sent if f.get("type") == ftype]


def _wait_for(pred, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met within timeout")


@pytest.fixture(autouse=True)
def _clean_inflight():
    """_ops_inflight is module state; never let one test leak into the next."""
    rc._ops_inflight.clear()
    yield
    rc._ops_inflight.clear()


@pytest.fixture
def blocked_op(monkeypatch):
    """Make _run_command hang until released, so ops stay in flight on demand.

    Yields (release, started): `started` is released once per op that actually
    began running, `release` frees them all. Always set on teardown so a failing
    assert can't leave a worker parked.
    """
    release = threading.Event()
    started = threading.Semaphore(0)

    def _fake_run_command(cmd_id: str):
        started.release()
        release.wait(timeout=5)
        return "done", {"scan_id": 1}

    monkeypatch.setattr(rc, "_run_command", _fake_run_command)
    try:
        yield release, started
    finally:
        release.set()


def test_duplicate_op_is_refused_while_in_flight(blocked_op):
    release, started = blocked_op
    ws = _FakeWS()

    rc._run_op_async(ws, "run-scan")
    assert started.acquire(timeout=5), "first op should have started"

    # A second run-scan while the first is still running: refused, not stacked.
    rc._run_op_async(ws, "run-scan")

    errs = ws.frames("err")
    assert len(errs) == 1
    assert "already running" in errs[0]["message"]
    assert errs[0]["id"] == "run-scan"
    # Refused means refused: no second worker announced itself.
    assert len(ws.frames("begin")) == 1

    release.set()


def test_a_flood_of_the_same_op_starts_exactly_one(blocked_op):
    release, started = blocked_op
    ws = _FakeWS()

    for _ in range(25):
        rc._run_op_async(ws, "run-scan")

    assert started.acquire(timeout=5)
    assert len(ws.frames("begin")) == 1, "only one force scan may ever be launched"
    assert len(ws.frames("err")) == 24

    release.set()


def test_total_concurrency_is_capped_across_different_ops(blocked_op):
    release, started = blocked_op
    ws = _FakeWS()

    ops = ["run-scan", "upload-now", "config-backup", "collect-logs"]
    assert len(ops) > rc.MAX_CONCURRENT_OPS, "need a spare op left over to be refused"

    # The cap's worth of DISTINCT ops may run together (the per-id guard alone
    # would happily allow every _LIVE_OPS member at once)...
    for cmd_id in ops[:rc.MAX_CONCURRENT_OPS]:
        rc._run_op_async(ws, cmd_id)
    for _ in range(rc.MAX_CONCURRENT_OPS):
        assert started.acquire(timeout=5)

    # ...and the next distinct one is refused as busy rather than piling on.
    extra = ops[rc.MAX_CONCURRENT_OPS]
    rc._run_op_async(ws, extra)

    errs = ws.frames("err")
    assert len(errs) == 1
    assert "busy" in errs[0]["message"]
    assert errs[0]["id"] == extra
    assert len(ws.frames("begin")) == rc.MAX_CONCURRENT_OPS

    release.set()


def test_slot_is_released_when_the_op_finishes(monkeypatch):
    """A completed op must free its slot, or that cmd_id would be refused for the
    rest of the session."""
    monkeypatch.setattr(rc, "_run_command", lambda _c: ("done", {"scan_id": 1}))
    ws = _FakeWS()

    for _ in range(3):
        rc._run_op_async(ws, "run-scan")
        _wait_for(lambda: "run-scan" not in rc._ops_inflight)

    assert len(ws.frames("begin")) == 3, "each sequential run should start"
    assert ws.frames("err") == []
    assert len(ws.frames("exit")) == 3


def test_slot_is_released_when_the_op_raises(monkeypatch):
    """A crashing op must not wedge its cmd_id either — the release sits in a
    finally that wraps the whole worker."""

    def _boom(_cmd_id):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(rc, "_run_command", _boom)
    ws = _FakeWS()

    rc._run_op_async(ws, "run-scan")
    _wait_for(lambda: "run-scan" not in rc._ops_inflight)

    errs = ws.frames("err")
    assert len(errs) == 1
    assert "scan blew up" in errs[0]["message"]
    assert rc._ops_inflight == set()
