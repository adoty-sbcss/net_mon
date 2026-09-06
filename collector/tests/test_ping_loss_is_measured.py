"""`loss_pct` must be a MEASUREMENT — never fabricated when ping did not count.

`_ping` used to report `loss_pct: 100.0` for every branch that produced no
packet-loss line: a missing CAP_NET_RAW after a container restart, no route, a
name that would not resolve, a hung ping process. All of those are the INSTRUMENT
failing, not the path — and each was written to `latency_results` as total packet
loss, i.e. as a WAN fault.

That matters beyond one bad number. The dashboard's `latencyRowUnavailable`
(lib/rules/wan-edge-core.ts) keys "we measured nothing" on `ok = false` with a
NULL loss, so a fabricated 100.0 walks straight past the guard and lands in
`rule:wan-edge` as evidence of a degraded shared edge. An image regression or a
container-runtime change hits every box on that collector version at once, which
is precisely the correlated, control-clean shape that rule fires on.

The distinction under test is whether ping COUNTED, not whether it succeeded:

  * a real unreachable host still prints its statistics block → 100.0 is a real
    measurement and is reported;
  * partial loss and clean runs are untouched;
  * no statistics block → NO `loss_pct` KEY AT ALL, so the column is NULL.

Every `ping` output below is copied from the real thing (iputils on Ubuntu),
including the stderr wording, so a fixture cannot certify a parser that no real
output would satisfy.

Pure unit tests: `subprocess.run` is monkeypatched, so there is no network.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from collector.latency import _ping

# --- real iputils output, copied verbatim ----------------------------------

CLEAN = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 2712ms
rtt min/avg/max/mdev = 8.921/9.412/10.883/0.552 ms
"""

PARTIAL = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
10 packets transmitted, 6 received, 40% packet loss, time 2718ms
rtt min/avg/max/mdev = 14.002/15.771/18.330/1.402 ms
"""

# Unreachable host: ping COUNTED, and lost everything. There is no rtt line, but
# there IS a statistics block — this is the case that must keep reporting 100.
TOTAL_LOSS = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9210ms
"""


def _run(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Monkeypatch target: a completed `ping` with the given output."""

    def fake(*_a, **_kw):
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)

    return fake


def test_clean_run_reports_its_measurement(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _run(CLEAN))
    r = _ping("1.1.1.1")
    assert r["ok"] is True
    assert r["loss_pct"] == 0.0
    assert r["latency_ms"] == 9.412


def test_partial_loss_is_reported_as_measured(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _run(PARTIAL))
    r = _ping("8.8.8.8")
    assert r["loss_pct"] == 40.0
    assert r["ok"] is True  # 40% is degraded, not "failed" — the rule judges it


def test_a_real_total_loss_still_reports_100(monkeypatch):
    """THE REGRESSION GUARD. Narrowing what counts as measured must not stop the
    genuine outage — the one this whole channel exists to see — being reported."""
    monkeypatch.setattr(subprocess, "run", _run(TOTAL_LOSS, returncode=1))
    r = _ping("1.1.1.1")
    assert r["ok"] is False
    assert r["loss_pct"] == 100.0, "a counted 100% loss is a measurement, not a fabrication"


# --- the branches that must NOT invent a loss figure ------------------------


def test_missing_binary_reports_no_loss(monkeypatch):
    def boom(*_a, **_kw):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", boom)
    r = _ping("1.1.1.1")
    assert r["ok"] is False
    assert "loss_pct" not in r
    assert r["error"] == "ping not installed"


def test_hung_ping_reports_no_loss(monkeypatch):
    """`-w 12` makes ping print a summary and exit, so hitting the subprocess
    timeout at deadline+5 means the PROCESS hung, not that the network was slow."""

    def boom(*_a, **_kw):
        raise subprocess.TimeoutExpired(cmd="ping", timeout=17)

    monkeypatch.setattr(subprocess, "run", boom)
    r = _ping("1.1.1.1")
    assert r["ok"] is False
    assert "loss_pct" not in r, "a hung instrument measured nothing"
    assert r["error"] == "ping timed out"


def test_no_cap_net_raw_reports_no_loss(monkeypatch):
    """The container lost CAP_NET_RAW — e.g. after a runtime or image change.
    Fleet-correlated, and the exact shape rule:wan-edge would misread."""
    monkeypatch.setattr(
        subprocess, "run", _run(stderr="ping: socket: Operation not permitted", returncode=2)
    )
    r = _ping("1.1.1.1")
    assert r["ok"] is False
    assert "loss_pct" not in r
    assert "Operation not permitted" in r["error"]


def test_no_route_reports_no_loss(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", _run(stderr="connect: Network is unreachable", returncode=2)
    )
    r = _ping("1.1.1.1")
    assert "loss_pct" not in r
    assert "Network is unreachable" in r["error"]


def test_unresolvable_name_reports_no_loss(monkeypatch):
    """A custom hostname target that will not resolve. Real, but it is a DNS fact
    — saying "100% of packets to this host were lost" is a different claim."""
    monkeypatch.setattr(
        subprocess,
        "run",
        _run(stderr="ping: probe.example.invalid: Name or service not known", returncode=2),
    )
    r = _ping("probe.example.invalid")
    assert "loss_pct" not in r
    assert "Name or service not known" in r["error"]


def test_silent_failure_still_carries_a_diagnosis(monkeypatch):
    """No stdout, no stderr. The loss is unmeasured, but the row must not be blank."""
    monkeypatch.setattr(subprocess, "run", _run(returncode=1))
    r = _ping("1.1.1.1")
    assert "loss_pct" not in r
    assert r["error"] == "host unreachable"


def test_the_wire_shape_distinguishes_unmeasured_from_total_loss(monkeypatch):
    """What the dashboard actually keys on: `ok = false` for both, but the loss is
    NULL for the instrument failure and 100.0 for the real outage. If these two
    ever collapse, `latencyRowUnavailable` silently stops protecting anything."""
    monkeypatch.setattr(subprocess, "run", _run(TOTAL_LOSS, returncode=1))
    outage = _ping("1.1.1.1")
    monkeypatch.setattr(
        subprocess, "run", _run(stderr="ping: socket: Operation not permitted", returncode=2)
    )
    broken = _ping("1.1.1.1")

    assert outage["ok"] is broken["ok"] is False
    assert outage.get("loss_pct") == 100.0
    assert broken.get("loss_pct") is None
    assert outage.get("loss_pct") != broken.get("loss_pct")
