"""Reverse-DNS (PTR) enrichment: the parallel pass and its dead-resolver gate.

Pure unit tests: `subprocess.run` is the single boundary and is faked, so there is
no `dig` and no network. What matters here is the distinction the gate rests on —

  * a resolver that never REPLIES (scan.py appends the GATEWAY as a resolver and
    it usually does not serve DNS at all) must get benched for the rest of the
    batch, or every unresolvable IP burns a full `+time=N` timeout on it; but
  * a HEALTHY resolver answering "no PTR record" for host after host is the NORMAL
    case on a client subnet, and benching it would silently lose every hostname.

Getting that backwards is invisible in production — hostnames just quietly stop
appearing — so both directions are pinned here.
"""
from __future__ import annotations

from collector.discovery import rdns


class _Res:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _resolver_of(cmd: list[str]) -> str | None:
    """The '@resolver' argv _dig_ptr injected, or None for the system resolver."""
    for arg in cmd:
        if arg.startswith("@"):
            return arg[1:]
    return None


def _ip_of(cmd: list[str]) -> str:
    return cmd[cmd.index("-x") + 1]


# A resolver that is simply not a DNS server: dig gives up with exit 9.
_NO_REPLY = _Res(stderr=";; communications error to 10.0.0.1#53: timed out", returncode=9)
# A resolver that IS a DNS server but holds no PTR for the IP: +short prints
# nothing and dig exits 0. This is the common client-subnet answer.
_NO_PTR = _Res(stdout="", returncode=0)


def test_dead_resolver_is_benched_for_the_rest_of_the_batch(monkeypatch):
    """The gateway never answers, so it must stop being tried after a few strikes
    instead of costing all 200 hosts a timeout — while the real resolver still
    names every host."""
    calls: list[str | None] = []

    def _fake_run(cmd, **_kw):
        resolver = _resolver_of(cmd)
        calls.append(resolver)
        if resolver == "10.0.0.1":
            return _NO_REPLY
        return _Res(stdout=f"host-{_ip_of(cmd).split('.')[-1]}.lan.\n", returncode=0)

    monkeypatch.setattr(rdns.subprocess, "run", _fake_run)

    ips = [f"10.0.0.{i}" for i in range(1, 201)]
    out = rdns.resolve_ptr(ips, ["10.0.0.1", "10.0.0.53"], timeout=2)

    assert len(out) == 200, "the working resolver must still name every host"
    assert out["10.0.0.7"] == "host-7.lan"

    gw_calls = [c for c in calls if c == "10.0.0.1"]
    # Upper bound: the strike threshold plus whatever was already in flight across
    # the pool when the counter tripped. Without the gate this would be 200.
    assert len(gw_calls) <= rdns._DEAD_STRIKES + rdns._MAX_WORKERS
    assert len(gw_calls) < 200


def test_resolver_answering_no_ptr_is_never_benched(monkeypatch):
    """NXDOMAIN / "no PTR" is a REPLY — the resolver is alive and healthy. Most
    DHCP/IoT clients have no PTR, so if that counted as a strike the resolver would
    be benched early and the hosts that DO have a PTR would be missed."""

    def _fake_run(cmd, **_kw):
        # Only the very last IP has a PTR; every earlier one answers "no record".
        if _ip_of(cmd) == "10.0.0.200":
            return _Res(stdout="switch1.lan.\n", returncode=0)
        return _NO_PTR

    monkeypatch.setattr(rdns.subprocess, "run", _fake_run)

    ips = [f"10.0.0.{i}" for i in range(1, 201)]
    out = rdns.resolve_ptr(ips, ["10.0.0.53"], timeout=2)

    # Far more than _DEAD_STRIKES no-PTR answers precede it, so this only passes
    # if an answered-but-empty lookup leaves the resolver in service.
    assert out == {"10.0.0.200": "switch1.lan"}


def test_falls_through_to_the_next_resolver_that_has_the_record(monkeypatch):
    """A resolver answering "no PTR" is alive but unhelpful for THIS ip, so the
    per-host loop must still try the next one (the pre-existing behavior)."""

    def _fake_run(cmd, **_kw):
        if _resolver_of(cmd) == "10.0.0.53":
            return _NO_PTR
        return _Res(stdout="internal-host.lan.\n", returncode=0)

    monkeypatch.setattr(rdns.subprocess, "run", _fake_run)

    out = rdns.resolve_ptr(["10.0.0.9"], ["10.0.0.53", "10.0.0.54"], timeout=2)
    assert out == {"10.0.0.9": "internal-host.lan"}


def test_non_hostname_output_is_rejected(monkeypatch):
    """The charset restriction on PTR output is what keeps resolver-controlled
    text from flowing into the device record; keep it enforced."""
    for junk in (
        ";; connection timed out; no servers could be reached",
        "host name with spaces",
        "$(whoami).lan.",
        "a;rm -rf /",
    ):
        monkeypatch.setattr(rdns.subprocess, "run",
                            lambda _c, _j=junk, **_kw: _Res(stdout=_j + "\n", returncode=0))
        assert rdns.resolve_ptr(["10.0.0.9"], ["10.0.0.53"], timeout=2) == {}, junk


def test_hard_timeout_counts_as_no_reply(monkeypatch):
    """A dig that hangs past its own timeout is the same signal as exit 9 — the
    resolver is not answering."""
    import subprocess as _sp

    def _fake_run(cmd, **_kw):
        if _resolver_of(cmd) == "10.0.0.1":
            raise _sp.TimeoutExpired(cmd, 4)
        return _Res(stdout="named.lan.\n", returncode=0)

    monkeypatch.setattr(rdns.subprocess, "run", _fake_run)

    ips = [f"10.0.0.{i}" for i in range(1, 61)]
    out = rdns.resolve_ptr(ips, ["10.0.0.1", "10.0.0.53"], timeout=2)
    assert len(out) == 60


def test_respects_the_host_cap(monkeypatch):
    seen: set[str] = set()

    def _fake_run(cmd, **_kw):
        seen.add(_ip_of(cmd))
        return _NO_PTR

    monkeypatch.setattr(rdns.subprocess, "run", _fake_run)

    rdns.resolve_ptr([f"10.0.{i // 256}.{i % 256}" for i in range(600)],
                     ["10.0.0.53"], timeout=2, limit=10)
    assert len(seen) == 10
