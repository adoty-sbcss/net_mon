"""WAN-path evidence (PERF-7): the rules that keep a hop table honest.

A district lost its internet for a week and NetMon could not say what broke.
This module's job is to name the hop — and, just as importantly, to REFUSE to
name one when the measurement does not support it.

Every traceroute fixture below is COPIED VERBATIM from a real production sensor
(Monitor1, 2026-09-05), including the awkward ones. That matters more than usual
here: the whole design turns on empirical facts about how traceroute behaves on
this network, and an invented fixture would encode the textbook behaviour instead
of the real one — which is precisely backwards. In particular `_ICMP_INTERIOR_STAR`
is a genuine healthy run where hop 10 did not answer and hop 11 did. A tidier
fixture would have quietly deleted the exact case the artifact rule exists for.

No network, no DB: subprocess and socket are the only edges and they are
monkeypatched.
"""

from __future__ import annotations

from types import SimpleNamespace

from collector import wan_path


# --- Real traceroute output, copied from Monitor1 --------------------------

# Healthy TCP-443 trace, no --sport: all 11 hops, 0.06s.
_HEALTHY = """traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 60 byte packets
 1  10.8.3.254  0.429 ms
 2  10.1.251.134  0.319 ms
 3  10.2.20.254  0.377 ms
 4  163.150.15.189  0.624 ms
 5  137.164.3.90  2.299 ms
 6  137.164.11.86  2.362 ms
 7  137.164.11.111  2.281 ms
 8  141.101.72.12  2.547 ms
 9  141.101.72.105  2.261 ms
10  141.101.72.110  5.935 ms
11  1.1.1.1  2.788 ms
"""

# A HEALTHY ICMP run in which hop 10 declined to answer but hop 11 (the
# destination) did. Routers rate-limit ICMP from their own control plane, so an
# interior star says nothing about forwarding. Keep this fixture ugly.
_ICMP_INTERIOR_STAR = """traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 60 byte packets
 1  10.8.3.254  0.464 ms
 2  10.1.251.134  0.329 ms
 3  10.2.20.254  0.421 ms
 4  163.150.15.189  0.906 ms
 5  137.164.3.90  2.643 ms
 6  137.164.11.86  2.639 ms
 7  137.164.11.111  2.564 ms
 8  141.101.72.12  3.220 ms
 9  141.101.72.105  2.466 ms
10  *
11  1.1.1.1  2.934 ms
"""

# The blackout shape: three hops then stars to the limit. Copied from the real
# `--sport` run, which produced this ON A HEALTHY PATH — the observation that
# removed --sport from the design. It is also what a genuine break looks like,
# which is exactly why the baseline has to arbitrate.
_TRUNCATED = """traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 60 byte packets
 1  10.8.3.254  0.473 ms
 2  10.1.251.134  0.280 ms
 3  10.2.20.254  0.274 ms
 4  *
 5  *
 6  *
 7  *
 8  *
 9  *
10  *
11  *
12  *
"""


def _hops(text: str):
    return wan_path._parse_hops(text)


# --- Hop analysis ----------------------------------------------------------


def test_interior_star_is_not_a_break():
    """A star with a LIVE hop after it is ICMP policing, not a broken path."""
    hops = _hops(_ICMP_INTERIOR_STAR)
    assert hops[9]["ip"] is None, "fixture must keep the real interior star"
    assert wan_path.last_responding_hop(hops) == 11, (
        "hop 11 answered, so the path did not stop at 10 — reporting 10 here "
        "would name an innocent router as the break"
    )
    assert wan_path.trailing_star_count(hops) == 0


def test_trailing_stars_mark_where_the_path_stops():
    hops = _hops(_TRUNCATED)
    assert wan_path.last_responding_hop(hops) == 3
    assert wan_path.trailing_star_count(hops) == 9


def test_nothing_answered_yields_no_hop():
    assert wan_path.last_responding_hop([{"hop": 1, "ip": None, "rtt_ms": None}]) is None


def test_parse_keeps_stars_as_positions():
    hops = _hops(_TRUNCATED)
    assert len(hops) == 12, "a star is still a hop position, not a dropped row"
    assert hops[3] == {"hop": 4, "ip": None, "rtt_ms": None}


# --- Baseline / ECMP -------------------------------------------------------


def _baseline_from(*texts, mode="icmp"):
    traces = [
        {"mode": mode, "dest": "1.1.1.1", "hops": _hops(t),
         "reached_at": 11, "error": None}
        for t in texts
    ]
    return wan_path.merge_baseline(wan_path.empty_baseline(), traces)


def test_baseline_accumulates_ecmp_alternatives_per_hop():
    """Hops that load-balance must collect their alternatives, not overwrite."""
    # Two real runs that differ only at hop 5 (CENIC) and hop 10 (Cloudflare).
    other = _HEALTHY.replace("137.164.3.90", "137.164.1.114").replace(
        "141.101.72.110", "141.101.72.125"
    )
    base = _baseline_from(_HEALTHY, other)
    hop_ips = base["modes"]["icmp"]["hop_ips"]
    assert hop_ips["5"] == ["137.164.3.90", "137.164.1.114"]
    assert hop_ips["10"] == ["141.101.72.110", "141.101.72.125"]
    assert hop_ips["1"] == ["10.8.3.254"], "a stable hop keeps exactly one address"
    assert base["modes"]["icmp"]["deepest_responding_hop"] == 11
    assert base["sample_count"] == 2


def test_known_ecmp_arm_is_not_reported_as_a_reroute():
    """The false positive that would fire on every healthy capture.

    EVERY arm the baseline has seen must be accepted, so this checks both. An
    earlier version asserted only against the arm that happened to be merged
    LAST — which a baseline that overwrote instead of accumulating would also
    satisfy, leaving the assertion decorative. (Caught by mutating the source:
    the overwrite bug walked straight through the single-arm version.)
    """
    other = _HEALTHY.replace("137.164.3.90", "137.164.1.114")
    base = _baseline_from(_HEALTHY, other)
    for text, arm in ((_HEALTHY, "137.164.3.90"), (other, "137.164.1.114")):
        tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(text),
              "reached_at": 11, "last_responding_hop": 11, "error": None}
        diff = wan_path.compare(base, tr)
        assert diff["new_ips"] == [], f"hop-5 arm {arm} is in the baseline set"
        assert diff["short_by"] is None


def test_genuinely_new_hop_is_reported_as_a_reroute():
    base = _baseline_from(_HEALTHY)
    rerouted = _HEALTHY.replace("137.164.3.90", "203.0.113.7")
    tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(rerouted),
          "reached_at": 11, "last_responding_hop": 11, "error": None}
    diff = wan_path.compare(base, tr)
    assert [n["hop"] for n in diff["new_ips"]] == [5]
    assert diff["new_ips"][0]["ip"] == "203.0.113.7"
    assert diff["short_by"] is None, "a reroute that still arrives is not a break"


def test_break_is_named_only_relative_to_the_baseline():
    """The headline claim: 'the path stops after 10.2.20.254'."""
    base = _baseline_from(_HEALTHY)
    tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(_TRUNCATED),
          "reached_at": None, "last_responding_hop": 3, "error": None}
    diff = wan_path.compare(base, tr)
    assert diff["short_by"] == 8, "baseline reached 11, we stopped at 3"
    assert diff["break_after_hop"] == 3
    assert diff["break_after_ip"] == "10.2.20.254"


def test_a_single_silent_tail_hop_is_not_a_break():
    """The false alarm a healthy sensor would otherwise raise on itself.

    We send one query per hop, so ONE dropped probe at the tail costs one hop of
    apparent depth. A live healthy capture on Monitor1 had hop 10 silent and hop
    11 answering; if hop 11 had also missed its single probe, the headline would
    have read "PATH ENDS HERE" on a working path. A real break is not subtle.
    """
    base = _baseline_from(_HEALTHY)  # reaches hop 11
    quiet_tail = _HEALTHY.replace("11  1.1.1.1  2.788 ms", "11  *")
    tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(quiet_tail),
          "reached_at": None, "last_responding_hop": 10, "error": None}
    diff = wan_path.compare(base, tr)
    assert diff["short_by"] is None, "one silent tail hop is probe loss, not a break"
    assert diff["break_after_ip"] is None


def test_a_real_truncation_still_counts_as_a_break():
    """The threshold must not swallow the case the feature exists for."""
    base = _baseline_from(_HEALTHY)
    tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(_TRUNCATED),
          "reached_at": None, "last_responding_hop": 3, "error": None}
    assert wan_path.compare(base, tr)["short_by"] == 8


def test_no_baseline_means_no_break_claim():
    """Without a known-good path, stars are uninterpretable — say nothing.

    This is the guard against the feature's worst failure mode: every trace to
    the dashboard ends in a star in production, so a baseline-free reading would
    report a break on a perfectly healthy box, forever.
    """
    tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(_TRUNCATED),
          "reached_at": None, "last_responding_hop": 3, "error": None}
    diff = wan_path.compare(wan_path.empty_baseline(), tr)
    assert diff["have_baseline"] is False
    assert diff["break_after_ip"] is None
    assert diff["short_by"] is None


def test_a_baseline_for_a_different_destination_is_not_used():
    """Found on a live sensor, with every gate green.

    A capture aimed at a target one hop away was headlined "the path stops after
    hop 1" — not because anything was broken, but because the stored baseline had
    been measured to 1.1.1.1, eleven hops out. Changing `wan_path_targets` would
    have left every sensor claiming a permanent break until its next daily
    baseline. Fail closed: no comparable baseline means no claim.
    """
    base = _baseline_from(_HEALTHY)  # measured to 1.1.1.1
    tr = {"mode": "icmp", "dest": "10.8.3.254",
          "hops": [{"hop": 1, "ip": "10.8.3.254", "rtt_ms": 0.5}],
          "reached_at": 1, "last_responding_hop": 1, "error": None}
    diff = wan_path.compare(base, tr)
    assert diff["have_baseline"] is False
    assert diff["break_after_ip"] is None, "a different destination is not a break"


def test_reaching_the_destination_is_never_a_break():
    """Arrival is the strongest evidence the path works — outrank the baseline.

    Otherwise a route that legitimately shortened (a closer anycast node) reads
    as a failure.
    """
    base = _baseline_from(_HEALTHY)
    short = """traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 60 byte packets
 1  10.8.3.254  0.4 ms
 2  1.1.1.1  1.2 ms
"""
    tr = {"mode": "icmp", "dest": "1.1.1.1", "hops": _hops(short),
          "reached_at": 2, "last_responding_hop": 2, "error": None}
    diff = wan_path.compare(base, tr)
    assert diff["short_by"] is None, "we got there; there is no break to report"
    assert diff["break_after_ip"] is None


def test_changing_the_destination_resets_that_mode_baseline():
    """No chimera baselines: new dest + old hops would defeat the dest check.

    Sibling of the bug above. `compare()` refuses a baseline built for another
    destination — but only if the stored `dest` still says so. Merging a new
    target's traces into the old entry rewrites `dest` while leaving the previous
    route's `hop_ips` and depth in place, so the guard passes and the two
    unrelated paths get diffed against each other.
    """
    base = _baseline_from(_HEALTHY)  # to 1.1.1.1, 11 hops deep
    moved = wan_path.merge_baseline(
        base,
        [{"mode": "icmp", "dest": "9.9.9.9",
          "hops": [{"hop": 1, "ip": "10.8.3.254", "rtt_ms": 0.4},
                   {"hop": 2, "ip": "9.9.9.9", "rtt_ms": 3.0}],
          "reached_at": 2, "error": None}],
    )
    entry = moved["modes"]["icmp"]
    assert entry["dest"] == "9.9.9.9"
    assert entry["deepest_responding_hop"] == 2, (
        "depth must describe the NEW path, not inherit the old one's 11 hops"
    )
    assert "163.150.15.189" not in str(entry["hop_ips"]), "old route must be gone"


def test_baseline_ignores_failed_traces():
    """A trace that errored must not teach the baseline that the path is short."""
    base = wan_path.merge_baseline(
        _baseline_from(_HEALTHY),
        [{"mode": "icmp", "dest": "1.1.1.1", "hops": [],
          "reached_at": None, "error": "traceroute timed out"}],
    )
    assert base["modes"]["icmp"]["deepest_responding_hop"] == 11
    assert base["sample_count"] == 1


# --- The probe itself ------------------------------------------------------


def test_traceroute_argv_never_pins_the_source_port():
    """Regression guard on a measured, counter-intuitive fact.

    `--sport` is the textbook way to hold an ECMP flow steady, and on Monitor1 it
    turned a healthy 11-hop TCP trace into 'hops 1-3 then stars', in 18s instead
    of 0.06s — indistinguishable from a total blackout, on a path whose TCP
    connect succeeded in 15ms. Anyone 'fixing' the ECMP noise by adding it back
    would make every capture report a false break. ECMP is absorbed in the
    baseline instead (see the tests above).
    """
    for mode in ("icmp", "tcp443"):
        argv = wan_path._trace_argv("1.1.1.1", mode, 15, 2)
        assert not any(a.startswith("--sport") for a in argv), (
            "--sport manufactures a blackout reading on a healthy path"
        )
        assert argv[-1] == "1.1.1.1", "destination goes last"
        assert "-n" in argv, "never resolve hops: DNS may be the thing that is broken"
    assert "-I" in wan_path._trace_argv("1.1.1.1", "icmp", 15, 2)
    tcp = wan_path._trace_argv("1.1.1.1", "tcp443", 15, 2)
    assert "-T" in tcp and "443" in tcp


def test_targets_must_be_ip_literals():
    """Structural guard: the first target becomes traceroute's destination argv.

    A blocklist of 'dangerous characters' is the wrong shape here — an
    ip_address() parse makes an option-looking target impossible by construction.
    """
    s = SimpleNamespace(
        wan_path_targets="1.1.1.1, --help , cloudflare.com, 8.8.8.8, , 1.1.1.1"
    )
    assert wan_path.targets_from(s) == ["1.1.1.1", "8.8.8.8"], (
        "'--help' would be read as an OPTION; a hostname would make a dead "
        "resolver look like a dead circuit"
    )


def test_targets_empty_when_unset():
    assert wan_path.targets_from(SimpleNamespace(wan_path_targets="")) == []


# --- The verdict ladder ----------------------------------------------------

_ALIVE = {"target": "10.8.3.254", "alive": True, "loss_pct": 0.0}
_DEAD = {"target": "10.8.3.254", "alive": False, "loss_pct": 100.0}
_OK = {"target": "1.1.1.1", "ok": True}
_FAIL = {"target": "1.1.1.1", "ok": False}
_DNS_OK = {"name": "cloudflare.com", "ok": True}
_DNS_FAIL = {"name": "cloudflare.com", "ok": False}


def test_stateful_firewall_signature_is_distinguished_from_a_dead_circuit():
    """The case this feature exists for: ICMP passes, new TCP sessions die.

    A ping-based trigger calls this healthy — which is how a week-long outage
    went unexplained while every gate stayed green.
    """
    blocked = wan_path.decide(_ALIVE, [_FAIL, _FAIL], _FAIL, _DNS_OK, icmp_internet_ok=True)
    assert blocked["code"] == wan_path.VERDICT_TCP_BLOCKED

    dead = wan_path.decide(_ALIVE, [_FAIL, _FAIL], _FAIL, _DNS_OK, icmp_internet_ok=False)
    assert dead["code"] == wan_path.VERDICT_WAN_DOWN
    assert blocked["summary"] != dead["summary"], "different faults, different owners"


def test_a_dashboard_outage_is_never_reported_as_a_site_outage():
    """The misattribution guard, in the direction that would embarrass us.

    A dashboard that is fully down also makes the check-in POST fail with no HTTP
    status, which is the trigger. Independent controls are what stop that from
    being announced as 'the district's internet is down'.
    """
    v = wan_path.decide(_ALIVE, [_OK, _OK], _FAIL, _DNS_OK, icmp_internet_ok=True)
    assert v["code"] == wan_path.VERDICT_DASHBOARD_ONLY


def test_lan_fault_outranks_a_wan_claim():
    v = wan_path.decide(_DEAD, [_FAIL, _FAIL], _FAIL, _DNS_FAIL, icmp_internet_ok=False)
    assert v["code"] == wan_path.VERDICT_LAN, (
        "if our own gateway is silent we cannot say anything about the WAN"
    )


def test_dns_fault_is_its_own_finding():
    v = wan_path.decide(_ALIVE, [_OK, _OK], _OK, _DNS_FAIL, icmp_internet_ok=True)
    assert v["code"] == wan_path.VERDICT_DNS, (
        "IP literals connect but names do not resolve: the circuit is up"
    )


def test_healthy_is_healthy():
    v = wan_path.decide(_ALIVE, [_OK, _OK], _OK, _DNS_OK, icmp_internet_ok=True)
    assert v["code"] == wan_path.VERDICT_OK


# --- Capture orchestration -------------------------------------------------


def test_capture_is_bounded_and_skips_traces_it_cannot_finish(monkeypatch):
    """A partial capture delivered beats a complete one killed mid-write.

    The check-in unit is Type=oneshot and the watchdog recreates the collector
    after a prolonged upload stall — which an outage produces by definition.
    """
    monkeypatch.setattr(wan_path, "ping", lambda *a, **k: dict(_ALIVE))
    monkeypatch.setattr(wan_path, "tcp_connect", lambda *a, **k: dict(_FAIL))
    monkeypatch.setattr(wan_path, "dns_resolves", lambda *a, **k: dict(_DNS_OK))
    traced: list[str] = []

    def _never_called(dest, mode, **kw):
        traced.append(mode)
        return {"mode": mode, "dest": dest, "hops": [], "reached_at": None,
                "last_responding_hop": None, "error": None}

    monkeypatch.setattr(wan_path, "trace", _never_called)

    rec = wan_path.capture(reason="outage", controls=["1.1.1.1"], budget_sec=0)
    assert traced == [], "no trace may start that the budget cannot cover"
    assert rec["truncated"] is True, "and the record must SAY it was cut short"
    assert rec["verdict"]["code"] in {
        wan_path.VERDICT_TCP_BLOCKED, wan_path.VERDICT_WAN_DOWN
    }


def test_capture_records_the_break_on_the_verdict(monkeypatch):
    monkeypatch.setattr(wan_path, "ping", lambda *a, **k: dict(_ALIVE))
    monkeypatch.setattr(wan_path, "tcp_connect", lambda *a, **k: dict(_FAIL))
    monkeypatch.setattr(wan_path, "dns_resolves", lambda *a, **k: dict(_DNS_FAIL))
    monkeypatch.setattr(
        wan_path, "trace",
        lambda dest, mode, **kw: {
            "mode": mode, "dest": dest, "hops": _hops(_TRUNCATED),
            "reached_at": None, "last_responding_hop": 3, "error": None},
    )
    base = _baseline_from(_HEALTHY)
    base = wan_path.merge_baseline(
        base, [{"mode": "tcp443", "dest": "1.1.1.1", "hops": _hops(_HEALTHY),
                "reached_at": 11, "error": None}]
    )
    rec = wan_path.capture(
        reason="outage", controls=["1.1.1.1"], gateway_ip="10.8.3.254", baseline=base
    )
    assert rec["verdict"]["breakAfterIp"] == "10.2.20.254"
    assert rec["verdict"]["breakAfterHop"] == 3
    assert "10.2.20.254" in wan_path.render(rec, base)
    assert "PATH ENDS HERE" in wan_path.render(rec, base)


def test_render_warns_when_there_is_no_baseline(monkeypatch):
    """An operator must not read stars as a break on a box with no known-good path."""
    monkeypatch.setattr(wan_path, "ping", lambda *a, **k: dict(_ALIVE))
    monkeypatch.setattr(wan_path, "tcp_connect", lambda *a, **k: dict(_OK))
    monkeypatch.setattr(wan_path, "dns_resolves", lambda *a, **k: dict(_DNS_OK))
    monkeypatch.setattr(
        wan_path, "trace",
        lambda dest, mode, **kw: {
            "mode": mode, "dest": dest, "hops": _hops(_TRUNCATED),
            "reached_at": None, "last_responding_hop": 3, "error": None},
    )
    rec = wan_path.capture(reason="manual", controls=["1.1.1.1"])
    out = wan_path.render(rec, wan_path.empty_baseline())
    assert "no baseline captured yet" in out
    assert "PATH ENDS HERE" not in out


def test_capture_eviction_keeps_the_cap(monkeypatch, tmp_path):
    monkeypatch.setattr(wan_path, "CAPTURE_DIR", tmp_path / "captures")
    monkeypatch.setattr(wan_path, "CAPTURE_MAX", 3)
    for i in range(5):
        wan_path.save_capture({"startedAt": f"t{i}", "reason": "manual"})
    files = sorted((tmp_path / "captures").glob("*.json"))
    assert len(files) == 3, "bounded disk use on a field box"


def test_state_and_baseline_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr(wan_path, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(wan_path, "BASELINE_FILE", tmp_path / "baseline.json")
    assert wan_path.load_state() == {}, "a missing state file is not an error"
    assert wan_path.load_baseline()["modes"] == {}
    wan_path.save_state({"degraded": True})
    assert wan_path.load_state()["degraded"] is True
    (tmp_path / "baseline.json").write_text("{ this is not json")
    assert wan_path.load_baseline()["modes"] == {}, "corrupt state must not crash a probe"
