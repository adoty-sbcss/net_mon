"""PERF-9 call-quality probe: parsing, scoring, the three outcomes, and the
check-in wiring.

Scoring constants are the ITU's (G.107 / G.113), so the tests pin the E-model at
reference points rather than re-deriving it: a clean LAN must score "good", loss
must cost what G.113 says it costs for G.711+PLC, and a stream that lost
everything must report NO score — a MOS of 1.0 would read as "terrible call
quality" when the truth is "no reply", and an ICMP-filtering gateway is not a
broken phone network.

⚠️ The ping transcripts below are TYPED in iputils' documented output shape, not
copied from a box: the verification sensor was unreachable when this was written.
The live check on the sensor is what certifies the parser against real output.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from collector import checkin, voice


def _transcript(host: str, replies: dict[int, float], transmitted: int) -> str:
    lines = [f"PING {host} ({host}) 172(200) bytes of data."]
    for seq in sorted(replies):
        lines.append(f"180 bytes from {host}: icmp_seq={seq} ttl=57 time={replies[seq]} ms")
    received = len(replies)
    loss = round(100 * (transmitted - received) / transmitted, 1)
    lines += ["", f"--- {host} ping statistics ---",
              f"{transmitted} packets transmitted, {received} received, {loss:g}% packet loss, time 4983ms"]
    if replies:
        vals = list(replies.values())
        lines.append(f"rtt min/avg/max/mdev = {min(vals)}/{sum(vals)/len(vals):.3f}/{max(vals)}/0.100 ms")
    return "\n".join(lines) + "\n"


def test_parse_ping_reads_sequence_numbers_and_ignores_duplicates():
    out = _transcript("1.1.1.1", {1: 9.1, 2: 9.3, 4: 9.2}, 4)
    out = out.replace("time=9.3 ms", "time=9.3 ms\n180 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=55.0 ms (DUP!)")
    transmitted, rtts = voice.parse_ping(out)
    assert transmitted == 4
    assert rtts == {1: 9.1, 2: 9.3, 4: 9.2}, "a DUP! reply must not overwrite the first"


def test_parse_ping_without_statistics_never_counted():
    assert voice.parse_ping("ping: sendmsg: Operation not permitted\n") == (None, {})


def test_clean_lan_scores_good():
    s = voice.score(250, {i: 1.0 + (i % 3) * 0.1 for i in range(1, 251)})
    assert s["loss_pct"] == 0.0 and s["max_loss_burst"] == 0
    assert s["grade"] == "good" and s["mos"] >= 4.3


def test_loss_costs_what_g113_says():
    # 5% random loss on G.711+PLC: Ie,eff = 95 * 5 / (5 + 25.1) ~= 15.8
    rtts = {i: 10.0 for i in range(1, 201) if i % 20 != 0}  # every 20th of 200 lost
    s = voice.score(200, rtts)
    assert s["loss_pct"] == 5.0 and s["max_loss_burst"] == 1
    assert 76 <= s["r_factor"] <= 78
    assert s["grade"] == "fair"


def test_bursty_loss_scores_worse_than_the_same_loss_spread_out():
    spread = {i: 10.0 for i in range(1, 201) if i % 20 != 0}
    burst = {i: 10.0 for i in range(1, 201) if not (100 <= i < 110)}
    assert voice.score(200, burst)["loss_pct"] == voice.score(200, spread)["loss_pct"] == 5.0
    assert voice.score(200, burst)["max_loss_burst"] == 10
    assert voice.score(200, burst)["r_factor"] < voice.score(200, spread)["r_factor"]


def test_jitter_is_between_consecutive_received_packets():
    rtts = {1: 10.0, 2: 30.0, 3: 10.0, 4: 30.0}
    assert voice.score(4, rtts)["jitter_ms"] == 20.0


def test_total_loss_reports_no_score():
    s = voice.score(250, {})
    assert s["loss_pct"] == 100.0 and s["max_loss_burst"] == 250
    assert s["mos"] is None and s["r_factor"] is None and s["grade"] is None


def test_mos_bounds():
    assert voice.mos_from_r(-5) == 1.0
    assert voice.mos_from_r(120) == 4.5
    assert 4.3 < voice.mos_from_r(93.2) < 4.5


def _run_returning(stdout: str, stderr: str = "", returncode: int = 0):
    def fake_run(cmd, capture_output, text, timeout):
        fake_run.cmd = cmd
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)
    return fake_run


def test_probe_argv_is_voice_shaped(monkeypatch):
    fake = _run_returning(_transcript("1.1.1.1", {1: 9.0}, 1))
    monkeypatch.setattr(voice.subprocess, "run", fake)
    voice._probe_one("internet", "1.1.1.1")
    cmd = fake.cmd
    assert cmd[cmd.index("-i") + 1] == "0.02"
    assert cmd[cmd.index("-s") + 1] == "172"
    assert cmd[cmd.index("-Q") + 1] == str(46 << 2), "DSCP EF in the TOS byte"
    assert "-w" not in cmd, (
        "-w keeps ping sending past -c under loss and exits at the first ICMP error")
    assert cmd[-1] == "1.1.1.1", "the host is the last operand"


def test_all_lost_is_no_reply_with_a_real_100(monkeypatch):
    monkeypatch.setattr(voice.subprocess, "run", _run_returning(_transcript("10.0.0.1", {}, 250), returncode=1))
    r = voice._probe_one("gateway", "10.0.0.1")
    assert r["status"] == "no_reply" and r["loss_pct"] == 100.0 and r["mos"] is None


def test_instrument_failure_is_unavailable_with_no_loss_figure(monkeypatch):
    monkeypatch.setattr(voice.subprocess, "run",
                        _run_returning("", "ping: socket: Operation not permitted", 2))
    r = voice._probe_one("internet", "1.1.1.1")
    assert r["status"] == "unavailable"
    assert r["loss_pct"] is None and r["sent"] is None and r["mos"] is None
    assert "Operation not permitted" in r["error"]


def test_hung_ping_is_unavailable(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ping", timeout=1)
    monkeypatch.setattr(voice.subprocess, "run", boom)
    r = voice._probe_one("internet", "1.1.1.1")
    assert r["status"] == "unavailable" and r["loss_pct"] is None


def test_probe_voice_dedupes_hosts(monkeypatch):
    calls = []
    def fake(label, host, tos=voice.TOS_EF):
        calls.append((label, host, tos))
        return {"label": label, "host": host, "status": "ok"}
    monkeypatch.setattr(voice, "_probe_one", fake)
    out = voice.probe_voice([("gateway", "10.0.0.1"), ("voice", "10.0.0.1"), ("internet", "1.1.1.1")])
    ef = sorted((label, host) for label, host, tos in calls if tos == voice.TOS_EF)
    assert ef == [("gateway", "10.0.0.1"), ("internet", "1.1.1.1")]
    # Plus the internet target's best-effort twin (test_voice_qos_twin.py).
    assert [(label, host) for label, host, tos in calls if tos == voice.TOS_BE] == [("internet", "1.1.1.1")]
    assert len(out) == 2


# --- check-in wiring ----------------------------------------------------------


def test_targets_are_gateway_internet_then_district_voice(monkeypatch):
    import collector.latency as latency_mod
    monkeypatch.setattr(latency_mod, "default_gateway", lambda: "10.0.0.1")
    settings = SimpleNamespace(latency_targets="1.1.1.1,8.8.8.8",
                               voice_targets="pbx.k12.org,-f,10.5.5.5")
    assert checkin._voice_targets(settings) == [
        ("gateway", "10.0.0.1"),
        ("internet", "1.1.1.1"),
        ("voice", "pbx.k12.org"),
        ("voice", "10.5.5.5"),
    ], "an option-shaped token never reaches ping's argv"


def test_pushed_voice_targets_are_screened():
    import pytest
    with pytest.raises(ValueError):
        checkin._validate_desired_config({"voice_targets": "-f"})
    with pytest.raises(ValueError):
        checkin._validate_desired_config({"voice_targets": "a.k12.org,b.k12.org,c.k12.org,d.k12.org,e.k12.org"})
    checkin._validate_desired_config({"voice_targets": "pbx.k12.org,10.5.5.5"})


def test_offline_voice_results_are_spooled_not_posted(monkeypatch):
    spooled = []
    monkeypatch.setattr(checkin, "_spool_results", lambda ep, p: spooled.append((ep, p)))
    monkeypatch.setattr(checkin, "_post_result", lambda *a, **k: (_ for _ in ()).throw(AssertionError("posted")))
    checkin._report_voice("https://d", "t", [{"label": "internet", "host": "1.1.1.1", "status": "ok",
                                              "mos": 4.4}], spool_only=True)
    assert spooled and spooled[0][0] == "/api/sensor/voice-result"
    assert spooled[0][1][0]["mos"] == 4.4 and spooled[0][1][0]["startedAt"]
