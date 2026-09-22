"""The call-quality probe's best-effort QoS twin (voice.py docstring).

The internet target gets a second, otherwise identical stream at TOS 0, run at
the same time as its EF stream, and the twin's figures ride on the internet
result as `be_*`. What must hold:

* the EF stream is untouched — byte-identical argv, same figures, same keys —
  whatever the twin does, including crashing;
* only the internet target is twinned;
* the twin really overlaps its sibling (nothing queues behind a worker cap);
* an unmeasured twin carries no figures at all.

The ping transcripts are built by the same helper shape as test_voice.py, which
is itself TYPED in iputils' documented format (see that module's warning).
"""

from __future__ import annotations

import subprocess
import threading
from types import SimpleNamespace

import pytest

from collector import checkin, voice

BE_KEYS = ("be_status", "be_sent", "be_received", "be_loss_pct", "be_max_loss_burst",
           "be_rtt_avg_ms", "be_rtt_p95_ms", "be_jitter_ms")


def _transcript(host: str, replies: dict[int, float], transmitted: int) -> str:
    # Copied from test_voice.py so both files parse the same shape.
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


# EF: clean, steady. BE: a 12-packet loss burst and alternating delay, so every
# be_* figure differs from its EF counterpart — a twin that copied the EF numbers
# (or scored the wrong stream) cannot pass.
EF_REPLIES = {i: 10.0 for i in range(1, 251)}
BE_REPLIES = {i: (20.0 if i % 2 else 40.0) for i in range(1, 251) if not (100 <= i < 112)}


def _tos(cmd: list[str]) -> str:
    return cmd[cmd.index("-Q") + 1]


def _ef_argv(host: str) -> list[str]:
    """The EF stream's argv exactly as it was before the twin existed."""
    return ["ping", "-n", "-c", "250", "-i", "0.02", "-s", "172", "-Q", "184", "-W", "1", host]


class FakePing:
    """subprocess.run stand-in: records every argv; replies by TOS byte."""

    def __init__(self, be_behaviour=None, barrier: threading.Barrier | None = None):
        self.cmds: list[list[str]] = []
        self._lock = threading.Lock()
        self.be_behaviour = be_behaviour
        self.barrier = barrier

    def __call__(self, cmd, capture_output, text, timeout):
        with self._lock:
            self.cmds.append(list(cmd))
        if self.barrier is not None:
            # Every stream must be running at once for all of them to get past.
            self.barrier.wait()
        host = cmd[-1]
        if _tos(cmd) == "0":
            if isinstance(self.be_behaviour, BaseException):
                raise self.be_behaviour
            if isinstance(self.be_behaviour, str):
                return SimpleNamespace(stdout=self.be_behaviour, stderr="", returncode=0)
            if callable(self.be_behaviour):
                return self.be_behaviour(cmd)
            return SimpleNamespace(stdout=_transcript(host, BE_REPLIES, 250), stderr="", returncode=0)
        return SimpleNamespace(stdout=_transcript(host, EF_REPLIES, 250), stderr="", returncode=0)


TARGETS = [("gateway", "10.0.0.1"), ("internet", "1.1.1.1"), ("voice", "10.5.5.5")]


def _by_label(results):
    return {r["label"]: r for r in results}


def test_internet_target_runs_ef_and_best_effort_streams(monkeypatch):
    fake = FakePing()
    monkeypatch.setattr(voice.subprocess, "run", fake)
    voice.probe_voice(TARGETS)
    internet = [c for c in fake.cmds if c[-1] == "1.1.1.1"]
    assert sorted(_tos(c) for c in internet) == ["0", "184"]
    # The twin changes the TOS byte and nothing else.
    be = next(c for c in internet if _tos(c) == "0")
    assert be == _ef_argv("1.1.1.1")[:9] + ["0"] + _ef_argv("1.1.1.1")[10:]


def test_ef_argv_is_byte_identical_for_every_label(monkeypatch):
    fake = FakePing()
    monkeypatch.setattr(voice.subprocess, "run", fake)
    voice.probe_voice(TARGETS)
    ef = sorted((c for c in fake.cmds if _tos(c) == "184"), key=lambda c: c[-1])
    assert ef == sorted((_ef_argv(h) for _, h in TARGETS), key=lambda c: c[-1])
    assert len(fake.cmds) == len(TARGETS) + 1, "exactly one extra stream: the twin"


def test_be_keys_carry_the_twins_own_scored_figures(monkeypatch):
    monkeypatch.setattr(voice.subprocess, "run", FakePing())
    r = _by_label(voice.probe_voice(TARGETS))["internet"]
    expected = voice.score(250, BE_REPLIES)
    assert r["be_status"] == "ok"
    for k in ("sent", "received", "loss_pct", "max_loss_burst", "rtt_avg_ms", "rtt_p95_ms", "jitter_ms"):
        assert r[f"be_{k}"] == expected[k], k
    # Positive control: the twin's figures are NOT the EF stream's.
    assert r["be_loss_pct"] != r["loss_pct"] and r["be_jitter_ms"] != r["jitter_ms"]
    assert r["be_max_loss_burst"] == 12
    # No score for the twin — it is a comparison baseline, not a call.
    assert not [k for k in r if k.startswith("be_") and k[3:] in ("r_factor", "mos", "grade")]
    # The EF stream still carries its own score.
    assert r["status"] == "ok" and r["mos"] is not None and r["dscp"] == 46


def test_only_the_internet_target_is_twinned(monkeypatch):
    fake = FakePing()
    monkeypatch.setattr(voice.subprocess, "run", fake)
    results = _by_label(voice.probe_voice(TARGETS))
    for label in ("gateway", "voice"):
        assert all(results[label].get(k) is None for k in BE_KEYS), label
    assert [c[-1] for c in fake.cmds if _tos(c) == "0"] == ["1.1.1.1"]


def test_internet_host_deduped_under_another_label_gets_no_twin(monkeypatch):
    # First label wins the de-dupe; the host is then probed as the gateway, and a
    # gateway row is informational — it must not grow a QoS comparison.
    fake = FakePing()
    monkeypatch.setattr(voice.subprocess, "run", fake)
    out = voice.probe_voice([("gateway", "1.1.1.1"), ("internet", "1.1.1.1")])
    assert len(out) == 1 and out[0]["label"] == "gateway"
    assert [_tos(c) for c in fake.cmds] == ["184"]


def test_twin_overlaps_every_other_stream(monkeypatch):
    # 6 targets (the most _voice_targets can produce) + the twin = 7 streams. A
    # barrier of 7 only opens if all 7 are running at once, so this fails (with a
    # BrokenBarrierError) if any stream queues behind a worker cap — including
    # the twin running after its EF sibling instead of alongside it.
    targets = [("gateway", "10.0.0.1"), ("internet", "1.1.1.1"), ("voice", "10.5.5.1"),
               ("voice", "10.5.5.2"), ("voice", "10.5.5.3"), ("voice", "10.5.5.4")]
    fake = FakePing(barrier=threading.Barrier(len(targets) + 1, timeout=10))
    monkeypatch.setattr(voice.subprocess, "run", fake)
    out = voice.probe_voice(targets)
    assert len(out) == 6 and len(fake.cmds) == 7
    assert _by_label(out)["internet"]["be_status"] == "ok"


@pytest.mark.parametrize("failure", [
    FileNotFoundError("ping"),
    subprocess.TimeoutExpired(cmd="ping", timeout=20),
    RuntimeError("anything else the twin could raise"),
    "ping: bad TOS value: 0\n",  # ping ran and never counted: no statistics block
])
def test_failed_twin_is_unavailable_and_the_ef_result_is_unaffected(monkeypatch, failure):
    monkeypatch.setattr(voice.subprocess, "run", FakePing())
    baseline = voice._probe_one("internet", "1.1.1.1")

    monkeypatch.setattr(voice.subprocess, "run", FakePing(be_behaviour=failure))
    results = _by_label(voice.probe_voice(TARGETS))
    r = results["internet"]

    assert r["be_status"] == "unavailable"
    # Unavailable carries NO figures — not the zero received/burst an unscored
    # stream reports — so "could not measure" never reads as "nothing lost".
    assert all(r[k] is None for k in BE_KEYS if k != "be_status")
    assert {k: v for k, v in r.items() if not k.startswith("be_")} == baseline
    assert results["gateway"]["status"] == results["voice"]["status"] == "ok"


def test_twin_that_got_no_reply_reports_a_real_100(monkeypatch):
    fake = FakePing(be_behaviour=lambda cmd: SimpleNamespace(
        stdout=_transcript(cmd[-1], {}, 250), stderr="", returncode=1))
    monkeypatch.setattr(voice.subprocess, "run", fake)
    r = _by_label(voice.probe_voice(TARGETS))["internet"]
    assert r["be_status"] == "no_reply"
    assert r["be_loss_pct"] == 100.0 and r["be_sent"] == 250 and r["be_received"] == 0
    assert r["be_rtt_avg_ms"] is None and r["be_jitter_ms"] is None
    assert r["status"] == "ok", "the EF stream is judged on its own replies"


def test_twin_fields_treats_an_unknown_status_as_unavailable():
    out = voice.twin_fields({"status": "weird", "sent": 250, "loss_pct": 0.0})
    assert out["be_status"] == "unavailable" and out["be_sent"] is None
    assert voice.twin_fields(None)["be_status"] == "unavailable"


# --- check-in wiring ----------------------------------------------------------


def test_report_voice_sends_the_twin_camelcased_and_null_elsewhere(monkeypatch):
    monkeypatch.setattr(voice.subprocess, "run", FakePing())
    results = voice.probe_voice(TARGETS)
    posted: list[dict] = []
    monkeypatch.setattr(checkin, "_post_result", lambda url, token, ep, p: posted.append(p))
    checkin._report_voice("https://d", "t", results)

    by = {p["label"]: p for p in posted}
    internet = by["internet"]
    r = _by_label(results)["internet"]
    assert internet["beStatus"] == "ok"
    assert internet["beSent"] == r["be_sent"] and internet["beReceived"] == r["be_received"]
    assert internet["beLossPct"] == r["be_loss_pct"]
    assert internet["beMaxLossBurst"] == r["be_max_loss_burst"]
    assert internet["beRttAvgMs"] == r["be_rtt_avg_ms"]
    assert internet["beRttP95Ms"] == r["be_rtt_p95_ms"]
    assert internet["beJitterMs"] == r["be_jitter_ms"]
    # The EF fields keep their meaning: they are still the EF stream's.
    assert internet["lossPct"] == r["loss_pct"] and internet["mos"] == r["mos"]
    assert internet["dscp"] == 46
    be_payload_keys = ("beStatus", "beSent", "beReceived", "beLossPct", "beMaxLossBurst",
                       "beRttAvgMs", "beRttP95Ms", "beJitterMs")
    for label in ("gateway", "voice"):
        assert all(by[label][k] is None for k in be_payload_keys), label
