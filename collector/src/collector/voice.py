"""Call-quality probe (PERF-9): a voice-shaped packet stream, scored as MOS.

The latency probe (latency.py) sends 10 small pings 300 ms apart. That is a fine
health check and a poor stand-in for a phone call: a call is ~50 packets a second,
each ~200 bytes, marked for priority queueing, and what degrades it — queueing
jitter, short loss bursts, a congested uplink that drops the low-priority queue —
mostly does not show at 3 packets a second.

So this sends what a G.711 call sends: 250 ICMP echoes at 20 ms spacing, sized to
a 200-byte IP packet (160 bytes of audio + RTP/UDP/IP headers), carrying DSCP EF
(46) — the marking phones use — for five seconds per target. From the replies it
computes loss, the longest loss burst, round-trip latency, jitter, and scores the
result with the ITU-T G.107 E-model (R-factor -> MOS).

Honest limits, stated because every one of them is somewhere a reader could be
misled:

* ICMP is a proxy for RTP. Most networks queue it the same way; some rate-limit
  it, which reads as loss. A router answering pings from its own CPU (the default
  gateway) can add jitter and loss that forwarded calls never see — the dashboard
  treats the gateway row as informational for exactly that reason.
* EF is what we SEND. Nothing here proves the path honoured it; a network that
  re-marks EF to best effort scores the same as one that never marked it.
* Round-trip, not one-way: the one-way delay fed to the E-model is half the RTT.
* The thresholds are the ITU's (G.107 Annex B satisfaction bands), constants in
  this file, never learned from the site's own history.

Three outcomes per target (`status`), mirroring latency.py's honesty rule:

* `ok`         — ping counted replies; every figure is a measurement.
* `no_reply`   — ping counted and got nothing back (100% loss). Loss is a real
  100; latency, jitter and MOS are None, not zero.
* `unavailable`— ping could not measure (no binary, no permission, DNS failure,
  hung). Every figure is None, loss included.

The QoS twin (internet target only). Alongside the EF stream to the internet
target runs a second, otherwise identical stream sent best effort (TOS 0), at
the SAME time, so both cross the same congestion. Its figures ride on the
internet result as `be_*` (`be_status` carries the same three outcomes); it is a
comparison baseline, not a call, so it gets no R/MOS/grade. The point is the
difference: EF clearly beating BE while the path is loaded is evidence that
priority queueing works. Equal results are INCONCLUSIVE, never "QoS broken" —
no congestion during those five seconds, the marking stripped at the sensor's
own switch port (normal: a data port does not trust DSCP), and a path with no
priority queue all look exactly alike. The twin doubles the probe rate to that
one target for five seconds, so a target that rate-limits ICMP drops from both
streams at once — which reads as equal, i.e. still inconclusive — AND lowers the
EF stream's own score, the number the call-quality verdicts judge by. That is
why the rollout compares the internet row's EF loss before and after the twin.
"""
from __future__ import annotations

import re
import subprocess
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# A G.711 20 ms packet: 160 B audio + 12 RTP + 8 UDP + 20 IP = 200 B on the wire.
# ICMP: 172 B payload + 8 ICMP + 20 IP = 200 B.
PAYLOAD_BYTES = 172
PACKETS = 250  # 5 s of audio at 50 packets/s
INTERVAL_SEC = 0.02
DSCP_EF = 46
TOS_EF = DSCP_EF << 2  # 0xB8
TOS_BE = 0  # best effort: the QoS twin's marking

# The label that gets a best-effort twin, and the twin's figures as they ride on
# that label's result (prefixed `be_`). Deliberately no r_factor/mos/grade.
TWIN_LABEL = "internet"
_TWIN_FIELDS = ("sent", "received", "loss_pct", "max_loss_burst",
                "rtt_avg_ms", "rtt_p95_ms", "jitter_ms")

# ITU-T G.107 defaults / G.113 Appendix I for G.711 with packet-loss concealment.
_R0_MINUS_IS = 93.2
_IE_G711 = 0.0
_BPL_G711 = 25.1
# Packetization + codec + jitter-buffer allowance added to the network one-way
# delay. 20 ms packetization is the G.711 default frame.
_CODEC_DELAY_MS = 20.0

# G.107 Annex B user-satisfaction bands on R.
R_GOOD = 80.0  # "satisfied" or better
R_FAIR = 70.0  # "some users dissatisfied"; below this, "many"

_TRANSMITTED_RE = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received")
_REPLY_RE = re.compile(r"icmp_seq=(\d+)\b.*?time=([\d.]+)\s*ms")


def r_factor(one_way_ms: float, jitter_ms: float, loss_pct: float, burst_ratio: float) -> float:
    """Simplified G.107 E-model R for G.711+PLC. Exported for the tests."""
    ta = one_way_ms + 2.0 * jitter_ms + _CODEC_DELAY_MS
    idd = 0.024 * ta
    if ta > 177.3:
        idd += 0.11 * (ta - 177.3)
    ppl = max(0.0, min(100.0, loss_pct))
    br = max(1.0, burst_ratio)
    ie_eff = _IE_G711 + (95.0 - _IE_G711) * ppl / (ppl / br + _BPL_G711)
    return _R0_MINUS_IS - idd - ie_eff


def mos_from_r(r: float) -> float:
    """G.107 R -> MOS-CQE. Exported for the tests."""
    if r <= 0:
        return 1.0
    if r >= 100:
        return 4.5
    return 1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6


def grade(r: float | None) -> str | None:
    if r is None:
        return None
    if r >= R_GOOD:
        return "good"
    if r >= R_FAIR:
        return "fair"
    return "poor"


def score(transmitted: int, rtts: dict[int, float]) -> dict[str, Any]:
    """Turn a probe's replies ({icmp_seq: rtt_ms}) into the reported figures.

    Exported for the tests. `transmitted` is ping's own count; sequence numbers
    1..transmitted that never replied are the losses, in order, so bursts are real.
    """
    received = len(rtts)
    loss_pct = round(100.0 * (transmitted - received) / transmitted, 2) if transmitted else None
    out: dict[str, Any] = {
        "sent": transmitted,
        "received": received,
        "loss_pct": loss_pct,
        "max_loss_burst": 0,
        "rtt_avg_ms": None,
        "rtt_p95_ms": None,
        "rtt_max_ms": None,
        "jitter_ms": None,
        "r_factor": None,
        "mos": None,
        "grade": None,
    }
    # Loss bursts over the sent sequence.
    longest = run = 0
    runs: list[int] = []
    for seq in range(1, transmitted + 1):
        if seq in rtts:
            if run:
                runs.append(run)
            run = 0
        else:
            run += 1
            longest = max(longest, run)
    if run:
        runs.append(run)
    out["max_loss_burst"] = longest
    if not rtts:
        return out
    ordered = [rtts[s] for s in sorted(rtts)]
    avg = sum(ordered) / len(ordered)
    srt = sorted(ordered)
    p95 = srt[min(len(srt) - 1, int(round(0.95 * (len(srt) - 1))))]
    # Jitter as the mean absolute difference between consecutive received
    # packets' delay — the IPDV the E-model calculators use. Consecutive in
    # SEQUENCE: a lost packet between two replies does not add a fake gap.
    diffs = [abs(ordered[i] - ordered[i - 1]) for i in range(1, len(ordered))]
    jitter = sum(diffs) / len(diffs) if diffs else 0.0
    # Burst ratio (G.107): observed mean loss-burst length over the mean burst
    # length random loss would give at the same rate, 1 / (1 - p).
    p = (transmitted - received) / transmitted if transmitted else 0.0
    burst_ratio = 1.0
    if runs and p < 1.0:
        burst_ratio = (sum(runs) / len(runs)) * (1.0 - p)
    r = r_factor(avg / 2.0, jitter, loss_pct or 0.0, burst_ratio)
    out.update({
        "rtt_avg_ms": round(avg, 2),
        "rtt_p95_ms": round(p95, 2),
        "rtt_max_ms": round(srt[-1], 2),
        "jitter_ms": round(jitter, 2),
        "r_factor": round(r, 1),
        "mos": round(mos_from_r(r), 2),
        "grade": grade(r),
    })
    return out


def parse_ping(stdout: str) -> tuple[int | None, dict[int, float]]:
    """(transmitted, {seq: rtt}) from iputils ping output. Exported for the tests.
    transmitted is None when ping printed no statistics block (it never counted)."""
    rtts: dict[int, float] = {}
    for m in _REPLY_RE.finditer(stdout):
        seq = int(m.group(1))
        # A duplicate reply (DUP!) must not overwrite the first measurement.
        rtts.setdefault(seq, float(m.group(2)))
    tm = _TRANSMITTED_RE.search(stdout)
    return (int(tm.group(1)) if tm else None), rtts


def _probe_one(label: str, host: str, tos: int = TOS_EF) -> dict[str, Any]:
    """One voice-shaped stream to `host`. `tos` is the whole TOS byte (DSCP << 2):
    TOS_EF for the call itself, TOS_BE for the internet target's QoS twin — the
    only thing the twin changes."""
    base: dict[str, Any] = {"label": label, "host": host, "dscp": tos >> 2,
                            "payload_bytes": PAYLOAD_BYTES, "error": None}
    # No `-w`, deliberately. iputils keeps SENDING past `-c` while `-w` has time
    # left (pinger()'s guard is `&& !deadline`), so under loss the stream would run
    # to the deadline and `sent` would stop meaning "one 5-second call"; and `-w`
    # makes ping exit at the FIRST ICMP error, truncating the sample mid-stream.
    # `-W 1` bounds the wait for the last reply; the subprocess timeout bounds a hang.
    cmd = ["ping", "-n", "-c", str(PACKETS), "-i", str(INTERVAL_SEC), "-s", str(PAYLOAD_BYTES),
           "-Q", str(tos), "-W", "1", host]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=int(PACKETS * INTERVAL_SEC) + 15)
    except FileNotFoundError:
        return {**base, "status": "unavailable", "error": "ping not installed", **score(0, {}),
                "sent": None, "loss_pct": None}
    except subprocess.TimeoutExpired:
        return {**base, "status": "unavailable", "error": "ping timed out", **score(0, {}),
                "sent": None, "loss_pct": None}
    transmitted, rtts = parse_ping(proc.stdout or "")
    if not transmitted:
        err = (proc.stderr or "").strip()[:200] or "ping produced no statistics"
        return {**base, "status": "unavailable", "error": err, **score(0, {}),
                "sent": None, "loss_pct": None}
    scored = score(transmitted, rtts)
    status = "ok" if scored["received"] else "no_reply"
    return {**base, "status": status, **scored}


def twin_fields(twin: dict[str, Any] | None) -> dict[str, Any]:
    """The best-effort twin's figures as the `be_*` keys. Exported for the tests.

    `unavailable` — including a twin that raised, passed as None — carries NO
    figures, not even the zero received/burst an unscored stream reports, so
    "could not measure" can never read as "measured, nothing lost"."""
    status = (twin or {}).get("status")
    if status not in ("ok", "no_reply"):
        status = "unavailable"
    out: dict[str, Any] = {"be_status": status}
    for k in _TWIN_FIELDS:
        out[f"be_{k}"] = (twin or {}).get(k) if status != "unavailable" else None
    return out


def probe_voice(targets: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Probe each (label, host) concurrently — all targets finish in ~one stream's
    time, so the check-in grows by seconds, not by seconds x targets. De-dupes by
    host (first label wins). The internet target also gets its best-effort twin
    (module docstring), reported on its result as `be_*`."""
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, host in targets:
        if host and host not in seen:
            seen.add(host)
            unique.append((label, host))
    if not unique:
        return []
    # One worker per stream, so every stream STARTS together: the twin has to
    # overlap its EF sibling in time (the comparison means nothing unless both saw
    # the same congestion), and nothing may queue behind a worker cap and run a
    # second five seconds. At most gateway + internet + 4 voice + 1 twin = 7.
    # Each twin is submitted straight after its sibling to keep the start skew to
    # a thread spawn.
    twin_hosts = [host for label, host in unique if label == TWIN_LABEL]
    with ThreadPoolExecutor(max_workers=len(unique) + len(twin_hosts)) as pool:
        ef_futures: list[Future[dict[str, Any]]] = []
        twin_futures: dict[str, Future[dict[str, Any]]] = {}
        for label, host in unique:
            ef_futures.append(pool.submit(_probe_one, label, host))
            if label == TWIN_LABEL:
                twin_futures[host] = pool.submit(_probe_one, label, host, tos=TOS_BE)
        results = [f.result() for f in ef_futures]
        twins: dict[str, dict[str, Any] | None] = {}
        for host, fut in twin_futures.items():
            # The twin is an add-on: nothing it does may cost the EF measurement.
            try:
                twins[host] = fut.result()
            except Exception as exc:  # noqa: BLE001
                log.warning("voice probe best-effort twin failed", host=host, error=str(exc))
                twins[host] = None
    for r in results:
        be: dict[str, Any] = {}
        if r.get("label") == TWIN_LABEL and r.get("host") in twins:
            twin = twins[r["host"]]
            be = twin_fields(twin)
            r.update(be)
            if be["be_status"] == "unavailable" and twin is not None:
                log.info("voice probe best-effort twin unavailable", host=r["host"],
                         error=twin.get("error"))
        log.info("voice probe", label=r["label"], host=r["host"], status=r["status"],
                 mos=r.get("mos"), loss_pct=r.get("loss_pct"), jitter_ms=r.get("jitter_ms"),
                 **({"be_status": be["be_status"], "be_loss_pct": be["be_loss_pct"],
                     "be_jitter_ms": be["be_jitter_ms"]} if be else {}))
    return results
