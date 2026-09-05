"""PERF-7 delivery: getting a stored capture to the dashboard, exactly once.

A capture is written by a detached child DURING an outage. The process that
reports it is therefore a later check-in — one that succeeded, because the
capture only exists in the first place when the dashboard was unreachable.

WHY THIS DOES NOT USE THE RESULT SPOOL
--------------------------------------
`_drain_result_spool` stops at the FIRST payload the dashboard will not accept
and returns, and a 4xx-rejected file is never unlinked. Putting a 2-6 KB capture
at the head of that oldest-first queue would risk stalling redelivery of the
LATENCY rows behind it — the rows that are the record of the outage itself. The
captures are already a durable, capped, atomically-written queue on disk, so they
are drained directly with their own marker and the shared spool is left alone.

That decision is what these tests protect. The interesting behaviour is all in
the queue: what advances the marker, what does not, and what a partial delivery
leaves behind for the next check-in.

ADDRESSES: the private-side shape is the real one from a production sensor, but
every PUBLIC hop here is from the documentation ranges (RFC 5737). This repo is
public and must not carry tenant identifiers; the delivery logic does not read
hop contents at all, so nothing is lost by it.
"""

from __future__ import annotations

import json

from collector import checkin
from collector import wan_path


def _capture(reason: str = "outage", verdict: str = "wan_down") -> dict:
    """A capture with the real record shape (keys and nesting from
    `wan_path.capture`), trimmed to what delivery touches."""
    return {
        "startedAt": "2026-09-05T18:22:24.893287+00:00",
        "reason": reason,
        "gateway": {"target": "10.8.3.254", "alive": True, "rtt_ms": 0.5,
                    "loss_pct": 0.0, "error": None},
        "dns": {"name": "cloudflare.com", "ok": True, "ms": 7.4, "error": None},
        "controls": [{"target": "192.0.2.1", "port": 443, "ok": False,
                      "ms": 5000.0, "error": "timed out"}],
        "dashboardControl": None,
        "icmpInternetOk": False,
        "traces": [{"mode": "icmp", "dest": "192.0.2.1",
                    "hops": [{"hop": 1, "ip": "10.8.3.254", "rtt_ms": 0.43},
                             {"hop": 2, "ip": None, "rtt_ms": None}],
                    "reached_at": None, "last_responding_hop": 1, "error": None}],
        "diffs": [{"mode": "icmp", "have_baseline": False, "short_by": None,
                   "break_after_hop": None, "break_after_ip": None, "new_ips": []}],
        "baseline": None,
        "verdict": {"code": verdict, "summary": "…"},
        "truncated": False,
        "elapsedMs": 14675,
    }


def _stage(monkeypatch, tmp_path, names, statuses):
    """Write capture files under `names` and stub the POST to return `statuses`
    in order. Returns the recorded calls."""
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir(parents=True, exist_ok=True)
    for n in names:
        (cap_dir / n).write_text(json.dumps(_capture()))
    monkeypatch.setattr(wan_path, "CAPTURE_DIR", cap_dir)
    monkeypatch.setattr(checkin, "WAN_PATH_REPORTED_FILE", tmp_path / "reported.json")

    calls: list[tuple[str, dict]] = []
    seq = list(statuses)

    def fake_post_status(url, token, body):
        calls.append((url, body))
        status = seq.pop(0) if seq else 200
        return ({"ok": True} if status and 200 <= status < 300 else None), status

    monkeypatch.setattr(checkin, "_post_status", fake_post_status)
    return calls


def _marker(tmp_path) -> str:
    p = tmp_path / "reported.json"
    if not p.exists():
        return ""
    return str(json.loads(p.read_text()).get("last_reported") or "")


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_posts_each_stored_capture_to_the_right_endpoint(monkeypatch, tmp_path):
    calls = _stage(monkeypatch, tmp_path,
                   ["00000000000000000001.json", "00000000000000000002.json"],
                   [200, 200])
    checkin._report_wan_path("https://dash", "tok")
    assert [u for u, _ in calls] == [
        "https://dash/api/sensor/wan-path-result",
        "https://dash/api/sensor/wan-path-result",
    ]


def test_posts_the_capture_record_verbatim(monkeypatch, tmp_path):
    """The route parses the on-disk shape, so delivery must not reshape it."""
    calls = _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [200])
    checkin._report_wan_path("https://dash", "tok")
    assert calls[0][1] == _capture()


def test_oldest_first(monkeypatch, tmp_path):
    """Zero-padded ns filenames sort chronologically, and an incident is only
    readable in order."""
    calls = _stage(monkeypatch, tmp_path,
                   ["00000000000000000009.json", "00000000000000000010.json"],
                   [200, 200])
    checkin._report_wan_path("https://dash", "tok")
    assert [c[1]["startedAt"] for c in calls] == [_capture()["startedAt"]] * 2
    assert _marker(tmp_path) == "00000000000000000010.json"


def test_a_delivered_capture_is_never_sent_twice(monkeypatch, tmp_path):
    calls = _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [200, 200])
    checkin._report_wan_path("https://dash", "tok")
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 1


def test_the_capture_file_survives_delivery(monkeypatch, tmp_path):
    """Unlike a spool file, a capture is EVIDENCE and stays readable on the box
    via `diag-wan-path` after the dashboard has it."""
    _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [200])
    checkin._report_wan_path("https://dash", "tok")
    assert (tmp_path / "captures" / "00000000000000000001.json").exists()


def test_a_capture_written_later_is_picked_up_next_run(monkeypatch, tmp_path):
    calls = _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [200, 200])
    checkin._report_wan_path("https://dash", "tok")
    (tmp_path / "captures" / "00000000000000000002.json").write_text(
        json.dumps(_capture(reason="recovery", verdict="ok"))
    )
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 2
    assert calls[1][1]["reason"] == "recovery"


# ---------------------------------------------------------------------------
# Nothing to do
# ---------------------------------------------------------------------------


def test_no_capture_dir_is_silent(monkeypatch, tmp_path):
    monkeypatch.setattr(wan_path, "CAPTURE_DIR", tmp_path / "nope")
    monkeypatch.setattr(checkin, "WAN_PATH_REPORTED_FILE", tmp_path / "reported.json")
    called: list[object] = []
    monkeypatch.setattr(checkin, "_post_status",
                        lambda *a, **k: called.append(1) or (None, None))
    checkin._report_wan_path("https://dash", "tok")
    assert called == []


def test_no_new_captures_makes_no_request(monkeypatch, tmp_path):
    calls = _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [200])
    checkin._report_wan_path("https://dash", "tok")
    calls.clear()
    checkin._report_wan_path("https://dash", "tok")
    assert calls == []


# ---------------------------------------------------------------------------
# Failure: stop, keep the evidence, retry later
# ---------------------------------------------------------------------------


def test_a_network_failure_stops_the_run_and_advances_nothing(monkeypatch, tmp_path):
    """status None = the request never completed. The path is down again; every
    further attempt would burn a full 25s urllib timeout for nothing."""
    calls = _stage(monkeypatch, tmp_path,
                   ["00000000000000000001.json", "00000000000000000002.json",
                    "00000000000000000003.json"],
                   [None, 200, 200])
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 1
    assert _marker(tmp_path) == ""


def test_a_failure_midway_keeps_what_was_delivered(monkeypatch, tmp_path):
    calls = _stage(monkeypatch, tmp_path,
                   ["00000000000000000001.json", "00000000000000000002.json",
                    "00000000000000000003.json"],
                   [200, None, 200])
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 2
    assert _marker(tmp_path) == "00000000000000000001.json"
    # The next check-in resumes at 2, and does not re-send 1.
    calls.clear()
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 2


def test_a_5xx_stops_rather_than_discarding(monkeypatch, tmp_path):
    """A dashboard mid-deploy is transient. The capture waits."""
    calls = _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [502, 200])
    checkin._report_wan_path("https://dash", "tok")
    assert _marker(tmp_path) == ""
    calls.clear()
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 1
    assert _marker(tmp_path) == "00000000000000000001.json"


def test_a_401_never_skips_the_backlog(monkeypatch, tmp_path):
    """A rotated token is a fact about our CREDENTIAL, not about the capture.
    Treating it as a permanent rejection would silently discard the whole
    incident record while the enrol self-heal was still fixing the token."""
    _stage(monkeypatch, tmp_path,
           ["00000000000000000001.json", "00000000000000000002.json"],
           [401, 401])
    checkin._report_wan_path("https://dash", "tok")
    assert _marker(tmp_path) == ""


# ---------------------------------------------------------------------------
# Failure: a capture the dashboard will NEVER take must not wedge the queue
# ---------------------------------------------------------------------------


def test_a_permanently_rejected_capture_is_skipped(monkeypatch, tmp_path):
    """This is the spool's failure mode, deliberately not reproduced: one
    unacceptable payload at the head must not block every capture behind it."""
    calls = _stage(monkeypatch, tmp_path,
                   ["00000000000000000001.json", "00000000000000000002.json"],
                   [400, 200])
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 2
    assert _marker(tmp_path) == "00000000000000000002.json"


def test_an_unreadable_capture_is_skipped(monkeypatch, tmp_path):
    calls = _stage(monkeypatch, tmp_path,
                   ["00000000000000000001.json", "00000000000000000002.json"],
                   [200])
    (tmp_path / "captures" / "00000000000000000001.json").write_text("{ not json")
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 1
    assert _marker(tmp_path) == "00000000000000000002.json"


def test_a_corrupt_marker_does_not_lose_the_backlog(monkeypatch, tmp_path):
    """Re-sending is safe — the dashboard dedups on (sensor, startedAt) — but
    losing captures is not, so an unreadable marker restarts from the top."""
    calls = _stage(monkeypatch, tmp_path, ["00000000000000000001.json"], [200])
    (tmp_path / "reported.json").write_text("{{{")
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_work_per_run_is_bounded(monkeypatch, tmp_path):
    names = [f"{i:020d}.json" for i in range(1, 13)]
    calls = _stage(monkeypatch, tmp_path, names, [200] * 12)
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == checkin.WAN_PATH_REPORT_PER_RUN
    # …and the backlog drains across subsequent check-ins rather than being lost.
    calls.clear()
    checkin._report_wan_path("https://dash", "tok")
    assert len(calls) == checkin.WAN_PATH_REPORT_PER_RUN
    assert _marker(tmp_path) == f"{2 * checkin.WAN_PATH_REPORT_PER_RUN:020d}.json"


# ---------------------------------------------------------------------------
# The capture carries the baseline it was judged against
# ---------------------------------------------------------------------------


def test_capture_embeds_the_baseline_it_diffed_against(monkeypatch):
    """"the baseline gets further" is only readable next to the baseline it
    refers to, and the reader is the dashboard — elsewhere, later, by which time
    the live baseline has merged more samples."""
    monkeypatch.setattr(wan_path, "ping",
                        lambda *a, **k: {"target": "10.8.3.254", "alive": True,
                                         "rtt_ms": 0.4, "loss_pct": 0.0, "error": None})
    monkeypatch.setattr(wan_path, "tcp_connect",
                        lambda h, p=443, timeout=5.0: {"target": h, "port": p, "ok": True,
                                                       "ms": 1.0, "error": None})
    monkeypatch.setattr(wan_path, "dns_resolves",
                        lambda n, timeout=5.0: {"name": n, "ok": True, "ms": 1.0,
                                                "error": None})
    monkeypatch.setattr(wan_path, "trace",
                        lambda dest, mode="icmp", **k: {
                            "mode": mode, "dest": dest,
                            "hops": [{"hop": 1, "ip": "10.8.3.254", "rtt_ms": 0.4}],
                            "reached_at": None, "last_responding_hop": 1, "error": None})
    baseline = {
        "updated_at": "2026-09-05T17:56:33+00:00",
        "sample_count": 8,
        "modes": {"icmp": {"dest": "192.0.2.1",
                           "hop_ips": {"1": ["10.8.3.254"], "2": ["198.51.100.7"]},
                           "deepest_responding_hop": 2}},
    }
    rec = wan_path.capture(reason="manual", controls=["192.0.2.1"],
                           gateway_ip="10.8.3.254", baseline=baseline)
    assert rec["baseline"] == baseline


def test_capture_without_a_baseline_embeds_none_not_an_empty_dict(monkeypatch):
    """An empty document would read downstream as "a baseline exists" and would
    silence the warning that stars are uninterpretable without one."""
    monkeypatch.setattr(wan_path, "ping",
                        lambda *a, **k: {"target": None, "alive": None, "rtt_ms": None,
                                         "loss_pct": None, "error": None})
    monkeypatch.setattr(wan_path, "tcp_connect",
                        lambda h, p=443, timeout=5.0: {"target": h, "port": p, "ok": True,
                                                       "ms": 1.0, "error": None})
    monkeypatch.setattr(wan_path, "dns_resolves",
                        lambda n, timeout=5.0: {"name": n, "ok": True, "ms": 1.0,
                                                "error": None})
    monkeypatch.setattr(wan_path, "trace",
                        lambda dest, mode="icmp", **k: {
                            "mode": mode, "dest": dest, "hops": [],
                            "reached_at": None, "last_responding_hop": None,
                            "error": None})
    rec = wan_path.capture(reason="manual", controls=["192.0.2.1"], baseline={})
    assert rec["baseline"] is None


def test_render_falls_back_to_the_embedded_baseline(monkeypatch):
    """`--report` passes the box's CURRENT baseline, but a capture read without
    one must still show the comparison it was actually judged against."""
    rec = _capture()
    rec["baseline"] = {
        "modes": {"icmp": {"dest": "192.0.2.1",
                           "hop_ips": {"1": ["10.8.3.254"], "2": ["198.51.100.7"]},
                           "deepest_responding_hop": 2}}
    }
    out = wan_path.render(rec)
    assert "198.51.100.7" in out
    assert "no baseline captured yet" not in out
