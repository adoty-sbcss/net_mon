"""A hard outage must leave EVIDENCE, not a hole in the timeline.

`run_checkin` used to `return 1` the moment the check-in POST failed, and
`_maybe_latency` was called far below that early return. So during a WAN outage —
the one window where a latency sample is worth having — the sensor took no sample
at all, and the database recorded a GAP in timestamps rather than rows showing
100% loss. A gap reads as "the sensor was off"; 100% loss on the internet targets
while the gateway target still answers reads as "the WAN is down". Those are very
different findings, and the collector was reporting the wrong one.

The rules under test:
  * the latency probe RUNS on the check-in failure path;
  * its results are SPOOLED, not POSTed — the dashboard is already known
    unreachable, and each POST would burn the full urllib timeout;
  * the whole cycle lands in ONE spool file (the spool caps FILES, so batching is
    what stops a multi-day outage from evicting its own onset);
  * `startedAt` is preserved so the rows land in the right time bucket on delivery;
  * the healthy path is unchanged: results still POST.

Pure unit tests: no network, no DB. `_post_status` / `_post` are the network
chokepoints and are monkeypatched; the spool dir is redirected to tmp_path.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import collector as collector_pkg
import collector.latency  # noqa: F401  — so the package attribute exists to patch
from collector import checkin


def _settings(**over):
    base = {
        "dashboard_url": "https://dash",
        "enroll_token": "tok",
        "update_channel": "stable",
        "latency_enabled": True,
        "latency_targets": "1.1.1.1",
        # Off: this file is about the LATENCY channel. The speed channel's own
        # failure-path record is test_speedtest_outage_slot.py's subject, and a
        # spooled row from it would break the "one file per cycle" assertion below.
        "speedtest_enabled": False,
        "speedtest_schedule_sec": 6 * 3600,
        "snmp_enabled": False,
        "snmp_communities": "",
        "snmp_exclude": "",
        "snmp_topology_enabled": False,
        "snmp_topology_scope": "",
        "snmp_topology_max_depth": 2,
        "snmp_topology_interval": 3600,
        "bundle_transport": "blob",
        # Reported in the check-in's currentConfig block so the dashboard can show
        # the box's ACTUAL scan cadence (capture_seconds especially: two sensors
        # silently disagreeing about their sampling window makes any per-site
        # comparison of capture-derived rates unsound).
        "capture_seconds": 120,
        "capture_interval": 900,
        "rescan_interval": 3600,
    }
    base.update(over)
    return SimpleNamespace(**base)


# A real `ping` outage result, as latency.probe_latency returns it: the gateway
# still answers, the internet target is gone. This shape is what distinguishes a
# WAN outage from a dead sensor.
_OUTAGE_PROBE = [
    {
        "label": "internet",
        "host": "1.1.1.1",
        "ok": False,
        "latency_ms": None,
        "jitter_ms": None,
        "loss_pct": 100.0,
        "error": "host unreachable",
    },
    {
        "label": "gateway",
        "host": "10.8.2.1",
        "ok": True,
        "latency_ms": 0.712,
        "jitter_ms": 0.104,
        "loss_pct": 0.0,
    },
]


def _harness(monkeypatch, tmp_path, *, checkin_ok: bool):
    """Stand run_checkin up with every side-effecting edge stubbed, so the only
    thing under test is what it does when the check-in POST fails."""
    spool = tmp_path / "result-spool"
    monkeypatch.setattr(checkin, "RESULT_SPOOL_DIR", spool)
    monkeypatch.setattr(checkin, "get_settings", lambda: _settings())
    monkeypatch.setattr(checkin, "_current_token", lambda _s: "tok")
    monkeypatch.setattr(checkin, "wait_for_db", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_read_applied_version", lambda: 7)
    monkeypatch.setattr(checkin, "_local_net", lambda: ("10.8.2.100", "eth0", "10.8.2.0/24"))
    monkeypatch.setattr(checkin, "_current_sha", lambda: "abc123")
    monkeypatch.setattr(checkin, "_last_update", lambda: None)
    monkeypatch.setattr(checkin, "_last_host_action", lambda: None)
    monkeypatch.setattr(checkin, "_interfaces", lambda: [])
    monkeypatch.setattr(checkin, "_note_checkin_auth", lambda *a, **k: None)
    monkeypatch.setattr(checkin.host_metrics_mod, "collect", lambda: {})
    # The other schedulers are not under test — only latency is.
    monkeypatch.setattr(checkin, "_maybe_scheduled_iperf", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_maybe_scheduled_speedtest", lambda *a, **k: None)
    monkeypatch.setattr(checkin, "_maybe_webperf", lambda *a, **k: None)
    resp = ({"config": None, "commands": []}, 200) if checkin_ok else (None, None)
    monkeypatch.setattr(checkin, "_post_status", lambda *a, **k: resp)

    posted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        checkin, "_post", lambda u, t, b: (posted.append((u, b)), {} if checkin_ok else None)[1]
    )

    # The probe itself: stub the module the check-in imports, and record that it ran.
    ran: list[bool] = []

    def _probe(_targets, count=10):
        ran.append(True)
        return list(_OUTAGE_PROBE)

    fake_latency = SimpleNamespace(
        probe_latency=_probe, default_gateway=lambda: None
    )
    # Patch the ATTRIBUTE on the package, which is what `from . import latency`
    # resolves to. A sys.modules patch only works while the real submodule has
    # never been imported — the moment any other test file imports it, the package
    # attribute exists, getattr wins, and this harness silently runs the REAL ping.
    monkeypatch.setattr(collector_pkg, "latency", fake_latency)
    # No DNS target: this file is about the outage path, not resolver discovery
    # (see test_dns_latency_target.py). Returns (host, unavailable_reason).
    monkeypatch.setattr(checkin, "_dns_latency_target", lambda: (None, None))
    return spool, posted, ran


def test_latency_is_sampled_and_spooled_when_the_checkin_fails(monkeypatch, tmp_path):
    spool, posted, ran = _harness(monkeypatch, tmp_path, checkin_ok=False)

    rc = checkin.run_checkin()

    assert rc == 1, "a failed check-in still reports failure"
    assert ran, "the latency probe MUST run on the failure path — that is the sample"
    assert posted == [], "no POST attempts: the dashboard is already known unreachable"

    files = list(spool.glob("*.json"))
    assert len(files) == 1, "the whole cycle is one spool file, not one file per target"
    doc = json.loads(files[0].read_text())
    assert doc["endpoint"] == "/api/sensor/latency-result"
    payloads = doc["payloads"]
    assert [p["target"] for p in payloads] == ["1.1.1.1", "10.8.2.1"]
    assert payloads[0]["ok"] is False and payloads[0]["lossPct"] == 100.0
    assert payloads[1]["ok"] is True, "the gateway still answering is the distinguishing fact"
    assert payloads[0]["startedAt"], "startedAt is stamped at measurement time"
    assert payloads[0]["trigger"] == "scheduled"


def test_healthy_checkin_still_posts_latency(monkeypatch, tmp_path):
    spool, posted, ran = _harness(monkeypatch, tmp_path, checkin_ok=True)

    checkin.run_checkin()

    assert ran
    latency_posts = [b for u, b in posted if u.endswith("/api/sensor/latency-result")]
    assert len(latency_posts) == 2, "healthy path is unchanged: one POST per target"
    assert not list(spool.glob("*.json")), "nothing spooled when delivery succeeds"
