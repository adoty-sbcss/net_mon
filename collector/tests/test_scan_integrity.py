"""Failure-injection tests for scan ordering and data integrity."""

from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from collector import db, scan, uploader
from collector.discovery.tshark import CaptureResult
from collector.models import ScanContext


@contextmanager
def _lock(acquired: bool):
    yield acquired


def test_overlapping_scan_is_skipped_before_discovery(monkeypatch) -> None:
    called = False

    def unexpected_scan(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(scan, "try_scan_lock", lambda: _lock(False))
    monkeypatch.setattr(scan, "_run_scan_locked", unexpected_scan)

    result = scan.run_scan(interface="eth0", trigger_reason="periodic", force=False)

    assert result is None
    assert called is False


def test_acquired_scan_lock_wraps_discovery(monkeypatch) -> None:
    monkeypatch.setattr(scan, "try_scan_lock", lambda: _lock(True))
    monkeypatch.setattr(scan, "_run_scan_locked", lambda **kwargs: 42)

    result = scan.run_scan(interface="eth0", trigger_reason="periodic", force=False)

    assert result == 42


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ({"rx_bytes": 10}, {"rx_bytes": 25}, 15),
        ({"rx_bytes": 25}, {"rx_bytes": 10}, None),
        ({}, {"rx_bytes": 10}, None),
        ({"rx_bytes": 10}, {}, None),
    ],
)
def test_counter_delta_rejects_reset_or_missing_sample(before, after, expected) -> None:
    assert scan._counter_delta(before, after, "rx_bytes") == expected


def test_every_scan_table_uses_the_supplied_transaction(monkeypatch) -> None:
    connection = object()
    seen_connections: list[object] = []

    def record_insert(table, rows, *, connection=None):
        seen_connections.append(connection)

    monkeypatch.setattr(scan, "insert_many", record_insert)
    monkeypatch.setattr(
        scan,
        "get_settings",
        lambda: SimpleNamespace(rdns_enabled=False, inventory_enabled=False),
    )
    now = datetime.now(UTC)

    scan._persist(
        ScanContext(1, "eth0", "192.0.2.2/24", None, None, "network", 0.0),
        connection=connection,
        pre_counters={"rx_bytes": 10},
        post_counters={"rx_bytes": 20},
        cap_results=CaptureResult(started_at=now, completed_at=now),
        lldp_neighbors=[],
        arp_results=[],
        nmap_results=[],
        snmp_results=[],
    )

    assert seen_connections
    assert all(item is connection for item in seen_connections)


def test_persistence_error_escapes_for_transaction_rollback(monkeypatch) -> None:
    def fail_insert(table, rows, *, connection=None):
        raise RuntimeError("injected database failure")

    monkeypatch.setattr(scan, "insert_many", fail_insert)
    monkeypatch.setattr(
        scan,
        "get_settings",
        lambda: SimpleNamespace(rdns_enabled=False, inventory_enabled=False),
    )
    now = datetime.now(UTC)

    with pytest.raises(RuntimeError, match="injected database failure"):
        scan._persist(
            ScanContext(1, "eth0", "192.0.2.2/24", None, None, "network", 0.0),
            connection=object(),
            pre_counters={},
            post_counters={},
            cap_results=CaptureResult(started_at=now, completed_at=now),
            lldp_neighbors=[],
            arp_results=[],
            nmap_results=[],
            snmp_results=[],
        )


def test_failed_scans_are_excluded_from_freshness_and_bundles() -> None:
    source = Path(db.__file__).read_text(encoding="utf-8")

    recent_query = source[source.index("def recent_network_scan") : source.index("def last_topology_crawl")]
    bundle_query = source[source.index("def list_scan_runs_in_window") : source.index("def list_scan_runs(")]
    catchup_query = source[
        source.index("def list_completed_scan_times_since") : source.index("def get_bundle_rows")
    ]

    assert "completed_at IS NOT NULL" in recent_query
    assert "error IS NULL" in recent_query
    assert "error IS NULL" in bundle_query
    assert "error IS NULL" in catchup_query


def test_bundle_queries_fresh_scan_ids_inside_filename_lock(monkeypatch) -> None:
    lock_active = False

    @contextmanager
    def fake_lock(filename):
        nonlocal lock_active
        lock_active = True
        try:
            yield
        finally:
            lock_active = False

    def list_runs(start, end):
        assert lock_active is True
        return [{"id": 9}]

    monkeypatch.setattr(uploader, "bundle_build_lock", fake_lock)
    monkeypatch.setattr(uploader, "list_scan_runs_in_window", list_runs)
    monkeypatch.setattr(
        uploader,
        "get_settings",
        lambda: SimpleNamespace(bundle_dir=Path.cwd(), device_name="sensor"),
    )
    monkeypatch.setattr(uploader, "_filename_for", lambda end: "locked-hour.zip")
    monkeypatch.setattr(uploader, "build_hourly_bundle", lambda *args, **kwargs: None)
    monkeypatch.setattr(uploader, "record_bundle_built", lambda *args: None)
    monkeypatch.setattr(uploader, "audit", lambda *args, **kwargs: None)

    result = uploader._build_hour(datetime.now(UTC))

    assert result == ("locked-hour.zip", 1)
    assert lock_active is False


def test_nmap_failure_does_not_fail_the_scan(monkeypatch) -> None:
    # nmap is enrichment, not a required source: a failure must degrade the scan
    # (section error) and still persist + return the scan id, NOT discard the
    # whole scan (capture, ARP, SNMP, topology) and ship nothing for the hour.
    now = datetime.now(UTC)
    state = SimpleNamespace(
        name="eth0", has_usable_ip=True, is_up=True, has_carrier=True,
        ipv4_addrs=["192.0.2.5/24"], primary_cidr="192.0.2.0/24",
        gateway_ip=None, gateway_mac="aa:bb:cc:dd:ee:ff",
    )
    monkeypatch.setattr(scan.iface_mod, "get_one", lambda iface: state)
    monkeypatch.setattr(scan.iface_mod, "read_counters", lambda iface: {})
    monkeypatch.setattr(
        scan.tshark_mod, "run_capture",
        lambda **kw: CaptureResult(started_at=now, completed_at=now),
    )
    monkeypatch.setattr(scan.lldp_mod, "fetch_neighbors", lambda: [])
    monkeypatch.setattr(scan.arp_mod, "run", lambda iface: [])
    monkeypatch.setattr(scan, "_snmp_candidates", lambda *a, **k: [])

    def nmap_boom(cidr):
        raise RuntimeError("nmap timed out scanning 192.0.2.0/24")

    monkeypatch.setattr(scan.nmap_mod, "host_discovery", nmap_boom)
    monkeypatch.setattr(scan, "insert_scan_run", lambda **kw: 7)
    monkeypatch.setattr(scan, "audit", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_persist", lambda *a, **k: None)
    monkeypatch.setattr(scan, "connect", lambda: _lock(object()))

    completed: dict[str, object] = {}

    def record_complete(scan_id, *, duration_sec, error, notes):
        completed["error"] = error
        completed["notes"] = notes

    monkeypatch.setattr(scan, "complete_scan_run", record_complete)
    monkeypatch.setattr(
        scan, "get_settings",
        lambda: SimpleNamespace(
            capture_seconds=1, snmp_enabled=False, snmp_poll_all_hosts=False,
            snmp_topology_enabled=False, dns_enabled=False,
            reachability_enabled=False, mdns_enabled=False,
        ),
    )

    result = scan._run_scan_locked(
        interface="eth0", trigger_reason="periodic", force=True)

    assert result == 7                        # scan succeeded despite nmap failing
    assert completed["error"] is None         # not marked as a failed scan
    assert "nmap" in str(completed["notes"])  # nmap failure kept as a section error


def test_recent_scan_floor_can_include_failed_attempts(monkeypatch) -> None:
    # The cadence gate counts only successful scans (so failed data isn't "fresh"),
    # but the anti-flap cooldown floor must count EVERY attempt or a persistently
    # failing scan would be retried every poll tick with no backoff.
    captured: dict[str, str] = {}

    class FakeCur:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql, params):
            captured["sql"] = sql

        def fetchone(self):
            return None

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def cursor(self):
            return FakeCur()

    monkeypatch.setattr(db, "connect", lambda: FakeConn())

    db.recent_network_scan("net", 300)  # cadence gate: success-only
    assert "completed_at IS NOT NULL" in captured["sql"]
    assert "error IS NULL" in captured["sql"]

    db.recent_network_scan("net", 300, require_success=False)  # anti-flap floor
    assert "completed_at IS NOT NULL" not in captured["sql"]
    assert "error IS NULL" not in captured["sql"]


def test_snmp_candidate_order_puts_registered_infra_before_oui_guesses(monkeypatch) -> None:
    """ORDER IS COVERAGE, not preference.

    poll() walks this list SEQUENTIALLY under one time budget and stops dead when
    it expires, so a device near the end is not polled late — it is not polled at
    all. The order is stable, so it is the SAME devices missing every scan.

    Operator-registered targets used to be appended LAST, behind every OUI-matched
    access point and camera, which made this module's own promise ("always polled
    even if the OUI/heuristic selection would miss it") false under exactly the
    budget pressure that promise exists for.
    """
    monkeypatch.setattr(
        scan,
        "get_settings",
        lambda: SimpleNamespace(
            snmp_extra_target_list=("10.0.0.9",),
            # A per-device credential override is the OTHER form of "an operator
            # said to poll this", and the dashboard promises it is tried FIRST.
            snmp_credential_override_map={"10.0.0.8": "secret"},
            snmp_exclude_list=(),
        ),
    )
    ips = scan._snmp_candidates(
        "10.0.0.1",
        [{"mgmt_ip": "10.0.0.2"}],
        [{"ip": "10.0.0.50", "vendor": "Aruba Networks"}],
        [{"ip": "10.0.0.51", "vendor": "Cisco Systems"}],
    )

    # gateway, then LLDP-ANNOUNCED infra, then both OPERATOR-ASSERTED forms,
    # and only then the OUI guesses.
    assert ips[:5] == ["10.0.0.1", "10.0.0.2", "10.0.0.9", "10.0.0.8", "10.0.0.50"]
    for asserted in ("10.0.0.9", "10.0.0.8"):
        assert ips.index(asserted) < ips.index("10.0.0.50")
        assert ips.index(asserted) < ips.index("10.0.0.51")

    # POSITIVE CONTROL. Every assertion above is also satisfied by a change that
    # DROPS the OUI-guessed devices instead of merely demoting them, which would
    # trade one silent coverage hole for a worse one.
    assert set(ips) == {"10.0.0.1", "10.0.0.2", "10.0.0.9", "10.0.0.8", "10.0.0.50", "10.0.0.51"}


def test_snmp_candidates_dedupe_keeps_the_earliest_position(monkeypatch) -> None:
    """A registered target that is ALSO an LLDP neighbour must keep the earlier
    slot, not be demoted to the registered block — otherwise adding a device to
    the registry could push it later in the list and reduce its chance of being
    polled, which is the opposite of what registering it means."""
    monkeypatch.setattr(
        scan,
        "get_settings",
        lambda: SimpleNamespace(
            snmp_extra_target_list=("10.0.0.2",), snmp_credential_override_map={"10.0.0.1": "s"},
            snmp_exclude_list=(),
        ),
    )
    ips = scan._snmp_candidates(
        "10.0.0.1", [{"mgmt_ip": "10.0.0.2"}], [], [],
    )
    assert ips == ["10.0.0.1", "10.0.0.2"]


def test_snmp_candidates_drops_excluded_ips_from_every_block(monkeypatch) -> None:
    """An excluded IP must not reach the poll from ANY source.

    Exclusion used to be honoured by the topology crawl alone, so the dashboard's
    "the sensors will stop SNMP-polling them" was false, and — the part that cost
    real coverage — an excluded device still consumed one of the
    snmp_poll_max_candidates slots and still burned budget failing to answer.

    Every block is exercised, including the two OPERATOR-ASSERTED ones: a later
    "stop polling this" has to beat an earlier "always poll this", or unexcluding
    would be the only way to undo a registry entry.
    """
    monkeypatch.setattr(
        scan,
        "get_settings",
        lambda: SimpleNamespace(
            snmp_extra_target_list=("10.0.0.9",),
            snmp_credential_override_map={"10.0.0.8": "secret"},
            snmp_exclude_list=(
                "10.0.0.1",   # gateway
                "10.0.0.2",   # LLDP-announced
                "10.0.0.9",   # registered target
                "10.0.0.8",   # credential override
                "10.0.0.50",  # OUI-guessed (arp)
            ),
        ),
    )
    ips = scan._snmp_candidates(
        "10.0.0.1",
        [{"mgmt_ip": "10.0.0.2"}],
        [{"ip": "10.0.0.50", "vendor": "Aruba Networks"}],
        [{"ip": "10.0.0.51", "vendor": "Cisco Systems"}],
    )

    # POSITIVE CONTROL FIRST: the one un-excluded device must survive. Without it
    # this test passes just as well against a change that returns [] always,
    # which would take the whole SNMP poll down while looking like a clean pass.
    assert ips == ["10.0.0.51"]


def test_snmp_candidates_exclusion_does_not_reorder_the_survivors(monkeypatch) -> None:
    """Removing an excluded device must CLOSE the gap, not shuffle the rest.

    Order is coverage here (the poll walks the list and stops), so an exclusion
    that reordered survivors would silently change which devices get reached —
    the same class of bug the exclusion is meant to fix.
    """
    monkeypatch.setattr(
        scan,
        "get_settings",
        lambda: SimpleNamespace(
            snmp_extra_target_list=("10.0.0.9",),
            snmp_credential_override_map={},
            snmp_exclude_list=("10.0.0.2",),  # the LLDP block, i.e. the MIDDLE
        ),
    )
    ips = scan._snmp_candidates(
        "10.0.0.1",
        [{"mgmt_ip": "10.0.0.2"}],
        [{"ip": "10.0.0.50", "vendor": "Aruba Networks"}],
        [],
    )
    assert ips == ["10.0.0.1", "10.0.0.9", "10.0.0.50"]
