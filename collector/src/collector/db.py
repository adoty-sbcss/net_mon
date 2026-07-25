from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
import structlog
from psycopg.rows import DictRow, dict_row

from .config import get_settings

log = structlog.get_logger(__name__)
DbConnection = psycopg.Connection[DictRow]

# One sensor-wide session lock. PostgreSQL releases it automatically if the
# collector process dies or loses its DB connection.
_SCAN_LOCK_ID = 0x4E65744D6F6E


@contextmanager
def connect() -> Iterator[DbConnection]:
    # row_factory=dict_row makes every cursor yield dict rows (not tuples), so
    # the connection is typed Connection[DictRow]. Without this annotation mypy
    # assumes the default tuple rows and flags every row["col"] access.
    settings = get_settings()
    conn = psycopg.connect(settings.dsn, row_factory=dict_row, autocommit=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def connection_scope(connection: DbConnection | None = None) -> Iterator[DbConnection]:
    """Use an existing transaction, or create and own one when omitted."""
    if connection is not None:
        yield connection
        return
    with connect() as owned_connection:
        yield owned_connection


@contextmanager
def try_scan_lock() -> Iterator[bool]:
    """Try to exclude every other scan process for the lifetime of the context."""
    settings = get_settings()
    with psycopg.connect(
        settings.dsn, row_factory=dict_row, autocommit=True
    ) as connection:
        with connection.cursor() as cur:
            cur.execute(
                "SELECT pg_try_advisory_lock(%s) AS acquired",
                (_SCAN_LOCK_ID,),
            )
            row = cur.fetchone()
            acquired = bool(row and row["acquired"])
        try:
            yield acquired
        finally:
            if acquired:
                with connection.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (_SCAN_LOCK_ID,))


@contextmanager
def bundle_build_lock(filename: str) -> Iterator[None]:
    """Serialize query/build/record for one hourly bundle across processes."""
    settings = get_settings()
    lock_name = f"netmon-bundle:{filename}"
    with psycopg.connect(
        settings.dsn, row_factory=dict_row, autocommit=True
    ) as connection:
        with connection.cursor() as cur:
            cur.execute(
                "SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                (lock_name,),
            )
        try:
            yield
        finally:
            with connection.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                    (lock_name,),
                )


def wait_for_db(timeout_seconds: int = 60) -> None:
    """Block until Postgres accepts connections, or raise after timeout."""
    settings = get_settings()
    deadline = time.monotonic() + timeout_seconds
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(settings.dsn, connect_timeout=3) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            return
        except Exception as exc:  # pragma: no cover — startup race
            last_err = exc
            time.sleep(1)
    raise RuntimeError(f"Postgres not reachable within {timeout_seconds}s: {last_err}")


def insert_scan_run(
    *,
    trigger_reason: str,
    interface: str,
    interface_cidr: str | None,
    gateway_ip: str | None,
    gateway_mac: str | None,
    network_id: str | None,
    is_primary: bool = False,
    vlan_id: int | None = None,
    parent_interface: str | None = None,
) -> int:
    s = get_settings()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (
                    trigger_reason, interface, interface_cidr,
                    gateway_ip, gateway_mac, network_id, is_primary,
                    district_slug, school_slug, device_slug,
                    vlan_id, parent_interface
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (trigger_reason, interface, interface_cidr, gateway_ip,
                 gateway_mac, network_id, is_primary,
                 s.district_slug or None,
                 s.school_slug or None,
                 s.device_slug or None,
                 vlan_id, parent_interface),
            )
            row = cur.fetchone()
            assert row is not None
            return int(row["id"])


def complete_scan_run(
    scan_id: int,
    *,
    duration_sec: int,
    error: str | None = None,
    notes: str | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_runs
                   SET completed_at = NOW(),
                       duration_sec = %s,
                       error = %s,
                       notes = %s
                 WHERE id = %s
                """,
                (duration_sec, error, notes, scan_id),
            )


def recent_network_scan(
    network_id: str,
    within_seconds: int,
    exclude_capture: bool = False,
    require_success: bool = True,
) -> dict[str, Any] | None:
    """Most recent scan_runs row for this network inside the window, or None.

    exclude_capture=True skips the light capture-only passes (trigger_reason
    'capture') so the caller sees only FULL scans. The full-scan freshness gate
    needs this: a light pass writes a scan_runs row every capture_interval, and
    if those counted toward the (longer) rescan window the full periodic scan
    would be starved forever once light passes are enabled. The light-pass gate
    leaves it False so a full scan still resets the capture clock.

    require_success=True (the freshness/cadence gates) counts only successfully
    completed scans, so a failed scan doesn't masquerade as fresh data. The
    anti-flap cooldown floor passes require_success=False so it also counts
    failed/in-progress attempts — otherwise a persistently failing scan would
    never count as "recent" and would be retried every poll tick with no backoff.
    """
    success_filter = (
        "AND completed_at IS NOT NULL AND error IS NULL" if require_success else ""
    )
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, started_at
                  FROM scan_runs
                 WHERE network_id = %s
                   {success_filter}
                   AND started_at > NOW() - (%s || ' seconds')::interval
                   AND (NOT %s OR trigger_reason IS DISTINCT FROM 'capture')
                 ORDER BY started_at DESC
                 LIMIT 1
                """,
                (network_id, str(within_seconds), exclude_capture),
            )
            return cur.fetchone()


def last_topology_crawl(network_id: str) -> Any | None:
    """Return the started_at of the most recent scan on this network that
    actually produced topology rows, or None if we've never crawled it.

    Used to gate the (expensive) SNMP topology crawl to a slow cadence:
    topology is physical cabling + switch config, so it changes far slower
    than the hourly host inventory and doesn't need rediscovery every scan.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT max(sr.started_at) AS last_at
                  FROM topology_nodes tn
                  JOIN scan_runs sr ON sr.id = tn.scan_run_id
                 WHERE sr.network_id = %s
                """,
                (network_id,),
            )
            row = cur.fetchone()
            return row["last_at"] if row else None


def last_snmp_bulk(network_id: str) -> Any | None:
    """started_at of the most recent scan on this network that walked the HEAVY
    bulk SNMP OIDs (detected via an ifTable row), or None. Gates the bulk walk to
    a slow cadence — FDB / ifTable / ARP cache change far slower than the hourly
    host inventory, so re-walking them every scan is wasted compute + db/bundle
    bloat."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT max(sr.started_at) AS last_at
                  FROM snmp_polls sp
                  JOIN scan_runs sr ON sr.id = sp.scan_run_id
                 WHERE sr.network_id = %s AND sp.oid_name = 'ifTable'
                """,
                (network_id,),
            )
            row = cur.fetchone()
            return row["last_at"] if row else None


def last_dns_probe() -> Any | None:
    """started_at of the most recent scan (this box, ANY network) that ran DNS
    probes, or None. DNS health tests the box's resolver path — identical across
    VLANs/networks — so it runs at most once per cadence box-wide, not per scan."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT max(sr.started_at) AS last_at
                  FROM dns_probes dp
                  JOIN scan_runs sr ON sr.id = dp.scan_run_id
                """
            )
            row = cur.fetchone()
            return row["last_at"] if row else None


def purge_old_scans(retention_days: int) -> int:
    """Delete scan_runs (and cascaded per-scan tables) older than retention_days
    from the collector's local db. The durable inventory survives (its scan FK is
    SET NULL, not CASCADE). Returns the number of scan_runs deleted; <=0 disables."""
    if retention_days <= 0:
        return 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM scan_runs WHERE started_at < NOW() - (%s || ' days')::interval",
                (str(retention_days),),
            )
            return cur.rowcount


# The HEAVY topology OIDs. Slow-changing (physical cabling + switch config), yet
# stored IN FULL on every bulk walk — measured at ~97% of snmp_polls on a live box,
# where snmp_polls was 13 GB / 45.7M rows = 95% of that box's ENTIRE local db. Row
# counts at the time:
#   dot1dStpPortTable 19.7M (43%); entPhysical{Class,Name,SerialNum,Descr,ModelName}
#   ~3.2M each; ifName 2.7M; ifTable 2.7M; dot1dBasePortIfIndex 1.9M;
#   dot1qTpFdbPort 1.2M.
# These get their own SHORTER window (snmp_bulk_retention_days) while genuine host
# inventory — sys*, hrDevice*, prtGeneral*, and the smaller dot1dTpFdbTable /
# ipNetToMediaTable, a minority of rows — keeps the full local_retention_days.
# Nothing is lost: every row ships in the hourly bundle first and the dashboard is
# its durable home; the box only needs recent scans for bundling + crawl gates.
#
# NOTE ifTable doubles as the marker last_snmp_bulk() dates the last bulk walk by.
# Purging it early is safe while snmp_bulk_retention_days > snmp_bulk_interval
# (defaults: 3 days vs 24h). If an operator raised the interval PAST the retention
# window, the marker would age out first and the walk would re-run on roughly the
# retention cadence instead of the configured one — bounded and self-correcting
# (a walk rewrites the marker), never a runaway, but it would undercut the saving.
HEAVY_SNMP_OID_NAMES: tuple[str, ...] = (
    "dot1dStpPortTable",
    "entPhysicalDescr",
    "entPhysicalClass",
    "entPhysicalName",
    "entPhysicalSerialNum",
    "entPhysicalModelName",
    "ifName",
    "ifTable",
    "dot1dBasePortIfIndex",
    "dot1qTpFdbPort",
)


def purge_heavy_snmp_polls(retention_days: int) -> int:
    """Delete snmp_polls rows for the HEAVY topology OIDs (HEAVY_SNMP_OID_NAMES)
    whose scan started more than retention_days ago, leaving host inventory on the
    longer local_retention_days window. Returns rows deleted; <=0 disables."""
    if retention_days <= 0:
        return 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM snmp_polls sp
                 USING scan_runs sr
                 WHERE sp.scan_run_id = sr.id
                   AND sp.oid_name = ANY(%s)
                   AND sr.started_at < NOW() - (%s || ' days')::interval
                """,
                (list(HEAVY_SNMP_OID_NAMES), str(retention_days)),
            )
            return cur.rowcount


def list_scan_runs_in_window(start, end) -> list[dict[str, Any]]:
    """Scans whose completed_at falls in [start, end). Times must be tz-aware."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, started_at, completed_at, interface, interface_cidr,
                       gateway_ip, mode, duration_sec, error, trigger_reason
                  FROM scan_runs
                 WHERE completed_at IS NOT NULL
                   AND error IS NULL
                   AND completed_at >= %s
                   AND completed_at <  %s
                 ORDER BY started_at ASC
                """,
                (start, end),
            )
            return list(cur.fetchall())


def list_scan_runs(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, started_at, completed_at, trigger_reason,
                       interface, interface_cidr, gateway_ip, mode,
                       duration_sec, error
                  FROM scan_runs
                 ORDER BY started_at DESC
                 LIMIT %s
                """,
                (limit,),
            )
            return list(cur.fetchall())


def fetch_scan(scan_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scan_runs WHERE id = %s", (scan_id,))
            return cur.fetchone()


def fetch_table_for_scan(table: str, scan_id: int) -> list[dict[str, Any]]:
    """Fetch all rows from a scan-scoped table. Table name is whitelisted."""
    allowed = {
        "devices", "neighbors", "arp_entries", "dhcp_observations",
        "stp_events", "traffic_stats", "snmp_polls", "findings",
        "topology_nodes", "topology_edges", "dns_probes",
        "network_reachability", "service_discovery",
    }
    if table not in allowed:
        raise ValueError(f"table {table!r} is not allowed")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM {table} WHERE scan_run_id = %s ORDER BY id", (scan_id,))
            return list(cur.fetchall())


def get_snmp_credential(device_ip: str) -> dict[str, Any] | None:
    """Return cached (community, version, failure_count, last_attempt_at) for a device.

    Returns None if we've never tried this device before.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT device_ip, community, version, last_succeeded_at,
                       last_attempt_at, failure_count
                  FROM snmp_credentials
                 WHERE device_ip = %s
                """,
                (device_ip,),
            )
            return cur.fetchone()


def get_snmp_credentials(device_ips: list[str]) -> dict[str, dict[str, Any]]:
    """Batch form of get_snmp_credential: cached creds for many devices in ONE
    round-trip (a single connection), keyed by device_ip. Devices we've never
    tried are simply absent. Avoids opening a fresh psycopg connection per
    candidate during a scan."""
    if not device_ips:
        return {}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT device_ip, community, version, last_succeeded_at,
                       last_attempt_at, failure_count
                  FROM snmp_credentials
                 WHERE device_ip = ANY(%s)
                """,
                (list(device_ips),),
            )
            return {r["device_ip"]: r for r in cur.fetchall()}


def list_snmp_credentials() -> list[dict[str, Any]]:
    """Every cached per-device SNMP credential, for the bundle → dashboard device
    page ("which community works on this device"). Includes devices that never
    succeeded (community NULL) so the UI can show SNMP history."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT device_ip, community, version, last_succeeded_at,
                       last_attempt_at, failure_count
                  FROM snmp_credentials
                 ORDER BY device_ip
                """
            )
            return list(cur.fetchall())


def record_snmp_success(device_ip: str, community: str, version: str = "2c") -> None:
    """Record a working community for a device. Resets failure counter."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snmp_credentials
                    (device_ip, community, version, last_succeeded_at,
                     last_attempt_at, failure_count)
                VALUES (%s, %s, %s, NOW(), NOW(), 0)
                ON CONFLICT (device_ip) DO UPDATE
                    SET community = EXCLUDED.community,
                        version   = EXCLUDED.version,
                        last_succeeded_at = NOW(),
                        last_attempt_at   = NOW(),
                        failure_count     = 0
                """,
                (device_ip, community, version),
            )


def record_snmp_failure(device_ip: str) -> None:
    """Mark a failed attempt. Increments failure_count and clears the cached
    community (so the next scan re-trials)."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snmp_credentials
                    (device_ip, community, version, last_attempt_at, failure_count)
                VALUES (%s, NULL, '2c', NOW(), 1)
                ON CONFLICT (device_ip) DO UPDATE
                    SET community = NULL,
                        last_attempt_at = NOW(),
                        failure_count   = snmp_credentials.failure_count + 1
                """,
                (device_ip,),
            )


def record_bundle_built(filename: str, local_path: str, size_bytes: int) -> None:
    """Record that a bundle file was just built. Upserts on filename so a
    rebuilt-same-hour ZIP doesn't create duplicate rows.

    A rebuild fully RESURRECTS the row: the prior upload is stale, and the retry
    budget / give-up tombstone belong to the bundle we just replaced, not to the
    new one. Resetting them is what makes an operator's explicit `upload-now`
    work again after the automation gave up on an hour (gave_up_at is terminal
    for automation only), and what stops a stale retry_count from putting a
    freshly-built bundle straight into 12h backoff.

    Safe against a rebuild loop because the scheduler's catch-up only rebuilds an
    hour whose bundle is MISSING or PARTIAL (built_at < window_end) — a predicate
    that is false the moment this row is written for a closed hour.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO bundle_uploads
                    (filename, local_path, built_at, size_bytes)
                VALUES (%s, %s, NOW(), %s)
                ON CONFLICT (filename) DO UPDATE
                    SET local_path = EXCLUDED.local_path,
                        built_at   = NOW(),
                        size_bytes = EXCLUDED.size_bytes,
                        -- If we're rebuilding, the prior upload is stale.
                        uploaded_at = NULL,
                        remote_path = NULL,
                        -- ...and so is the prior bundle's failure history.
                        gave_up_at  = NULL,
                        retry_count = 0,
                        last_error  = NULL
                """,
                (filename, local_path, size_bytes),
            )


def record_bundle_uploaded(filename: str, remote_path: str) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE bundle_uploads
                   SET uploaded_at     = NOW(),
                       last_attempt_at = NOW(),
                       remote_path     = %s,
                       last_error      = NULL
                 WHERE filename = %s
                """,
                (remote_path, filename),
            )


def record_bundle_upload_failure(filename: str, error: str) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE bundle_uploads
                   SET last_attempt_at = NOW(),
                       last_error      = %s,
                       retry_count     = retry_count + 1
                 WHERE filename = %s
                """,
                (error[:500] if error else error, filename),
            )


def list_pending_bundles() -> list[dict[str, Any]]:
    """Bundles built, not yet uploaded, and not given up on. FIFO order.

    Given-up bundles (see mark_bundles_gave_up) are excluded so a permanently
    un-shippable file can't be re-tried forever — that's what bounded the flush.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, filename, local_path, built_at, last_attempt_at,
                       retry_count, last_error
                  FROM bundle_uploads
                 WHERE uploaded_at IS NULL
                   AND gave_up_at IS NULL
                 ORDER BY built_at ASC
                """,
            )
            return list(cur.fetchall())


def list_completed_scan_times_since(hours: int) -> list[Any]:
    """completed_at of every scan that finished within the last N hours.

    Feeds the uploader's catch-up: which hour windows actually have data that
    needs bundling. Returns raw timestamps and groups into hours in PYTHON, on
    purpose — date_trunc() would truncate in the psycopg session's timezone (the
    postgres container's UTC), while bundle filenames are stamped in the
    COLLECTOR's local timezone. Grouping server-side would silently mis-bucket
    every box that isn't on UTC.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT completed_at
                  FROM scan_runs
                 WHERE completed_at IS NOT NULL
                   AND error IS NULL
                   AND completed_at >= NOW() - (%s || ' hours')::interval
                 ORDER BY completed_at ASC
                """,
                (str(hours),),
            )
            return [r["completed_at"] for r in cur.fetchall()]


def get_bundle_rows(filenames: list[str]) -> dict[str, dict[str, Any]]:
    """Build/upload state for a batch of bundle filenames, keyed by filename.

    One round-trip for the whole catch-up horizon. Absent filenames simply don't
    appear in the result — that's the "never built this hour" case.
    """
    if not filenames:
        return {}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT filename, built_at, uploaded_at, gave_up_at
                  FROM bundle_uploads
                 WHERE filename = ANY(%s)
                """,
                (list(filenames),),
            )
            return {r["filename"]: r for r in cur.fetchall()}


def mark_bundles_gave_up(max_age_days: int, max_retries: int) -> list[dict[str, Any]]:
    """Tombstone every pending bundle that is too old or has burned its retries.

    Returns the rows we just gave up on (so the caller can unlink their local
    ZIPs and audit them). The age cap normally binds first: 60 retries at the
    uploader's backoff is ~26 days, while 7 days of hourly bundles is the disk
    bound we actually care about (~168 files).
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE bundle_uploads
                   SET gave_up_at = NOW()
                 WHERE uploaded_at IS NULL
                   AND gave_up_at IS NULL
                   AND (built_at < NOW() - (%s || ' days')::interval
                        OR retry_count >= %s)
                RETURNING filename, local_path, built_at, retry_count, last_error
                """,
                (str(max_age_days), max_retries),
            )
            return list(cur.fetchall())


def mark_bundle_gave_up(filename: str, reason: str) -> None:
    """Tombstone ONE pending bundle (e.g. its local file vanished).

    No-op if the bundle already uploaded or was already given up on, so this is
    safe to call from a racing manual upload-now.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE bundle_uploads
                   SET gave_up_at      = NOW(),
                       last_attempt_at = NOW(),
                       last_error      = %s
                 WHERE filename = %s
                   AND uploaded_at IS NULL
                   AND gave_up_at IS NULL
                """,
                (reason[:500] if reason else reason, filename),
            )


def list_uploaded_bundles_older_than(days: int) -> list[dict[str, Any]]:
    """Successfully-uploaded bundles whose local file we can safely prune."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, filename, local_path, uploaded_at
                  FROM bundle_uploads
                 WHERE uploaded_at IS NOT NULL
                   AND uploaded_at < NOW() - (%s || ' days')::interval
                """,
                (str(days),),
            )
            return list(cur.fetchall())


def insert_topology(
    scan_run_id: int,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    connection: DbConnection | None = None,
) -> None:
    """Persist topology crawl output. Each node/edge is stamped with scan_run_id."""
    if not nodes and not edges:
        return
    with connection_scope(connection) as conn:
        with conn.cursor() as cur:
            for n in nodes:
                cur.execute(
                    """
                    INSERT INTO topology_nodes
                        (scan_run_id, chassis_id, system_name, system_description,
                         mgmt_ips, discovered_via_ip, source, capabilities, extra)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        scan_run_id,
                        n.get("chassis_id"),
                        n.get("system_name"),
                        n.get("system_description"),
                        n.get("mgmt_ips") or None,
                        n.get("discovered_via_ip"),
                        n.get("source") or "snmp",
                        n.get("capabilities") or None,
                        # CORE-2: per-interface health + STP port roles ride in `extra`
                        # (existing jsonb column — no migration). Empty when none collected.
                        # PERF-3: the resolved uplink's octet-counter sample rides
                        # alongside as `uplink` (present only on spine-crawled switches).
                        json.dumps({
                            "interfaces": n.get("interfaces") or {},
                            "uplink": n.get("uplink"),
                        }),
                    ),
                )
            for e in edges:
                cur.execute(
                    """
                    INSERT INTO topology_edges
                        (scan_run_id, local_chassis_id, local_port_id, local_port_desc,
                         remote_chassis_id, remote_port_id, remote_port_desc,
                         via, discovered_via_ip)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_run_id,
                        e.get("local_chassis_id"),
                        e.get("local_port_id"),
                        e.get("local_port_desc"),
                        e.get("remote_chassis_id"),
                        e.get("remote_port_id"),
                        e.get("remote_port_desc"),
                        e.get("via") or "lldp",
                        e.get("discovered_via_ip"),
                    ),
                )


# ---------------------------------------------------------------------------
# Persistent device inventory (cross-scan, MAC-keyed). See migration 0010.
# ---------------------------------------------------------------------------


def upsert_inventory_devices(
    rows: list[dict[str, Any]], *, connection: DbConnection | None = None
) -> tuple[int, int]:
    """Upsert this scan's discovered devices into the persistent MAC-keyed
    inventory. Returns (upserted, new) where `new` counts first-time devices.

    Each row needs a `mac`; rows without one are skipped (MAC is the inventory's
    identity). On conflict we bump last_seen_at + times_seen and refresh the
    location/IP, but COALESCE hostname/vendor/device_class so a scan that failed
    to resolve a name doesn't blank out a value we already had.
    """
    if not rows:
        return (0, 0)
    upserted = 0
    new = 0
    with connection_scope(connection) as conn:
        with conn.cursor() as cur:
            for r in rows:
                mac = r.get("mac")
                if not mac:
                    continue
                cur.execute(
                    """
                    INSERT INTO inventory_devices
                        (mac, last_ip, hostname, vendor, device_class, last_source,
                         last_network_id, last_interface, last_scan_run_id,
                         district_slug, school_slug, device_slug)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (mac) DO UPDATE SET
                        last_seen_at     = NOW(),
                        times_seen       = inventory_devices.times_seen + 1,
                        last_ip          = EXCLUDED.last_ip,
                        hostname         = COALESCE(EXCLUDED.hostname, inventory_devices.hostname),
                        vendor           = COALESCE(EXCLUDED.vendor, inventory_devices.vendor),
                        device_class     = COALESCE(EXCLUDED.device_class, inventory_devices.device_class),
                        last_source      = EXCLUDED.last_source,
                        last_network_id  = EXCLUDED.last_network_id,
                        last_interface   = EXCLUDED.last_interface,
                        last_scan_run_id = EXCLUDED.last_scan_run_id,
                        district_slug    = EXCLUDED.district_slug,
                        school_slug      = EXCLUDED.school_slug,
                        device_slug      = EXCLUDED.device_slug
                    -- xmax = 0 only for a freshly INSERTed row; non-zero means
                    -- the ON CONFLICT path updated an existing one.
                    RETURNING (xmax = 0) AS inserted
                    """,
                    (mac, r.get("last_ip"), r.get("hostname"), r.get("vendor"),
                     r.get("device_class"), r.get("last_source"),
                     r.get("last_network_id"), r.get("last_interface"),
                     r.get("last_scan_run_id"),
                     r.get("district_slug"), r.get("school_slug"), r.get("device_slug")),
                )
                row = cur.fetchone()
                upserted += 1
                if row and row.get("inserted"):
                    new += 1
    return (upserted, new)


def list_inventory(limit: int | None = None) -> list[dict[str, Any]]:
    """The persistent inventory, most-recently-seen first."""
    sql = """
        SELECT mac, first_seen_at, last_seen_at, times_seen, last_ip, hostname,
               vendor, device_class, last_source, last_network_id, last_interface,
               last_scan_run_id, district_slug, school_slug, device_slug
          FROM inventory_devices
         ORDER BY last_seen_at DESC
    """
    params: tuple[Any, ...] = ()
    if limit is not None:
        sql += " LIMIT %s"
        params = (limit,)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())


def inventory_counts() -> dict[str, int]:
    """Headline inventory numbers for the bundle summary."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    count(*)                                                  AS total,
                    count(*) FILTER (WHERE first_seen_at > NOW() - INTERVAL '24 hours') AS new_24h,
                    count(*) FILTER (WHERE last_seen_at  > NOW() - INTERVAL '24 hours') AS seen_24h
                  FROM inventory_devices
                """
            )
            row = cur.fetchone() or {}
            return {
                "total": int(row.get("total") or 0),
                "new_24h": int(row.get("new_24h") or 0),
                "seen_24h": int(row.get("seen_24h") or 0),
            }


def _strip_nul(value: Any) -> Any:
    """Recursively strip NUL (0x00) characters from string values.

    PostgreSQL text/jsonb columns cannot store a NUL, so a single malformed
    discovery record -- e.g. an Android TV whose mDNS/SSDP data carries an
    embedded NUL -- would otherwise fail the WHOLE batch insert (and thus the
    entire scan's persist) with `UntranslatableCharacter`, silently taking a
    sensor's monitoring offline. Sanitize at this one batch-insert chokepoint;
    recurse into dict/list so jsonb payloads are cleaned too.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_strip_nul(v) for v in value)
    return value


def insert_many(
    table: str,
    rows: list[dict[str, Any]],
    *,
    connection: DbConnection | None = None,
) -> None:
    """Insert a batch of rows by column-name dict. Table name is whitelisted."""
    if not rows:
        return
    allowed = {
        "devices", "neighbors", "arp_entries", "dhcp_observations",
        "stp_events", "traffic_stats", "snmp_polls", "findings",
        "dns_probes", "network_reachability", "service_discovery",
    }
    if table not in allowed:
        raise ValueError(f"table {table!r} is not allowed")
    cols = list(rows[0].keys())
    placeholders = ", ".join(["%s"] * len(cols))
    col_sql = ", ".join(cols)
    with connection_scope(connection) as conn:
        with conn.cursor() as cur:
            cur.executemany(
                f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})",
                [tuple(_strip_nul(r.get(c)) for c in cols) for r in rows],
            )
