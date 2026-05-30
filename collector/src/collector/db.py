from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
import structlog
from psycopg.rows import DictRow, dict_row

from .config import get_settings

log = structlog.get_logger(__name__)


@contextmanager
def connect() -> Iterator[psycopg.Connection[DictRow]]:
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
) -> int:
    s = get_settings()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (
                    trigger_reason, interface, interface_cidr,
                    gateway_ip, gateway_mac, network_id, is_primary,
                    district_slug, school_slug, device_slug
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (trigger_reason, interface, interface_cidr, gateway_ip,
                 gateway_mac, network_id, is_primary,
                 s.district_slug or None,
                 s.school_slug or None,
                 s.device_slug or None),
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


def recent_network_scan(network_id: str, within_seconds: int) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, started_at
                  FROM scan_runs
                 WHERE network_id = %s
                   AND started_at > NOW() - (%s || ' seconds')::interval
                 ORDER BY started_at DESC
                 LIMIT 1
                """,
                (network_id, str(within_seconds)),
            )
            return cur.fetchone()


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
    rebuilt-same-hour ZIP doesn't create duplicate rows."""
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
                        remote_path = NULL
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
    """Bundles built but not yet successfully uploaded. FIFO order."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, filename, local_path, built_at, last_attempt_at,
                       retry_count, last_error
                  FROM bundle_uploads
                 WHERE uploaded_at IS NULL
                 ORDER BY built_at ASC
                """,
            )
            return list(cur.fetchall())


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


def insert_topology(scan_run_id: int, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    """Persist topology crawl output. Each node/edge is stamped with scan_run_id."""
    if not nodes and not edges:
        return
    with connect() as conn:
        with conn.cursor() as cur:
            for n in nodes:
                cur.execute(
                    """
                    INSERT INTO topology_nodes
                        (scan_run_id, chassis_id, system_name, system_description,
                         mgmt_ips, discovered_via_ip, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_run_id,
                        n.get("chassis_id"),
                        n.get("system_name"),
                        n.get("system_description"),
                        n.get("mgmt_ips") or None,
                        n.get("discovered_via_ip"),
                        n.get("source") or "snmp",
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


def insert_many(table: str, rows: list[dict[str, Any]]) -> None:
    """Insert a batch of rows by column-name dict. Table name is whitelisted."""
    if not rows:
        return
    allowed = {
        "devices", "neighbors", "arp_entries", "dhcp_observations",
        "stp_events", "traffic_stats", "snmp_polls", "findings",
        "dns_probes",
    }
    if table not in allowed:
        raise ValueError(f"table {table!r} is not allowed")
    cols = list(rows[0].keys())
    placeholders = ", ".join(["%s"] * len(cols))
    col_sql = ", ".join(cols)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})",
                [tuple(r.get(c) for c in cols) for r in rows],
            )
