from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg
import structlog
from psycopg.rows import dict_row

from .config import get_settings

log = structlog.get_logger(__name__)


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
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
    mode: str,
) -> int:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (
                    trigger_reason, interface, interface_cidr,
                    gateway_ip, gateway_mac, network_id, mode
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (trigger_reason, interface, interface_cidr, gateway_ip,
                 gateway_mac, network_id, mode),
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
    }
    if table not in allowed:
        raise ValueError(f"table {table!r} is not allowed")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM {table} WHERE scan_run_id = %s ORDER BY id", (scan_id,))
            return list(cur.fetchall())


def insert_many(table: str, rows: list[dict[str, Any]]) -> None:
    """Insert a batch of rows by column-name dict. Table name is whitelisted."""
    if not rows:
        return
    allowed = {
        "devices", "neighbors", "arp_entries", "dhcp_observations",
        "stp_events", "traffic_stats", "snmp_polls", "findings",
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
