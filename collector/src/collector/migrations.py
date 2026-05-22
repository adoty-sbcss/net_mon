"""Schema migration runner.

Migrations are plain `.sql` files in /app/migrations (mounted from
`db/migrations/` on the host). Each file is applied at most once; we track
applied filenames in the `schema_migrations` table.

Conventions:
- Filenames sort lexicographically and are applied in that order:
  `0001_*.sql`, `0002_*.sql`, ...
- Each migration is wrapped in a transaction by Postgres' implicit BEGIN/COMMIT
  via psycopg autocommit=False — if any statement fails, the whole file rolls
  back and the migration is NOT recorded as applied.
- Migrations should be idempotent (use `IF NOT EXISTS`, `IF EXISTS`, etc.) so
  they're safe to run against a fresh schema where init.sql already created
  the same objects.

This runner is invoked once at collector startup (in `cmd_run`). If any
migration fails, the collector refuses to start — better than running with a
half-applied schema.
"""
from __future__ import annotations

from pathlib import Path

import psycopg
import structlog

from .config import get_settings

log = structlog.get_logger(__name__)

DEFAULT_MIGRATIONS_DIR = Path("/app/migrations")


def apply_pending(migrations_dir: Path | None = None) -> int:
    """Apply any migrations not already recorded. Returns count applied."""
    mdir = migrations_dir or DEFAULT_MIGRATIONS_DIR
    if not mdir.is_dir():
        log.warning("migrations directory not found, skipping", path=str(mdir))
        return 0

    _ensure_migrations_table()
    already = _list_applied()

    files = sorted(mdir.glob("*.sql"))
    if not files:
        log.info("no migration files present", path=str(mdir))
        return 0

    applied_count = 0
    for path in files:
        if path.name in already:
            continue
        sql = path.read_text()
        if not sql.strip():
            log.info("empty migration, recording as applied", name=path.name)
            _record(path.name)
            applied_count += 1
            continue
        log.info("applying migration", name=path.name)
        try:
            settings = get_settings()
            with psycopg.connect(settings.dsn, autocommit=False) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    cur.execute(
                        "INSERT INTO schema_migrations (filename) VALUES (%s)",
                        (path.name,),
                    )
                conn.commit()
        except Exception:
            log.exception("migration failed", name=path.name)
            raise
        applied_count += 1

    if applied_count:
        log.info("migrations complete", applied=applied_count, total=len(files))
    else:
        log.info("schema already up to date", total=len(files))
    return applied_count


def _ensure_migrations_table() -> None:
    settings = get_settings()
    with psycopg.connect(settings.dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    filename   TEXT PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )


def _list_applied() -> set[str]:
    settings = get_settings()
    with psycopg.connect(settings.dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT filename FROM schema_migrations")
            return {row[0] for row in cur.fetchall()}


def _record(filename: str) -> None:
    settings = get_settings()
    with psycopg.connect(settings.dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO schema_migrations (filename) VALUES (%s) "
                "ON CONFLICT (filename) DO NOTHING",
                (filename,),
            )
