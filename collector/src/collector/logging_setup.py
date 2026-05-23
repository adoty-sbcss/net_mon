"""Central logging configuration.

Goals:
- Console output (stdout) so `docker compose logs -f collector` works.
- Persistent rotated log files under /var/log/netmon so history survives
  container restarts and grows past Docker's buffer.
- A separate audit.log for high-signal events (scan started/completed,
  upload result, errors). Easy to skim without wading through info logs.
- Single `NETMON_LOG_LEVEL` env var to dial verbosity.

Call configure_logging() exactly once at process startup.
"""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

import structlog

LOG_DIR = Path(os.environ.get("NETMON_LOG_DIR", "/var/log/netmon"))
LOG_LEVEL_NAME = os.environ.get("NETMON_LOG_LEVEL", "INFO").upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL_NAME, logging.INFO)

# How long to keep on-disk logs. Rotates daily, gzipped.
COLLECTOR_LOG_BACKUP_COUNT = 14   # ~2 weeks
AUDIT_LOG_BACKUP_COUNT = 30       # ~1 month — audit lines are tiny

_AUDIT_LOGGER_NAME = "netmon.audit"


def configure_logging() -> None:
    """Wire up stdlib logging + structlog. Safe to call once at startup."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    # Wipe any prior handlers (defensive — important when re-imported under tests).
    for h in list(root.handlers):
        root.removeHandler(h)

    plain_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # Console handler — what `docker compose logs` sees.
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(LOG_LEVEL)
    console.setFormatter(plain_fmt)
    root.addHandler(console)

    # Rotating file handler — collector.log on the host, rolled nightly.
    try:
        file_handler = TimedRotatingFileHandler(
            filename=str(LOG_DIR / "collector.log"),
            when="midnight",
            backupCount=COLLECTOR_LOG_BACKUP_COUNT,
            encoding="utf-8",
            utc=False,
        )
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(plain_fmt)
        # Gzip rotated files (saves disk).
        file_handler.namer = lambda name: name + ".gz"
        file_handler.rotator = _gzip_rotator
        root.addHandler(file_handler)
    except (PermissionError, OSError) as exc:
        # Container might not have write access to mount; fall back to console only.
        sys.stderr.write(f"WARN: file logging disabled: {exc}\n")

    # Audit logger — only high-signal events. Independent logger,
    # WARN level by default so caller-controlled (we always log audit lines
    # at INFO via the dedicated logger). Doesn't propagate to root, so audit
    # events don't double-up in collector.log.
    audit = logging.getLogger(_AUDIT_LOGGER_NAME)
    audit.setLevel(logging.INFO)
    audit.propagate = False
    for h in list(audit.handlers):
        audit.removeHandler(h)
    try:
        audit_handler = TimedRotatingFileHandler(
            filename=str(LOG_DIR / "audit.log"),
            when="midnight",
            backupCount=AUDIT_LOG_BACKUP_COUNT,
            encoding="utf-8",
            utc=False,
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(plain_fmt)
        audit_handler.namer = lambda name: name + ".gz"
        audit_handler.rotator = _gzip_rotator
        audit.addHandler(audit_handler)
    except (PermissionError, OSError) as exc:
        sys.stderr.write(f"WARN: audit logging disabled: {exc}\n")

    # structlog: keep its console-friendly output flowing into stdlib so
    # everything ends up in both stdout AND the file handler.
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(LOG_LEVEL),
        cache_logger_on_first_use=True,
    )

    # Apply structlog's renderer to the formatter used by both handlers.
    # We swap formatters so that structlog events look the same in console
    # and file output, while still working with plain stdlib log() calls.
    structlog_fmt = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=False),
        foreign_pre_chain=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
        ],
    )
    for h in root.handlers:
        h.setFormatter(structlog_fmt)


def get_audit_logger() -> logging.Logger:
    """High-signal event logger. Writes only to audit.log, not to stdout."""
    return logging.getLogger(_AUDIT_LOGGER_NAME)


def audit(event: str, **fields) -> None:
    """Convenience: log a structured event to audit.log."""
    logger = get_audit_logger()
    if fields:
        kv = " ".join(f"{k}={v}" for k, v in fields.items())
        logger.info("%s  %s", event, kv)
    else:
        logger.info(event)


def _gzip_rotator(source: str, dest: str) -> None:
    """Rotate a log file by gzipping the source to dest, then deleting source."""
    import gzip
    import shutil
    try:
        with open(source, "rb") as fin, gzip.open(dest, "wb") as fout:
            shutil.copyfileobj(fin, fout)
        os.remove(source)
    except OSError:
        # Best-effort — if compression fails, leave the uncompressed file.
        try:
            shutil.move(source, dest)
        except OSError:
            pass
