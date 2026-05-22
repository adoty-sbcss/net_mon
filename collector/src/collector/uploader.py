from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import structlog

from .bundle import build_hourly_bundle
from .config import get_settings
from .db import list_scan_runs_in_window

log = structlog.get_logger(__name__)


def _local_now() -> datetime:
    """Local-time tz-aware now, using whatever zone the container is configured for."""
    return datetime.now().astimezone()


def _next_hour_boundary(now: datetime | None = None) -> datetime:
    n = now or _local_now()
    return n.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)


def device_name() -> str:
    s = get_settings()
    if s.device_name:
        return s.device_name
    return socket.gethostname()


def _filename_for(window_end: datetime) -> str:
    """Window end is the top-of-hour we're closing. File names the hour just completed."""
    completed_hour = window_end - timedelta(hours=1)
    return f"{device_name()}_{completed_hour.strftime('%Y_%m_%d_%H')}.zip"


# ---------------------------------------------------------------------------
# Building + uploading
# ---------------------------------------------------------------------------


def build_and_upload_hour(window_end: datetime) -> dict[str, str | None]:
    """Build a bundle for the hour ending at window_end and upload it.

    Returns dict with: local_path, remote_path, status, message, scans.
    """
    settings = get_settings()
    window_start = window_end - timedelta(hours=1)
    runs = list_scan_runs_in_window(window_start, window_end)
    result: dict[str, str | None] = {
        "local_path": None, "remote_path": None,
        "status": "skipped", "message": None,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "scans": "0",
    }
    if not runs:
        result["message"] = "no scans completed in this hour"
        log.info("hourly upload skipped, no scans",
                 start=window_start.isoformat(), end=window_end.isoformat())
        return result

    scan_ids = [int(r["id"]) for r in runs]
    result["scans"] = str(len(scan_ids))

    filename = _filename_for(window_end)
    bundle_path = settings.bundle_dir / filename
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    build_hourly_bundle(
        scan_ids,
        bundle_path,
        device_name=device_name(),
        window_start=window_start,
        window_end=window_end,
    )
    result["local_path"] = str(bundle_path)

    if not settings.sftp_enabled:
        result["status"] = "saved_only"
        result["message"] = "SFTP disabled (APPMON_SFTP_ENABLED=false); bundle kept locally"
        log.info("hourly bundle built but not uploaded",
                 path=str(bundle_path), reason="sftp disabled")
        return result

    try:
        remote = upload_file(bundle_path)
        result["remote_path"] = remote
        result["status"] = "uploaded"
        result["message"] = f"uploaded {bundle_path.name}"
    except Exception as exc:
        log.exception("sftp upload failed", path=str(bundle_path), error=str(exc))
        result["status"] = "upload_failed"
        result["message"] = str(exc)
    return result


def upload_file(local_path: Path) -> str:
    """Upload a single file to the configured SFTP server. Returns remote path."""
    settings = get_settings()
    if not settings.sftp_host:
        raise RuntimeError("APPMON_SFTP_HOST not set")

    # Paramiko import deferred so module loads without it during tests.
    import paramiko

    log.info("sftp connecting", host=settings.sftp_host, port=settings.sftp_port,
             user=settings.sftp_user, remote_path=settings.sftp_remote_path)

    transport = paramiko.Transport((settings.sftp_host, settings.sftp_port))
    try:
        transport.connect(username=settings.sftp_user, password=settings.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise RuntimeError("could not open SFTP channel")
        try:
            _ensure_remote_dir(sftp, settings.sftp_remote_path)
            remote = f"{settings.sftp_remote_path.rstrip('/') or ''}/{local_path.name}"
            sftp.put(str(local_path), remote)
            log.info("sftp upload complete", local=str(local_path), remote=remote,
                     size=local_path.stat().st_size)
            return remote
        finally:
            sftp.close()
    finally:
        transport.close()


def _ensure_remote_dir(sftp, path: str) -> None:
    """mkdir -p the remote path, ignoring 'already exists'."""
    if not path or path == "/":
        return
    parts = [p for p in path.strip("/").split("/") if p]
    current = ""
    for p in parts:
        current = current + "/" + p
        try:
            sftp.stat(current)
        except IOError:
            try:
                sftp.mkdir(current)
            except IOError as exc:
                # Race or read-only — try to stat again before giving up.
                try:
                    sftp.stat(current)
                except IOError:
                    raise exc


def test_connection() -> tuple[bool, str]:
    """Quick connectivity + auth + remote-path-exists check."""
    settings = get_settings()
    if not settings.sftp_host:
        return False, "APPMON_SFTP_HOST is not set — run ./setup.sh"
    try:
        import paramiko
    except ImportError as exc:
        return False, f"paramiko not installed: {exc}"
    try:
        transport = paramiko.Transport((settings.sftp_host, settings.sftp_port))
        transport.connect(username=settings.sftp_user, password=settings.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            transport.close()
            return False, "could not open SFTP channel"
        try:
            try:
                entries = sftp.listdir(settings.sftp_remote_path)
                msg = (f"connected to {settings.sftp_host}:{settings.sftp_port} as "
                       f"{settings.sftp_user}; remote path {settings.sftp_remote_path!r} "
                       f"has {len(entries)} entries")
            except IOError:
                msg = (f"connected to {settings.sftp_host}:{settings.sftp_port} as "
                       f"{settings.sftp_user}; remote path {settings.sftp_remote_path!r} "
                       f"does not exist yet (will be created on first upload)")
            return True, msg
        finally:
            sftp.close()
            transport.close()
    except Exception as exc:
        return False, f"connection failed: {exc}"


# ---------------------------------------------------------------------------
# Hourly scheduler thread
# ---------------------------------------------------------------------------


_stop_event = threading.Event()


def request_stop() -> None:
    _stop_event.set()


def _run_scheduler_loop() -> None:
    s = get_settings()
    if not s.sftp_enabled:
        log.info("uploader disabled (APPMON_SFTP_ENABLED=false), scheduler not running")
        return
    log.info("uploader scheduler started",
             host=s.sftp_host, port=s.sftp_port,
             remote_path=s.sftp_remote_path, device=device_name())

    while not _stop_event.is_set():
        target = _next_hour_boundary()
        log.debug("uploader sleeping until next top-of-hour", target=target.isoformat())
        # Wake on the hour, but check every 60s in case the process is stopping.
        while not _stop_event.is_set():
            remaining = (target - _local_now()).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(60.0, remaining))
        if _stop_event.is_set():
            return
        try:
            build_and_upload_hour(target)
        except Exception as exc:
            log.exception("hourly upload tick failed", error=str(exc))


def start_in_background() -> threading.Thread | None:
    """Spawn the scheduler as a daemon thread. Returns the thread (or None if disabled)."""
    s = get_settings()
    if not s.sftp_enabled:
        log.info("uploader disabled, not spawning scheduler thread")
        return None
    t = threading.Thread(target=_run_scheduler_loop, name="appmon-uploader", daemon=True)
    t.start()
    return t
