from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import structlog

from .bundle import build_hourly_bundle
from .config import get_settings
from .db import (
    list_pending_bundles,
    list_scan_runs_in_window,
    list_uploaded_bundles_older_than,
    record_bundle_built,
    record_bundle_upload_failure,
    record_bundle_uploaded,
)
from .logging_setup import audit

# How long we keep successfully-uploaded ZIPs on local disk before pruning.
# Adjust by editing here; not surfaced as env to keep config simple for v1.
LOCAL_BUNDLE_RETENTION_DAYS = 30

log = structlog.get_logger(__name__)


def _local_now() -> datetime:
    """Local-time tz-aware now, using whatever zone the container is configured for."""
    return datetime.now().astimezone()


def _next_hour_boundary(now: datetime | None = None) -> datetime:
    n = now or _local_now()
    return n.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)


def device_name() -> str:
    """Human-readable device label for bundle metadata. Falls back to hostname."""
    s = get_settings()
    if s.device_name:
        return s.device_name
    return socket.gethostname()


def _identity_slugs() -> tuple[str, str, str] | None:
    """Return (district, school, device) slugs if all three are set, else None.
    Pre-wizard boxes have empty slugs and fall back to legacy flat uploads."""
    s = get_settings()
    if s.district_slug and s.school_slug and s.device_slug:
        return s.district_slug, s.school_slug, s.device_slug
    return None


def _filename_for(window_end: datetime) -> str:
    """Filename for the bundle covering the hour that just completed.

    With identity set:  <device_slug>_YYYY_MM_DD_HH.zip
    Legacy fallback:    <device_name>_YYYY_MM_DD_HH.zip

    The slug variant avoids spaces in filenames and stays consistent with the
    hierarchical SFTP path that contains the same slug.
    """
    completed_hour = window_end - timedelta(hours=1)
    stamp = completed_hour.strftime('%Y_%m_%d_%H')
    slugs = _identity_slugs()
    if slugs is not None:
        _, _, device_slug = slugs
        return f"{device_slug}_{stamp}.zip"
    return f"{device_name()}_{stamp}.zip"


def _remote_dir() -> str:
    """Where to put uploads on the SFTP server.

    With identity set:  <sftp_remote_path>/<district>/<school>/<device>
    Legacy fallback:    <sftp_remote_path>

    Trailing slashes stripped; the upload step adds the filename.
    """
    s = get_settings()
    base = (s.sftp_remote_path or "/").rstrip("/")
    slugs = _identity_slugs()
    if slugs is None:
        return base or "/"
    district, school, device = slugs
    return f"{base}/{district}/{school}/{device}"


# ---------------------------------------------------------------------------
# Building + uploading
# ---------------------------------------------------------------------------


def build_and_upload_hour(window_end: datetime) -> dict[str, str | None]:
    """Build a bundle for the hour ending at window_end and upload it.
    Also retries any prior bundle whose upload failed, and prunes old
    successfully-uploaded local files.

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
        "retried": "0",
    }

    # 1. Build the current-hour bundle (if there's anything to bundle).
    if runs:
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
        try:
            size = bundle_path.stat().st_size
        except OSError:
            size = 0
        record_bundle_built(filename, str(bundle_path), size)
        audit("bundle_built", filename=filename, size_bytes=size,
              scans=len(scan_ids))
    else:
        log.info("no scans in this hour, nothing new to bundle",
                 start=window_start.isoformat(), end=window_end.isoformat())

    # 2. Try to upload every pending bundle (today's plus anything orphaned
    # from earlier failed runs).
    if not settings.sftp_enabled:
        result["status"] = "saved_only"
        result["message"] = "SFTP disabled (NETMON_SFTP_ENABLED=false); bundles kept locally"
        return result

    pending = list_pending_bundles()
    if not pending:
        if runs:
            result["status"] = "uploaded"
            result["message"] = "current bundle was the only pending one and it shipped"
        else:
            result["message"] = "nothing pending to upload"
        # Still prune old uploaded files so we don't fill the disk.
        _prune_old_uploaded_bundles()
        return result

    log.info("uploading pending bundles", count=len(pending))
    succeeded = 0
    failed = 0
    last_error: str | None = None
    for row in pending:
        fname = row["filename"]
        path = Path(row["local_path"])
        if not path.exists():
            log.warning("pending bundle file missing on disk, marking failed",
                        filename=fname, path=str(path))
            record_bundle_upload_failure(fname, "local file missing")
            failed += 1
            last_error = "local file missing"
            continue
        try:
            remote = upload_file(path)
            record_bundle_uploaded(fname, remote)
            audit("bundle_uploaded", filename=fname, remote_path=remote,
                  size_bytes=path.stat().st_size)
            succeeded += 1
            if path.name == Path(result.get("local_path") or "").name:
                result["remote_path"] = remote
        except Exception as exc:
            err = str(exc)
            log.exception("sftp upload failed", filename=fname, error=err)
            record_bundle_upload_failure(fname, err)
            audit("bundle_upload_failed", filename=fname, error=err)
            failed += 1
            last_error = err

    # 3. Result summary.
    result["retried"] = str(len(pending) - (1 if runs else 0))
    if failed == 0:
        result["status"] = "uploaded"
        result["message"] = f"uploaded {succeeded} bundle(s)"
    elif succeeded == 0:
        result["status"] = "upload_failed"
        result["message"] = last_error or "all uploads failed"
    else:
        result["status"] = "partial"
        result["message"] = (f"{succeeded} bundle(s) uploaded, "
                             f"{failed} failed (last error: {last_error})")

    # 4. Disk hygiene.
    _prune_old_uploaded_bundles()
    return result


def _prune_old_uploaded_bundles() -> None:
    """Delete local bundle files that were uploaded > N days ago."""
    try:
        rows = list_uploaded_bundles_older_than(LOCAL_BUNDLE_RETENTION_DAYS)
    except Exception as exc:
        log.warning("prune query failed", error=str(exc))
        return
    if not rows:
        return
    n = 0
    for row in rows:
        p = Path(row["local_path"])
        if p.exists():
            try:
                p.unlink()
                n += 1
            except OSError as exc:
                log.warning("could not delete bundle file",
                            filename=row["filename"], error=str(exc))
    if n:
        log.info("pruned old uploaded bundles", count=n,
                 retention_days=LOCAL_BUNDLE_RETENTION_DAYS)
        audit("bundles_pruned", count=n, retention_days=LOCAL_BUNDLE_RETENTION_DAYS)


def upload_file(local_path: Path) -> str:
    """Upload a single file to the configured SFTP server. Returns remote path.

    Path on the server is hierarchical when identity is set:
        <sftp_remote_path>/<district>/<school>/<device>/<filename>
    Otherwise (pre-wizard boxes) the file lands flat at:
        <sftp_remote_path>/<filename>

    _ensure_remote_dir does mkdir -p for the full hierarchy on each upload,
    so a brand-new district/school/device combo creates its subtree
    automatically on first upload.
    """
    settings = get_settings()
    if not settings.sftp_host:
        raise RuntimeError("NETMON_SFTP_HOST not set")

    # Paramiko import deferred so module loads without it during tests.
    import paramiko

    target_dir = _remote_dir()
    log.info("sftp connecting", host=settings.sftp_host, port=settings.sftp_port,
             user=settings.sftp_user, remote_dir=target_dir)

    transport = paramiko.Transport((settings.sftp_host, settings.sftp_port))
    try:
        transport.connect(username=settings.sftp_user, password=settings.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise RuntimeError("could not open SFTP channel")
        try:
            _ensure_remote_dir(sftp, target_dir)
            remote = f"{target_dir.rstrip('/') or ''}/{local_path.name}"
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
        except OSError:
            try:
                sftp.mkdir(current)
            except OSError as exc:
                # Race or read-only — try to stat again before giving up.
                try:
                    sftp.stat(current)
                except OSError:
                    raise exc from None


def test_connection() -> tuple[bool, str]:
    """Quick connectivity + auth + remote-path-exists check.

    Tests against the hierarchical target directory (district/school/device)
    when identity is set, so the operator sees the actual upload destination,
    not just the SFTP root.
    """
    settings = get_settings()
    if not settings.sftp_host:
        return False, "NETMON_SFTP_HOST is not set — run: sudo netmon-wizard sftp"
    try:
        import paramiko
    except ImportError as exc:
        return False, f"paramiko not installed: {exc}"

    target_dir = _remote_dir()
    try:
        transport = paramiko.Transport((settings.sftp_host, settings.sftp_port))
        transport.connect(username=settings.sftp_user, password=settings.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            transport.close()
            return False, "could not open SFTP channel"
        try:
            try:
                entries = sftp.listdir(target_dir)
                msg = (f"connected to {settings.sftp_host}:{settings.sftp_port} as "
                       f"{settings.sftp_user}; target {target_dir!r} "
                       f"has {len(entries)} entries")
            except OSError:
                msg = (f"connected to {settings.sftp_host}:{settings.sftp_port} as "
                       f"{settings.sftp_user}; target {target_dir!r} "
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
        log.info("uploader disabled (NETMON_SFTP_ENABLED=false), scheduler not running")
        return
    log.info("uploader scheduler started",
             host=s.sftp_host, port=s.sftp_port,
             remote_dir=_remote_dir(), device=device_name(),
             identity_set=_identity_slugs() is not None)

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
    t = threading.Thread(target=_run_scheduler_loop, name="netmon-uploader", daemon=True)
    t.start()
    return t
