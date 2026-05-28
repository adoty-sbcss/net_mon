"""Daily configuration backup + restore download.

Uploads /etc/netmon/netmon.env + /etc/netmon/snmp.yaml (if present) as a
small ZIP to <sftp_remote_path>/_config/<district>/<school>/<device>/ so the
box's config survives a factory reset.

Restore is two steps:
  1. python -m collector config-download [--date YYYY-MM-DD]
     pulls the chosen backup ZIP into /var/lib/netmon/config-restore.zip
  2. (on the host) netmon-config-restore unzips it into /etc/netmon with sudo
     and restarts containers

This split exists because /etc/netmon is bind-mounted read-only into the
container — the container can prepare the zip but only the host can apply it.
"""
from __future__ import annotations

import io
import json
import socket
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from . import __version__
from .config import get_settings

log = structlog.get_logger(__name__)


# Items we back up. Each entry is (in-container path, archive name).
# The collector container mounts /etc/netmon read-only; that's fine for read.
_BACKUP_ITEMS: list[tuple[Path, str]] = [
    (Path("/etc/netmon/netmon.env"), "netmon.env"),
    (Path("/etc/netmon/snmp.yaml"), "snmp.yaml"),
]


def _config_dir() -> str:
    """Subdirectory under sftp_remote_path where config backups land.

    Returns "_config/<district>/<school>/<device>" when identity is set,
    falling back to "_config/<hostname>" otherwise.
    """
    s = get_settings()
    base = (s.sftp_remote_path or "/").rstrip("/")
    if s.district_slug and s.school_slug and s.device_slug:
        return f"{base}/_config/{s.district_slug}/{s.school_slug}/{s.device_slug}"
    return f"{base}/_config/{socket.gethostname()}"


def _today_filename() -> str:
    return f"config_{datetime.now(UTC).strftime('%Y-%m-%d')}.zip"


def build_backup_zip() -> bytes:
    """Build the in-memory ZIP of config items + manifest. Returns bytes."""
    s = get_settings()
    buf = io.BytesIO()
    manifest: dict[str, Any] = {
        "device_name": s.device_name or socket.gethostname(),
        "district": getattr(s, "district_slug", ""),
        "school": getattr(s, "school_slug", ""),
        "device": getattr(s, "device_slug", ""),
        "collector_version": __version__,
        "backed_up_at": datetime.now(UTC).isoformat(),
        "files": [],
    }
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, archive_name in _BACKUP_ITEMS:
            if not src.exists():
                continue
            data = src.read_bytes()
            zf.writestr(archive_name, data)
            manifest["files"].append({"name": archive_name, "size_bytes": len(data)})
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    return buf.getvalue()


def upload_backup() -> str:
    """Build + upload today's backup. Returns the remote path."""
    from . import uploader as uploader_mod  # avoid circular at import time

    s = get_settings()
    if not s.sftp_enabled or not s.sftp_host:
        raise RuntimeError("SFTP not configured; cannot upload config backup")

    payload = build_backup_zip()
    remote_dir = _config_dir()
    filename = _today_filename()
    remote_path = f"{remote_dir.rstrip('/')}/{filename}"

    # Use paramiko directly — slightly different shape than file uploader.
    import paramiko
    log.info("config-backup uploading", host=s.sftp_host, remote=remote_path,
             size_bytes=len(payload))
    transport = paramiko.Transport((s.sftp_host, s.sftp_port))
    try:
        transport.connect(username=s.sftp_user, password=s.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise RuntimeError("could not open SFTP channel")
        try:
            uploader_mod._ensure_remote_dir(sftp, remote_dir)
            with sftp.file(remote_path, "wb") as f:
                f.write(payload)
            log.info("config-backup uploaded", remote=remote_path, size_bytes=len(payload))
            return remote_path
        finally:
            sftp.close()
    finally:
        transport.close()


def list_available_backups() -> list[str]:
    """Return filenames of backups on the SFTP server for this box, newest first."""
    s = get_settings()
    if not s.sftp_host:
        raise RuntimeError("SFTP not configured")
    import paramiko
    remote_dir = _config_dir()
    transport = paramiko.Transport((s.sftp_host, s.sftp_port))
    try:
        transport.connect(username=s.sftp_user, password=s.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise RuntimeError("could not open SFTP channel")
        try:
            try:
                entries = sftp.listdir(remote_dir)
            except OSError:
                return []
            backups = sorted(
                (e for e in entries if e.startswith("config_") and e.endswith(".zip")),
                reverse=True,
            )
            return backups
        finally:
            sftp.close()
    finally:
        transport.close()


def download_backup(date: str | None = None, out_path: Path | None = None) -> Path:
    """Download a backup ZIP to local disk. Returns the local path.

    date: YYYY-MM-DD string. Defaults to the most recent available.
    out_path: defaults to /var/lib/netmon/config-restore.zip
    """
    s = get_settings()
    if not s.sftp_host:
        raise RuntimeError("SFTP not configured")
    import paramiko

    backups = list_available_backups()
    if not backups:
        raise RuntimeError(f"no config backups found at {_config_dir()!r}")

    if date is None:
        chosen = backups[0]
    else:
        wanted = f"config_{date}.zip"
        if wanted not in backups:
            raise RuntimeError(f"no backup for {date}; available: {backups[:5]}")
        chosen = wanted

    remote_dir = _config_dir()
    remote_path = f"{remote_dir.rstrip('/')}/{chosen}"
    out = out_path or Path("/var/lib/netmon/config-restore.zip")
    out.parent.mkdir(parents=True, exist_ok=True)

    transport = paramiko.Transport((s.sftp_host, s.sftp_port))
    try:
        transport.connect(username=s.sftp_user, password=s.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise RuntimeError("could not open SFTP channel")
        try:
            sftp.get(remote_path, str(out))
            log.info("config-backup downloaded", remote=remote_path, local=str(out))
            return out
        finally:
            sftp.close()
    finally:
        transport.close()
