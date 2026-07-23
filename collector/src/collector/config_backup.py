"""Daily configuration backup + restore download.

Uploads /etc/netmon/netmon.env + /etc/netmon/snmp.yaml (if present) as a small
ZIP to the depot's blob container at
  _config/<district>/<school>/<device>/config_YYYY-MM-DD.zip
so the box's config survives a factory reset.

Transport is HTTPS/blob (SFTP->HTTPS migration): the depot's SFTP protocol
feature is disabled, so the box asks the dashboard to mint a short-lived,
blob-scoped SAS URL (Bearer enrollment token) and streams the ZIP straight to
Azure Blob over HTTPS — mirroring blob_upload.py (the hourly-bundle path) and
reusing its _token/_post_json helpers. The dashboard derives the blob path from
the sensor's OWN DB identity, so the box never supplies a path.

Restore is two steps:
  1. python -m collector config-download [--date YYYY-MM-DD]
     pulls the chosen backup ZIP into /var/lib/netmon/config-restore.zip
  2. (on the host) netmon-config-restore unzips it into /etc/netmon with sudo
     and restarts containers

This split exists because /etc/netmon is bind-mounted read-only into the
container — the container can prepare the zip but only the host can apply it.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import socket
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from . import __version__, blob_upload
from .config import get_settings

log = structlog.get_logger(__name__)

# Same socket bound as blob_upload's PUT: a small config ZIP on a slow school
# uplink can still take a moment, but nowhere near the hourly-bundle ceiling.
_BLOB_TIMEOUT_SEC = 300


# Items we back up. Each entry is (in-container path, archive name).
# The collector container mounts /etc/netmon read-only; that's fine for read.
_BACKUP_ITEMS: list[tuple[Path, str]] = [
    (Path("/etc/netmon/netmon.env"), "netmon.env"),
    (Path("/etc/netmon/snmp.yaml"), "snmp.yaml"),
]


def _today_filename() -> str:
    return f"config_{datetime.now(UTC).strftime('%Y-%m-%d')}.zip"


def _require_dashboard() -> tuple[str, str]:
    """Return (dashboard_base_url, token) or raise if the blob path is unusable.

    New gate (replaces the old sftp_enabled/sftp_host check): config backup rides
    the same dashboard + enrollment-token path as the hourly bundle, so all it
    needs is a dashboard URL and a non-empty token.
    """
    s = get_settings()
    if not s.dashboard_url:
        raise RuntimeError("NETMON_DASHBOARD_URL not set; cannot back up config over blob")
    token = blob_upload._token(s)
    if not token:
        raise RuntimeError("no enrollment token; cannot back up config over blob")
    return s.dashboard_url.rstrip("/"), token


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


def _mint_config_upload(base_url: str, token: str, filename: str) -> dict:
    """Ask the dashboard to mint a create+write SAS for one config backup.

    Returns {"url": <sas put url>, "blobPath": <durable url, no sas>,
    "expiresAt": <iso>} — same shape as blob_upload.get_upload_target.
    """
    url = f"{base_url}/api/sensor/config-upload-url"
    try:
        out = blob_upload._post_json(url, token, {"filename": filename})
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"config-upload mint failed HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"config-upload mint request failed: {exc}") from exc
    if not out.get("url") or not out.get("blobPath"):
        raise RuntimeError("config-upload mint response missing url/blobPath")
    return out


def upload_backup() -> str:
    """Build + upload today's backup to the depot over HTTPS. Returns the blob path.

    Mints a fresh SAS then PUTs the ZIP bytes to Azure Blob, mirroring
    blob_upload.upload_file_blob (incl. the single in-place 403 re-mint for an
    expired/skewed SAS). Content-MD5 gives server-side integrity.
    """
    base_url, token = _require_dashboard()

    payload = build_backup_zip()
    filename = _today_filename()
    size = len(payload)
    md5_b64 = base64.b64encode(hashlib.md5(payload).digest()).decode("ascii")

    target = _mint_config_upload(base_url, token, filename)
    log.info("config-backup uploading", blob=target["blobPath"], size_bytes=size)

    for attempt in (1, 2):
        try:
            req = urllib.request.Request(
                target["url"],
                data=payload,
                method="PUT",
                headers={
                    "x-ms-blob-type": "BlockBlob",
                    "Content-Type": "application/zip",
                    "Content-Length": str(size),
                    "Content-MD5": md5_b64,
                },
            )
            with urllib.request.urlopen(req, timeout=_BLOB_TIMEOUT_SEC) as resp:
                if resp.status in (200, 201):
                    log.info("config-backup uploaded", blob=target["blobPath"],
                             size_bytes=size)
                    return str(target["blobPath"])
                raise RuntimeError(f"config PUT unexpected status {resp.status}")
        except urllib.error.HTTPError as exc:
            if exc.code == 403 and attempt == 1:
                log.info("config SAS rejected (403); re-minting once")
                target = _mint_config_upload(base_url, token, filename)
                continue
            raise RuntimeError(f"config PUT HTTP {exc.code}: {exc.reason}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise RuntimeError(f"config PUT failed: {exc}") from exc

    raise RuntimeError("config backup upload failed after re-mint")


def list_available_backups() -> list[str]:
    """Return filenames of this box's config backups in the depot, newest first."""
    base_url, token = _require_dashboard()
    url = f"{base_url}/api/sensor/config-backups"
    try:
        out = blob_upload._post_json(url, token, {})
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"config-list failed HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"config-list request failed: {exc}") from exc
    backups = out.get("backups")
    if not isinstance(backups, list):
        return []
    return [str(b) for b in backups]


def download_backup(date: str | None = None, out_path: Path | None = None) -> Path:
    """Download a config backup ZIP to local disk. Returns the local path.

    date: YYYY-MM-DD string. Defaults to the most recent available.
    out_path: defaults to /var/lib/netmon/config-restore.zip

    Asks the dashboard to mint a short-lived read-only SAS for the chosen file,
    then GETs it over HTTPS and streams it to disk (constant memory).
    """
    base_url, token = _require_dashboard()

    backups = list_available_backups()
    if not backups:
        raise RuntimeError("no config backups found for this box")

    if date is None:
        chosen = backups[0]
    else:
        wanted = f"config_{date}.zip"
        if wanted not in backups:
            raise RuntimeError(f"no backup for {date}; available: {backups[:5]}")
        chosen = wanted

    url = f"{base_url}/api/sensor/config-download-url"
    try:
        minted = blob_upload._post_json(url, token, {"filename": chosen})
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"config-download mint failed HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"config-download mint request failed: {exc}") from exc
    sas_url = minted.get("url")
    if not sas_url:
        raise RuntimeError("config-download response missing url")

    out = out_path or Path("/var/lib/netmon/config-restore.zip")
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        with urllib.request.urlopen(sas_url, timeout=_BLOB_TIMEOUT_SEC) as resp, \
                out.open("wb") as fh:
            shutil.copyfileobj(resp, fh)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"config GET HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise RuntimeError(f"config GET failed: {exc}") from exc

    log.info("config-backup downloaded", blob=chosen, local=str(out))
    return out
