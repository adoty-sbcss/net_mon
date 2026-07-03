"""HTTPS blob upload path for hourly bundles (SFTP->HTTPS migration, Transport A).

Instead of paramiko-SFTP to the depot, the box asks the dashboard to mint a
short-lived, blob-scoped SAS URL (POST /api/sensor/bundle-upload-url, Bearer
enrollment token) and streams the ZIP to Azure Blob over HTTPS with a single
Put Blob. Streams from disk (constant memory, so a 100 MB bundle can't OOM the
container); an explicit Content-Length keeps http.client from switching to
chunked transfer-encoding, which Azure Blob rejects. Content-MD5 gives
server-side integrity SFTP never had.

Retry/backoff lives where it already does — the bundle_uploads queue in db.py
retries the whole hour on the next tick. This module only adds a single in-place
403 re-mint (expired/skewed SAS) so a queued bundle never dies on a stale URL.

Stdlib HTTP only (no azure-storage-blob dep — the container's deps stay lean and
ship to the whole fleet nightly), mirroring checkin.py. Its own tiny _post/token
loader rather than importing checkin: checkin imports uploader, uploader imports
this, so importing checkin back would be a cycle.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

import structlog

from .config import get_settings

log = structlog.get_logger(__name__)

# Bound on the mint request; and on each socket op of the PUT (a 10-100 MB
# bundle on a slow school uplink can legitimately take minutes).
_MINT_TIMEOUT_SEC = 25
_BLOB_TIMEOUT_SEC = 300

# Auto-enroll token state file (mirrors checkin.TOKEN_FILE — duplicated, not
# imported, to avoid a checkin<->uploader import cycle).
_TOKEN_FILE = Path("/var/lib/netmon/enroll-token")


class BlobUploadError(RuntimeError):
    """Raised when the blob upload path fails (mint or PUT)."""


def _token(settings) -> str:
    """Bearer token from env (manual enroll) else the auto-enroll state file."""
    if settings.enroll_token:
        return settings.enroll_token
    try:
        return _TOKEN_FILE.read_text().strip()
    except OSError:
        return ""


def _post_json(url: str, token: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=_MINT_TIMEOUT_SEC) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_upload_target(filename: str) -> dict:
    """Ask the dashboard to mint a SAS URL for this bundle.

    Returns {"url": <sas put url>, "blobPath": <durable url, no sas>,
    "expiresAt": <iso>}. Raises BlobUploadError on any failure so the caller
    records it and the queue retries next hour.
    """
    settings = get_settings()
    if not settings.dashboard_url:
        raise BlobUploadError("NETMON_DASHBOARD_URL not set")
    token = _token(settings)
    if not token:
        raise BlobUploadError("no enrollment token (blob upload needs the dashboard token)")
    url = settings.dashboard_url.rstrip("/") + "/api/sensor/bundle-upload-url"
    try:
        out = _post_json(url, token, {"filename": filename})
    except urllib.error.HTTPError as exc:
        raise BlobUploadError(f"mint failed HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise BlobUploadError(f"mint request failed: {exc}") from exc
    if not out.get("url") or not out.get("blobPath"):
        raise BlobUploadError("mint response missing url/blobPath")
    return out


def _file_md5_b64(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return base64.b64encode(h.digest()).decode("ascii")


def upload_file_blob(local_path: Path) -> str:
    """Mint a fresh SAS and stream-PUT the ZIP to blob over HTTPS.

    Returns the durable blob URL (no SAS) for bundle_uploads.remote_path. One
    in-place 403 re-mint handles an expired/skewed SAS; anything else raises
    BlobUploadError (the queue then retries the whole hour next tick).
    """
    size = local_path.stat().st_size
    md5_b64 = _file_md5_b64(local_path)
    target = get_upload_target(local_path.name)

    for attempt in (1, 2):
        try:
            with local_path.open("rb") as fh:
                req = urllib.request.Request(
                    target["url"],
                    data=fh,  # file object => http.client streams it in blocks
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
                        log.info("blob upload complete", file=local_path.name,
                                 size=size, blob=target["blobPath"])
                        return str(target["blobPath"])
                    raise BlobUploadError(f"blob PUT unexpected status {resp.status}")
        except urllib.error.HTTPError as exc:
            if exc.code == 403 and attempt == 1:
                log.info("blob SAS rejected (403); re-minting once", file=local_path.name)
                target = get_upload_target(local_path.name)
                continue
            raise BlobUploadError(f"blob PUT HTTP {exc.code}: {exc.reason}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise BlobUploadError(f"blob PUT failed: {exc}") from exc

    raise BlobUploadError("blob upload failed after re-mint")
