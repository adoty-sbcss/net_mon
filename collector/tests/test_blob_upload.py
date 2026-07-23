"""Guards the SFTP->HTTPS bundle transport (A, P0). Pure unit tests: no DB, no
real network — the SAS mint (get_upload_target) and the blob PUT
(urllib.urlopen) are the network chokepoints and are monkeypatched. The
bundle_uploads retry queue is deliberately untouched by this path and is not
exercised here.
"""

from __future__ import annotations

import base64
import hashlib
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from collector import blob_upload, uploader

# ---- transport selector (uploader._active_transport) ----
# Blob is the only transport now: "blob" ships, anything else keeps bundles local.

def test_active_transport_blob_ships():
    s = SimpleNamespace(bundle_transport="blob")
    assert uploader._active_transport(s) == "blob"


def test_active_transport_sftp_value_is_now_off():
    # "sftp" is the pre-install staging value — uploads OFF, no SFTP transport.
    s = SimpleNamespace(bundle_transport="sftp")
    assert uploader._active_transport(s) is None


def test_active_transport_none_when_not_blob():
    s = SimpleNamespace(bundle_transport="")
    assert uploader._active_transport(s) is None


# ---- integrity helper ----

def test_file_md5_b64_matches_hashlib(tmp_path):
    p = tmp_path / "b.zip"
    p.write_bytes(b"hello netmon bundle")
    expect = base64.b64encode(hashlib.md5(b"hello netmon bundle").digest()).decode()
    assert blob_upload._file_md5_b64(p) == expect


# ---- mint guards ----

def test_get_upload_target_requires_dashboard_url(monkeypatch):
    monkeypatch.setattr(
        blob_upload, "get_settings",
        lambda: SimpleNamespace(dashboard_url="", enroll_token="t"),
    )
    with pytest.raises(blob_upload.BlobUploadError):
        blob_upload.get_upload_target("dev_2026_01_01_00.zip")


def test_get_upload_target_requires_token(monkeypatch):
    monkeypatch.setattr(
        blob_upload, "get_settings",
        lambda: SimpleNamespace(dashboard_url="https://dash", enroll_token=""),
    )
    monkeypatch.setattr(blob_upload, "_TOKEN_FILE", Path("/nonexistent/enroll-token"))
    with pytest.raises(blob_upload.BlobUploadError):
        blob_upload.get_upload_target("dev_2026_01_01_00.zip")


# ---- upload_file_blob: a rejected SAS is re-minted exactly once, then succeeds ----

class _Resp:
    def __init__(self, status: int):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_upload_file_blob_remints_once_on_403(monkeypatch, tmp_path):
    p = tmp_path / "dev_2026_01_01_00.zip"
    p.write_bytes(b"zipdata")

    mints: list[str] = []

    def fake_mint(fname: str) -> dict:
        mints.append(fname)
        return {
            "url": f"https://sas.example/{len(mints)}",
            "blobPath": "https://depot.example/bundles/upload/d/s/dev/dev.zip",
            "expiresAt": "2026-01-01T01:00:00Z",
        }

    monkeypatch.setattr(blob_upload, "get_upload_target", fake_mint)

    calls: list[str] = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
        return _Resp(201)

    monkeypatch.setattr(blob_upload.urllib.request, "urlopen", fake_urlopen)

    remote = blob_upload.upload_file_blob(p)

    assert remote == "https://depot.example/bundles/upload/d/s/dev/dev.zip"
    assert len(mints) == 2   # initial mint + exactly one re-mint on 403
    assert len(calls) == 2   # PUT attempted twice (403 then 201)


def test_upload_file_blob_raises_after_persistent_403(monkeypatch, tmp_path):
    p = tmp_path / "dev_2026_01_01_00.zip"
    p.write_bytes(b"zipdata")
    monkeypatch.setattr(
        blob_upload, "get_upload_target",
        lambda fname: {"url": "https://sas.example/x", "blobPath": "https://depot/x", "expiresAt": "z"},
    )

    def always_403(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(blob_upload.urllib.request, "urlopen", always_403)

    with pytest.raises(blob_upload.BlobUploadError):
        blob_upload.upload_file_blob(p)
