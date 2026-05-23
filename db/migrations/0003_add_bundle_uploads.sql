-- Tracks SFTP upload state per bundle file so we can retry orphans.
-- The hourly uploader scans bundles/ and ships any whose `uploaded_at` is
-- NULL. Once a file succeeds, retry_count freezes and last_attempt_at is the
-- timestamp of the successful upload.
CREATE TABLE IF NOT EXISTS bundle_uploads (
    id              SERIAL PRIMARY KEY,
    filename        TEXT NOT NULL UNIQUE,
    local_path      TEXT NOT NULL,
    built_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    uploaded_at     TIMESTAMPTZ,
    remote_path     TEXT,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    size_bytes      BIGINT
);
CREATE INDEX IF NOT EXISTS idx_bundle_uploads_pending
    ON bundle_uploads(uploaded_at)
    WHERE uploaded_at IS NULL;
