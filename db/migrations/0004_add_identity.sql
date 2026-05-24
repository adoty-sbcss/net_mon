-- District / school / device identity columns on each scan run.
-- Populated by the collector from the NETMON_DISTRICT_SLUG / _SCHOOL_SLUG /
-- _DEVICE_SLUG env vars in /etc/netmon/netmon.env. All nullable so existing
-- scan_runs rows continue to satisfy the schema; rows produced after Phase 2
-- (when the first-boot wizard collects the values) will be populated.
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS district_slug TEXT;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS school_slug   TEXT;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS device_slug   TEXT;

-- Composite index supports the future central-dashboard query pattern
-- "show every scan from school X" without a sequential scan.
CREATE INDEX IF NOT EXISTS idx_scan_runs_identity
    ON scan_runs(district_slug, school_slug, device_slug, started_at DESC);
