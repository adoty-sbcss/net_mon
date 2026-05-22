-- Per-device SNMP community cache. The collector trials configured communities
-- against each candidate device and records the winning string here, so
-- subsequent scans skip the trial. NULL community + failure_count >= 5 means
-- "we tried everything and nothing worked, back off for 24h".
CREATE TABLE IF NOT EXISTS snmp_credentials (
    device_ip         INET PRIMARY KEY,
    community         TEXT,
    version           TEXT NOT NULL DEFAULT '2c',
    last_succeeded_at TIMESTAMPTZ,
    last_attempt_at   TIMESTAMPTZ,
    failure_count     INTEGER NOT NULL DEFAULT 0
);
