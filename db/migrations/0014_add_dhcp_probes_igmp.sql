-- DHCP-6: active rogue-DHCP probe results, one row per (scan, interface).
-- `offers` holds every DHCP server that answered the probe's DISCOVER; an empty
-- list with status 'no_answer' is NOT "clean" (see discovery/dhcp_probe.py).
CREATE TABLE IF NOT EXISTS dhcp_probes (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    interface       TEXT NOT NULL,
    probed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL,          -- answered | no_answer | error
    error           TEXT,
    client_mac      TEXT,
    wait_ms         INTEGER,
    self_test_seen  BOOLEAN,
    offers          JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_dhcp_probes_scan ON dhcp_probes(scan_run_id);

-- PERF-9: IGMP querier / multicast-group listener, one row per (scan, interface).
-- status 'none_heard' is only written after the listener's positive control
-- passed and it ran longer than a default query interval (discovery/igmp.py).
CREATE TABLE IF NOT EXISTS igmp_observations (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    interface       TEXT NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL,          -- querier_seen | none_heard | unavailable
    reason          TEXT,
    window_sec      INTEGER,
    listened_sec    DOUBLE PRECISION,
    self_test_seen  BOOLEAN,
    queriers        JSONB NOT NULL DEFAULT '[]'::jsonb,
    groups          JSONB NOT NULL DEFAULT '[]'::jsonb,
    reports_seen    INTEGER,
    leaves_seen     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_igmp_observations_scan ON igmp_observations(scan_run_id);
