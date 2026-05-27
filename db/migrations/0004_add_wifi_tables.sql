-- Phase 1 Wi-Fi monitoring tables. Idempotent; safe to re-run.

CREATE TABLE IF NOT EXISTS wifi_scans (
    id               SERIAL PRIMARY KEY,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    trigger_reason   TEXT NOT NULL,
    interface        TEXT NOT NULL,
    profile          TEXT NOT NULL,            -- 'survey' or 'monitor'
    duration_sec    INTEGER,
    channels_scanned INTEGER[],
    error            TEXT,
    notes            TEXT
);
CREATE INDEX IF NOT EXISTS idx_wifi_scans_started ON wifi_scans(started_at DESC);

CREATE TABLE IF NOT EXISTS wifi_aps (
    id              SERIAL PRIMARY KEY,
    wifi_scan_id    INTEGER NOT NULL REFERENCES wifi_scans(id) ON DELETE CASCADE,
    bssid           MACADDR NOT NULL,
    essid           TEXT,
    channel         INTEGER,
    frequency_mhz   INTEGER,
    band            TEXT,                       -- '2.4GHz', '5GHz', '6GHz'
    privacy         TEXT,                       -- 'OPEN', 'WEP', 'WPA', 'WPA2', 'WPA3', 'WPA2-WPA3', etc.
    cipher          TEXT,
    auth            TEXT,
    signal_dbm      INTEGER,
    beacon_count    INTEGER,
    data_count      INTEGER,
    vendor          TEXT,
    first_seen_at   TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    extra           JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wifi_aps_scan  ON wifi_aps(wifi_scan_id);
CREATE INDEX IF NOT EXISTS idx_wifi_aps_bssid ON wifi_aps(bssid);

CREATE TABLE IF NOT EXISTS wifi_stations (
    id                SERIAL PRIMARY KEY,
    wifi_scan_id      INTEGER NOT NULL REFERENCES wifi_scans(id) ON DELETE CASCADE,
    station_mac       MACADDR NOT NULL,
    associated_bssid  MACADDR,                  -- NULL when station is only probing
    probed_essids     TEXT[],
    signal_dbm        INTEGER,
    frame_count       INTEGER,
    vendor            TEXT,
    first_seen_at     TIMESTAMPTZ,
    last_seen_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_wifi_stations_scan ON wifi_stations(wifi_scan_id);
CREATE INDEX IF NOT EXISTS idx_wifi_stations_mac  ON wifi_stations(station_mac);

CREATE TABLE IF NOT EXISTS wifi_channel_stats (
    id              SERIAL PRIMARY KEY,
    wifi_scan_id    INTEGER NOT NULL REFERENCES wifi_scans(id) ON DELETE CASCADE,
    channel         INTEGER NOT NULL,
    frequency_mhz   INTEGER,
    band            TEXT,
    ap_count        INTEGER NOT NULL DEFAULT 0,
    noise_dbm       INTEGER,
    active_ms       BIGINT,                     -- from iw survey
    busy_ms         BIGINT,
    busy_pct        NUMERIC(5,2)
);
CREATE INDEX IF NOT EXISTS idx_wifi_channel_stats_scan ON wifi_channel_stats(wifi_scan_id);

CREATE TABLE IF NOT EXISTS wifi_events (
    id              SERIAL PRIMARY KEY,
    wifi_scan_id    INTEGER NOT NULL REFERENCES wifi_scans(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,              -- 'weak_security', 'duplicate_ssid', 'channel_saturation', etc.
    severity        TEXT NOT NULL,              -- 'info', 'low', 'medium', 'high'
    title           TEXT NOT NULL,
    detail          TEXT,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wifi_events_scan ON wifi_events(wifi_scan_id);
