-- App_Mon database schema. Loaded on first postgres startup.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS scan_runs (
    id              SERIAL PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    trigger_reason  TEXT NOT NULL,
    interface       TEXT NOT NULL,
    -- INET, not CIDR: stores an address-plus-netmask like 10.6.0.12/22.
    -- CIDR rejects values with host bits set ("must be a network address").
    interface_cidr  INET,
    gateway_ip      INET,
    gateway_mac     MACADDR,
    network_id      TEXT,
    duration_sec    INTEGER,
    mode            TEXT NOT NULL DEFAULT 'field',
    notes           TEXT,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_network ON scan_runs(network_id, started_at DESC);

CREATE TABLE IF NOT EXISTS devices (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip              INET,
    mac             MACADDR,
    hostname        TEXT,
    vendor          TEXT,
    source          TEXT NOT NULL,
    extra           JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);

CREATE TABLE IF NOT EXISTS neighbors (
    id                  SERIAL PRIMARY KEY,
    scan_run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    local_port          TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    chassis_id          TEXT,
    port_id             TEXT,
    system_name         TEXT,
    system_description  TEXT,
    port_description    TEXT,
    vlan_id             INTEGER,
    mgmt_ip             INET,
    capabilities        TEXT[],
    seen_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_neighbors_scan ON neighbors(scan_run_id);

CREATE TABLE IF NOT EXISTS arp_entries (
    id          SERIAL PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip          INET NOT NULL,
    mac         MACADDR NOT NULL,
    interface   TEXT NOT NULL,
    vendor      TEXT,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_arp_scan ON arp_entries(scan_run_id);

CREATE TABLE IF NOT EXISTS dhcp_observations (
    id           SERIAL PRIMARY KEY,
    scan_run_id  INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    message_type TEXT NOT NULL,
    server_ip    INET,
    server_mac   MACADDR,
    client_mac   MACADDR,
    offered_ip   INET,
    subnet_mask  TEXT,
    router       INET,
    dns_servers  TEXT,
    seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dhcp_scan ON dhcp_observations(scan_run_id);

CREATE TABLE IF NOT EXISTS stp_events (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    bpdu_type       TEXT NOT NULL,
    root_bridge_id  TEXT,
    bridge_id       TEXT,
    port_id         TEXT,
    root_path_cost  BIGINT,
    topology_change BOOLEAN,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_stp_scan ON stp_events(scan_run_id);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id                  SERIAL PRIMARY KEY,
    scan_run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    interface           TEXT NOT NULL,
    bucket_start        TIMESTAMPTZ NOT NULL,
    bucket_end          TIMESTAMPTZ NOT NULL,
    rx_packets          BIGINT,
    rx_bytes            BIGINT,
    rx_errors           BIGINT,
    rx_dropped          BIGINT,
    tx_packets          BIGINT,
    tx_bytes            BIGINT,
    broadcast_packets   BIGINT,
    multicast_packets   BIGINT
);
CREATE INDEX IF NOT EXISTS idx_traffic_scan ON traffic_stats(scan_run_id);

CREATE TABLE IF NOT EXISTS snmp_polls (
    id          SERIAL PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    device_ip   INET NOT NULL,
    oid         TEXT NOT NULL,
    oid_name    TEXT,
    value       TEXT,
    polled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_snmp_scan ON snmp_polls(scan_run_id);

CREATE TABLE IF NOT EXISTS findings (
    id          SERIAL PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT,
    evidence    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_run_id);
