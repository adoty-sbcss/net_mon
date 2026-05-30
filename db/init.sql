-- NetMon database schema. Loaded on first postgres startup.

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
    -- `mode` is retained for backward compatibility with old rows; field/monitor
    -- modes were removed in favor of continuous rescan-interval monitoring.
    mode            TEXT NOT NULL DEFAULT 'continuous',
    -- True when this interface is the box's own default-route uplink; false
    -- for secondary networks the box is monitoring (Wi-Fi, VLAN sub-ifaces).
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    notes           TEXT,
    error           TEXT,
    -- Box identity, populated from NETMON_*_SLUG env vars. Nullable so a
    -- box that hasn't been through the first-boot wizard yet still inserts.
    district_slug   TEXT,
    school_slug     TEXT,
    device_slug     TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_network ON scan_runs(network_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_identity
    ON scan_runs(district_slug, school_slug, device_slug, started_at DESC);

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
    -- Device-fingerprint options from client DISCOVER/REQUEST (opt 60/55/12),
    -- used by the dashboard to classify endpoints that don't speak SNMP.
    vendor_class_id TEXT,           -- option 60, e.g. "MSFT 5.0", "ArubaAP"
    param_req_list  TEXT,           -- option 55, e.g. "1,3,6,15,31,33,43"
    client_hostname TEXT,           -- option 12
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
    multicast_packets   BIGINT,
    -- Total packets tshark observed (post-filter). This is the right
    -- denominator for broadcast/multicast percentages — rx_packets above
    -- counts only kernel-accepted frames and isn't comparable.
    tshark_total_packets BIGINT
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

-- SNMP credential cache.
-- The collector tries each configured community string (NETMON_SNMP_COMMUNITIES)
-- against each candidate device. Once one succeeds we remember it here so
-- subsequent scans go straight to the known-working community and don't waste
-- time on misses. NULL community means "we tried everything and nothing worked"
-- (used together with failure_count for backoff).
CREATE TABLE IF NOT EXISTS snmp_credentials (
    device_ip         INET PRIMARY KEY,
    community         TEXT,
    version           TEXT NOT NULL DEFAULT '2c',
    last_succeeded_at TIMESTAMPTZ,
    last_attempt_at   TIMESTAMPTZ,
    failure_count     INTEGER NOT NULL DEFAULT 0
);

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

-- SNMP-discovered topology (see migration 0006).
CREATE TABLE IF NOT EXISTS topology_nodes (
    id                  SERIAL PRIMARY KEY,
    scan_run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    chassis_id          TEXT NOT NULL,
    system_name         TEXT,
    system_description  TEXT,
    mgmt_ips            TEXT[],
    discovered_via_ip   INET,
    source              TEXT NOT NULL,
    capabilities        TEXT[],
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb,
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_topology_nodes_scan    ON topology_nodes(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_topology_nodes_chassis ON topology_nodes(chassis_id);

CREATE TABLE IF NOT EXISTS topology_edges (
    id                  SERIAL PRIMARY KEY,
    scan_run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    local_chassis_id    TEXT NOT NULL,
    local_port_id       TEXT,
    local_port_desc     TEXT,
    remote_chassis_id   TEXT NOT NULL,
    remote_port_id      TEXT,
    remote_port_desc    TEXT,
    via                 TEXT NOT NULL,
    discovered_via_ip   INET,
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_topology_edges_scan    ON topology_edges(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_topology_edges_local   ON topology_edges(local_chassis_id);
CREATE INDEX IF NOT EXISTS idx_topology_edges_remote  ON topology_edges(remote_chassis_id);

-- DNS health probes (see migration 0007).
CREATE TABLE IF NOT EXISTS dns_probes (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    resolver_ip     INET NOT NULL,
    resolver_source TEXT NOT NULL,
    query_name      TEXT NOT NULL,
    query_type      TEXT NOT NULL DEFAULT 'A',
    expected_status TEXT,
    status          TEXT,
    query_time_ms   INTEGER,
    answer_count    INTEGER,
    answers_text    TEXT,
    error           TEXT,
    probed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_probes_scan     ON dns_probes(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_dns_probes_resolver ON dns_probes(resolver_ip, probed_at DESC);

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
