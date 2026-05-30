-- SNMP-discovered network topology.
--
-- Populated by discovery/snmp_topology.py: starting from a seed device
-- (gateway + LLDP mgmt IPs), walk each device's lldpRemTable /
-- lldpRemManAddrTable / cdpCacheTable via SNMP, recurse to discovered
-- neighbors with a depth+time budget, and persist nodes + edges per scan.

CREATE TABLE IF NOT EXISTS topology_nodes (
    id                  SERIAL PRIMARY KEY,
    scan_run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    chassis_id          TEXT NOT NULL,        -- LLDP chassis ID (MAC) or CDP device-id
    system_name         TEXT,
    system_description  TEXT,
    mgmt_ips            TEXT[],
    discovered_via_ip   INET,                 -- the SNMP target that surfaced this node
    source              TEXT NOT NULL,        -- 'snmp' (self), 'lldp', 'cdp'
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
    via                 TEXT NOT NULL,        -- 'lldp' or 'cdp'
    discovered_via_ip   INET,
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_topology_edges_scan    ON topology_edges(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_topology_edges_local   ON topology_edges(local_chassis_id);
CREATE INDEX IF NOT EXISTS idx_topology_edges_remote  ON topology_edges(remote_chassis_id);
