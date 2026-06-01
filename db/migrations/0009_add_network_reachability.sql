-- Network-device reachability, per scan.
--
-- Populated by discovery/reachability.py: for each infrastructure candidate
-- (gateway + LLDP mgmt IPs + network-vendor OUIs) record ICMP ping result,
-- whether it answered SNMP, and the traceroute path. Answers "which switches
-- are out there, and which respond to SNMP vs. only ping?" — the common case
-- where access switches are L3-reachable but silently drop SNMP (ACL/disabled).

CREATE TABLE IF NOT EXISTS network_reachability (
    id                SERIAL PRIMARY KEY,
    scan_run_id       INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip                INET NOT NULL,
    hostname          TEXT,
    vendor            TEXT,
    source            TEXT,                 -- why it's a candidate: gateway|lldp|oui
    ping_alive        BOOLEAN,
    ping_rtt_ms       DOUBLE PRECISION,
    ping_loss_pct     INTEGER,
    snmp_responded    BOOLEAN,
    snmp_version      TEXT,
    traceroute_hops   INTEGER,              -- hop count to destination, NULL = never reached
    traceroute_path   JSONB NOT NULL DEFAULT '[]'::jsonb,
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_net_reach_scan ON network_reachability(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_net_reach_ip   ON network_reachability(ip);
