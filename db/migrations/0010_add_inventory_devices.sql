-- Persistent device inventory (cross-scan, keyed on MAC).
--
-- Every other discovery table is scan-scoped (scan_run_id ... ON DELETE CASCADE):
-- it answers "what did THIS scan see." This table is the rolled-up, durable
-- answer to "what devices exist on the networks this box monitors, and when did
-- we first/last see each one." It survives scan-run pruning (last_scan_run_id is
-- SET NULL, not CASCADE) so the long-term inventory outlives the raw evidence.
--
-- Keyed on MAC because MAC is the stable hardware identity; IP is reassignable
-- by DHCP. Devices discovered without a MAC (e.g. an off-subnet nmap host or an
-- LLDP mgmt IP) are not inventoried here — they stay in the per-scan `devices`
-- table only.
--
-- Foundation for: DHCP/SNMP device-class enrichment, per-switch-port change
-- detection, AD/LDAP cross-reference, CVE matching, and cross-site MAC
-- correlation in the dashboard.

CREATE TABLE IF NOT EXISTS inventory_devices (
    mac              MACADDR PRIMARY KEY,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    times_seen       INTEGER NOT NULL DEFAULT 1,
    last_ip          INET,
    hostname         TEXT,
    vendor           TEXT,
    -- Device classification (printer / switch / ap / phone / camera / ...).
    -- Populated later by the DHCP-fingerprint + SNMP classifiers; nullable
    -- until then so this column can ship ahead of those features.
    device_class     TEXT,
    last_source      TEXT,           -- how last discovered: arp-scan | nmap | lldp | +rdns
    last_network_id  TEXT,           -- which monitored network it was last on
    last_interface   TEXT,           -- which box interface saw it last
    -- Nullable + SET NULL (not CASCADE) on purpose: the inventory is the durable
    -- rollup and must outlive the scan that last touched it.
    last_scan_run_id INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
    -- Box identity copied from scan_runs so the dashboard can aggregate the
    -- inventory across boxes (cross-site correlation) without a join back.
    district_slug    TEXT,
    school_slug      TEXT,
    device_slug      TEXT,
    extra            JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_inventory_last_seen ON inventory_devices(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_inventory_vendor    ON inventory_devices(vendor);
CREATE INDEX IF NOT EXISTS idx_inventory_network   ON inventory_devices(last_network_id);
