-- VLAN attribution for scans taken on an 802.1Q trunk.
--
-- When the box monitors a trunk via VLAN sub-interfaces (e.g. eth0.10, eth0.20),
-- each sub-interface scans its VLAN independently — the poller already treats it
-- like any NIC. These columns record which VLAN + parent trunk a scan covered,
-- so every scan (and the devices/neighbors/etc. that hang off it, and the rolled
-- up inventory) is attributable to its VLAN. NULL on a plain untagged interface.

ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS vlan_id          INTEGER;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS parent_interface TEXT;
CREATE INDEX IF NOT EXISTS idx_scan_runs_vlan ON scan_runs(vlan_id, started_at DESC);
