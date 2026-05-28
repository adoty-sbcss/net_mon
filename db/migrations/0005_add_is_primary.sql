-- Mark scans of the box's primary uplink (the default-route interface) so
-- downstream tooling can tell the box's own network apart from secondary
-- connections it monitors (Wi-Fi, future VLAN sub-interfaces). Nullable /
-- default false so existing rows remain valid.
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT FALSE;
