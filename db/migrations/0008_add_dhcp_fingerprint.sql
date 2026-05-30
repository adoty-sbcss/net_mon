-- DHCP device-fingerprint fields.
--
-- Captured by discovery/tshark.py from client-originated DHCP messages
-- (DISCOVER / REQUEST / INFORM). These let the dashboard classify endpoints
-- that never speak SNMP — printers, PCs, phones, IoT:
--   * option 60 (vendor class id): often self-describing ("MSFT 5.0", "ArubaAP")
--   * option 55 (parameter request list): ordered option codes the client asks
--     for — highly OS-specific; the classic DHCP fingerprint (Fingerbank keys
--     on this). Stored as a comma-joined string, e.g. "1,3,6,15,31,33,43".
--   * option 12 (hostname): the name the client advertises.
--
-- Idempotent: safe on a fresh schema where init.sql already added these.

ALTER TABLE dhcp_observations ADD COLUMN IF NOT EXISTS vendor_class_id TEXT;
ALTER TABLE dhcp_observations ADD COLUMN IF NOT EXISTS param_req_list  TEXT;
ALTER TABLE dhcp_observations ADD COLUMN IF NOT EXISTS client_hostname TEXT;
