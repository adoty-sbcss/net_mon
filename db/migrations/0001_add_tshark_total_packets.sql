-- Adds the column used as the denominator for broadcast/multicast pct.
-- See bundle.py::_build_metrics. Idempotent.
ALTER TABLE traffic_stats
    ADD COLUMN IF NOT EXISTS tshark_total_packets BIGINT;
