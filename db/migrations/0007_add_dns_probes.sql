-- DNS health probes (per-scan).
--
-- Populated by discovery/dns_health.py: every scan, query a small set of
-- test names against each known resolver (public list from env + whatever
-- the host's /etc/resolv.conf advertises — DHCP-assigned or static) and
-- record per-(resolver, name) status, latency, and answer.
--
-- Schema is intentionally flat. The dashboard/Claude analyze by grouping:
--   * latency_ms per resolver over time → slow ISP DNS, intermittent loss
--   * status per resolver → SERVFAIL/TIMEOUT spikes
--   * answers diff across resolvers for the same name → split-horizon
--     issues, ISP DNS hijacking, ad-rewrite of NXDOMAIN

CREATE TABLE IF NOT EXISTS dns_probes (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    resolver_ip     INET NOT NULL,
    resolver_source TEXT NOT NULL,    -- 'public', 'dhcp', 'static', 'system-stub'
    query_name      TEXT NOT NULL,
    query_type      TEXT NOT NULL DEFAULT 'A',
    expected_status TEXT,             -- e.g. 'NXDOMAIN' for the negative probe
    status          TEXT,              -- NOERROR / NXDOMAIN / SERVFAIL / TIMEOUT / ERROR
    query_time_ms   INTEGER,
    answer_count    INTEGER,
    answers_text    TEXT,              -- semicolon-separated first ~3 answers
    error           TEXT,
    probed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_probes_scan     ON dns_probes(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_dns_probes_resolver ON dns_probes(resolver_ip, probed_at DESC);
