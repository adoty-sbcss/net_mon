-- mDNS (Bonjour) + SSDP (UPnP) service discovery, per scan.
--
-- Populated by discovery/mdns_ssdp.py: the chatty service-advertising devices
-- that barely show up in ARP/nmap — AirPrint printers, Apple TV/AirPlay,
-- Chromecasts, Sonos, Rokus, smart TVs, IP cameras, DLNA/UPnP media servers.
-- One row per (responder IP, protocol). `device_hint` is an advisory coarse
-- class derived from the advertised service types; authoritative device
-- classification stays in the dashboard ingest.

CREATE TABLE IF NOT EXISTS service_discovery (
    id            SERIAL PRIMARY KEY,
    scan_run_id   INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip            INET NOT NULL,
    source        TEXT NOT NULL,          -- mdns | ssdp
    hostname      TEXT,
    service_types TEXT[],                 -- e.g. {_ipp._tcp.local,_googlecast._tcp.local}
    device_hint   TEXT,                   -- printer | chromecast | apple-av | camera | ...
    details       JSONB NOT NULL DEFAULT '{}'::jsonb,
    seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_service_discovery_scan ON service_discovery(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_service_discovery_ip   ON service_discovery(ip);
