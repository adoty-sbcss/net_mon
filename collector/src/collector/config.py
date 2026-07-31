from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Self

import structlog
from pydantic import Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=None, extra="ignore")

    postgres_host: str = Field(default="127.0.0.1", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, ge=1, le=65535, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="netmon", alias="POSTGRES_USER")
    postgres_password: str = Field(default="netmon", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="netmon", alias="POSTGRES_DB")

    # Passive-capture window length per scan (full OR light): tshark listens
    # this long for DHCP/STP/ARP/broadcast on the scanned interface.
    capture_seconds: int = Field(default=120, ge=1, le=3600, alias="NETMON_CAPTURE_SECONDS")
    poll_interval: int = Field(default=30, ge=1, le=3600, alias="NETMON_POLL_INTERVAL")
    # The poller re-scans any active interface whose network hasn't been
    # scanned within this window. Covers both link-up (no prior scan) and
    # periodic re-scan of a stable network. Replaces the old field/monitor mode.
    rescan_interval: int = Field(default=3600, ge=60, le=604800, alias="NETMON_RESCAN_INTERVAL")
    # Between full re-scans, run a LIGHT capture-only pass (passive tshark + a
    # quick ARP sweep — no LLDP / nmap / SNMP / reachability / DNS / mDNS)
    # whenever the network hasn't had ANY scan within this window. Lets sporadic
    # DHCP/STP get sampled far more often than the hourly full scan without
    # paying for full discovery each time. Must be < rescan_interval to have any
    # effect; a full scan also resets this clock. 0 disables the light pass.
    capture_interval: int = Field(default=900, ge=0, le=604800, alias="NETMON_CAPTURE_INTERVAL")
    # Anti-flap floor only: never scan the same network twice within this many
    # seconds, even if something asks. Much smaller than rescan_interval.
    cooldown_seconds: int = Field(default=300, ge=0, le=86400, alias="NETMON_COOLDOWN_SECONDS")
    # Local Postgres retention: delete scan_runs (+ cascaded per-scan tables)
    # older than this many days from the COLLECTOR's OWN db. Bundles upload hourly,
    # so the box only needs recent scans for bundling + the crawl-gate lookups;
    # without this the local db grows unbounded. The durable inventory survives
    # (its scan FK is SET NULL, not CASCADE). 0 disables.
    local_retention_days: int = Field(default=14, ge=0, le=3650, alias="NETMON_LOCAL_RETENTION_DAYS")
    # A much SHORTER window for the heavy topology SNMP rows (db.HEAVY_SNMP_OID_NAMES:
    # dot1dStpPortTable, entPhysical*, ifName/ifTable, dot1dBasePortIfIndex,
    # dot1qTpFdbPort). Measured on a live box, snmp_polls was 13 GB / 45.7M rows =
    # 95% of its whole db, and those slow-changing topology OIDs are ~97% of that —
    # stored IN FULL on every bulk walk. Retention was never broken (the oldest row
    # sat exactly at the local_retention_days window); the problem is VOLUME. They
    # ship in the hourly bundle and the dashboard is their durable home, so the box
    # only needs them briefly. Genuine host inventory keeps local_retention_days.
    # Keep this ABOVE snmp_bulk_interval (see db.HEAVY_SNMP_OID_NAMES). 0 disables.
    snmp_bulk_retention_days: int = Field(
        default=3, ge=0, le=365, alias="NETMON_SNMP_BULK_RETENTION_DAYS"
    )
    exclude_ifaces: str = Field(
        default="lo,docker0,br-,veth,virbr,tun,tap",
        alias="NETMON_EXCLUDE_IFACES",
    )
    # VLAN IDs the poller must NOT auto-scan even if a sub-interface exists
    # (comma-separated). Lets an operator drop noisy/irrelevant VLANs from a
    # monitored trunk without removing the sub-interface. A manual `scan` is
    # explicit and ignores this.
    exclude_vlans: str = Field(default="", alias="NETMON_EXCLUDE_VLANS")

    # On by default. With no community configured this is a no-op (nothing to
    # authenticate with), so arming it costs nothing and the box starts polling
    # the moment a community is pushed for its district.
    snmp_enabled: bool = Field(default=True, alias="NETMON_SNMP_ENABLED")
    snmp_config: Path = Field(default=Path("/etc/netmon/snmp.yaml"), alias="NETMON_SNMP_CONFIG")
    # Comma-separated list of v2c communities to try, in order. The first one
    # to get a response for a given device gets cached in snmp_credentials.
    snmp_communities: str = Field(default="", alias="NETMON_SNMP_COMMUNITIES")
    # By default SNMP only polls likely network gear (gateway + LLDP mgmt IPs
    # + network-vendor OUIs) to keep scans fast. Turn this on to also poll
    # every discovered host so printers / PCs / IoT get classified via SNMP
    # (Printer-MIB, Host-Resources, etc.). Costs a community trial per host.
    snmp_poll_all_hosts: bool = Field(default=False, alias="NETMON_SNMP_POLL_ALL_HOSTS")
    # Hard bounds for the optional poll-all-hosts mode. The time budget is for
    # the whole identity/bulk pass; one in-flight net-snmp command may finish
    # just after it expires, but no new work starts beyond the deadline.
    snmp_poll_max_candidates: int = Field(
        default=64, ge=1, le=1024, alias="NETMON_SNMP_POLL_MAX_CANDIDATES"
    )
    snmp_poll_time_budget: int = Field(
        default=120, ge=10, le=3600, alias="NETMON_SNMP_POLL_TIME_BUDGET"
    )
    # Explicit extra SNMP target IPs beyond the auto-discovered candidate set,
    # pushed from the dashboard equipment registry (devices the operator marked
    # monitor=SNMP) so registered gear is always polled even when the OUI/heuristic
    # candidate selection would miss it. Comma-separated.
    snmp_extra_targets: str = Field(default="", alias="NETMON_SNMP_EXTRA_TARGETS")
    # Management IPs the SNMP topology crawl must NEVER poll or recurse THROUGH —
    # pushed from the dashboard when an operator purges/excludes a device (e.g. a
    # switch the crawl reached outside the school boundary). This is how an admin
    # stops the box from re-discovering gear they removed from inventory.
    # Comma-separated.
    snmp_exclude: str = Field(default="", alias="NETMON_SNMP_EXCLUDE")

    # SNMP topology crawl (Path B). On by default, but it can't run away: it
    # needs snmp_enabled AND a working community AND candidate seeds, and it is
    # interval-gated (see snmp_topology_interval below), so at most ~weekly. The
    # scope defaults to 'spine' (path-to-internet), not a full-fabric crawl.
    snmp_topology_enabled: bool = Field(default=True, alias="NETMON_SNMP_TOPOLOGY_ENABLED")
    # Max hops from a seed device. 5 covers most school-district fabrics
    # without going wild on internet-facing gear.
    snmp_topology_max_depth: int = Field(
        default=5, ge=1, le=32, alias="NETMON_SNMP_TOPOLOGY_MAX_DEPTH"
    )
    # Wall-clock cap per crawl so it can't blow scan duration on a large
    # fabric. Stops cleanly when the budget is reached. Because the crawl is
    # interval-gated (see below) it runs at most ~weekly by default, so we can
    # afford a generous budget to "really crawl" without slowing hourly scans.
    snmp_topology_time_budget: int = Field(
        default=300, ge=10, le=3600, alias="NETMON_SNMP_TOPOLOGY_TIME_BUDGET"
    )
    # How often to actually run the crawl, per monitored network. Topology
    # changes slowly (it's physical cabling + switch config), so rediscovering
    # it every hourly scan is wasted compute. Default 7 days; the crawl runs
    # only if the last one for this network was longer ago than this. A manual
    # `./netmon scan` (force=True) always crawls, giving an on-demand override.
    # Set to 0 to crawl on every scan (the old behavior).
    snmp_topology_interval: int = Field(
        default=7 * 24 * 3600,
        ge=0,
        le=365 * 24 * 3600,
        alias="NETMON_SNMP_TOPOLOGY_INTERVAL",
    )
    # Crawl SCOPE. 'spine' (default) = directional: from the local switch, follow
    # only the uplink toward the internet (gateway-MAC FDB port -> STP root port ->
    # toward-gateway), so the crawl stops climbing at the L3 edge instead of
    # flooding sideways into every IDF; where an uplink can't be resolved it falls
    # back to a normal (capability-gated, budgeted) crawl at that switch, so
    # visibility is never lost. 'full' = the historical omnidirectional walk.
    # Validated on a live fabric (Monitor1): polled 35 devices vs 197 / 6s vs 15min
    # for the same coverage. Sibling switches a sensor isn't on the path to surface
    # as uncovered in the dashboard coverage view rather than being crawled.
    snmp_topology_scope: str = Field(default="spine", alias="NETMON_SNMP_TOPOLOGY_SCOPE")
    # Safety backstops (apply to BOTH scopes): stop enqueuing once this many nodes
    # are known, and never fan out into more than N neighbors from one device — so
    # a 200-port core can't explode the crawl regardless of depth/time.
    snmp_topology_max_nodes: int = Field(
        default=600, ge=1, le=10000, alias="NETMON_SNMP_TOPOLOGY_MAX_NODES"
    )
    snmp_topology_fanout_cap: int = Field(
        default=40, ge=1, le=1000, alias="NETMON_SNMP_TOPOLOGY_FANOUT_CAP"
    )
    # How often to walk the HEAVY bulk SNMP OIDs (ifTable, the bridge FDB tables,
    # ipNetToMediaTable). These are large — one row per interface / learned MAC /
    # ARP entry — and change slowly, so walking them every hourly scan wastes
    # compute and bloats the db + bundle. Walked at most once per this interval per
    # network (default daily); the small identity/STP/port OIDs are still polled
    # every scan. A manual `./netmon scan` (force=True) always walks them. 0 =
    # every scan (the old behavior).
    snmp_bulk_interval: int = Field(
        default=24 * 3600, ge=0, le=365 * 24 * 3600, alias="NETMON_SNMP_BULK_INTERVAL"
    )

    # Release channel (read by scripts/auto-update.sh; reported at check-in so the
    # dashboard rollout view knows each box's channel). 'stable' (default) tracks
    # the dashboard-pinned good SHA in update_ref (empty => origin/main, i.e. the
    # historical behavior); 'canary' tracks origin/main (latest); 'hold' pauses
    # auto-update. Pushed from the dashboard like the other knobs.
    update_channel: str = Field(default="stable", alias="NETMON_UPDATE_CHANNEL")
    update_ref: str = Field(default="", alias="NETMON_UPDATE_REF")

    # --- Reverse DNS (PTR) enrichment ---
    # After discovery, look up PTR records for devices that still have no
    # hostname, querying the LOCAL site resolver(s) (DHCP-assigned DNS + gateway)
    # rather than only nmap's container resolver — which is often public DNS with
    # no internal records. Fills internal hostnames nmap can't.
    rdns_enabled: bool = Field(default=True, alias="NETMON_RDNS_ENABLED")
    rdns_timeout_sec: int = Field(default=2, ge=1, le=30, alias="NETMON_RDNS_TIMEOUT_SEC")

    # --- Persistent device inventory ---
    # Maintain a durable, MAC-keyed inventory across scans (first/last seen,
    # times seen, last known IP/hostname/vendor/location). The per-scan tables
    # stay the raw evidence; this is the rolled-up "what's on the networks this
    # box monitors" view the discovery/security/fleet features build on. Cheap
    # (one indexed upsert per discovered device, in a single transaction per
    # scan); a kill-switch rather than a tuning knob.
    inventory_enabled: bool = Field(default=True, alias="NETMON_INVENTORY_ENABLED")

    # --- mDNS (Bonjour) + SSDP (UPnP) service discovery ---
    # Each scan, send a few multicast queries (mDNS 224.0.0.251:5353, SSDP
    # 239.255.255.250:1900) and read the replies. Catches AirPrint printers,
    # Apple TV/AirPlay, Chromecasts, Sonos, Rokus, smart TVs, IP cameras, and
    # UPnP/DLNA media servers — most of which barely show up in ARP/nmap. Cheap
    # and read-only beyond the small query packets; time-bounded by the seconds
    # below so it can't stretch a scan.
    mdns_enabled: bool = Field(default=True, alias="NETMON_MDNS_ENABLED")
    mdns_seconds: float = Field(default=3.0, ge=0.1, le=60, alias="NETMON_MDNS_SECONDS")
    ssdp_seconds: float = Field(default=3.0, ge=0.1, le=60, alias="NETMON_SSDP_SECONDS")

    # --- Network-device reachability (ping + traceroute + SNMP-response) ---
    # Each scan, probe the infrastructure candidate set (gateway + LLDP mgmt IPs
    # + network-vendor OUIs) so the dashboard can show which switches are out
    # there and which answer SNMP vs. only ping. Cheap; traceroute is skipped
    # gracefully if the binary is missing.
    reachability_enabled: bool = Field(default=True, alias="NETMON_REACHABILITY_ENABLED")
    reachability_traceroute: bool = Field(default=True, alias="NETMON_REACHABILITY_TRACEROUTE")
    reachability_max_hops: int = Field(
        default=10, ge=1, le=64, alias="NETMON_REACHABILITY_MAX_HOPS"
    )

    # --- DNS health probes ---
    # Per scan, query each test name against each resolver (public + DHCP).
    dns_enabled: bool = Field(default=True, alias="NETMON_DNS_ENABLED")
    # Comma-separated public resolvers — measures the box's path to upstream DNS.
    dns_public_resolvers: str = Field(
        default="1.1.1.1,8.8.8.8,9.9.9.9",
        alias="NETMON_DNS_PUBLIC_RESOLVERS",
    )
    # Comma-separated test names. Keep small; ~4 names × ~5 resolvers/scan.
    dns_test_names: str = Field(
        default="google.com,microsoft.com,cloudflare.com",
        alias="NETMON_DNS_TEST_NAMES",
    )
    # Per-query timeout (seconds). dig +time=N +tries=1.
    dns_timeout_sec: int = Field(default=2, ge=1, le=30, alias="NETMON_DNS_TIMEOUT_SEC")
    # Send a unique nonexistent name per scan to catch resolvers that rewrite
    # NXDOMAIN to an ad/filter page.
    dns_include_nxdomain_probe: bool = Field(
        default=True,
        alias="NETMON_DNS_INCLUDE_NXDOMAIN_PROBE",
    )

    # --- Wi-Fi RF / AP survey (WIFI-2) ---
    # Passive neighbor-AP survey (SSIDs/BSSIDs/channels/signal/encryption). The
    # scan itself runs HOST-side (scripts/netmon-wifi-survey.sh, on a timer)
    # because the container has no iw/nmcli and NM owns the radio; the collector
    # just reads + normalizes the envelope at /var/lib/netmon/wifi_survey.json and
    # ships it in the hourly bundle. ON by default — the passive survey is safe on a
    # timer and a box with no Wi-Fi NIC just no-ops (empty envelope). Set false to
    # opt a sensor out. (The active client-join test, WIFI-6, stays opt-in.)
    wifi_survey_enabled: bool = Field(default=True, alias="NETMON_WIFI_SURVEY_ENABLED")
    # Comma-separated SSIDs owned by the district — used to flag is_district_ssid
    # (own APs vs. neighbors). Empty => the flag is left unknown (null).
    wifi_district_ssids: str = Field(default="", alias="NETMON_WIFI_DISTRICT_SSIDS")
    # Treat the envelope as stale past this age (sec); the bundle still ships it
    # with stale=true so the dashboard can show "as of HH:MM". Default 30 min.
    wifi_survey_max_age: int = Field(
        default=1800, ge=60, le=604800, alias="NETMON_WIFI_SURVEY_MAX_AGE"
    )

    # --- Wi-Fi analysis-radio JOIN (WIFI-1) ---
    # Join a spare Wi-Fi NIC to a network so the poller can analyze it like any other
    # interface. OFF by default; applied HOST-side via the host-wifi-join action
    # (lib/wifi.sh) with routes-off so the analysis radio can never become the uplink.
    # Auth: open | psk | peap | ttls (peap/ttls = WPA2-Enterprise username+password;
    # EAP-TLS client certs are a separate SEC-gated follow-up). The secret is written
    # to a 0600 NM keyfile on apply, never passed on the nmcli command line.
    wifi_join_enabled: bool = Field(default=False, alias="NETMON_WIFI_JOIN_ENABLED")
    wifi_join_iface: str = Field(default="", alias="NETMON_WIFI_JOIN_IFACE")
    wifi_join_ssid: str = Field(default="", alias="NETMON_WIFI_JOIN_SSID")
    wifi_join_auth: str = Field(default="open", alias="NETMON_WIFI_JOIN_AUTH")
    wifi_join_identity: str = Field(default="", alias="NETMON_WIFI_JOIN_IDENTITY")
    wifi_join_secret: str = Field(default="", alias="NETMON_WIFI_JOIN_SECRET")
    # WIFI-6 unattended scheduler: run the experience battery every N seconds
    # (0 = manual / dashboard "Test now" only). Optional box-local quiet-hours window
    # "START-END" (24h, may wrap midnight, e.g. "22-6") where it won't fire. The host
    # timer + tick (scripts/netmon-wifi-experience-tick.sh) read these from netmon.env;
    # the multi-profile list itself rides WIFI_PROFILES_FILE.
    wifi_join_schedule_sec: int = Field(
        default=0, ge=0, le=30 * 24 * 3600, alias="NETMON_WIFI_JOIN_SCHEDULE_SEC"
    )
    wifi_join_quiet: str = Field(default="", alias="NETMON_WIFI_JOIN_QUIET")

    # --- Authoritative DHCP server intelligence (DHCP-2) ---
    # Actively query authorized Windows DHCP servers over WinRM (PowerShell
    # DhcpServer module) for scopes, per-scope utilization, options, reservations,
    # and failover state — the authoritative view the passive OFFER/ACK sniffing
    # (dhcp_observations) can't give. OFF by default. The target LIST + per-server
    # credentials ride a 0600 JSON file (checkin.DHCP_TARGETS_FILE), NOT env, since
    # it carries secrets and its quotes/braces don't survive EnvironmentFile parsing
    # — exactly like the Wi-Fi join profiles. Least-privilege: a domain account in
    # the server's read-only "DHCP Users" group is sufficient.
    dhcp_intel_enabled: bool = Field(default=False, alias="NETMON_DHCP_INTEL_ENABLED")
    # How often to query each server (seconds). Scope config changes slowly, so we
    # don't re-query every poll. Default 1h; a manual `dhcp-intel` run overrides.
    dhcp_intel_interval: int = Field(
        default=3600, ge=60, le=30 * 24 * 3600, alias="NETMON_DHCP_INTEL_INTERVAL"
    )
    # Wall-clock cap for the whole DHCP pass across all targets, so a slow/unreachable
    # server can't stretch the poll loop.
    dhcp_intel_time_budget: int = Field(
        default=120, ge=10, le=3600, alias="NETMON_DHCP_INTEL_TIME_BUDGET"
    )
    # Per-server WinRM operation timeout (seconds).
    dhcp_intel_winrm_timeout: int = Field(
        default=30, ge=1, le=300, alias="NETMON_DHCP_INTEL_WINRM_TIMEOUT"
    )

    # --- Network DEVICE config backup (NCM-1): fetch running/startup configs over
    #     READ-ONLY SSH from the district's managed devices. OFF by default; the
    #     target list + per-device SSH creds ride a 0600 JSON file (like DHCP). ---
    device_config_enabled: bool = Field(default=False, alias="NETMON_DEVICE_CONFIG_ENABLED")
    # How often to back up each device (seconds). Configs change slowly; default 24h.
    device_config_interval: int = Field(
        default=86400, ge=300, le=365 * 24 * 3600, alias="NETMON_DEVICE_CONFIG_INTERVAL"
    )
    # Wall-clock cap for the whole config-backup pass across all devices.
    device_config_time_budget: int = Field(
        default=300, ge=10, le=7200, alias="NETMON_DEVICE_CONFIG_TIME_BUDGET"
    )
    # Per-device SSH connect/read timeout (seconds).
    device_config_ssh_timeout: int = Field(
        default=30, ge=1, le=300, alias="NETMON_DEVICE_CONFIG_SSH_TIMEOUT"
    )

    # Bundle delivery transport: "blob" (HTTPS PUT with a dashboard-minted SAS
    # URL) is the only transport that ships bundles; any other value (default
    # "sftp") leaves the box in the pre-install staging state with uploads OFF.
    # Pushed from the dashboard via desired-config.
    # NOTE: the default stays "sftp" (i.e. NOT "blob") so the staging gate holds —
    # _active_transport() only returns a transport when this is "blob", so an
    # un-installed box never uploads until the dashboard's enable-uploads flow
    # flips it to "blob" (see #6 fix).
    bundle_transport: str = Field(default="sftp", alias="NETMON_BUNDLE_TRANSPORT")
    device_name: str = Field(default="", alias="NETMON_DEVICE_NAME")

    # iperf3 throughput testing (#10). Pushed from the dashboard via desired_config.
    iperf_enabled: bool = Field(default=False, alias="NETMON_IPERF_ENABLED")
    iperf_server: str = Field(default="", alias="NETMON_IPERF_SERVER")
    iperf_port: int = Field(default=5201, ge=1, le=65535, alias="NETMON_IPERF_PORT")
    iperf_schedule_sec: int = Field(
        default=3600, ge=60, le=30 * 24 * 3600, alias="NETMON_IPERF_SCHEDULE_SEC"
    )
    iperf_duration: int = Field(default=10, ge=1, le=60, alias="NETMON_IPERF_DURATION")
    iperf_direction: str = Field(default="down", alias="NETMON_IPERF_DIRECTION")
    iperf_protocol: str = Field(default="tcp", alias="NETMON_IPERF_PROTOCOL")
    # Timezone the multi-schedule cron times are evaluated in (IANA name). The box
    # OS clock may be UTC, but a schedule says "5am Pacific" — so we evaluate in
    # this zone via zoneinfo, falling back to box-local if it's unknown. The
    # per-schedule list itself rides a JSON file (see checkin.IPERF_SCHEDULES_FILE),
    # not an env var, since its quotes/commas don't survive EnvironmentFile parsing.
    iperf_timezone: str = Field(default="America/Los_Angeles", alias="NETMON_IPERF_TIMEZONE")

    # Public internet speed test (PERF-2). ON by default so every box reports
    # bandwidth from day one; the schedule below keeps it infrequent (real
    # bandwidth cost). Set false to opt a sensor out.
    speedtest_enabled: bool = Field(default=True, alias="NETMON_SPEEDTEST_ENABLED")
    # Provider — Cloudflare only (Ookla removed: unreliable on filtered school
    # networks). Kept as a field for forward-compat; values are normalized to
    # "cloudflare" by the runner.
    speedtest_providers: str = Field(default="cloudflare", alias="NETMON_SPEEDTEST_PROVIDERS")
    # Default 6h — speed tests consume real bandwidth, so less frequent than iperf.
    speedtest_schedule_sec: int = Field(
        default=6 * 3600, ge=900, le=30 * 24 * 3600, alias="NETMON_SPEEDTEST_SCHEDULE_SEC"
    )

    # Latency / jitter / loss probes (PERF-4). Cheap pings each check-in; ON by
    # default (negligible cost, always-useful signal alongside the speed test).
    latency_enabled: bool = Field(default=True, alias="NETMON_LATENCY_ENABLED")
    # CSV of internet targets to ping; gateway + DNS resolver are added automatically.
    latency_targets: str = Field(default="1.1.1.1,8.8.8.8", alias="NETMON_LATENCY_TARGETS")

    # Website / end-user experience probes (PERF-5). Per configured URL, one curl
    # captures the DNS/TCP/TLS/TTFB/total waterfall + status + speed. The URL LIST
    # rides a JSON file (checkin.WEBPERF_URLS_FILE), pushed from the dashboard's
    # district-managed website list; run on a cadence (default 15m) like speedtest.
    webperf_enabled: bool = Field(default=False, alias="NETMON_WEBPERF_ENABLED")
    webperf_schedule_sec: int = Field(
        default=900, ge=60, le=30 * 24 * 3600, alias="NETMON_WEBPERF_SCHEDULE_SEC"
    )

    # Box identity (set by the first-boot wizard; empty on pre-wizard installs).
    # Used to tag scan_runs rows and, in a future phase, to drive the
    # hierarchical SFTP path and bundle filenames.
    district_slug: str = Field(default="", alias="NETMON_DISTRICT_SLUG")
    school_slug: str = Field(default="", alias="NETMON_SCHOOL_SLUG")
    device_slug: str = Field(default="", alias="NETMON_DEVICE_SLUG")

    # --- Dashboard control plane (outbound check-in; no inbound connectivity) ---
    # When both are set, `python -m collector checkin` polls the dashboard for
    # desired config + queued commands and reports results. Set NETMON_ENROLL_TOKEN
    # to the one-time token generated on the sensor's page in the dashboard.
    dashboard_url: str = Field(default="", alias="NETMON_DASHBOARD_URL")
    enroll_token: str = Field(default="", alias="NETMON_ENROLL_TOKEN")
    # Shared bootstrap key for AUTO-enrollment: if enroll_token is empty but this
    # + dashboard_url + identity slugs are set, the box self-registers on its
    # first check-in and writes its issued token back to netmon.env. Same key on
    # every box; baked into setup so techs don't copy per-sensor tokens.
    bootstrap_key: str = Field(default="", alias="NETMON_BOOTSTRAP_KEY")

    bundle_dir: Path = Field(default=Path("/var/lib/netmon/bundles"), alias="NETMON_BUNDLE_DIR")

    @model_validator(mode="after")
    def validate_cadence_relationships(self) -> Self:
        # The collector's OWN env belongs to the operator; a bad cadence
        # relationship should degrade gracefully (warn + tolerate), NOT
        # crash-loop the collector on a value it accepted before these checks
        # existed. Dashboard-PUSHED config is still hard-rejected upstream
        # (checkin._validate_desired_config), so this only softens self-config.
        if self.capture_interval and self.capture_interval >= self.rescan_interval:
            log.warning(
                "capture_interval >= rescan_interval; light passes will be ineffective",
                capture_interval=self.capture_interval,
                rescan_interval=self.rescan_interval,
            )
        if self.capture_interval and self.cooldown_seconds > self.capture_interval:
            log.warning(
                "cooldown_seconds > capture_interval; light passes will be skipped "
                "by the cooldown floor",
                cooldown_seconds=self.cooldown_seconds,
                capture_interval=self.capture_interval,
            )
        if (
            self.snmp_bulk_retention_days
            and self.snmp_bulk_interval
            and self.snmp_bulk_retention_days * 86400 <= self.snmp_bulk_interval
        ):
            log.warning(
                "snmp_bulk_retention shorter than the bulk poll interval; heavy rows "
                "may be purged before the next bulk poll",
                retention_days=self.snmp_bulk_retention_days,
                bulk_interval=self.snmp_bulk_interval,
            )
        return self

    @property
    def dsn(self) -> str:
        # Build via libpq's own quoting (make_conninfo) so credentials containing
        # a space, single quote, or backslash — e.g. a strong/generated password —
        # don't corrupt the conninfo string. A plain f-string silently broke those.
        from psycopg.conninfo import make_conninfo

        return make_conninfo(
            host=self.postgres_host,
            port=self.postgres_port,
            user=self.postgres_user,
            password=self.postgres_password,
            dbname=self.postgres_db,
        )

    @property
    def exclude_prefixes(self) -> tuple[str, ...]:
        return tuple(s.strip() for s in self.exclude_ifaces.split(",") if s.strip())

    @property
    def exclude_vlan_set(self) -> set[int]:
        return {int(v.strip()) for v in self.exclude_vlans.split(",") if v.strip().isdigit()}

    @property
    def snmp_community_list(self) -> tuple[str, ...]:
        return tuple(s.strip() for s in self.snmp_communities.split(",") if s.strip())

    @property
    def snmp_extra_target_list(self) -> tuple[str, ...]:
        return tuple(s.strip() for s in self.snmp_extra_targets.split(",") if s.strip())

    @property
    def snmp_exclude_list(self) -> tuple[str, ...]:
        return tuple(s.strip() for s in self.snmp_exclude.split(",") if s.strip())


_settings: Settings | None = None


def _build_settings() -> Settings:
    """Construct Settings, clamping any out-of-range env var to its bound.

    The field bounds exist to catch fat-fingered config, but the collector's OWN
    env must never crash-loop the box on a value that was tolerated before a
    bound was added — clamp + warn instead, using each field's declared bound as
    the single source of truth. Dashboard-pushed config is validated separately
    (hard-reject) in checkin._validate_desired_config, so this does not weaken it.
    """
    try:
        return Settings()
    except ValidationError:
        pass  # fall through and clamp the offending value(s)

    overrides: dict[str, Any] = {}
    for name, field in Settings.model_fields.items():
        if field.annotation not in (int, float):
            continue
        ge = le = None
        for meta in field.metadata:
            if getattr(meta, "ge", None) is not None:
                ge = meta.ge
            if getattr(meta, "le", None) is not None:
                le = meta.le
        if ge is None and le is None:
            continue
        key = field.alias or name  # env vars / init kwargs populate by alias
        raw = os.environ.get(key)
        if raw is None:
            continue
        try:
            value = float(raw)
        except ValueError:
            continue  # non-numeric env for a numeric field; let Settings() surface it
        clamped = value
        if ge is not None and clamped < ge:
            clamped = ge
        if le is not None and clamped > le:
            clamped = le
        if clamped != value:
            coerced: Any = int(clamped) if field.annotation is int else clamped
            overrides[key] = coerced
            log.warning(
                "clamped out-of-range setting to its bound",
                setting=key, given=raw, clamped=coerced, minimum=ge, maximum=le,
            )
    return Settings(**overrides)


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = _build_settings()
    return _settings
