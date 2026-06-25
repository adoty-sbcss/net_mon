from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=None, extra="ignore")

    postgres_host: str = Field(default="127.0.0.1", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="netmon", alias="POSTGRES_USER")
    postgres_password: str = Field(default="netmon", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="netmon", alias="POSTGRES_DB")

    capture_seconds: int = Field(default=60, alias="NETMON_CAPTURE_SECONDS")
    poll_interval: int = Field(default=30, alias="NETMON_POLL_INTERVAL")
    # The poller re-scans any active interface whose network hasn't been
    # scanned within this window. Covers both link-up (no prior scan) and
    # periodic re-scan of a stable network. Replaces the old field/monitor mode.
    rescan_interval: int = Field(default=3600, alias="NETMON_RESCAN_INTERVAL")
    # Anti-flap floor only: never scan the same network twice within this many
    # seconds, even if something asks. Much smaller than rescan_interval.
    cooldown_seconds: int = Field(default=300, alias="NETMON_COOLDOWN_SECONDS")
    # Local Postgres retention: delete scan_runs (+ cascaded per-scan tables)
    # older than this many days from the COLLECTOR's OWN db. Bundles upload hourly,
    # so the box only needs recent scans for bundling + the crawl-gate lookups;
    # without this the local db grows unbounded. The durable inventory survives
    # (its scan FK is SET NULL, not CASCADE). 0 disables.
    local_retention_days: int = Field(default=14, alias="NETMON_LOCAL_RETENTION_DAYS")
    exclude_ifaces: str = Field(
        default="lo,docker0,br-,veth,virbr,tun,tap",
        alias="NETMON_EXCLUDE_IFACES",
    )
    # VLAN IDs the poller must NOT auto-scan even if a sub-interface exists
    # (comma-separated). Lets an operator drop noisy/irrelevant VLANs from a
    # monitored trunk without removing the sub-interface. A manual `scan` is
    # explicit and ignores this.
    exclude_vlans: str = Field(default="", alias="NETMON_EXCLUDE_VLANS")

    snmp_enabled: bool = Field(default=False, alias="NETMON_SNMP_ENABLED")
    snmp_config: Path = Field(default=Path("/etc/netmon/snmp.yaml"), alias="NETMON_SNMP_CONFIG")
    # Comma-separated list of v2c communities to try, in order. The first one
    # to get a response for a given device gets cached in snmp_credentials.
    snmp_communities: str = Field(default="", alias="NETMON_SNMP_COMMUNITIES")
    # By default SNMP only polls likely network gear (gateway + LLDP mgmt IPs
    # + network-vendor OUIs) to keep scans fast. Turn this on to also poll
    # every discovered host so printers / PCs / IoT get classified via SNMP
    # (Printer-MIB, Host-Resources, etc.). Costs a community trial per host.
    snmp_poll_all_hosts: bool = Field(default=False, alias="NETMON_SNMP_POLL_ALL_HOSTS")
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

    # SNMP topology crawl (Path B). Off by default — turn on once SNMP is
    # working against your switches and you want fabric topology in bundles.
    snmp_topology_enabled: bool = Field(default=False, alias="NETMON_SNMP_TOPOLOGY_ENABLED")
    # Max hops from a seed device. 5 covers most school-district fabrics
    # without going wild on internet-facing gear.
    snmp_topology_max_depth: int = Field(default=5, alias="NETMON_SNMP_TOPOLOGY_MAX_DEPTH")
    # Wall-clock cap per crawl so it can't blow scan duration on a large
    # fabric. Stops cleanly when the budget is reached. Because the crawl is
    # interval-gated (see below) it runs at most ~weekly by default, so we can
    # afford a generous budget to "really crawl" without slowing hourly scans.
    snmp_topology_time_budget: int = Field(default=300, alias="NETMON_SNMP_TOPOLOGY_TIME_BUDGET")
    # How often to actually run the crawl, per monitored network. Topology
    # changes slowly (it's physical cabling + switch config), so rediscovering
    # it every hourly scan is wasted compute. Default 7 days; the crawl runs
    # only if the last one for this network was longer ago than this. A manual
    # `./netmon scan` (force=True) always crawls, giving an on-demand override.
    # Set to 0 to crawl on every scan (the old behavior).
    snmp_topology_interval: int = Field(default=7 * 24 * 3600,
                                        alias="NETMON_SNMP_TOPOLOGY_INTERVAL")
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
    snmp_topology_max_nodes: int = Field(default=600, alias="NETMON_SNMP_TOPOLOGY_MAX_NODES")
    snmp_topology_fanout_cap: int = Field(default=40, alias="NETMON_SNMP_TOPOLOGY_FANOUT_CAP")
    # How often to walk the HEAVY bulk SNMP OIDs (ifTable, the bridge FDB tables,
    # ipNetToMediaTable). These are large — one row per interface / learned MAC /
    # ARP entry — and change slowly, so walking them every hourly scan wastes
    # compute and bloats the db + bundle. Walked at most once per this interval per
    # network (default daily); the small identity/STP/port OIDs are still polled
    # every scan. A manual `./netmon scan` (force=True) always walks them. 0 =
    # every scan (the old behavior).
    snmp_bulk_interval: int = Field(default=24 * 3600, alias="NETMON_SNMP_BULK_INTERVAL")

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
    rdns_timeout_sec: int = Field(default=2, alias="NETMON_RDNS_TIMEOUT_SEC")

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
    mdns_seconds: float = Field(default=3.0, alias="NETMON_MDNS_SECONDS")
    ssdp_seconds: float = Field(default=3.0, alias="NETMON_SSDP_SECONDS")

    # --- Network-device reachability (ping + traceroute + SNMP-response) ---
    # Each scan, probe the infrastructure candidate set (gateway + LLDP mgmt IPs
    # + network-vendor OUIs) so the dashboard can show which switches are out
    # there and which answer SNMP vs. only ping. Cheap; traceroute is skipped
    # gracefully if the binary is missing.
    reachability_enabled: bool = Field(default=True, alias="NETMON_REACHABILITY_ENABLED")
    reachability_traceroute: bool = Field(default=True, alias="NETMON_REACHABILITY_TRACEROUTE")
    reachability_max_hops: int = Field(default=10, alias="NETMON_REACHABILITY_MAX_HOPS")

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
    dns_timeout_sec: int = Field(default=2, alias="NETMON_DNS_TIMEOUT_SEC")
    # Send a unique nonexistent name per scan to catch resolvers that rewrite
    # NXDOMAIN to an ad/filter page.
    dns_include_nxdomain_probe: bool = Field(
        default=True,
        alias="NETMON_DNS_INCLUDE_NXDOMAIN_PROBE",
    )

    sftp_enabled: bool = Field(default=False, alias="NETMON_SFTP_ENABLED")
    sftp_host: str = Field(default="", alias="NETMON_SFTP_HOST")
    sftp_port: int = Field(default=22, alias="NETMON_SFTP_PORT")
    sftp_user: str = Field(default="", alias="NETMON_SFTP_USER")
    sftp_password: str = Field(default="", alias="NETMON_SFTP_PASSWORD")
    sftp_remote_path: str = Field(default="/", alias="NETMON_SFTP_REMOTE_PATH")
    device_name: str = Field(default="", alias="NETMON_DEVICE_NAME")

    # iperf3 throughput testing (#10). Pushed from the dashboard via desired_config.
    iperf_enabled: bool = Field(default=False, alias="NETMON_IPERF_ENABLED")
    iperf_server: str = Field(default="", alias="NETMON_IPERF_SERVER")
    iperf_port: int = Field(default=5201, alias="NETMON_IPERF_PORT")
    iperf_schedule_sec: int = Field(default=3600, alias="NETMON_IPERF_SCHEDULE_SEC")
    iperf_duration: int = Field(default=10, alias="NETMON_IPERF_DURATION")
    iperf_direction: str = Field(default="down", alias="NETMON_IPERF_DIRECTION")
    iperf_protocol: str = Field(default="tcp", alias="NETMON_IPERF_PROTOCOL")
    # Timezone the multi-schedule cron times are evaluated in (IANA name). The box
    # OS clock may be UTC, but a schedule says "5am Pacific" — so we evaluate in
    # this zone via zoneinfo, falling back to box-local if it's unknown. The
    # per-schedule list itself rides a JSON file (see checkin.IPERF_SCHEDULES_FILE),
    # not an env var, since its quotes/commas don't survive EnvironmentFile parsing.
    iperf_timezone: str = Field(default="America/Los_Angeles", alias="NETMON_IPERF_TIMEZONE")

    # Public internet speed test (PERF-2). Pushed from the dashboard via desired_config.
    speedtest_enabled: bool = Field(default=False, alias="NETMON_SPEEDTEST_ENABLED")
    # Provider — Cloudflare only (Ookla removed: unreliable on filtered school
    # networks). Kept as a field for forward-compat; values are normalized to
    # "cloudflare" by the runner.
    speedtest_providers: str = Field(default="cloudflare", alias="NETMON_SPEEDTEST_PROVIDERS")
    # Default 6h — speed tests consume real bandwidth, so less frequent than iperf.
    speedtest_schedule_sec: int = Field(default=6 * 3600, alias="NETMON_SPEEDTEST_SCHEDULE_SEC")

    # Latency / jitter / loss probes (PERF-4). Cheap pings each check-in when on.
    latency_enabled: bool = Field(default=False, alias="NETMON_LATENCY_ENABLED")
    # CSV of internet targets to ping; gateway + DNS resolver are added automatically.
    latency_targets: str = Field(default="1.1.1.1,8.8.8.8", alias="NETMON_LATENCY_TARGETS")

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

    @property
    def dsn(self) -> str:
        return (
            f"host={self.postgres_host} port={self.postgres_port} "
            f"user={self.postgres_user} password={self.postgres_password} "
            f"dbname={self.postgres_db}"
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


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
