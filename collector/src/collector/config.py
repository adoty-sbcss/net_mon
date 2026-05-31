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
    exclude_ifaces: str = Field(
        default="lo,docker0,br-,veth,virbr,tun,tap",
        alias="NETMON_EXCLUDE_IFACES",
    )

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

    # --- Reverse DNS (PTR) enrichment ---
    # After discovery, look up PTR records for devices that still have no
    # hostname, querying the LOCAL site resolver(s) (DHCP-assigned DNS + gateway)
    # rather than only nmap's container resolver — which is often public DNS with
    # no internal records. Fills internal hostnames nmap can't.
    rdns_enabled: bool = Field(default=True, alias="NETMON_RDNS_ENABLED")
    rdns_timeout_sec: int = Field(default=2, alias="NETMON_RDNS_TIMEOUT_SEC")

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
        default="google.com,microsoft.com,cloudflare.com,sbcss.k12.ca.us",
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
    def snmp_community_list(self) -> tuple[str, ...]:
        return tuple(s.strip() for s in self.snmp_communities.split(",") if s.strip())


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
