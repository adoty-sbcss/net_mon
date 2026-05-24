from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=None, extra="ignore")

    postgres_host: str = Field(default="127.0.0.1", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="netmon", alias="POSTGRES_USER")
    postgres_password: str = Field(default="netmon", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="netmon", alias="POSTGRES_DB")

    mode: Literal["field", "monitor"] = Field(default="field", alias="NETMON_MODE")
    capture_seconds: int = Field(default=60, alias="NETMON_CAPTURE_SECONDS")
    poll_interval: int = Field(default=30, alias="NETMON_POLL_INTERVAL")
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
