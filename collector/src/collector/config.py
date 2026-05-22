from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=None, extra="ignore")

    postgres_host: str = Field(default="127.0.0.1", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="appmon", alias="POSTGRES_USER")
    postgres_password: str = Field(default="appmon", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="appmon", alias="POSTGRES_DB")

    mode: Literal["field", "monitor"] = Field(default="field", alias="APPMON_MODE")
    capture_seconds: int = Field(default=60, alias="APPMON_CAPTURE_SECONDS")
    poll_interval: int = Field(default=30, alias="APPMON_POLL_INTERVAL")
    cooldown_seconds: int = Field(default=300, alias="APPMON_COOLDOWN_SECONDS")
    exclude_ifaces: str = Field(
        default="lo,docker0,br-,veth,virbr,tun,tap",
        alias="APPMON_EXCLUDE_IFACES",
    )

    snmp_enabled: bool = Field(default=False, alias="APPMON_SNMP_ENABLED")
    snmp_config: Path = Field(default=Path("/etc/appmon/snmp.yaml"), alias="APPMON_SNMP_CONFIG")

    sftp_enabled: bool = Field(default=False, alias="APPMON_SFTP_ENABLED")
    sftp_host: str = Field(default="", alias="APPMON_SFTP_HOST")
    sftp_port: int = Field(default=22, alias="APPMON_SFTP_PORT")
    sftp_user: str = Field(default="", alias="APPMON_SFTP_USER")
    sftp_password: str = Field(default="", alias="APPMON_SFTP_PASSWORD")
    sftp_remote_path: str = Field(default="/", alias="APPMON_SFTP_REMOTE_PATH")
    device_name: str = Field(default="", alias="APPMON_DEVICE_NAME")

    bundle_dir: Path = Field(default=Path("/var/lib/appmon/bundles"), alias="APPMON_BUNDLE_DIR")

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


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
