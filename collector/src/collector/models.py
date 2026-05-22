from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class InterfaceState:
    name: str
    is_up: bool
    has_carrier: bool
    mac: str | None
    ipv4_addrs: list[str] = field(default_factory=list)  # CIDR-form, e.g. "10.0.0.5/24"
    gateway_ip: str | None = None
    gateway_mac: str | None = None

    @property
    def primary_cidr(self) -> str | None:
        return self.ipv4_addrs[0] if self.ipv4_addrs else None

    @property
    def has_usable_ip(self) -> bool:
        return self.is_up and self.has_carrier and bool(self.ipv4_addrs)


@dataclass
class ScanContext:
    """Mutable state collected during a single scan run."""
    scan_id: int
    interface: str
    interface_cidr: str | None
    gateway_ip: str | None
    gateway_mac: str | None
    network_id: str | None
    started_monotonic: float
    raw_outputs: dict[str, Any] = field(default_factory=dict)
