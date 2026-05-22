from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass
class CaptureResult:
    started_at: datetime
    completed_at: datetime
    broadcast_packets: int = 0
    multicast_packets: int = 0
    dhcp: list[dict[str, Any]] = field(default_factory=list)
    stp: list[dict[str, Any]] = field(default_factory=list)
    raw: list[dict[str, Any]] = field(default_factory=list)


# Display filter for the relevant control-plane traffic. We capture everything
# matching and let post-processing pull out DHCP/STP/etc.
CAPTURE_FILTER = (
    "stp or cdp or lldp or bootp or arp or "
    "(eth.dst == ff:ff:ff:ff:ff:ff) or (eth.dst[0] & 0x01 == 0x01)"
)


def run_capture(*, interface: str, seconds: int) -> CaptureResult:
    """Run tshark for `seconds` and parse out the structured events we care about."""
    started_at = datetime.now(timezone.utc)
    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{seconds}",
        "-Y", CAPTURE_FILTER,
        "-T", "ek",   # elastic-stack JSON (one JSON object per line)
        "-n",         # no name resolution
        "-l",         # line-buffered
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=seconds + 30,
            check=False,
        )
    except FileNotFoundError:
        log.warning("tshark not found")
        return CaptureResult(started_at=started_at, completed_at=datetime.now(timezone.utc))
    except subprocess.TimeoutExpired:
        log.warning("tshark hard-timeout", seconds=seconds)
        return CaptureResult(started_at=started_at, completed_at=datetime.now(timezone.utc))

    if proc.returncode not in (0, 1):  # 1 means it captured nothing matching
        log.warning("tshark failed", returncode=proc.returncode, stderr=proc.stderr[:500])

    result = CaptureResult(started_at=started_at, completed_at=datetime.now(timezone.utc))
    for line in proc.stdout.splitlines():
        if not line.strip() or line.startswith('{"index"'):
            continue
        try:
            packet = json.loads(line)
        except json.JSONDecodeError:
            continue
        layers = (packet.get("layers") or {})
        eth = layers.get("eth", {})
        dst = (eth.get("eth_eth_dst") or "").lower()

        if dst == "ff:ff:ff:ff:ff:ff":
            result.broadcast_packets += 1
        elif _is_multicast(dst):
            result.multicast_packets += 1

        if "bootp" in layers or "dhcp" in layers:
            evt = _parse_dhcp(layers)
            if evt:
                result.dhcp.append(evt)
        if "stp" in layers:
            evt = _parse_stp(layers)
            if evt:
                result.stp.append(evt)
        result.raw.append({
            "ts": packet.get("timestamp"),
            "summary": {k: v for k, v in layers.items() if k in {"stp", "lldp", "cdp", "dhcp", "bootp", "arp"}},
        })
    return result


def _is_multicast(mac: str) -> bool:
    if not mac or mac == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x01)


def _parse_dhcp(layers: dict[str, Any]) -> dict[str, Any] | None:
    body = layers.get("bootp") or layers.get("dhcp") or {}
    if not isinstance(body, dict):
        return None
    msg_type = (
        _scalar(body.get("bootp_bootp_option_dhcp"))
        or _scalar(body.get("dhcp_option_dhcp"))
    )
    msg_type_map = {
        "1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE",
        "5": "ACK", "6": "NAK", "7": "RELEASE", "8": "INFORM",
    }
    msg_name = msg_type_map.get(str(msg_type), str(msg_type) if msg_type else "UNKNOWN")
    server_ip = _scalar(body.get("bootp_bootp_option_dhcp_server_id") or body.get("dhcp_option_dhcp_server_id"))
    client_mac = _scalar(body.get("bootp_bootp_hw_mac_addr") or body.get("dhcp_hw_mac_addr"))
    offered = _scalar(body.get("bootp_bootp_ip_your") or body.get("dhcp_ip_your"))
    router = _scalar(body.get("bootp_bootp_option_router") or body.get("dhcp_option_router"))
    subnet = _scalar(body.get("bootp_bootp_option_subnet_mask") or body.get("dhcp_option_subnet_mask"))
    dns = _scalar(body.get("bootp_bootp_option_domain_name_server") or body.get("dhcp_option_domain_name_server"))
    eth = layers.get("eth", {})
    server_mac = _scalar(eth.get("eth_eth_src"))
    return {
        "message_type": msg_name,
        "server_ip": server_ip if msg_name in {"OFFER", "ACK", "NAK"} else None,
        "server_mac": server_mac if msg_name in {"OFFER", "ACK", "NAK"} else None,
        "client_mac": client_mac,
        "offered_ip": offered if msg_name in {"OFFER", "ACK"} else None,
        "subnet_mask": subnet,
        "router": router,
        "dns_servers": dns,
    }


def _parse_stp(layers: dict[str, Any]) -> dict[str, Any] | None:
    body = layers.get("stp") or {}
    if not isinstance(body, dict):
        return None
    bpdu_type_raw = _scalar(body.get("stp_stp_type"))
    bpdu_type_map = {"0": "Configuration", "128": "TCN", "2": "RST/MST"}
    bpdu_type = bpdu_type_map.get(str(bpdu_type_raw), str(bpdu_type_raw) if bpdu_type_raw else "STP")
    flags = _scalar(body.get("stp_stp_flags"))
    tc = False
    if flags is not None:
        try:
            tc = bool(int(flags, 16) & 0x01) if isinstance(flags, str) and flags.startswith("0x") else bool(int(flags) & 0x01)
        except ValueError:
            tc = False
    return {
        "bpdu_type": bpdu_type,
        "root_bridge_id": _scalar(body.get("stp_stp_root")),
        "bridge_id": _scalar(body.get("stp_stp_bridge")),
        "port_id": _scalar(body.get("stp_stp_port")),
        "root_path_cost": _safe_int(_scalar(body.get("stp_stp_root_pathcost"))),
        "topology_change": tc,
    }


def _scalar(v: Any) -> Any:
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _safe_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None
