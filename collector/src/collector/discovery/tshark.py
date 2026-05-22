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
    total_packets: int = 0           # everything tshark saw (post-filter)
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
        dst = (_scalar(eth.get("eth_eth_dst")) or "").lower()

        result.total_packets += 1
        if dst == "ff:ff:ff:ff:ff:ff":
            result.broadcast_packets += 1
        elif _is_multicast(dst):
            result.multicast_packets += 1

        # DHCP: in Wireshark 3.x+ the layer is "dhcp"; older Wireshark 2.x calls
        # it "bootp". Try both. The fields inside follow the same renaming.
        dhcp_body = layers.get("dhcp") or layers.get("bootp")
        if isinstance(dhcp_body, dict):
            evt = _parse_dhcp(dhcp_body, eth)
            if evt:
                result.dhcp.append(evt)

        if "stp" in layers:
            evt = _parse_stp(layers["stp"])
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


# ---------------------------------------------------------------------------
# DHCP parsing
# ---------------------------------------------------------------------------


def _parse_dhcp(body: dict[str, Any], eth: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a DHCP event from a tshark ek-format layer dict.

    tshark's field names have changed over time:
    - Wireshark 2.x: `bootp.option.dhcp`, ek-name `bootp_bootp_option_dhcp`
    - Wireshark 3.0+: `dhcp.option.dhcp`, ek-name `dhcp_dhcp_option_dhcp`
    Some versions also emit the un-doubled `dhcp_option_dhcp`. Try all.
    """
    msg_type = _dhcp_field(
        body,
        "dhcp_dhcp_option_dhcp",
        "dhcp_option_dhcp",
        "bootp_bootp_option_dhcp",
        "bootp_option_dhcp",
        "dhcp_dhcp_option_dhcp_message_type",
    )

    msg_type_map = {
        "1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE",
        "5": "ACK", "6": "NAK", "7": "RELEASE", "8": "INFORM",
    }
    msg_name = msg_type_map.get(str(msg_type)) if msg_type is not None else None
    if msg_name is None and msg_type is not None:
        msg_name = f"TYPE_{msg_type}"
    elif msg_name is None:
        msg_name = "UNKNOWN"

    server_ip = _dhcp_field(
        body,
        "dhcp_dhcp_option_dhcp_server_id",
        "dhcp_option_dhcp_server_id",
        "bootp_bootp_option_dhcp_server_id",
        "bootp_option_dhcp_server_id",
        # Some versions just expose the option as `dhcp.server.id`
        "dhcp_dhcp_server_id",
    )
    client_mac = _dhcp_field(
        body,
        "dhcp_dhcp_hw_mac_addr",
        "dhcp_hw_mac_addr",
        "bootp_bootp_hw_mac_addr",
        "bootp_hw_mac_addr",
    )
    offered = _dhcp_field(
        body,
        "dhcp_dhcp_ip_your",
        "dhcp_ip_your",
        "bootp_bootp_ip_your",
        "bootp_ip_your",
    )
    router = _dhcp_field(
        body,
        "dhcp_dhcp_option_router",
        "dhcp_option_router",
        "bootp_bootp_option_router",
        "bootp_option_router",
    )
    subnet = _dhcp_field(
        body,
        "dhcp_dhcp_option_subnet_mask",
        "dhcp_option_subnet_mask",
        "bootp_bootp_option_subnet_mask",
        "bootp_option_subnet_mask",
    )
    dns = _dhcp_field(
        body,
        "dhcp_dhcp_option_domain_name_server",
        "dhcp_option_domain_name_server",
        "bootp_bootp_option_domain_name_server",
        "bootp_option_domain_name_server",
    )

    server_mac = _scalar(eth.get("eth_eth_src"))

    # OFFER/ACK/NAK come from the server side; for those, server_mac is meaningful.
    is_from_server = msg_name in {"OFFER", "ACK", "NAK"}

    # If we have *nothing* useful, treat as a bad parse and skip.
    if (msg_name == "UNKNOWN"
            and not any([server_ip, client_mac, offered, router, subnet, dns])):
        return None

    return {
        "message_type": msg_name,
        "server_ip": server_ip if is_from_server else None,
        "server_mac": server_mac if is_from_server else None,
        "client_mac": client_mac,
        "offered_ip": offered if msg_name in {"OFFER", "ACK"} else None,
        "subnet_mask": subnet,
        "router": router,
        "dns_servers": dns,
    }


def _dhcp_field(body: dict[str, Any], *candidates: str) -> Any:
    """Return the first non-None scalar value among the candidate field names."""
    for key in candidates:
        if key in body:
            v = _scalar(body[key])
            if v not in (None, ""):
                return v
    return None


# ---------------------------------------------------------------------------
# STP parsing
# ---------------------------------------------------------------------------


def _parse_stp(body: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None

    # BPDU type byte. Comes back from tshark as decimal "0", "2", "128" or as
    # hex string "0x00", "0x02", "0x80" depending on version. Normalize.
    bpdu_type_int = _parse_int_loose(_scalar(body.get("stp_stp_type")))
    bpdu_type_map = {0x00: "Configuration", 0x02: "RST/MST", 0x80: "TCN"}
    if bpdu_type_int is not None:
        bpdu_type = bpdu_type_map.get(bpdu_type_int, f"unknown_0x{bpdu_type_int:02x}")
    else:
        bpdu_type = "STP"

    # Root bridge ID: priority + extension + MAC. Tshark exposes them split.
    # Build a canonical string like "32768/000a/34c5.1555.4f80".
    root_prio = _scalar(body.get("stp_stp_root_prio")) or _scalar(body.get("stp_stp_root_priority"))
    root_ext  = _scalar(body.get("stp_stp_root_ext"))
    root_hw   = _scalar(body.get("stp_stp_root_hw")) or _scalar(body.get("stp_stp_root"))
    root_bridge_id = _format_bridge_id(root_prio, root_ext, root_hw)

    bridge_prio = _scalar(body.get("stp_stp_bridge_prio")) or _scalar(body.get("stp_stp_bridge_priority"))
    bridge_ext  = _scalar(body.get("stp_stp_bridge_ext"))
    bridge_hw   = _scalar(body.get("stp_stp_bridge_hw")) or _scalar(body.get("stp_stp_bridge"))
    bridge_id = _format_bridge_id(bridge_prio, bridge_ext, bridge_hw)

    port_id = _scalar(body.get("stp_stp_port"))
    cost = _parse_int_loose(_scalar(body.get("stp_stp_root_pathcost")) or _scalar(body.get("stp_stp_root_path_cost")))

    flags_raw = _scalar(body.get("stp_stp_flags"))
    tc = False
    if flags_raw is not None:
        flags_int = _parse_int_loose(flags_raw)
        if flags_int is not None:
            tc = bool(flags_int & 0x01)

    return {
        "bpdu_type": bpdu_type,
        "root_bridge_id": root_bridge_id,
        "bridge_id": bridge_id,
        "port_id": port_id,
        "root_path_cost": cost,
        "topology_change": tc,
    }


def _format_bridge_id(prio: Any, ext: Any, hw: Any) -> str | None:
    """Produce 'prio/ext/hw' (or 'prio/hw' if ext absent). Returns None if no hw."""
    if not hw:
        return None
    parts: list[str] = []
    if prio is not None:
        parts.append(str(prio))
    if ext is not None:
        parts.append(str(ext))
    parts.append(str(hw))
    return "/".join(parts)


def _parse_int_loose(v: Any) -> int | None:
    """Parse 'N', '0xNN', or int — return int or None."""
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s, 0)  # base 0 autodetects 0x prefix
    except ValueError:
        return None


def _scalar(v: Any) -> Any:
    """ek format wraps scalars as single-item lists; unwrap."""
    if isinstance(v, list):
        return v[0] if v else None
    return v
