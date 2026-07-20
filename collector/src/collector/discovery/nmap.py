from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def host_discovery(cidr: str, timeout: int = 120) -> list[dict[str, Any]]:
    """Ping/ARP sweep with no port scanning. Returns up hosts only."""
    # DNS is on by default — gives us hostnames where reverse PTR records
    # exist (gateways, switches, servers). Set NETMON_NMAP_NO_DNS=true to
    # disable when running on an isolated network with no resolver.
    import os as _os
    no_dns = _os.environ.get("NETMON_NMAP_NO_DNS", "").lower() in ("1", "true", "yes")
    cmd = [
        "nmap",
        "-sn",            # no port scan
        "-PE",            # ICMP echo
        "-PR",            # ARP ping (no-op for off-LAN)
        "-oX", "-",       # XML to stdout
    ]
    if no_dns:
        cmd.append("-n")
    else:
        cmd += ["--system-dns"]   # use container's resolver (inherits from host)
    cmd.append(cidr)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise RuntimeError("nmap executable not found") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nmap timed out scanning {cidr}") from None
    if out.returncode != 0:
        raise RuntimeError(
            f"nmap failed scanning {cidr} (rc={out.returncode}): "
            f"{(out.stderr or '').strip()[:500]}"
        )
    return _parse_xml(out.stdout)


def _parse_xml(xml_text: str) -> list[dict[str, Any]]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"nmap returned invalid XML: {exc}") from exc
    results: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = None
        mac = None
        vendor = None
        for addr in host.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4":
                ip = addr.get("addr")
            elif kind == "mac":
                mac = (addr.get("addr") or "").lower() or None
                vendor = addr.get("vendor")
        hostname = None
        names = host.find("hostnames")
        if names is not None:
            first = names.find("hostname")
            if first is not None:
                hostname = first.get("name")
        if ip:
            results.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
            })
    return results
