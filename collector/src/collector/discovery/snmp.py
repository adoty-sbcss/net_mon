from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import structlog
import yaml

from ..config import get_settings

log = structlog.get_logger(__name__)


def _load_config() -> dict[str, Any]:
    settings = get_settings()
    path = Path(settings.snmp_config)
    if not path.exists():
        log.info("snmp config not found, skipping", path=str(path))
        return {}
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        log.warning("snmp config parse failed", error=str(exc))
        return {}


def _community_for(ip: str, networks: list[dict[str, Any]]) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net["cidr"], strict=False):
                return net.get("community")
        except (KeyError, ValueError):
            continue
    return None


def poll(candidate_ips: list[str]) -> list[dict[str, Any]]:
    cfg = _load_config()
    if not cfg:
        return []

    networks = cfg.get("networks") or []
    explicit_targets = cfg.get("targets") or []
    oids = cfg.get("oids") or _default_oids()

    targets: list[tuple[str, str, str]] = []  # (ip, community, version)
    for t in explicit_targets:
        ip = t.get("ip")
        if ip:
            targets.append((ip, t.get("community", "public"), str(t.get("version", "2c"))))
    if not explicit_targets:
        for ip in candidate_ips:
            community = _community_for(ip, networks)
            if community:
                targets.append((ip, community, "2c"))

    if not targets:
        return []

    # pysnmp import is deferred so containers without snmp libs still start.
    try:
        from pysnmp.hlapi import (
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, getCmd, nextCmd,
        )
    except Exception as exc:
        log.warning("pysnmp unavailable, skipping SNMP", error=str(exc))
        return []

    results: list[dict[str, Any]] = []
    engine = SnmpEngine()

    for ip, community, _version in targets:
        for entry in oids:
            name = entry.get("name") or entry["oid"]
            oid = entry["oid"]
            walk = bool(entry.get("walk"))
            try:
                if walk:
                    iterator = nextCmd(
                        engine,
                        CommunityData(community, mpModel=1),  # 2c
                        UdpTransportTarget((ip, 161), timeout=2, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False,
                    )
                else:
                    iterator = getCmd(
                        engine,
                        CommunityData(community, mpModel=1),
                        UdpTransportTarget((ip, 161), timeout=2, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                    )
                for err_indication, err_status, _err_idx, varbinds in iterator:
                    if err_indication or err_status:
                        log.debug("snmp error", ip=ip, oid=name,
                                  indication=str(err_indication),
                                  status=str(err_status))
                        break
                    for vb in varbinds:
                        results.append({
                            "device_ip": ip,
                            "oid": str(vb[0]),
                            "oid_name": name,
                            "value": str(vb[1]),
                        })
            except Exception as exc:
                log.debug("snmp walk exception", ip=ip, oid=name, error=str(exc))
                continue
    log.info("snmp poll complete", targets=len(targets), rows=len(results))
    return results


def _default_oids() -> list[dict[str, Any]]:
    return [
        {"name": "sysDescr", "oid": "1.3.6.1.2.1.1.1.0"},
        {"name": "sysName", "oid": "1.3.6.1.2.1.1.5.0"},
        {"name": "ifTable", "oid": "1.3.6.1.2.1.2.2", "walk": True},
        {"name": "ipNetToMediaTable", "oid": "1.3.6.1.2.1.4.22", "walk": True},
    ]
