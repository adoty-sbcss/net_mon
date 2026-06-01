"""Outbound dashboard check-in (control plane).

The box NEVER accepts inbound connections. On a timer it POSTs to the dashboard
with its enrollment token, reports its agent + applied-config version, then:
  - applies any newer desired config (SNMP strings, scan interval) by rewriting
    /etc/netmon/netmon.env — which takes effect on the next collector restart;
  - runs any queued commands (run-scan / upload-now / config-backup) and reports
    each result back.

Returns exit code 10 when config changed so the host wrapper can restart the
collector container (the watchdog auto-rolls-back a bad restart). HTTP uses the
stdlib only — no new dependency.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

import structlog

from . import __version__
from . import config_backup as config_backup_mod
from . import uploader as uploader_mod
from .config import get_settings
from .db import list_scan_runs, wait_for_db
from .logging_setup import audit

log = structlog.get_logger(__name__)

ENV_FILE = Path("/etc/netmon/netmon.env")
APPLIED_VERSION_FILE = Path("/var/lib/netmon/applied-config-version")
TOKEN_FILE = Path("/var/lib/netmon/enroll-token")
EXIT_CONFIG_CHANGED = 10


def _post(url: str, token: str | None, body: dict) -> dict | None:
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        log.warning("checkin http error", status=exc.code, url=url)
    except Exception as exc:  # noqa: BLE001 — network is best-effort
        log.warning("checkin request failed", error=str(exc), url=url)
    return None


def _read_applied_version() -> int | None:
    try:
        return int(APPLIED_VERSION_FILE.read_text().strip())
    except Exception:
        return None


def _write_applied_version(v: int) -> None:
    try:
        APPLIED_VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        APPLIED_VERSION_FILE.write_text(str(v))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist applied config version", error=str(exc))


def _update_env_file(path: Path, mapping: dict[str, str]) -> None:
    """Idempotently set KEY=VALUE lines in an env file, preserving the rest."""
    lines = path.read_text().splitlines() if path.exists() else []
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        m = re.match(r"\s*([A-Z0-9_]+)\s*=", line)
        if m and m.group(1) in mapping:
            out.append(f"{m.group(1)}={mapping[m.group(1)]}")
            seen.add(m.group(1))
        else:
            out.append(line)
    for k, v in mapping.items():
        if k not in seen:
            out.append(f"{k}={v}")
    path.write_text("\n".join(out) + "\n")


def _apply_config(data: dict) -> None:
    mapping: dict[str, str] = {}
    if "snmp_communities" in data:
        mapping["NETMON_SNMP_COMMUNITIES"] = str(data.get("snmp_communities") or "")
    if "snmp_enabled" in data:
        mapping["NETMON_SNMP_ENABLED"] = "true" if data.get("snmp_enabled") else "false"
    if data.get("rescan_interval"):
        mapping["NETMON_RESCAN_INTERVAL"] = str(int(data["rescan_interval"]))
    # SFTP upload destination (pushed from the dashboard).
    if "sftp_enabled" in data:
        mapping["NETMON_SFTP_ENABLED"] = "true" if data.get("sftp_enabled") else "false"
    if "sftp_host" in data:
        mapping["NETMON_SFTP_HOST"] = str(data.get("sftp_host") or "")
    if data.get("sftp_port"):
        mapping["NETMON_SFTP_PORT"] = str(int(data["sftp_port"]))
    if "sftp_user" in data:
        mapping["NETMON_SFTP_USER"] = str(data.get("sftp_user") or "")
    if data.get("sftp_password"):  # only overwrite when a value is provided
        mapping["NETMON_SFTP_PASSWORD"] = str(data["sftp_password"])
    if "sftp_remote_path" in data:
        mapping["NETMON_SFTP_REMOTE_PATH"] = str(data.get("sftp_remote_path") or "/")
    if mapping:
        _update_env_file(ENV_FILE, mapping)
        log.info("applied desired config", keys=list(mapping))


def _local_net() -> tuple[str | None, str | None, str | None]:
    """Best-effort (primary_ip, interface, cidr) for the box to report at check-in."""
    try:
        from .discovery import interfaces as iface_mod

        name = iface_mod.primary_interface()
        if not name:
            return (None, None, None)
        st = iface_mod.get_one(name)
        addrs = list(getattr(st, "ipv4_addrs", None) or [])
        cidr = addrs[0] if addrs else None
        ip = cidr.split("/")[0] if cidr else None
        return (ip, name, cidr)
    except Exception:
        return (None, None, None)


def _collect_logs(lines: int = 250) -> tuple[str, dict]:
    """Return the tail of the collector + audit logs for the dashboard to show."""
    from .logging_setup import LOG_DIR

    out: dict[str, str] = {}
    for fname in ("collector.log", "audit.log"):
        p = LOG_DIR / fname
        try:
            tail = p.read_text(errors="replace").splitlines()[-lines:]
            text = "\n".join(tail)
            out[fname] = text[-20000:]  # cap size stored in the result
        except FileNotFoundError:
            out[fname] = "(no file)"
        except Exception as exc:  # noqa: BLE001
            out[fname] = f"(could not read: {exc})"
    return "done", out


def _run_command(command: str) -> tuple[str, dict]:
    """Execute a queued command. Returns (status, result)."""
    try:
        if command == "collect-logs":
            return _collect_logs()
        if command == "run-scan":
            from .discovery import interfaces as iface_mod
            from .scan import run_scan

            iface = iface_mod.primary_interface()
            if not iface:
                return "failed", {"error": "no primary interface"}
            scan_id = run_scan(
                interface=iface, trigger_reason="dashboard:run-scan", force=True, is_primary=True
            )
            return ("done", {"scan_id": scan_id}) if scan_id else ("failed", {"error": "scan did not run"})

        if command == "upload-now":
            from datetime import timedelta

            recent = list_scan_runs(limit=10)
            rc = next((s for s in recent if s.get("completed_at")), None)
            if rc is None:
                return "failed", {"error": "no completed scans"}
            completed_at = rc["completed_at"]
            if completed_at.tzinfo is None:
                completed_at = completed_at.astimezone()
            window_end = completed_at.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            res = uploader_mod.build_and_upload_hour(window_end)
            ok = res.get("status") in ("uploaded", "saved_only", "skipped")
            return ("done" if ok else "failed", {"status": res.get("status")})

        if command == "config-backup":
            remote = config_backup_mod.upload_backup()
            return "done", {"remote": str(remote)}

        return "failed", {"error": f"unknown command {command!r}"}
    except Exception as exc:  # noqa: BLE001
        log.warning("command failed", command=command, error=str(exc))
        return "failed", {"error": str(exc)}


def _store_token(token: str) -> None:
    try:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(token)
        TOKEN_FILE.chmod(0o600)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not store enroll token", error=str(exc))


def _current_token(settings) -> str:
    """Token from env (manual enroll) else the auto-enroll state file."""
    if settings.enroll_token:
        return settings.enroll_token
    try:
        return TOKEN_FILE.read_text().strip()
    except Exception:
        return ""


def _auto_enroll(settings, url: str) -> str:
    """Self-register with the shared bootstrap key; return the issued token or ''."""
    if not settings.bootstrap_key:
        return ""
    d, s, dev = settings.district_slug, settings.school_slug, settings.device_slug
    if not (d and s and dev):
        log.warning("auto-enroll skipped: identity slugs (district/school/device) not set")
        return ""
    resp = _post(
        f"{url}/api/sensor/enroll",
        None,
        {"bootstrapKey": settings.bootstrap_key, "district": d, "school": s, "device": dev},
    )
    token = (resp or {}).get("token") if isinstance(resp, dict) else None
    if not token:
        log.warning("auto-enroll failed (dashboard refused the bootstrap key or was unreachable)")
        return ""
    _store_token(token)
    log.info("auto-enrolled with dashboard; per-sensor token stored")
    audit("dashboard_auto_enrolled", district=d, school=s, device=dev)
    return token


def run_checkin() -> int:
    settings = get_settings()
    url = (settings.dashboard_url or "").rstrip("/")
    if not url:
        log.info("checkin skipped: NETMON_DASHBOARD_URL not set")
        return 0

    token = _current_token(settings)
    if not token:
        token = _auto_enroll(settings, url)
        if not token:
            log.info("checkin skipped: not enrolled (set NETMON_ENROLL_TOKEN, or "
                     "NETMON_BOOTSTRAP_KEY + identity slugs for auto-enroll)")
            return 0

    wait_for_db()
    applied = _read_applied_version()
    local_ip, iface, cidr = _local_net()
    resp = _post(
        f"{url}/api/sensor/checkin",
        token,
        {
            "agentVersion": __version__,
            "configVersion": applied,
            "localIp": local_ip,
            "interface": iface,
            "interfaceCidr": cidr,
            # Actual config the box is running, so the dashboard can show ground
            # truth (not just what it pushed). The SFTP password is NEVER reported.
            "currentConfig": {
                "snmp_enabled": settings.snmp_enabled,
                "snmp_communities": settings.snmp_communities,
                "sftp_enabled": settings.sftp_enabled,
                "sftp_host": settings.sftp_host,
                "sftp_port": settings.sftp_port,
                "sftp_user": settings.sftp_user,
            },
        },
    )
    if resp is None:
        return 1

    config_changed = False
    cfg = resp.get("config")
    if isinstance(cfg, dict):
        version = cfg.get("version")
        if isinstance(version, int) and version != applied:
            _apply_config(cfg.get("data") or {})
            _write_applied_version(version)
            applied = version
            config_changed = True
            audit("dashboard_config_applied", version=version)

    for cmd in resp.get("commands") or []:
        cid = cmd.get("id")
        name = cmd.get("command")
        log.info("running queued command", id=cid, command=name)
        status, result = _run_command(str(name))
        audit("dashboard_command_ran", id=cid, command=name, status=status)
        _post(
            f"{url}/api/sensor/result",
            token,
            {"commandId": cid, "status": status, "result": result, "configVersion": applied},
        )

    return EXIT_CONFIG_CHANGED if config_changed else 0
