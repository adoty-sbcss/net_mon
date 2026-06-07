"""Outbound dashboard check-in (control plane).

The box NEVER accepts inbound connections. On a timer it POSTs to the dashboard
with its enrollment token, reports its agent + applied-config version + self-health
metrics (CPU/RAM/disk/OS/uptime), then:
  - applies any newer desired config (SNMP strings, scan interval) by rewriting
    /etc/netmon/netmon.env — which takes effect on the next collector restart;
  - runs any queued commands (run-scan / upload-now / config-backup / update)
    and reports each result back.

Exit codes the host wrapper (netmon-checkin.sh) acts on:
  10 — config changed: recreate the collector so it loads the new env.
  11 — a dashboard "update" command was queued: the agent can't rebuild itself
       (it runs inside the container being replaced), so the host runs the code
       update afterwards. 11 also implies the config-recreate of 10, so a config
       push + update in the same cycle both take effect.
The watchdog/auto-update machinery auto-rolls-back a bad restart or update.
HTTP uses the stdlib only — no new dependency.
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
from . import host_metrics as host_metrics_mod
from . import uploader as uploader_mod
from .config import get_settings
from .db import list_scan_runs, wait_for_db
from .logging_setup import audit

log = structlog.get_logger(__name__)

ENV_FILE = Path("/etc/netmon/netmon.env")
APPLIED_VERSION_FILE = Path("/var/lib/netmon/applied-config-version")
TOKEN_FILE = Path("/var/lib/netmon/enroll-token")
EXIT_CONFIG_CHANGED = 10
EXIT_UPDATE_REQUESTED = 11

# Baked-in default dashboard URL (public hostname, not a secret). Used when
# NETMON_DASHBOARD_URL is unset OR blank, so a box can never silently fail to
# phone home just because provisioning left the URL empty. Only matters when a
# credential (bootstrap key or enroll token) is also present — an SFTP-only box
# with no key still no-ops at the "not enrolled" step.
DEFAULT_DASHBOARD_URL = "https://netmon.sbcss.net"


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
    if "snmp_targets" in data:
        mapping["NETMON_SNMP_EXTRA_TARGETS"] = str(data.get("snmp_targets") or "")
    if "snmp_exclude" in data:
        mapping["NETMON_SNMP_EXCLUDE"] = str(data.get("snmp_exclude") or "")
    if data.get("rescan_interval"):
        mapping["NETMON_RESCAN_INTERVAL"] = str(int(data["rescan_interval"]))
    # SNMP topology crawl (pushed from the dashboard so 'spine' / 'full' + tuning
    # are flippable without SSH). scope is validated to the known set; the rest are
    # ints. Mirrors the topology settings in config.py.
    if "snmp_topology_enabled" in data:
        mapping["NETMON_SNMP_TOPOLOGY_ENABLED"] = "true" if data.get("snmp_topology_enabled") else "false"
    if "snmp_topology_scope" in data:
        scope = str(data.get("snmp_topology_scope") or "full").lower()
        mapping["NETMON_SNMP_TOPOLOGY_SCOPE"] = scope if scope in ("full", "spine") else "full"
    if data.get("snmp_topology_max_depth"):
        mapping["NETMON_SNMP_TOPOLOGY_MAX_DEPTH"] = str(int(data["snmp_topology_max_depth"]))
    if data.get("snmp_topology_time_budget"):
        mapping["NETMON_SNMP_TOPOLOGY_TIME_BUDGET"] = str(int(data["snmp_topology_time_budget"]))
    if "snmp_topology_interval" in data and data.get("snmp_topology_interval") is not None:
        mapping["NETMON_SNMP_TOPOLOGY_INTERVAL"] = str(int(data["snmp_topology_interval"]))
    if data.get("snmp_topology_max_nodes"):
        mapping["NETMON_SNMP_TOPOLOGY_MAX_NODES"] = str(int(data["snmp_topology_max_nodes"]))
    if data.get("snmp_topology_fanout_cap"):
        mapping["NETMON_SNMP_TOPOLOGY_FANOUT_CAP"] = str(int(data["snmp_topology_fanout_cap"]))
    # Release channel (consumed by scripts/auto-update.sh on the host).
    if "update_channel" in data:
        ch = str(data.get("update_channel") or "stable").lower()
        mapping["NETMON_UPDATE_CHANNEL"] = ch if ch in ("stable", "canary", "hold") else "stable"
    if "update_ref" in data:
        mapping["NETMON_UPDATE_REF"] = str(data.get("update_ref") or "")
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
    # iperf3 schedule/params (#10) pushed from the dashboard.
    if "iperf_enabled" in data:
        mapping["NETMON_IPERF_ENABLED"] = "true" if data.get("iperf_enabled") else "false"
    if "iperf_server" in data:
        mapping["NETMON_IPERF_SERVER"] = str(data.get("iperf_server") or "")
    if data.get("iperf_port"):
        mapping["NETMON_IPERF_PORT"] = str(int(data["iperf_port"]))
    if data.get("iperf_schedule_sec"):
        mapping["NETMON_IPERF_SCHEDULE_SEC"] = str(int(data["iperf_schedule_sec"]))
    if data.get("iperf_duration"):
        mapping["NETMON_IPERF_DURATION"] = str(int(data["iperf_duration"]))
    if "iperf_direction" in data:
        mapping["NETMON_IPERF_DIRECTION"] = str(data.get("iperf_direction") or "down")
    if "iperf_protocol" in data:
        mapping["NETMON_IPERF_PROTOCOL"] = str(data.get("iperf_protocol") or "tcp")
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


IPERF_LAST_FILE = Path("/var/lib/netmon/iperf-last-run")


def _report_iperf(url: str, token: str | None, res: dict, trigger: str) -> None:
    """POST an iperf result to the dashboard (best-effort)."""
    from datetime import UTC, datetime

    _post(
        f"{url}/api/sensor/iperf-result",
        token,
        {
            "trigger": trigger,
            "serverHost": res.get("server"),
            "serverPort": res.get("port"),
            "protocol": res.get("protocol"),
            "direction": res.get("direction"),
            "durationSec": res.get("duration"),
            "throughputMbps": res.get("throughput_mbps"),
            "retransmits": res.get("retransmits"),
            "jitterMs": res.get("jitter_ms"),
            "lossPct": res.get("loss_pct"),
            "ok": res.get("ok", False),
            "error": res.get("error"),
            "raw": res.get("raw"),
            "startedAt": datetime.now(UTC).isoformat(),
        },
    )


def _run_iperf_command(url: str, token: str | None, args: dict, trigger: str) -> tuple[str, dict]:
    """On-demand iperf run from the command queue; reports the full result and
    returns a short command-status summary."""
    from .iperf import run_iperf

    res = run_iperf(
        server=str(args.get("server") or ""),
        port=int(args.get("port") or 5201),
        protocol=str(args.get("protocol") or "tcp"),
        direction=str(args.get("direction") or "down"),
        duration=int(args.get("duration") or 10),
    )
    _report_iperf(url, token, res, trigger)
    if res.get("ok"):
        return "done", {"throughput_mbps": res.get("throughput_mbps")}
    return "failed", {"error": res.get("error")}


def _maybe_scheduled_iperf(url: str, token: str | None, settings) -> None:
    """Run a scheduled iperf test if enabled and the interval has elapsed."""
    import time

    if not settings.iperf_enabled or not settings.iperf_server:
        return
    now = time.time()
    try:
        last = float(IPERF_LAST_FILE.read_text().strip())
    except Exception:
        last = 0.0
    if now - last < max(300, settings.iperf_schedule_sec):
        return
    from .iperf import run_iperf

    res = run_iperf(
        server=settings.iperf_server,
        port=settings.iperf_port,
        protocol=settings.iperf_protocol,
        direction=settings.iperf_direction,
        duration=settings.iperf_duration,
    )
    _report_iperf(url, token, res, "scheduled")
    try:
        IPERF_LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
        IPERF_LAST_FILE.write_text(str(now))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist iperf last-run", error=str(exc))


def _current_sha() -> str | None:
    """The git commit the box is running, written by scripts/auto-update.sh to a
    file the container can read (the repo itself lives on the host, not in here)."""
    try:
        sha = Path("/var/lib/netmon/current-sha").read_text().strip()
        return sha or None
    except Exception:
        return None


def run_checkin() -> int:
    settings = get_settings()
    # Fall back to the baked-in default when the env var is unset OR blank, so a
    # provisioning slip (empty NETMON_DASHBOARD_URL) can't silently disable
    # check-in/enrollment the way it did on baker-agent.
    url = (settings.dashboard_url or DEFAULT_DASHBOARD_URL).rstrip("/")
    if not url:
        log.info("checkin skipped: no dashboard URL configured")
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
            # Release-channel telemetry for the dashboard rollout view.
            "commitSha": _current_sha(),
            "updateChannel": settings.update_channel,
            "localIp": local_ip,
            "interface": iface,
            "interfaceCidr": cidr,
            # Sensor self-health (CPU/RAM/disk/OS/uptime) for the dashboard's
            # per-box health view + heartbeat. Best-effort: {} if collection fails.
            "hostMetrics": host_metrics_mod.collect(),
            # Actual config the box is running, so the dashboard can show ground
            # truth (not just what it pushed). The SFTP password is NEVER reported.
            "currentConfig": {
                "snmp_enabled": settings.snmp_enabled,
                "snmp_communities": settings.snmp_communities,
                "snmp_exclude": settings.snmp_exclude,
                "snmp_topology_enabled": settings.snmp_topology_enabled,
                "snmp_topology_scope": settings.snmp_topology_scope,
                "snmp_topology_max_depth": settings.snmp_topology_max_depth,
                "snmp_topology_interval": settings.snmp_topology_interval,
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
            # Don't let a config-apply failure (e.g. a read-only env file) abort
            # the whole check-in — command dispatch and reporting must still run.
            # Leave applied-version unbumped so the next check-in retries.
            try:
                _apply_config(cfg.get("data") or {})
                _write_applied_version(version)
                applied = version
                config_changed = True
                audit("dashboard_config_applied", version=version)
            except Exception as exc:  # noqa: BLE001
                log.error("failed to apply pushed config; will retry next check-in",
                          version=version, error=str(exc))
                audit("dashboard_config_apply_failed", version=version, error=str(exc))

    update_requested = False
    for cmd in resp.get("commands") or []:
        cid = cmd.get("id")
        name = cmd.get("command")
        log.info("running queued command", id=cid, command=name)
        if name == "iperf":
            status, result = _run_iperf_command(url, token, cmd.get("args") or {}, "manual")
        elif name in ("update", "self-update", "update-now"):
            # The agent runs INSIDE the container an update replaces, so it can't
            # rebuild itself. Acknowledge here; the host check-in wrapper runs the
            # code update after we exit (EXIT_UPDATE_REQUESTED). The dashboard
            # confirms success on the next check-in when agentVersion changes (or
            # a rollback leaves the old version).
            update_requested = True
            status, result = "scheduled", {
                "note": "host will run auto-update after this check-in",
                "fromVersion": __version__,
            }
        else:
            status, result = _run_command(str(name))
        audit("dashboard_command_ran", id=cid, command=name, status=status)
        _post(
            f"{url}/api/sensor/result",
            token,
            {"commandId": cid, "status": status, "result": result, "configVersion": applied},
        )

    # Scheduled iperf piggybacks on the check-in cadence (runs if due).
    _maybe_scheduled_iperf(url, token, settings)

    if update_requested:
        return EXIT_UPDATE_REQUESTED
    return EXIT_CONFIG_CHANGED if config_changed else 0
