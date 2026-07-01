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
  12 — a HOST-LEVEL maintenance action was queued (restart / rebuild / reboot /
       rollback). The agent can't perform these from inside the container, so it
       records the request to /var/lib/netmon/host-action-request (a shared
       host<->container bind mount) and the host wrapper drains + executes it via
       scripts/host-action.sh after this check-in. 12 also implies the
       config-recreate of 10. These are state-changing + privileged; the
       dashboard gates each behind explicit confirm + approval + audit.
The watchdog/auto-update machinery auto-rolls-back a bad restart or update.
HTTP uses the stdlib only — no new dependency.
"""
from __future__ import annotations

import json
import os
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
# Drained + executed on the HOST by netmon-checkin.sh -> scripts/host-action.sh.
# /var/lib/netmon is a shared host<->container bind mount, so this file is our
# one-way IPC for actions the in-container agent can't perform itself.
HOST_ACTION_FILE = Path("/var/lib/netmon/host-action-request")
EXIT_CONFIG_CHANGED = 10
EXIT_UPDATE_REQUESTED = 11
EXIT_HOST_ACTION = 12

# Baked-in default dashboard URL (public hostname, not a secret). Used when
# NETMON_DASHBOARD_URL is unset OR blank, so a box can never silently fail to
# phone home just because provisioning left the URL empty. Only matters when a
# credential (bootstrap key or enroll token) is also present — an SFTP-only box
# with no key still no-ops at the "not enrolled" step.
# No org URL is baked into the public repo. The dashboard URL is provided per
# deployment via NETMON_DASHBOARD_URL (set by the dashboard-generated installer
# or site provisioning); an unconfigured box just skips check-in (logged).
DEFAULT_DASHBOARD_URL = ""


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
    if "iperf_timezone" in data:
        mapping["NETMON_IPERF_TIMEZONE"] = str(data.get("iperf_timezone") or "America/Los_Angeles")
    # The multi-schedule cron list rides a JSON file, NOT the env file — its
    # quotes/commas/brackets don't survive systemd EnvironmentFile parsing.
    if "iperf_schedules" in data:
        _write_iperf_schedules(data.get("iperf_schedules") or [])
    # Public speed tests (PERF-2) pushed from the dashboard.
    if "speedtest_enabled" in data:
        mapping["NETMON_SPEEDTEST_ENABLED"] = "true" if data.get("speedtest_enabled") else "false"
    if "speedtest_providers" in data:
        # Cloudflare is the only provider now (Ookla removed); normalize anything.
        mapping["NETMON_SPEEDTEST_PROVIDERS"] = "cloudflare"
    if data.get("speedtest_schedule_sec"):
        mapping["NETMON_SPEEDTEST_SCHEDULE_SEC"] = str(int(data["speedtest_schedule_sec"]))
    # Latency probes (PERF-4) pushed from the dashboard.
    if "latency_enabled" in data:
        mapping["NETMON_LATENCY_ENABLED"] = "true" if data.get("latency_enabled") else "false"
    if "latency_targets" in data:
        mapping["NETMON_LATENCY_TARGETS"] = str(data.get("latency_targets") or "1.1.1.1,8.8.8.8")
    # VLAN trunk monitoring config. Writing these only records the desired sub-
    # interfaces; the actual netplan apply runs on the HOST via the
    # 'host-apply-vlan' host-action (the container can't create persistent NICs).
    if "trunk_parent" in data:
        mapping["NETMON_TRUNK_PARENT"] = str(data.get("trunk_parent") or "")
    if "trunk_vlans" in data:
        mapping["NETMON_TRUNK_VLANS"] = re.sub(r"[^0-9,]", "", str(data.get("trunk_vlans") or ""))
    if "trunk_statics" in data:
        mapping["NETMON_TRUNK_STATICS"] = str(data.get("trunk_statics") or "")
    # Wi-Fi RF/AP survey (WIFI-2) toggle pushed from the dashboard. The same flag
    # gates BOTH the host survey timer (netmon-wifi-survey.sh reads this env file)
    # and the collector's bundle inclusion, so one push enables/disables both.
    if "wifi_survey_enabled" in data:
        mapping["NETMON_WIFI_SURVEY_ENABLED"] = "true" if data.get("wifi_survey_enabled") else "false"
    if "wifi_district_ssids" in data:
        mapping["NETMON_WIFI_DISTRICT_SSIDS"] = str(data.get("wifi_district_ssids") or "")
    # Wi-Fi analysis-radio JOIN (WIFI-1) pushed from the dashboard. The join runs on
    # the HOST via the 'host-wifi-join' host-action (lib/wifi.sh, routes-off so it
    # can't hijack the uplink); these keys just record the desired network. OFF by
    # default. The secret lands in /etc/netmon/netmon.env (0600, log-redacted) and is
    # written into a 0600 NM keyfile on apply — never passed on the nmcli argv.
    if "wifi_join_enabled" in data:
        mapping["NETMON_WIFI_JOIN_ENABLED"] = "true" if data.get("wifi_join_enabled") else "false"
    if "wifi_join_iface" in data:
        mapping["NETMON_WIFI_JOIN_IFACE"] = str(data.get("wifi_join_iface") or "")
    if "wifi_join_ssid" in data:
        mapping["NETMON_WIFI_JOIN_SSID"] = str(data.get("wifi_join_ssid") or "")
    if "wifi_join_auth" in data:
        _wauth = str(data.get("wifi_join_auth") or "open").lower()
        mapping["NETMON_WIFI_JOIN_AUTH"] = _wauth if _wauth in ("open", "psk", "peap", "ttls") else "open"
    if "wifi_join_identity" in data:
        mapping["NETMON_WIFI_JOIN_IDENTITY"] = str(data.get("wifi_join_identity") or "")
    if data.get("wifi_join_secret"):  # only overwrite when provided (like sftp_password)
        mapping["NETMON_WIFI_JOIN_SECRET"] = str(data["wifi_join_secret"])
    # Multi-profile join list (WIFI-6) rides a 0600 JSON file, NOT env — secrets +
    # quotes/braces don't belong in the EnvironmentFile. Full-replace like the iperf
    # schedules; an empty list clears it (the feature stays gated by wifi_join_enabled).
    if "wifi_join_profiles" in data:
        _write_wifi_profiles(data.get("wifi_join_profiles") or [])
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


# Mask credential-looking values out of any text that leaves the box. The console
# `collect-logs` (raw log tails) and the diagnostic commands both surface output to
# the operator AND record it into the broker transcript, so even though our logs
# don't echo secrets today, scrub defensively (data-minimization): an SFTP
# password / SNMP community / token / bootstrap key must never ride out in clear.
_SECRET_KV_RE = re.compile(
    r"(?i)([A-Za-z0-9_.\-]*"
    r"(?:passwd|password|secret|token|communit|psk|api[_-]?key|bootstrap[_-]?key|auth[_-]?key|access[_-]?key)"
    r"[A-Za-z0-9_.\-]*)"        # 1: the key, e.g. NETMON_SFTP_PASSWORD / community
    r"[\"']?\s*[=:]\s*[\"']?"   # an = or : assignment (optionally quoted — env/JSON/CLI)
    r"([^\s\"';}]+)"            # 2: value, to next delimiter. Allows ',' so a
                                # comma-joined list (NETMON_SNMP_COMMUNITIES=
                                # public,private) is fully masked, not just the head.
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")


def _redact_secrets(text: str) -> str:
    """Replace credential VALUES (KEY=secret, KEY: "secret", Bearer <token>) with
    ***, leaving the key + surrounding log text intact. Only masks assignment-style
    secrets, so prose like "passwordauthentication no" is untouched."""
    text = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=***", text)
    text = _BEARER_RE.sub(r"\1 ***", text)
    return text


def _collect_logs(lines: int = 250) -> tuple[str, dict]:
    """Return the (secret-redacted) tail of the collector + audit logs for the dashboard."""
    from .logging_setup import LOG_DIR

    out: dict[str, str] = {}
    # auto-update.log is written by the host's scripts/auto-update.sh into the
    # /var/log/netmon bind mount, so include it here — it's the ONLY way to see
    # why a remote update failed without SSH (the rest goes to host syslog).
    for fname in ("collector.log", "audit.log", "auto-update.log"):
        p = LOG_DIR / fname
        try:
            tail = p.read_text(errors="replace").splitlines()[-lines:]
            text = _redact_secrets("\n".join(tail))  # scrub before it leaves the box
            out[fname] = text[-20000:]  # cap size stored in the result
        except FileNotFoundError:
            out[fname] = "(no file)"
        except Exception as exc:  # noqa: BLE001
            out[fname] = f"(could not read: {exc})"
    return "done", out


# Restricted "remote console" diagnostics. Each maps a command id to a FIXED argv
# (no shell, no operator-supplied input) so there is zero injection surface; output
# is captured + size-bounded. READ-ONLY only — state-changing actions (restart, etc.)
# are intentionally NOT here pending security-chat sign-off; they reuse the existing
# queue handlers below. The dashboard presents this same id set as the allow-list.
_DIAG_COMMANDS: dict[str, list[str]] = {
    "diag-interfaces": ["ip", "-br", "addr"],
    "diag-routes": ["ip", "route"],
    "diag-arp": ["ip", "-br", "neigh"],
    "diag-disk": ["df", "-h"],
    "diag-uptime": ["uptime"],
    "diag-dns": [
        "sh", "-c",
        "cat /etc/resolv.conf 2>/dev/null; echo '--- test lookup ---'; "
        "dig +time=2 +tries=1 +short google.com 2>&1 | head",
    ],
    # Reachability to the internet (fixed targets — no operator input, so no
    # injection surface). Mirrors the sensor menu's "Ping" diagnostic.
    "diag-ping": [
        "sh", "-c",
        "ping -c 4 -W 2 1.1.1.1 2>&1 | tail -n 6; echo '---'; "
        "ping -c 4 -W 2 8.8.8.8 2>&1 | tail -n 6",
    ],
    # "Test SFTP" — connect/auth/list the remote path. Read-only (uploads nothing)
    # and, crucially, surfaces whether uploads are actually ENABLED, since a plain
    # connection test passes even when NETMON_SFTP_ENABLED=false (the footgun).
    "diag-sftp-test": ["python", "-m", "collector", "upload-test"],
    # Sniff 802.1Q tags on the box's uplink (auto-detected) to discover which
    # VLANs a trunk carries — feeds the dashboard's VLAN picker. Read-only.
    "diag-detect-vlans": [
        "sh", "-c",
        "iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}'); "
        "if [ -n \"$iface\" ]; then echo \"sniffing $iface for 802.1Q tags (~8s)…\"; "
        "python -m collector detect-vlans \"$iface\" --seconds 8; "
        "else echo 'no default-route interface to sniff'; fi",
    ],
    "diag-selftest": ["python", "-m", "collector", "selftest"],
}

# HOST-LEVEL maintenance actions (restart / rebuild / reboot / rollback). Unlike
# the diagnostics/controls above, these CANNOT run from inside the container — the
# agent is a process in the very container some of them replace. So instead of
# executing them, the agent records the request to HOST_ACTION_FILE and returns
# EXIT_HOST_ACTION; the host wrapper (netmon-checkin.sh) drains the file and runs
# scripts/host-action.sh, which holds the authoritative host-side allow-list. The
# dashboard gates each behind explicit confirm + approval + audit. Keep this set
# tight and mirrored with scripts/host-action.sh; vet additions with security.
_HOST_ACTIONS: set[str] = {
    "host-restart",   # docker compose restart (lightweight; no rebuild)
    "host-rebuild",   # rebuild collector image + recreate (keeps DB/config/logs)
    "host-reboot",    # systemctl reboot the box
    "host-rollback",  # scripts/rollback.sh -> last-known-good SHA + image + DB
    "host-apply-vlan", # apply NETMON_TRUNK_* netplan sub-interfaces (lib/trunk.sh)
    "host-wifi-join",  # join NETMON_WIFI_JOIN_* on the analysis radio (lib/wifi.sh, routes-off)
    "host-wifi-leave", # tear down all netmon-owned Wi-Fi connections (lib/wifi.sh)
    "host-wifi-experience", # WIFI-3 client-experience battery (join->measure->leave)
    "host-cis-apply",  # apply the CIS safe subset (scripts/cis-apply.sh --apply; self-healing guard auto-reverts on connectivity loss)
    "host-cis-revert", # undo the CIS safe subset (scripts/cis-apply.sh --revert)
}

# State-changing "remote console" actions (CON-5). SAME safety model as
# _DIAG_COMMANDS — FIXED argv, no shell, no operator input, re-validated by the
# sensor, output captured + size-bounded — but these CHANGE state, so the
# dashboard gates them behind an explicit confirm + audit. IN-CONTAINER scope
# only: host-level actions (restart docker, reboot, renew the host DHCP lease)
# are intentionally NOT here — they need the separate host-execution path and
# security-chat sign-off (see registry CON-5 / CON-7). Add only fast, safe,
# reversible, container-reachable actions here; vet the list with the security chat.
_CONTROL_COMMANDS: dict[str, list[str]] = {
    # Flush the neighbor/ARP cache so stale entries are re-learned on next scan.
    "ctl-flush-arp": ["ip", "-s", "neigh", "flush", "all"],
}

# In-container OPERATIONAL commands that the live console may run directly (not
# fixed-argv — they reuse the rich `_run_command` handlers below). Safe to run
# from the detached console-session process because they execute entirely inside
# the container (no host privileges, no exit-code signalling needed). HOST-level
# actions + code `update` are deliberately excluded: those need the host wrapper's
# exit-code path, so they stay on the queued near-live path. Mirrored by the
# broker allow-list + the dashboard's CONSOLE_OP_COMMANDS. Vet additions with security.
_LIVE_OPS: set[str] = {
    "run-scan",       # force an immediate discovery scan
    "upload-now",     # build + ship the latest hour's bundle now
    "config-backup",  # snapshot + upload the collector config now
    "collect-logs",   # gather recent logs and return them inline
}


def _run_diag(command: str) -> tuple[str, dict]:
    """Run an allow-listed, fixed-argv diagnostic or control action; bounded output."""
    import subprocess

    argv = _DIAG_COMMANDS.get(command) or _CONTROL_COMMANDS.get(command)
    if argv is None:
        return "failed", {"error": f"unknown diagnostic {command!r}"}
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        # Scrub secrets (e.g. an SFTP/SNMP cred echoed by upload-test or a config
        # dump) before this output reaches the operator / broker transcript. Same
        # guard _collect_logs uses; redact first, then cap.
        out = _redact_secrets(((p.stdout or "") + (p.stderr or "")).strip())
        return "done", {"command": command, "exit": p.returncode, "output": out[-16000:]}
    except subprocess.TimeoutExpired:
        return "failed", {"command": command, "error": "timed out"}
    except Exception as exc:  # noqa: BLE001
        return "failed", {"command": command, "error": str(exc)}


def _spawn_console_session(args: dict) -> tuple[str, dict]:
    """Kick off a DETACHED remote-console session process.

    This check-in runs one-shot via `docker compose exec`, so a thread would die
    when we exit. Instead spawn `collector console-session` in its OWN session
    (start_new_session) so it reparents to the container's PID 1 and outlives us.
    It dials the broker on its own; we just report that it started. The one-time
    token is passed via env, NOT argv, to keep it out of the process list.
    """
    import os
    import subprocess
    import sys

    broker = str(args.get("broker") or "")
    token = str(args.get("token") or "")
    sid = str(args.get("sid") or "")
    # Full-shell mode (CON-7) is opt-in per session — the dashboard only sets it
    # after an email one-time-code step-up. Default to the safe allow-listed path
    # and never trust an unrecognized value.
    mode = "full" if str(args.get("mode") or "") == "full" else "restricted"
    if not broker or not token or not sid:
        return "failed", {"error": "missing broker/token/sid"}
    try:
        env = dict(os.environ)
        env["NETMON_CONSOLE_TOKEN"] = token
        subprocess.Popen(
            [sys.executable, "-m", "collector", "console-session",
             "--broker", broker, "--sid", sid, "--mode", mode],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        log.info("remote console: session spawned", sid=sid)
        return "done", {"started": True, "sid": sid}
    except Exception as exc:  # noqa: BLE001
        return "failed", {"error": str(exc)}


def _request_host_action(action: str, command_id) -> tuple[str, dict]:
    """Record a host-level action for the host wrapper to execute after check-in.

    The agent can't restart/rebuild/reboot/rollback from inside the container, so
    we append the (command_id, action) to HOST_ACTION_FILE — a shared bind mount
    netmon-checkin.sh drains on EXIT_HOST_ACTION. Like the `update` path, the
    outcome is observed on the NEXT check-in (uptime reset, recreated container,
    rolled-back agentVersion), so we report 'scheduled' here, not 'done'.
    """
    if action not in _HOST_ACTIONS:
        return "failed", {"error": f"unknown host action {action!r}"}
    try:
        HOST_ACTION_FILE.parent.mkdir(parents=True, exist_ok=True)
        with HOST_ACTION_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"{command_id}\t{action}\n")
        log.info("host action queued for host wrapper", action=action, id=command_id)
        return "scheduled", {
            "note": f"host will run '{action}' after this check-in",
            "action": action,
        }
    except Exception as exc:  # noqa: BLE001
        return "failed", {"error": f"could not record host action: {exc}"}


def _run_command(command: str) -> tuple[str, dict]:
    """Execute a queued command. Returns (status, result)."""
    try:
        if command in _DIAG_COMMANDS:
            return _run_diag(command)
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


# Multi-schedule cron list (pushed from the dashboard) + the per-day "already
# fired" ledger, both JSON files (not env — see _apply_config).
IPERF_SCHEDULES_FILE = Path("/var/lib/netmon/iperf-schedules.json")
IPERF_SLOTS_FILE = Path("/var/lib/netmon/iperf-slots.json")
# Wi-Fi join profiles (WIFI-6): the list of networks the experience battery joins,
# measures + leaves, pushed from the dashboard. Rides a JSON FILE (not env) for the
# same reason as the iperf schedules — quotes/commas/braces don't survive systemd
# EnvironmentFile parsing — AND it carries per-network secrets, so the file is 0600.
WIFI_PROFILES_FILE = Path("/var/lib/netmon/wifi-profiles.json")
# Fire a slot if we check in within this window after its scheduled time (covers
# the ~10-min check-in gap + a missed beat) — but never run it hours late.
IPERF_SLOT_GRACE_SEC = 45 * 60


def _write_iperf_schedules(schedules: list) -> None:
    """Persist the pushed iperf schedule list to the JSON file the scheduler reads."""
    try:
        IPERF_SCHEDULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        IPERF_SCHEDULES_FILE.write_text(json.dumps(schedules))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist iperf schedules", error=str(exc))


def _write_wifi_profiles(profiles: list) -> None:
    """Persist the pushed Wi-Fi join profiles to the 0600 JSON file the host
    experience battery (scripts/netmon-wifi-experience.sh) reads. Full-replace, like
    the iperf schedules; 0600 because each profile carries its resolved per-sensor
    secret (PSK / 802.1X password). Written to a temp created 0600 from the start,
    then atomically renamed, so the secret is never briefly world-readable nor a
    partial write ever seen by the host script."""
    try:
        WIFI_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(profiles if isinstance(profiles, list) else [])
        tmp = WIFI_PROFILES_FILE.with_suffix(".json.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        os.replace(str(tmp), str(WIFI_PROFILES_FILE))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist wifi profiles", error=str(exc))


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


def _load_iperf_schedules() -> list[dict]:
    try:
        data = json.loads(IPERF_SCHEDULES_FILE.read_text())
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _load_iperf_slots() -> dict:
    try:
        data = json.loads(IPERF_SLOTS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_iperf_slots(slots: dict) -> None:
    try:
        IPERF_SLOTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        IPERF_SLOTS_FILE.write_text(json.dumps(slots))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist iperf slots", error=str(exc))


def _run_iperf_slot(
    url: str, token: str | None, settings, proto: str, direction: str, duration: int
) -> None:
    """Run one scheduled slot. 'both' = a download then an upload (two results)."""
    from .iperf import run_iperf

    dirs = ["down", "up"] if direction == "both" else [direction]
    for d in dirs:
        res = run_iperf(
            server=settings.iperf_server,
            port=settings.iperf_port,
            protocol=proto,
            direction=d,
            duration=duration,
        )
        _report_iperf(url, token, res, "scheduled")


def _maybe_scheduled_iperf(url: str, token: str | None, settings) -> None:
    """Run any iperf schedule whose time-of-day + day-of-week has arrived and that
    hasn't fired yet today. Cron-style and evaluated in settings.iperf_timezone, so
    "5am" means 5am there regardless of the box's OS clock; each run is deduped per
    day via a slot ledger. Schedules are pushed from the dashboard's Speed &
    Bandwidth / sensor panel and persisted to IPERF_SCHEDULES_FILE."""
    from datetime import datetime

    if not settings.iperf_enabled or not settings.iperf_server:
        return
    schedules = _load_iperf_schedules()
    if not schedules:
        return

    try:
        from zoneinfo import ZoneInfo

        now = datetime.now(ZoneInfo(settings.iperf_timezone))
    except Exception:  # noqa: BLE001 — unknown zone / no tzdata → box-local clock
        now = datetime.now().astimezone()
    weekday = now.weekday()  # Mon=0 .. Sun=6 (matches the dashboard's day indices)
    today = now.strftime("%Y-%m-%d")

    slots = _load_iperf_slots()
    fired = False
    for sched in schedules:
        if not isinstance(sched, dict):
            continue
        day_set = {int(d) for d in (sched.get("days") or []) if isinstance(d, (int, float))}
        if weekday not in day_set:
            continue
        proto = "udp" if sched.get("protocol") == "udp" else "tcp"
        direction = sched.get("direction") or "down"
        if direction not in ("down", "up", "both"):
            direction = "down"
        try:
            duration = max(1, min(int(sched.get("duration") or 10), 60))
        except (TypeError, ValueError):
            duration = 10
        for hhmm in sched.get("times") or []:
            parts = str(hhmm).split(":")
            if len(parts) != 2:
                continue
            try:
                scheduled = now.replace(
                    hour=int(parts[0]), minute=int(parts[1]), second=0, microsecond=0
                )
            except ValueError:
                continue  # out-of-range HH/MM
            delta = (now - scheduled).total_seconds()
            if delta < 0 or delta > IPERF_SLOT_GRACE_SEC:
                continue  # not due yet, or too late to be useful
            slot_key = f"{proto}|{direction}|{hhmm}"
            if slots.get(slot_key) == today:
                continue  # already ran this slot today
            log.info(
                "running scheduled iperf", protocol=proto, direction=direction, at=str(hhmm)
            )
            _run_iperf_slot(url, token, settings, proto, direction, duration)
            slots[slot_key] = today
            fired = True
    if fired:
        # Keep only today's fires so the ledger doesn't accumulate stale slots.
        _save_iperf_slots({k: v for k, v in slots.items() if v == today})


SPEEDTEST_LAST_FILE = Path("/var/lib/netmon/speedtest-last-run")


def _report_speedtest(url: str, token: str | None, res: dict, trigger: str) -> None:
    """POST a public-speedtest result to the dashboard (best-effort)."""
    from datetime import UTC, datetime

    _post(
        f"{url}/api/sensor/speedtest-result",
        token,
        {
            "trigger": trigger,
            "provider": res.get("provider"),
            "downloadMbps": res.get("download_mbps"),
            "uploadMbps": res.get("upload_mbps"),
            "latencyMs": res.get("latency_ms"),
            "jitterMs": res.get("jitter_ms"),
            "lossPct": res.get("loss_pct"),
            "server": res.get("server"),
            "isp": res.get("isp"),
            "resultUrl": res.get("result_url"),
            "externalIp": res.get("external_ip"),
            "ok": res.get("ok", False),
            "error": res.get("error"),
            "raw": res.get("raw"),
            "startedAt": datetime.now(UTC).isoformat(),
        },
    )


def _run_speedtest_command(url: str, token: str | None, args: dict, trigger: str) -> tuple[str, dict]:
    """On-demand speed test from the command queue. Cloudflare is the only
    provider (Ookla removed); reports the result, returns a short status."""
    from .speedtest import run_speedtest

    res = run_speedtest("cloudflare", duration=int(args.get("duration") or 5))
    _report_speedtest(url, token, res, trigger)
    summary = (
        {"download_mbps": res.get("download_mbps"), "upload_mbps": res.get("upload_mbps")}
        if res.get("ok")
        else {"error": res.get("error")}
    )
    return ("done" if res.get("ok") else "failed"), {"cloudflare": summary}


def _maybe_scheduled_speedtest(url: str, token: str | None, settings) -> None:
    """Run the scheduled Cloudflare speed test if enabled and the interval elapsed."""
    import time

    if not settings.speedtest_enabled:
        return
    now = time.time()
    try:
        last = float(SPEEDTEST_LAST_FILE.read_text().strip())
    except Exception:
        last = 0.0
    if now - last < max(900, settings.speedtest_schedule_sec):  # 15-min floor (bandwidth)
        return
    from .speedtest import run_speedtest

    res = run_speedtest("cloudflare")
    _report_speedtest(url, token, res, "scheduled")
    try:
        SPEEDTEST_LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
        SPEEDTEST_LAST_FILE.write_text(str(now))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist speedtest last-run", error=str(exc))


def _report_latency(url: str, token: str | None, results: list[dict], trigger: str) -> None:
    """POST each latency probe result to the dashboard (best-effort)."""
    from datetime import UTC, datetime

    ts = datetime.now(UTC).isoformat()
    for r in results:
        _post(
            f"{url}/api/sensor/latency-result",
            token,
            {
                "trigger": trigger,
                "label": r.get("label"),
                "target": r.get("host"),
                "latencyMs": r.get("latency_ms"),
                "jitterMs": r.get("jitter_ms"),
                "lossPct": r.get("loss_pct"),
                "ok": r.get("ok", False),
                "error": r.get("error"),
                "startedAt": ts,
            },
        )


def _dns_resolver() -> str | None:
    """First nameserver from /etc/resolv.conf, for the latency 'dns' target."""
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            s = line.strip()
            if s.startswith("nameserver"):
                parts = s.split()
                if len(parts) >= 2:
                    return parts[1]
    except Exception:  # noqa: BLE001
        return None
    return None


def _maybe_latency(url: str, token: str | None, settings) -> None:
    """Probe latency/jitter/loss to internet + gateway + DNS each check-in (cheap)."""
    if not settings.latency_enabled:
        return
    from . import latency as latency_mod

    targets: list[tuple[str, str]] = []
    for host in str(settings.latency_targets or "").split(","):
        host = host.strip()
        if host:
            targets.append(("internet", host))
    gw = latency_mod.default_gateway()
    if gw:
        targets.append(("gateway", gw))
    dns = _dns_resolver()
    if dns:
        targets.append(("dns", dns))
    if not targets:
        return
    try:
        results = latency_mod.probe_latency(targets, count=10)
    except Exception as exc:  # noqa: BLE001
        log.warning("latency probe failed", error=str(exc))
        return
    _report_latency(url, token, results, "scheduled")


def _current_sha() -> str | None:
    """The git commit the box is running, written by scripts/auto-update.sh to a
    file the container can read (the repo itself lives on the host, not in here)."""
    try:
        sha = Path("/var/lib/netmon/current-sha").read_text().strip()
        return sha or None
    except Exception:
        return None


def _last_update() -> dict | None:
    """The outcome of the box's last auto-update run, written by auto-update.sh to
    a bind-mounted file (status/reason/from/to/channel/at). Reported at check-in so
    the dashboard can show WHY an update failed — the update runs host-side and
    async, so this is the only feedback the dashboard gets. Best-effort."""
    try:
        raw = Path("/var/lib/netmon/last-update-result").read_text().strip()
        data = json.loads(raw) if raw else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _last_host_action() -> dict | None:
    """Outcome of the last HOST-LEVEL action (apply-vlan / restart / reboot / …),
    written by scripts/host-action.sh to a bind-mounted file (action/status/reason/at).
    Host actions run host-side and async, so — exactly like _last_update — this is the
    only feedback the dashboard gets. Without it, a failed VLAN apply (e.g. the
    netplan-on-NetworkManager crash) was invisible to the dashboard. Best-effort."""
    try:
        raw = Path("/var/lib/netmon/host-action-result").read_text().strip()
        data = json.loads(raw) if raw else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _interfaces() -> list[dict]:
    """The box's live interface list (name / cidr / up / vlan / primary) so the
    dashboard can show per-VLAN status PRECISELY — which sub-interfaces actually came
    up and got a lease — instead of inferring it from scan data alone. Excludes
    virtual/container NICs. Best-effort: [] on any failure."""
    try:
        from .discovery import interfaces as iface_mod

        primary = iface_mod.primary_interface()
        out: list[dict] = []
        for st in iface_mod.snapshot(
            exclude_prefixes=("lo", "docker", "br-", "veth", "virbr", "tun", "tap")
        ):
            parent, _, tag = st.name.rpartition(".")
            vlan = int(tag) if parent and tag.isdigit() and 1 <= int(tag) <= 4094 else None
            out.append(
                {
                    "name": st.name,
                    "cidr": st.ipv4_addrs[0] if st.ipv4_addrs else None,
                    "up": bool(st.is_up),
                    "vlan": vlan,
                    "primary": st.name == primary,
                }
            )
        return out
    except Exception:
        return []


def run_console_poll() -> int:
    """Lightweight interactive-command poll (faster-pickup for the live console).

    Runs far more often than the full check-in (every ~30s) but does almost
    nothing: it asks the dashboard only for a queued `open-console` command and,
    if present, spawns the detached session process so a live console pairs in
    seconds instead of after the next ~10-min check-in. No config apply, no
    health report, no other command types. Best-effort and side-effect-free
    otherwise; enrollment + everything else stays with run_checkin().
    """
    settings = get_settings()
    url = (settings.dashboard_url or DEFAULT_DASHBOARD_URL).rstrip("/")
    if not url:
        return 0
    token = _current_token(settings)
    if not token:
        return 0  # not enrolled yet — the full check-in owns enrollment
    resp = _post(f"{url}/api/sensor/console-poll", token, {})
    if resp is None:
        return 0
    applied = _read_applied_version()
    for cmd in resp.get("commands") or []:
        cid = cmd.get("id")
        name = cmd.get("command")
        if name != "open-console":
            continue
        status, result = _spawn_console_session(cmd.get("args") or {})
        audit("console_poll_command_ran", id=cid, command=name, status=status)
        _post(
            f"{url}/api/sensor/result",
            token,
            {"commandId": cid, "status": status, "result": result, "configVersion": applied},
        )
    return 0


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
            # Outcome of the last host-side auto-update (so a failed update is
            # visible on the dashboard instead of fire-and-forget).
            "lastUpdate": _last_update(),
            # Outcome of the last host-level action (apply-vlan / restart / …) so a
            # failed VLAN apply is visible on the dashboard, not just the box journal.
            "lastHostAction": _last_host_action(),
            "localIp": local_ip,
            "interface": iface,
            "interfaceCidr": cidr,
            # Live interface list (uplink + VLAN sub-ifs) so the dashboard shows which
            # VLANs actually came up + got a lease, not just what was configured.
            "interfaces": _interfaces(),
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
    host_action_requested = False
    for cmd in resp.get("commands") or []:
        cid = cmd.get("id")
        name = cmd.get("command")
        log.info("running queued command", id=cid, command=name)
        if name == "iperf":
            status, result = _run_iperf_command(url, token, cmd.get("args") or {}, "manual")
        elif name == "speedtest":
            status, result = _run_speedtest_command(url, token, cmd.get("args") or {}, "manual")
        elif name in _HOST_ACTIONS:
            status, result = _request_host_action(str(name), cid)
            if status == "scheduled":
                host_action_requested = True
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
        elif name == "open-console":
            status, result = _spawn_console_session(cmd.get("args") or {})
        else:
            status, result = _run_command(str(name))
        audit("dashboard_command_ran", id=cid, command=name, status=status)
        _post(
            f"{url}/api/sensor/result",
            token,
            {"commandId": cid, "status": status, "result": result, "configVersion": applied},
        )

    # Scheduled iperf + public speedtests + latency probes piggyback on check-in.
    _maybe_scheduled_iperf(url, token, settings)
    _maybe_scheduled_speedtest(url, token, settings)
    _maybe_latency(url, token, settings)

    # Exit precedence: update (11) already recreates + may host-reboot via the
    # update path, so it wins; then host actions (12); then a plain config
    # recreate (10). Each higher code implies the recreate of 10.
    if update_requested:
        return EXIT_UPDATE_REQUESTED
    if host_action_requested:
        return EXIT_HOST_ACTION
    return EXIT_CONFIG_CHANGED if config_changed else 0
