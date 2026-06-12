from __future__ import annotations

import sys

import click
import structlog

from . import __version__
from . import config_backup as config_backup_mod
from . import migrations as migrations_mod
from . import selftest as selftest_mod
from . import uploader as uploader_mod
from .bundle import build_bundle
from .config import get_settings
from .db import fetch_scan, list_scan_runs, wait_for_db
from .logging_setup import audit, configure_logging
from .poller import run_poller
from .scan import run_scan


def _configure_logging() -> None:
    """Kept as a thin wrapper for backward-compat with the prior name."""
    configure_logging()


log = structlog.get_logger(__name__)


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """NetMon collector — discovers network state and exports evidence bundles."""
    _configure_logging()


@cli.command("run")
def cmd_run() -> None:
    """Run the interface poller and the hourly SFTP uploader."""
    settings = get_settings()
    log.info("collector starting",
             rescan_interval=settings.rescan_interval,
             poll_interval=settings.poll_interval,
             sftp_enabled=settings.sftp_enabled,
             device=uploader_mod.device_name())
    wait_for_db()
    # Apply any pending schema migrations BEFORE we start collecting. If a
    # migration fails, refuse to start — better than running with a half-
    # applied schema and corrupting data.
    migrations_mod.apply_pending()
    # Self-test once at startup. We log every check so operators can grep the
    # boot log for the state of the box; we DON'T refuse to start on failure
    # because some failures (e.g. no interface with carrier yet) are normal
    # at boot and resolve once a cable is plugged in.
    selftest_mod.log_results(selftest_mod.run_all())
    audit("collector_started", rescan_interval=settings.rescan_interval,
          sftp_enabled=settings.sftp_enabled,
          device=uploader_mod.device_name())
    uploader_mod.start_in_background()
    run_poller()


@cli.command("scan")
@click.argument("interface")
@click.option("--reason", default="manual", help="Trigger reason recorded with the scan.")
def cmd_scan(interface: str, reason: str) -> None:
    """Run a one-off scan on INTERFACE."""
    wait_for_db()
    from .discovery import interfaces as iface_mod
    is_primary = (interface == iface_mod.primary_interface())
    scan_id = run_scan(interface=interface, trigger_reason=reason, force=True,
                       is_primary=is_primary)
    if scan_id is None:
        click.echo("scan did not run", err=True)
        sys.exit(2)
    click.echo(f"scan complete, id={scan_id}")


@cli.command("detect-vlans")
@click.argument("interface")
@click.option("--seconds", default=8, show_default=True, help="Capture window.")
def cmd_detect_vlans(interface: str, seconds: int) -> None:
    """Sniff 802.1Q tags on INTERFACE and print the VLAN IDs seen (comma-separated).

    The trunk wizard runs this in the collector container (which has tshark +
    host networking) to propose which VLANs to monitor. Prints nothing — exit 0 —
    if no tagged frames are seen (a plain access port or a very quiet trunk).
    """
    from .discovery import vlan_detect
    vlans = vlan_detect.detect_vlans(interface, seconds=seconds)
    if vlans:
        click.echo(",".join(str(v) for v in vlans))


@cli.command("list")
@click.option("--limit", default=50, show_default=True, help="Max rows to show.")
def cmd_list(limit: int) -> None:
    """List recent scan runs."""
    wait_for_db()
    rows = list_scan_runs(limit=limit)
    if not rows:
        click.echo("(no scans yet)")
        return
    click.echo(f"{'id':>4}  {'started':<25}  {'iface':<10}  {'cidr':<20}  {'gw':<16}  reason")
    for r in rows:
        started = r["started_at"].strftime("%Y-%m-%d %H:%M:%S%z") if r.get("started_at") else "-"
        click.echo(
            f"{r['id']:>4}  {started:<25}  "
            f"{(r.get('interface') or '-'):<10}  "
            f"{str(r.get('interface_cidr') or '-'):<20}  "
            f"{str(r.get('gateway_ip') or '-'):<16}  "
            f"{r.get('trigger_reason') or '-'}"
        )


@cli.command("bundle")
@click.argument("scan_id", type=int)
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output path. Default: $NETMON_BUNDLE_DIR/network-scan-<host>-<ts>.zip")
def cmd_bundle(scan_id: int, output: str | None) -> None:
    """Export an evidence bundle ZIP for SCAN_ID."""
    wait_for_db()
    scan = fetch_scan(scan_id)
    if not scan:
        click.echo(f"scan id {scan_id} not found", err=True)
        sys.exit(2)
    path = build_bundle(scan_id, output_path=output)
    click.echo(str(path))


@cli.command("upload-test")
def cmd_upload_test() -> None:
    """Test the SFTP connection: connect, authenticate, list the remote path.

    NOTE: this only proves the *credentials* work — it deliberately bypasses the
    NETMON_SFTP_ENABLED gate. A box can pass this test yet never actually upload
    because uploads are disabled. We surface that here so a green test isn't
    mistaken for "uploads are working".
    """
    ok, msg = uploader_mod.test_connection()
    click.echo(("OK   " if ok else "FAIL ") + msg)
    if ok:
        settings = get_settings()
        if settings.sftp_enabled:
            click.echo("uploads:       ENABLED (NETMON_SFTP_ENABLED=true) — bundles will ship")
        else:
            click.echo("uploads:       DISABLED (NETMON_SFTP_ENABLED=false)")
            click.echo("  ⚠ Credentials work but real uploads are OFF, so NO data reaches the")
            click.echo("    dashboard. Enable from the dashboard (sensor SFTP settings -> save")
            click.echo("    with 'Enable' checked) or on the box:")
            click.echo("      sudo sed -i 's/^NETMON_SFTP_ENABLED=.*/NETMON_SFTP_ENABLED=true/' /etc/netmon/netmon.env")
            click.echo("      docker compose up -d --force-recreate collector")
    sys.exit(0 if ok else 2)


@cli.command("upload-now")
def cmd_upload_now() -> None:
    """Build and upload the most recent hour that has scans. No waiting."""
    wait_for_db()
    from datetime import timedelta

    # Find the most recent completed scan in the database and bundle the
    # one-hour window containing it. This makes upload-now do what users
    # expect after a manual `scan`: ship that scan's hour right now,
    # regardless of whether we're mid-hour or at a clean boundary.
    recent = list_scan_runs(limit=10)
    recent_completed = next((s for s in recent if s.get("completed_at")), None)
    if recent_completed is None:
        click.echo("no completed scans in the database yet.")
        click.echo("Plug a network cable in (auto-scan), or run:")
        click.echo("    docker compose exec collector python -m collector scan <iface>")
        sys.exit(2)

    completed_at = recent_completed["completed_at"]
    if completed_at.tzinfo is None:
        completed_at = completed_at.astimezone()  # treat naive as local
    window_start = completed_at.replace(minute=0, second=0, microsecond=0)
    window_end = window_start + timedelta(hours=1)

    click.echo(f"most recent completed scan: id={recent_completed['id']}  "
               f"completed_at={completed_at.isoformat()}")
    click.echo(f"bundling hour:              {window_start.isoformat()}  →  {window_end.isoformat()}")
    result = uploader_mod.build_and_upload_hour(window_end)
    click.echo(f"status:        {result['status']}")
    click.echo(f"window:        {result['window_start']}  →  {result['window_end']}")
    click.echo(f"scans in hour: {result['scans']}")
    if result.get("local_path"):
        click.echo(f"local bundle:  {result['local_path']}")
    if result.get("remote_path"):
        click.echo(f"remote path:   {result['remote_path']}")
    if result.get("message"):
        click.echo(f"detail:        {result['message']}")
    sys.exit(0 if result["status"] in ("uploaded", "saved_only", "skipped") else 2)


@cli.command("healthcheck")
@click.option("--verbose/--no-verbose", default=False, help="Print every check result.")
def cmd_healthcheck(verbose: bool) -> None:
    """Run the self-test and exit non-zero if any check failed.

    Used by Docker's HEALTHCHECK directive. The DB check is the one that
    matters most for "is the container actually working" — without it the
    collector can't persist anything. Other checks (disk, interfaces) are
    informational here; we don't fail healthcheck on them.
    """
    results = selftest_mod.run_all()
    critical_failures = []
    for r in results:
        prefix = "OK  " if r.ok else "FAIL"
        if verbose or not r.ok:
            click.echo(f"{prefix} {r.name}: {r.detail}")
        # Treat only the DB and capabilities checks as healthcheck-blocking;
        # disk/interfaces can be transiently bad without the collector being
        # truly unhealthy.
        if not r.ok and r.name in ("db", "capabilities"):
            critical_failures.append(r.name)
    if critical_failures:
        click.echo(f"healthcheck FAILED: {','.join(critical_failures)}", err=True)
        sys.exit(1)
    if not verbose:
        click.echo("healthcheck OK")


@cli.command("selftest")
def cmd_selftest() -> None:
    """Run every self-check and print results (does not block on any failure)."""
    results = selftest_mod.run_all()
    for r in results:
        prefix = "OK  " if r.ok else "WARN"
        click.echo(f"{prefix} {r.name}: {r.detail}")


@cli.command("config-backup")
def cmd_config_backup() -> None:
    """Build + upload a ZIP of /etc/netmon/* to the SFTP _config/ tree."""
    try:
        remote = config_backup_mod.upload_backup()
        click.echo(f"OK   uploaded to {remote}")
    except Exception as exc:
        click.echo(f"FAIL config-backup: {exc}", err=True)
        sys.exit(2)


@cli.command("checkin")
def cmd_checkin() -> None:
    """Check in with the dashboard: fetch desired config + run queued commands.

    Outbound HTTPS only. Exits 10 if config changed (the host wrapper restarts
    the collector so the new config takes effect); 0 otherwise; 1 on error.
    """
    from . import checkin as checkin_mod

    sys.exit(checkin_mod.run_checkin())


@cli.command("speedtest")
def cmd_speedtest() -> None:
    """Run a public internet speed test (Cloudflare) and print the result.

    Manual/diagnostic use; scheduled runs are driven by the check-in loop
    (NETMON_SPEEDTEST_*). Does NOT report to the dashboard — use the dashboard's
    'Run now' for that.
    """
    from .speedtest import run_speedtest

    res = run_speedtest("cloudflare")
    if res.get("ok"):
        click.echo(
            f"OK   cloudflare: down={res.get('download_mbps')} Mbps  up={res.get('upload_mbps')} Mbps  "
            f"latency={res.get('latency_ms')} ms  jitter={res.get('jitter_ms')} ms"
        )
        sys.exit(0)
    click.echo(f"FAIL cloudflare: {res.get('error')}", err=True)
    sys.exit(1)


@cli.command("console-poll")
def cmd_console_poll() -> None:
    """Fast interactive-command poll: pick up + start a live console quickly.

    Runs every ~30s (netmon-console-poll.timer) — much lighter than `checkin`.
    Only looks for an `open-console` command and spawns the session, so a live
    console pairs in seconds instead of after the next ~10-min check-in.
    Outbound HTTPS only. Always exits 0 (best-effort).
    """
    from . import checkin as checkin_mod

    sys.exit(checkin_mod.run_console_poll())


@cli.command("console-session", hidden=True)
@click.option("--broker", required=True, help="Broker WSS base URL (…/console).")
@click.option("--sid", required=True, help="Session id.")
def cmd_console_session(broker: str, sid: str) -> None:
    """Run a remote-console session (browser-SSH, sensor side).

    Spawned as a DETACHED subprocess by the check-in `open-console` handler — not
    meant to be run by hand. The one-time token is read from NETMON_CONSOLE_TOKEN
    (kept off the process argv). Dials the broker over WSS and services allow-
    listed read-only diagnostics until the session ends.
    """
    from . import remote_console

    sys.exit(remote_console.run_from_env(broker, sid))


@cli.command("config-list")
def cmd_config_list() -> None:
    """List available config backups on the SFTP server for this box."""
    try:
        backups = config_backup_mod.list_available_backups()
    except Exception as exc:
        click.echo(f"FAIL config-list: {exc}", err=True)
        sys.exit(2)
    if not backups:
        click.echo("(no backups found)")
        return
    for b in backups:
        click.echo(b)


@cli.command("config-download")
@click.option("--date", default=None,
              help="YYYY-MM-DD. Defaults to most recent available.")
@click.option("--out", default="/var/lib/netmon/config-restore.zip",
              show_default=True, help="Where to write the downloaded ZIP.")
def cmd_config_download(date: str | None, out: str) -> None:
    """Download a config backup ZIP to disk (host script then unzips it)."""
    from pathlib import Path
    try:
        path = config_backup_mod.download_backup(date=date, out_path=Path(out))
        click.echo(f"OK   {path}")
    except Exception as exc:
        click.echo(f"FAIL config-download: {exc}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    cli()
