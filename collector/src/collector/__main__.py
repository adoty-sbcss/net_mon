from __future__ import annotations

import logging
import sys

import click
import structlog

from . import __version__
from .bundle import build_bundle
from .config import get_settings
from .db import fetch_scan, list_scan_runs, wait_for_db
from .poller import run_poller
from .scan import run_scan
from . import uploader as uploader_mod


def _configure_logging() -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


log = structlog.get_logger(__name__)


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """App_Mon collector — discovers network state and exports evidence bundles."""
    _configure_logging()


@cli.command("run")
def cmd_run() -> None:
    """Run the interface poller and the hourly SFTP uploader."""
    settings = get_settings()
    log.info("collector starting",
             mode=settings.mode,
             poll_interval=settings.poll_interval,
             sftp_enabled=settings.sftp_enabled,
             device=uploader_mod.device_name())
    wait_for_db()
    uploader_mod.start_in_background()
    run_poller()


@cli.command("scan")
@click.argument("interface")
@click.option("--reason", default="manual", help="Trigger reason recorded with the scan.")
def cmd_scan(interface: str, reason: str) -> None:
    """Run a one-off scan on INTERFACE."""
    wait_for_db()
    scan_id = run_scan(interface=interface, trigger_reason=reason, force=True)
    if scan_id is None:
        click.echo("scan did not run", err=True)
        sys.exit(2)
    click.echo(f"scan complete, id={scan_id}")


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
              help="Output path. Default: $APPMON_BUNDLE_DIR/network-scan-<host>-<ts>.zip")
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
    """Test the SFTP connection: connect, authenticate, list the remote path."""
    ok, msg = uploader_mod.test_connection()
    click.echo(("OK   " if ok else "FAIL ") + msg)
    sys.exit(0 if ok else 2)


@cli.command("upload-now")
def cmd_upload_now() -> None:
    """Build and upload the previous hour's bundle right now, without waiting."""
    wait_for_db()
    now = uploader_mod._local_now()
    # The most recent top-of-hour that has already passed — closes the
    # just-completed hour. If it's 14:23 now, this is 14:00, and the
    # bundle covers 13:00 → 14:00.
    window_end = now.replace(minute=0, second=0, microsecond=0)
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


if __name__ == "__main__":
    cli()
