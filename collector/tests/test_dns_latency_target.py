"""The latency probe's 'dns' target must be a REAL resolver, not the local stub.

The collector runs `network_mode: host`, so its /etc/resolv.conf is literally the
host's — and on these Ubuntu boxes that file names systemd-resolved's stub,
127.0.0.53. The probe therefore pinged the sensor's own loopback and could not
report anything but a perfect DNS path. Confirmed live 2026-09-05 on three
districts at once (Cucamonga SD, Trona USD, SBCSS), every one of them reading
`Dns | 127.0.0.53 | 0.1 ms | 0.0 ms | 0.0%`. One of three latency signals was
inert fleet-wide while rendering as measured health — the failure mode this
product explicitly forbids.

The rules under test:
  * the real upstreams (/run/systemd/resolve/resolv.conf, mounted into the
    container) are preferred over the stub /etc/resolv.conf names;
  * a loopback nameserver is NEVER pinged, wherever in the search order it sits;
  * stub-only boxes report a THIRD state — not ok, every measurement NULL — which
    is distinguishable on the wire from a target that was probed and lost 100%;
  * an absent or directory-shaped mount is skipped, not fatal.

Pure unit tests: the resolver file paths are redirected to tmp_path and the ping
itself is monkeypatched, so there is no network and no /etc.
"""

from __future__ import annotations

from types import SimpleNamespace

import collector as collector_pkg
import collector.latency  # noqa: F401  — so the package attribute exists to patch
from collector import checkin

# Verbatim from Monitor1, 2026-09-05 — copied off the box, not typed from memory.
# The comment banner matters: it is what a naive "first nameserver" reader trips
# over, and the trailing `search` line must not be mistaken for a nameserver.
_STUB_RESOLV = """\
# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# Run "resolvectl status" to see details about the uplink DNS servers
# currently in use.

nameserver 127.0.0.53
options edns0 trust-ad
search sbcss.org
"""

_UPSTREAM_RESOLV = """\
# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.

nameserver 163.150.1.36
nameserver 163.150.1.32
search sbcss.org
"""


def _paths(monkeypatch, tmp_path, *, systemd=None, host=None, own=None):
    """Redirect the three resolver paths; a None entry is left absent on disk."""
    names = ("systemd.conf", "host.conf", "own.conf")
    for name, text in zip(names, (systemd, host, own), strict=True):
        if text is not None:
            (tmp_path / name).write_text(text)
    monkeypatch.setattr(
        checkin, "_RESOLV_CONF_PATHS", tuple(tmp_path / n for n in names)
    )


# --- picking the target -----------------------------------------------------


def test_upstream_is_preferred_over_the_stub(monkeypatch, tmp_path):
    """The exact Monitor1 layout: the stub file is present and readable, and the
    upstream file must still win."""
    _paths(monkeypatch, tmp_path, systemd=_UPSTREAM_RESOLV, own=_STUB_RESOLV)
    assert checkin._dns_latency_target() == ("163.150.1.36", None)


def test_loopback_is_never_the_target_even_when_it_is_listed_first(
    monkeypatch, tmp_path
):
    """Order within a single file must not rescue the stub either — the rule is
    'first NON-loopback', not 'first line of the best file'."""
    _paths(
        monkeypatch,
        tmp_path,
        systemd="nameserver 127.0.0.53\nnameserver 10.1.1.5\n",
    )
    assert checkin._dns_latency_target() == ("10.1.1.5", None)


def test_stub_only_box_reports_unavailable_not_a_target(monkeypatch, tmp_path):
    """The third state. `host` still names the stub so the row identifies what the
    box is pointed at, but a reason is set, and _maybe_latency must not ping it."""
    _paths(monkeypatch, tmp_path, own=_STUB_RESOLV)
    host, reason = checkin._dns_latency_target()
    assert host == "127.0.0.53"
    assert reason is not None and "not measured" in reason


def test_no_resolver_at_all_asserts_nothing(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    assert checkin._dns_latency_target() == (None, None)


def test_a_directory_shaped_mount_is_skipped_not_fatal(monkeypatch, tmp_path):
    """Docker materializes a bind mount whose source is missing as an empty
    DIRECTORY, so the systemd path can be a dir on a box with no systemd-resolved.
    read_text() then raises IsADirectoryError — an OSError, not FileNotFoundError."""
    (tmp_path / "systemd.conf").mkdir()
    (tmp_path / "own.conf").write_text("nameserver 10.2.2.9\n")
    monkeypatch.setattr(
        checkin,
        "_RESOLV_CONF_PATHS",
        (tmp_path / "systemd.conf", tmp_path / "missing.conf", tmp_path / "own.conf"),
    )
    assert checkin._dns_latency_target() == ("10.2.2.9", None)


def test_ipv6_upstream_is_usable_and_ipv6_loopback_is_not(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path, systemd="nameserver ::1\nnameserver 2001:db8::53\n")
    assert checkin._dns_latency_target() == ("2001:db8::53", None)


def test_garbage_nameserver_lines_are_ignored(monkeypatch, tmp_path):
    """Nothing that is not a literal IP address may be returned. `-f` in particular
    would turn the collector's root `ping` into a flood ping if it reached the argv
    as an option rather than the bare operand.

    Mutation-checked: widening _NAMESERVER_RE to (\\S+) does NOT break this, because
    ipaddress.ip_address() — not the regex — is what actually rejects these. The
    source comment says so; this test pins the property, not the mechanism.
    """
    _paths(
        monkeypatch,
        tmp_path,
        systemd=(
            "nameserver -f\n"           # would flood-ping as root if it got through
            "nameserver 999.1.1.1\n"    # parses as no address family
            "#nameserver 10.0.0.1\n"    # commented out
            "nameserver\n"              # no value
            "nameserver 10.3.3.3\n"
        ),
    )
    assert checkin._dns_latency_target() == ("10.3.3.3", None)


def test_a_nameserver_line_with_trailing_junk_is_ignored(monkeypatch, tmp_path):
    """This one IS the regex's contribution: anchored and single-token, so a line
    carrying an extra field is skipped rather than half-read."""
    _paths(
        monkeypatch,
        tmp_path,
        systemd="nameserver 10.4.4.4 extra\nnameserver 10.5.5.5\n",
    )
    assert checkin._dns_latency_target() == ("10.5.5.5", None)


def test_the_production_search_order_puts_the_real_upstreams_first(monkeypatch):
    """The whole fix is the ORDER of the REAL constant, and every other test in
    this file monkeypatches that constant away — so without this one, reversing the
    production order breaks nothing (confirmed by mutation).

    /etc/host-systemd-resolv.conf is the container's view of the host's
    /run/systemd/resolve/resolv.conf, the only file that names the district's real
    upstreams; /etc/resolv.conf names the 127.0.0.53 stub and must come last.
    """
    from collector.discovery import dns_health

    names = [p.as_posix() for p in checkin._RESOLV_CONF_PATHS]
    assert names[0] == "/etc/host-systemd-resolv.conf"
    assert names[-1] == "/etc/resolv.conf"
    # The source says "keep the two lists in step" — enforce it rather than trust it.
    assert names == [p.as_posix() for p in dns_health._HOST_RESOLV_CONF_PATHS]


# --- what reaches the wire --------------------------------------------------


def _latency_harness(monkeypatch):
    """Run _maybe_latency with ping and the reporter both captured."""
    pinged: list[tuple[str, str]] = []
    reported: list[list[dict]] = []

    def _probe(targets, count=10):
        pinged.extend(targets)
        return [
            {"label": lbl, "host": h, "ok": True, "latency_ms": 1.0,
             "jitter_ms": 0.1, "loss_pct": 0.0}
            for lbl, h in targets
        ]

    fake_latency = SimpleNamespace(
        probe_latency=_probe, default_gateway=lambda: "10.0.0.1"
    )
    # _maybe_latency does `from . import latency`, which resolves to the ATTRIBUTE
    # on the already-imported `collector` package — patching sys.modules would be
    # silently ignored here.
    monkeypatch.setattr(collector_pkg, "latency", fake_latency)
    monkeypatch.setattr(
        checkin,
        "_report_latency",
        lambda url, tok, results, trig, spool_only=False: reported.append(results),
    )
    settings = SimpleNamespace(latency_enabled=True, latency_targets="1.1.1.1")
    return settings, pinged, reported


def test_stub_only_box_emits_an_unavailable_row_and_never_pings_loopback(
    monkeypatch, tmp_path
):
    _paths(monkeypatch, tmp_path, own=_STUB_RESOLV)
    settings, pinged, reported = _latency_harness(monkeypatch)

    checkin._maybe_latency("https://dash", "tok", settings)

    assert "127.0.0.53" not in [h for _, h in pinged], "the loopback stub was pinged"
    assert [lbl for lbl, _ in pinged] == ["internet", "gateway"]

    dns_rows = [r for r in reported[0] if r["label"] == "dns"]
    assert len(dns_rows) == 1
    row = dns_rows[0]
    assert row["ok"] is False
    assert row["host"] == "127.0.0.53"
    # Every measurement NULL. lossPct in particular: 100.0 would mean "probed and
    # lost everything", which is a DIFFERENT finding from "never measured".
    assert row["latency_ms"] is None
    assert row["jitter_ms"] is None
    assert row["loss_pct"] is None
    assert row["error"]


def test_the_dns_row_survives_when_the_resolver_IS_the_gateway(monkeypatch, tmp_path):
    """probe_latency de-dupes by host. On a small network the router is often also
    the resolver, so the dns target collides with the gateway and its row used to
    vanish outright — an absence the operator cannot distinguish from "nobody
    looked". It must still be reported, carrying the measurement that was taken,
    and the identical address must NOT be pinged twice.

    Uses the REAL probe_latency with only _ping stubbed: a fake probe_latency does
    not de-dupe, so it would pass this test without exercising the bug at all.
    """
    from collector import latency as real_latency

    _paths(monkeypatch, tmp_path, systemd="nameserver 10.0.0.1\n")
    pings: list[str] = []

    def _fake_ping(host, count=10):
        pings.append(host)
        return {"host": host, "ok": True, "latency_ms": 0.9,
                "jitter_ms": 0.2, "loss_pct": 0.0}

    monkeypatch.setattr(real_latency, "_ping", _fake_ping)
    monkeypatch.setattr(real_latency, "default_gateway", lambda: "10.0.0.1")
    monkeypatch.setattr(collector_pkg, "latency", real_latency)
    reported: list[list[dict]] = []
    monkeypatch.setattr(
        checkin, "_report_latency",
        lambda url, tok, results, trig, spool_only=False: reported.append(results),
    )

    checkin._maybe_latency(
        "https://dash", "tok",
        SimpleNamespace(latency_enabled=True, latency_targets="1.1.1.1"),
    )

    assert pings.count("10.0.0.1") == 1, "the shared address was pinged twice"
    labels = [r["label"] for r in reported[0]]
    assert labels.count("dns") == 1, f"the dns row vanished: {labels}"
    dns_row = next(r for r in reported[0] if r["label"] == "dns")
    assert dns_row["host"] == "10.0.0.1"
    assert dns_row["latency_ms"] == 0.9   # the real measurement, not a fabrication
    assert dns_row["ok"] is True


def test_healthy_box_pings_the_real_upstream_and_emits_no_unavailable_row(
    monkeypatch, tmp_path
):
    _paths(monkeypatch, tmp_path, systemd=_UPSTREAM_RESOLV, own=_STUB_RESOLV)
    settings, pinged, reported = _latency_harness(monkeypatch)

    checkin._maybe_latency("https://dash", "tok", settings)

    assert ("dns", "163.150.1.36") in pinged
    dns_rows = [r for r in reported[0] if r["label"] == "dns"]
    assert len(dns_rows) == 1
    assert dns_rows[0]["ok"] is True
    assert dns_rows[0]["host"] == "163.150.1.36"
