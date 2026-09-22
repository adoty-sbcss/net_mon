"""PUB-21 egress self-report: validated, tri-state, cached.

The shapes under test are the ones this repo has shipped wrong before:

  * a fallback chain that validates only its LAST candidate prefers a bad early
    answer (a portal echoing a private address) over a good late one;
  * "no IP" must not collapse a refusal, a dead link and "this box simply has no
    IPv6" into one state — a refusing source and a broken link look identical
    otherwise (see test_speedtest_unavailable.py);
  * the value is cached, so a three-minute check-in is not a three-minute poll,
    and a failed measurement retries sooner than a good one refreshes.

Pure unit tests: the fetcher is injected, no network.
"""
from __future__ import annotations

import errno
import json
import ssl
import urllib.error
from pathlib import Path

from collector import egress
from collector.egress import (
    _HOSTNAME_TRACE,
    STATUS_FAILED,
    STATUS_NONE,
    STATUS_OK,
    STATUS_REFUSED,
    V4_SOURCES,
    V6_SOURCES,
    measure_family,
    observe,
    parse_trace,
)

TRACE_V4 = "fl=1\nh=1.1.1.1\nip=104.16.123.96\nts=1\ncolo=LAX\n"
TRACE_V6 = "fl=1\nip=2001:4860:4860::8888\ncolo=LAX\n"


def _fetcher(table: dict[str, object]):
    calls: list[str] = []

    def fetch(url: str) -> tuple[int, str]:
        calls.append(url)
        # A source the test didn't script is unreachable (not an answer).
        v = table.get(url, urllib.error.URLError(TimeoutError("unscripted")))
        if isinstance(v, BaseException):
            raise v
        assert isinstance(v, tuple)
        return v  # type: ignore[return-value]

    return fetch, calls


def _no_route() -> urllib.error.URLError:
    return urllib.error.URLError(OSError(errno.ENETUNREACH, "Network is unreachable"))


# --- parse_trace --------------------------------------------------------------

def test_parse_accepts_global_address_of_the_requested_family():
    assert parse_trace(TRACE_V4, 4) == "104.16.123.96"
    assert parse_trace(TRACE_V6, 6) == "2001:4860:4860::8888"


def test_parse_rejects_wrong_family():
    assert parse_trace(TRACE_V4, 6) is None
    assert parse_trace(TRACE_V6, 4) is None


def test_parse_rejects_every_non_public_range():
    for bad in ("10.1.2.3", "192.168.0.10", "172.16.5.4", "100.64.1.1", "127.0.0.1",
                "169.254.1.1", "192.0.2.1", "198.51.100.7", "0.0.0.0", "255.255.255.255"):
        assert parse_trace(f"ip={bad}\n", 4) is None, bad
    for bad in ("::1", "fe80::1", "fd00::1", "2001:db8::1"):
        assert parse_trace(f"ip={bad}\n", 6) is None, bad


def test_parse_rejects_garbage_and_missing_line():
    assert parse_trace("<html>Welcome to Guest Wi-Fi</html>", 4) is None
    assert parse_trace("ip=not-an-address\n", 4) is None
    assert parse_trace("", 4) is None


def test_parse_canonicalises_ipv6():
    assert parse_trace("ip=2001:0db9:0000:0000:0000:0000:0000:0001\n", 6) == "2001:db9::1"


# --- measure_family: the fallback chain ---------------------------------------

def test_bad_early_answer_does_not_beat_a_good_late_one():
    # First source is a middlebox echoing a private address with a 200.
    fetch, calls = _fetcher({
        V4_SOURCES[0]: (200, "ip=10.0.0.5\n"),
        V4_SOURCES[1]: (200, TRACE_V4),
    })
    r = measure_family(4, V4_SOURCES, fetch)
    assert r == {"ip": "104.16.123.96", "status": STATUS_OK}
    assert calls == list(V4_SOURCES[:2])


def test_first_valid_answer_short_circuits():
    fetch, calls = _fetcher({V4_SOURCES[0]: (200, TRACE_V4)})
    assert measure_family(4, V4_SOURCES, fetch)["ip"] == "104.16.123.96"
    assert calls == [V4_SOURCES[0]]


def test_http_refusal_is_refused_not_failed():
    err = urllib.error.HTTPError(V4_SOURCES[0], 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]
    fetch, _ = _fetcher({V4_SOURCES[0]: err, V4_SOURCES[1]: (200, "<html>blocked</html>")})
    r = measure_family(4, V4_SOURCES, fetch)
    assert r["status"] == STATUS_REFUSED and r["ip"] is None
    assert "HTTP 429" in r["error"] and "no usable ip=" in r["error"]


def test_transport_failure_everywhere_is_failed():
    fetch, _ = _fetcher({u: urllib.error.URLError(TimeoutError("timed out")) for u in V4_SOURCES})
    r = measure_family(4, V4_SOURCES, fetch)
    assert r["status"] == STATUS_FAILED and r["ip"] is None


def test_mixed_refusal_and_transport_failure_is_refused():
    # One source answered (with nothing usable) — the link reached the internet.
    fetch, _ = _fetcher({
        V4_SOURCES[0]: urllib.error.URLError(TimeoutError("timed out")),
        V4_SOURCES[1]: (503, ""),
    })
    assert measure_family(4, V4_SOURCES, fetch)["status"] == STATUS_REFUSED


def test_no_ipv6_route_is_none_not_a_fault():
    fetch, _ = _fetcher({u: _no_route() for u in V6_SOURCES})
    r = measure_family(6, V6_SOURCES, fetch)
    assert r == {"ip": None, "status": STATUS_NONE}


def test_no_ipv4_route_is_still_failed():
    # "none" is an IPv6-only state: a box with no IPv4 path is genuinely broken.
    fetch, _ = _fetcher({u: _no_route() for u in V4_SOURCES})
    assert measure_family(4, V4_SOURCES, fetch)["status"] == STATUS_FAILED


# --- observe: caching ---------------------------------------------------------

def _all_ok():
    t: dict[str, object] = {u: (200, TRACE_V4) for u in V4_SOURCES}
    t.update({u: _no_route() for u in V6_SOURCES})
    return t


def test_observe_payload_shape(tmp_path: Path):
    fetch, _ = _fetcher(_all_ok())
    p = observe(fetch=fetch, cache_path=tmp_path / "egress.json", now=1_790_000_000.0)
    assert p["source"] == "cloudflare-trace"
    assert p["ipv4"] == "104.16.123.96" and p["ipv4Status"] == STATUS_OK
    assert p["ipv6"] is None and p["ipv6Status"] == STATUS_NONE
    assert p["observedAt"].startswith("2026-09-21T")
    assert "errors" not in p


def test_fresh_ok_cache_is_served_without_a_fetch(tmp_path: Path):
    cache = tmp_path / "egress.json"
    fetch, calls = _fetcher(_all_ok())
    first = observe(fetch=fetch, cache_path=cache, now=1000.0)
    n = len(calls)
    again = observe(fetch=fetch, cache_path=cache, now=1000.0 + egress.REFRESH_SEC - 1)
    assert len(calls) == n, "re-measured inside the refresh window"
    # The reading keeps its ORIGINAL timestamp, so the dashboard sees its age.
    assert again["observedAt"] == first["observedAt"]


def test_stale_cache_re_measures(tmp_path: Path):
    cache = tmp_path / "egress.json"
    fetch, calls = _fetcher(_all_ok())
    observe(fetch=fetch, cache_path=cache, now=1000.0)
    n = len(calls)
    observe(fetch=fetch, cache_path=cache, now=1000.0 + egress.REFRESH_SEC + 1)
    assert len(calls) > n


def test_failed_measurement_retries_sooner(tmp_path: Path):
    cache = tmp_path / "egress.json"
    table: dict[str, object] = {u: urllib.error.URLError(TimeoutError("t")) for u in V4_SOURCES}
    table.update({u: _no_route() for u in V6_SOURCES})
    fetch, calls = _fetcher(table)
    observe(fetch=fetch, cache_path=cache, now=1000.0)
    n = len(calls)
    observe(fetch=fetch, cache_path=cache, now=1000.0 + egress.RETRY_SEC - 1)
    assert len(calls) == n, "a failed reading was not cached at all (every check-in would re-probe)"
    observe(fetch=fetch, cache_path=cache, now=1000.0 + egress.RETRY_SEC + 1)
    assert len(calls) > n, "a failed reading was held for the full refresh window"


def test_clock_stepping_backwards_re_measures(tmp_path: Path):
    cache = tmp_path / "egress.json"
    fetch, calls = _fetcher(_all_ok())
    observe(fetch=fetch, cache_path=cache, now=5000.0)
    n = len(calls)
    observe(fetch=fetch, cache_path=cache, now=100.0)
    assert len(calls) > n


def test_corrupt_cache_is_ignored(tmp_path: Path):
    cache = tmp_path / "egress.json"
    cache.write_text("{not json")
    fetch, _ = _fetcher(_all_ok())
    assert observe(fetch=fetch, cache_path=cache, now=1000.0)["ipv4"] == "104.16.123.96"
    assert json.loads(cache.read_text())["v4"]["status"] == STATUS_OK


def test_unwritable_cache_does_not_raise(tmp_path: Path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    fetch, _ = _fetcher(_all_ok())
    # parent "directory" is a regular file -> mkdir/write fails; observe must still answer
    assert observe(fetch=fetch, cache_path=blocker / "egress.json", now=1000.0)["ipv4"] == "104.16.123.96"


def test_errors_are_reported_per_family(tmp_path: Path):
    err = urllib.error.HTTPError(V4_SOURCES[0], 429, "x", {}, None)  # type: ignore[arg-type]
    table: dict[str, object] = {V4_SOURCES[0]: err, V4_SOURCES[1]: err}
    table.update({u: _no_route() for u in V6_SOURCES})
    fetch, _ = _fetcher(table)
    p = observe(fetch=fetch, cache_path=tmp_path / "e.json", now=1000.0)
    assert p["ipv4"] is None and p["ipv4Status"] == STATUS_REFUSED
    assert "HTTP 429" in p["errors"]["ipv4"]
    assert "ipv6" not in p.get("errors", {})


def test_filtered_anycast_falls_back_to_the_hostname():
    # A district firewall that blocks 1.1.1.1/1.0.0.1 (DoH-bypass control) still
    # lets ordinary Cloudflare-fronted sites through.
    blocked = urllib.error.URLError(ConnectionResetError("reset"))
    fetch, _ = _fetcher({V4_SOURCES[0]: blocked, V4_SOURCES[1]: blocked, _HOSTNAME_TRACE: (200, TRACE_V4)})
    assert measure_family(4, V4_SOURCES, fetch) == {"ip": "104.16.123.96", "status": STATUS_OK}


def test_hostname_answer_of_the_other_family_does_not_fill_this_one():
    # The box prefers IPv6, so the hostname trace answers with a v6 address; it
    # must not be reported as the IPv4 egress — and it is not a refusal either.
    blocked = urllib.error.URLError(ConnectionResetError("reset"))
    fetch, _ = _fetcher({V4_SOURCES[0]: blocked, V4_SOURCES[1]: blocked, _HOSTNAME_TRACE: (200, TRACE_V6)})
    r = measure_family(4, V4_SOURCES, fetch)
    assert r["ip"] is None and r["status"] == STATUS_FAILED


def test_hostname_refusal_never_decides_a_family_status():
    # Dual-stack box preferring v6; the anycast literals are RST by the firewall
    # and the hostname is 403'd by a filter over v6. No IPv4 source answered, so
    # IPv4 is `failed` — the hostname's 403 is noted, not charged to IPv4.
    blocked = urllib.error.URLError(ConnectionResetError("reset"))
    err = urllib.error.HTTPError(_HOSTNAME_TRACE, 403, "Forbidden", {}, None)  # type: ignore[arg-type]
    fetch, _ = _fetcher({V4_SOURCES[0]: blocked, V4_SOURCES[1]: blocked, _HOSTNAME_TRACE: err})
    r = measure_family(4, V4_SOURCES, fetch)
    assert r["status"] == STATUS_FAILED
    assert "hostname: HTTP 403" in r["error"]


def test_v4_only_box_is_none_even_when_the_hostname_is_filtered():
    # A healthy v4-only site behind a web filter must not read as an IPv6 fault.
    err = urllib.error.HTTPError(_HOSTNAME_TRACE, 403, "Forbidden", {}, None)  # type: ignore[arg-type]
    for hostname_answer in (err, (200, "<html>Blocked by policy</html>"), urllib.error.URLError(TimeoutError("t"))):
        table: dict[str, object] = {u: _no_route() for u in V6_SOURCES[:2]}
        table[_HOSTNAME_TRACE] = hostname_answer
        fetch, _ = _fetcher(table)
        assert measure_family(6, V6_SOURCES, fetch)["status"] == STATUS_NONE, hostname_answer


def test_tls_interception_is_refused_not_failed():
    # A decrypting K-12 web filter answers with its own certificate: the source
    # was reached and could not be trusted — not a dead link.
    bad = urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))
    fetch, _ = _fetcher({u: bad for u in V4_SOURCES})
    r = measure_family(4, V4_SOURCES, fetch)
    assert r["status"] == STATUS_REFUSED
    assert "TLS: SSLCertVerificationError" in r["error"]


def test_no_v6_route_is_none_even_when_the_hostname_answers_over_v4():
    table: dict[str, object] = {u: _no_route() for u in V6_SOURCES[:2]}
    table[_HOSTNAME_TRACE] = (200, TRACE_V4)
    fetch, _ = _fetcher(table)
    assert measure_family(6, V6_SOURCES, fetch) == {"ip": None, "status": STATUS_NONE}


def test_null_family_in_cache_does_not_raise(tmp_path: Path):
    cache = tmp_path / "egress.json"
    cache.write_text(json.dumps({"measuredAtEpoch": 1000.0, "v4": None, "v6": None}))
    fetch, _ = _fetcher(_all_ok())
    assert observe(fetch=fetch, cache_path=cache, now=1001.0)["ipv4"] == "104.16.123.96"
