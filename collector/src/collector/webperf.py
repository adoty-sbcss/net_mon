"""Website / end-user experience probes (PERF-5).

Synthetic web monitoring from the sensor's vantage point: for a district-managed
list of URLs, one `curl` per URL captures the full load waterfall — DNS lookup,
TCP connect, TLS handshake, time-to-first-byte, total time — plus the HTTP status
and download speed. That breakdown is the value: it says WHERE a slow site is slow
(name resolution vs the network path vs the origin server), not just "slow".

Times are reported CUMULATIVE from the start of the request (matching curl's own
timing model): dns <= tcp <= tls <= ttfb <= total. The dashboard can render the
waterfall or the per-phase deltas from these.

`srcip` binds the request to a source IP (`curl --interface`) so the SAME prober can
later run over a Wi-Fi analysis radio via the source-routing policy table (WIFI-6);
for the wired path it's left None and traffic takes the box's normal uplink.
"""
from __future__ import annotations

import subprocess

import structlog

log = structlog.get_logger(__name__)

# One space-separated line of curl timing vars — cheap + no body downloaded past the
# size curl needs. All times are seconds (converted to ms below).
_CURL_FMT = (
    "%{time_namelookup} %{time_connect} %{time_appconnect} "
    "%{time_starttransfer} %{time_total} %{http_code} %{size_download} %{speed_download}"
)


def probe_url(url: str, timeout: int = 15, srcip: str | None = None) -> dict:
    """Measure one URL's load waterfall via curl. Never raises — returns an
    ``{"ok": False, "error": …}`` shape on any failure."""
    cmd = [
        "curl", "-sS", "-o", "/dev/null", "-L",
        "--proto", "=http,https", "--proto-redir", "=http,https",
        "--max-time", str(timeout),
        "-w", _CURL_FMT,
    ]
    if srcip:
        cmd += ["--interface", srcip]
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except FileNotFoundError:
        return {"url": url, "ok": False, "error": "curl not installed"}
    except subprocess.TimeoutExpired:
        return {"url": url, "ok": False, "error": "timeout"}
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "ok": False, "error": str(exc)[:200]}

    parts = (proc.stdout or "").strip().split()
    if len(parts) < 8:
        err = (proc.stderr or "no timing output").strip()[:200] or "no timing output"
        return {"url": url, "ok": False, "error": err}

    def _ms(s: str) -> float | None:
        try:
            v = float(s)
        except ValueError:
            return None
        return round(v * 1000, 1)

    ns, con, app, ttfb, tot, code, size, speed = parts[:8]
    http = int(code) if code.isdigit() else 0
    ok = 200 <= http < 400
    tls = _ms(app)
    return {
        "url": url,
        "ok": ok,
        "dns_ms": _ms(ns),
        "tcp_ms": _ms(con),
        # appconnect is 0 on a plain-HTTP URL (no TLS) — report None, not 0.
        "tls_ms": tls if (tls or 0) > 0 else None,
        "ttfb_ms": _ms(ttfb),
        "total_ms": _ms(tot),
        "http_status": http,
        "size_bytes": int(float(size)) if size.replace(".", "", 1).isdigit() else None,
        "speed_mbps": round(float(speed) * 8 / 1_000_000, 2) if speed.replace(".", "", 1).isdigit() else None,
        "error": None if ok else (f"HTTP {http}" if http else "no response"),
    }


def probe_urls(urls: list[str], timeout: int = 15, srcip: str | None = None) -> list[dict]:
    """Probe each URL in turn (serial — these are light + we don't want to hammer)."""
    out: list[dict] = []
    for u in urls:
        u = (u or "").strip()
        if not u:
            continue
        # Be forgiving: bare hosts get https://.
        if "://" not in u:
            u = "https://" + u
        out.append(probe_url(u, timeout=timeout, srcip=srcip))
    return out
