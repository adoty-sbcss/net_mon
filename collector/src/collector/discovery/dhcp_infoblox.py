"""Authoritative DHCP intel from an Infoblox grid over its REST API (WAPI) — DHCP-7.

The Windows path (``dhcp_server.py``) asks the DHCP server itself. Infoblox is
different in one way that shapes everything here: the API lives on the **Grid
Master**, while the address that hands out leases (the one rogue detection
matches) is a **member**. So a target carries two addresses —

  * ``server_ip`` — the member that answers DHCP. Identity, as for Windows.
  * ``api_host``  — where WAPI answers (the Grid Master). Defaults to server_ip.

and the collector asks the Grid Master for the objects *served by that member*.

What one pass reads (all GET, read-only; a WAPI read-only account is enough):

  * ``member:dhcpproperties`` for the member — host name, member-level options,
    totals. No match means the address is not a DHCP member of this grid.
  * ``grid:dhcpproperties`` — grid-wide options the member inherits.
  * ``dhcpfailover`` — failover associations naming the member, with its state.
  * ``range`` — every DHCP range; kept when served by the member directly or by a
    failover association that includes it. ``dynamic_hosts`` / ``total_hosts``
    are plain counts; utilization is computed from them rather than read from
    ``dhcp_utilization``, whose documented scale ("multiplied by 1000") and the
    values seen in the field disagree.
  * ``network`` — the networks those ranges sit in. One network = one scope in
    the shared report shape (the Windows scope's equivalent).
  * ``fixedaddress`` — reservations in those networks.
  * ``lease`` (ACTIVE and STATIC) — only to tell whether a reserved address is in
    use and by whom. WAPI cannot filter leases by serving member, so the sensor
    filters; if the lease read is cut short by the page cap, reservations are
    left out rather than all reported as unused.

Output: the same entry shape the Windows probe produces (see dhcp_server.py), so
the dashboard ingests it unchanged; ``transport`` is ``"wapi"``.

TLS: Infoblox ships a self-signed certificate, so ordinary verification fails on
most installs. The owner's choice (2026-11-12) is **pin on first use**: the
first connection records the certificate's SHA-256 fingerprint and every later
connection must present the same one. The dashboard holds the pin of record and
pushes it as ``tls_fingerprint``; until it has one, the sensor keeps its own in
``PINS_FILE`` so the second run is already pinned. A changed certificate is the
``cert_changed`` error, carrying the new fingerprint (``tls_fingerprint_seen``)
so a person can compare it and accept it in Settings. Credentials are only ever
sent over a connection pinned to the expected fingerprint.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import ssl
from pathlib import Path
from typing import Any

import structlog

from .dhcp_server import _classify, _fail, _ok

log = structlog.get_logger(__name__)

# The sensor's own first-use pins, keyed "host:port". Holds fingerprints only
# (public certificate hashes), but kept 0600 beside the targets file anyway.
PINS_FILE = Path("/var/lib/netmon/dhcp-tls-pins.json")

# WAPI 2.7 is in every NIOS from 8.2 on and has every field read below.
WAPI_VERSION = "v2.7"
_PAGE_SIZE = 1000
# Hard cap on pages per object, so a huge grid can't eat the pass budget. 100 x
# 1000 leases is far past a K-12 district.
_MAX_PAGES = 100
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class _WapiError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Certificate pinning
# ---------------------------------------------------------------------------


def _norm_fp(fp: Any) -> str:
    """Lowercase hex, no separators — 'AB:CD:..' and 'abcd..' compare equal."""
    return "".join(ch for ch in str(fp or "").lower() if ch in "0123456789abcdef")


def _observed_fingerprint(host: str, port: int, timeout: int) -> str:
    """SHA-256 of the certificate the server presents right now (no trust check —
    this is only ever compared against a pin or recorded as one)."""
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def _load_pins() -> dict[str, str]:
    try:
        data = json.loads(PINS_FILE.read_text())
        return {str(k): _norm_fp(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # noqa: BLE001 — a corrupt pin file must not wedge collection
        log.warning("could not read dhcp tls pins", error=str(exc))
        return {}


def _save_pin(key: str, fp: str) -> None:
    pins = _load_pins()
    if pins.get(key) == fp:
        return
    pins[key] = fp
    try:
        PINS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = PINS_FILE.with_suffix(".json.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(pins))
        os.replace(str(tmp), str(PINS_FILE))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not write dhcp tls pins", error=str(exc))


def _pinned_session(fingerprint: str, user: str, password: str) -> Any:
    """A requests session that only completes a TLS handshake with a certificate
    whose SHA-256 matches `fingerprint` (urllib3 checks it after the handshake,
    before any request bytes — so the Authorization header never reaches another
    certificate). Chain/hostname validation is off: the pin replaces it."""
    import requests
    from requests.adapters import HTTPAdapter

    class _PinnedAdapter(HTTPAdapter):
        def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
            kwargs["assert_fingerprint"] = fingerprint
            kwargs["cert_reqs"] = "CERT_NONE"
            kwargs["assert_hostname"] = False
            super().init_poolmanager(*args, **kwargs)

    s = requests.Session()
    s.mount("https://", _PinnedAdapter())
    s.verify = False  # the adapter's fingerprint check is the trust decision
    s.auth = (user, password)
    s.headers["Accept"] = "application/json"
    return s


def _is_fingerprint_mismatch(exc: BaseException) -> bool:
    return "fingerprints did not match" in str(exc).lower()


# ---------------------------------------------------------------------------
# WAPI reads
# ---------------------------------------------------------------------------


class _Wapi:
    def __init__(self, session: Any, base: str, timeout: int) -> None:
        self.session = session
        self.base = base
        self.timeout = timeout

    def _get(self, obj: str, params: dict[str, Any]) -> Any:
        try:
            r = self.session.get(f"{self.base}/{obj}", params=params, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            if _is_fingerprint_mismatch(exc):
                raise _WapiError("cert_changed", str(exc)) from exc
            raise _WapiError(_classify(str(exc), "unreachable"), str(exc)) from exc
        if r.status_code == 401:
            raise _WapiError("auth_failed", f"HTTP 401 on {obj}")
        if r.status_code == 403:
            raise _WapiError("access_denied", f"HTTP 403 on {obj}")
        if r.status_code >= 400:
            # WAPI's error body names the object/field; it goes to the local log only.
            raise _WapiError("probe_failed", f"HTTP {r.status_code} on {obj}: {r.text[:300]}")
        if len(r.content) > _MAX_RESPONSE_BYTES:
            raise _WapiError("response_too_large", f"{len(r.content)} bytes from {obj}")
        try:
            return r.json()
        except ValueError as exc:
            raise _WapiError("response_unparseable", f"{obj}: {exc}") from exc

    def one(self, obj: str, fields: str, **search: str) -> list[dict[str, Any]]:
        data = self._get(obj, {**search, "_return_fields": fields})
        if not isinstance(data, list):
            raise _WapiError("response_unparseable", f"{obj}: expected a list")
        return [d for d in data if isinstance(d, dict)]

    def paged(self, obj: str, fields: str, **search: str) -> tuple[list[dict[str, Any]], bool]:
        """All rows of `obj` (paged). Returns (rows, complete) — complete is False
        when the page cap stopped the read."""
        rows: list[dict[str, Any]] = []
        params: dict[str, Any] = {
            **search, "_return_fields": fields, "_paging": 1,
            "_max_results": _PAGE_SIZE, "_return_as_object": 1,
        }
        for _ in range(_MAX_PAGES):
            data = self._get(obj, params)
            if not isinstance(data, dict) or not isinstance(data.get("result"), list):
                raise _WapiError("response_unparseable", f"{obj}: expected a paged result")
            rows.extend(d for d in data["result"] if isinstance(d, dict))
            page = data.get("next_page_id")
            if not page:
                return rows, True
            params = {"_page_id": page}
        return rows, False


# ---------------------------------------------------------------------------
# Shaping into the shared report
# ---------------------------------------------------------------------------


def _options(raw: Any) -> list[dict[str, Any]]:
    """WAPI dhcpoption structs -> [{id, name, value: [...]}]. An option whose
    `use_option` is explicitly False is an inherited placeholder, not a value set
    here, so it is left out. List-valued options come comma-joined."""
    out: list[dict[str, Any]] = []
    for o in raw if isinstance(raw, list) else []:
        if not isinstance(o, dict) or o.get("use_option") is False:
            continue
        try:
            num = int(o.get("num"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        value = str(o.get("value") or "")
        out.append({
            "id": num,
            "name": str(o.get("name") or "") or None,
            "value": [v.strip() for v in value.split(",") if v.strip()],
        })
    return out


def _overlay(base: list[dict[str, Any]], top: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {o["id"]: o for o in base}
    merged.update({o["id"]: o for o in top})
    return [merged[k] for k in sorted(merged)]


def _lease_seconds(opts: list[dict[str, Any]]) -> int | None:
    for o in opts:
        if o["id"] == 51 and o["value"]:
            try:
                return int(o["value"][0])
            except ValueError:
                return None
    return None


def _member_ip(member: Any) -> str:
    return str(member.get("ipv4addr") or "") if isinstance(member, dict) else ""


def _ip_key(ip: str) -> tuple[int, int]:
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return (1, 0)


def _mac(v: Any) -> str:
    s = str(v or "").strip().lower().replace("-", ":")
    return s if len(s) == 17 else ""


def collect_wapi(wapi: _Wapi, server_ip: str, *, want_leases: bool = True) -> dict[str, Any]:
    """Read the member's DHCP state and shape it like the Windows report."""
    members = wapi.one(
        "member:dhcpproperties",
        "host_name,ipv4addr,options,enable_dhcp,total_hosts,dynamic_hosts,static_hosts",
        ipv4addr=server_ip,
    )
    if not members:
        raise _WapiError("member_not_found", f"no member:dhcpproperties for {server_ip}")
    member = members[0]
    host_name = str(member.get("host_name") or "")
    me = {server_ip, host_name} - {""}

    grid = wapi.one("grid:dhcpproperties", "options")
    server_options = _overlay(_options(grid[0].get("options") if grid else None),
                              _options(member.get("options")))

    failovers, _ = wapi.paged(
        "dhcpfailover", "name,primary,secondary,primary_state,secondary_state,association_type",
    )
    mine_fo: dict[str, dict[str, Any]] = {}
    for f in failovers:
        primary, secondary = str(f.get("primary") or ""), str(f.get("secondary") or "")
        if primary in me:
            mine_fo[str(f.get("name"))] = {"partner": secondary, "state": f.get("primary_state")}
        elif secondary in me:
            mine_fo[str(f.get("name"))] = {"partner": primary, "state": f.get("secondary_state")}

    ranges, ranges_complete = wapi.paged(
        "range",
        "network,start_addr,end_addr,disable,member,failover_association,"
        "server_association_type,dynamic_hosts,total_hosts,static_hosts",
    )
    my_ranges = [
        r for r in ranges
        if _member_ip(r.get("member")) == server_ip
        or str(r.get("failover_association") or "") in mine_fo
    ]
    by_net: dict[str, list[dict[str, Any]]] = {}
    for r in my_ranges:
        by_net.setdefault(str(r.get("network") or ""), []).append(r)
    by_net.pop("", None)

    networks, _ = wapi.paged("network", "network,comment,disable,options")
    net_info = {str(n.get("network")): n for n in networks}

    reserved_by_net: dict[str, list[dict[str, Any]]] = {}
    fixed, _ = wapi.paged("fixedaddress", "ipv4addr,mac,name,network,disable,match_client")
    for fa in fixed:
        net = str(fa.get("network") or "")
        if net in by_net:
            reserved_by_net.setdefault(net, []).append(fa)

    lease_by_ip: dict[str, dict[str, Any]] = {}
    leases_complete = False
    if want_leases and reserved_by_net:
        leases_complete = True
        reserved_ips = {str(fa.get("ipv4addr")) for lst in reserved_by_net.values() for fa in lst}
        for state in ("ACTIVE", "STATIC"):
            rows, complete = wapi.paged(
                "lease", "address,hardware,binding_state,ends,served_by", binding_state=state,
            )
            leases_complete = leases_complete and complete
            for le in rows:
                addr = str(le.get("address") or "")
                if addr in reserved_ips:
                    lease_by_ip[addr] = le

    scopes: list[dict[str, Any]] = []
    fo_scopes: dict[str, set[str]] = {}
    tot_in_use = tot_total = 0
    for net, rs in sorted(by_net.items(), key=lambda kv: _ip_key(kv[0].split("/")[0])):
        info = net_info.get(net, {})
        try:
            iface = ipaddress.IPv4Network(net, strict=False)
            scope_id, mask = str(iface.network_address), str(iface.netmask)
        except ValueError:
            scope_id, mask = net.split("/")[0], None
        for r in rs:
            assoc = str(r.get("failover_association") or "")
            if assoc in mine_fo:
                fo_scopes.setdefault(assoc, set()).add(scope_id)
        in_use = sum(int(r.get("dynamic_hosts") or 0) for r in rs)
        total = sum(int(r.get("total_hosts") or 0) for r in rs)
        tot_in_use += in_use
        tot_total += total
        active = not info.get("disable") and any(not r.get("disable") for r in rs)
        starts = sorted((str(r.get("start_addr") or "") for r in rs), key=_ip_key)
        ends = sorted((str(r.get("end_addr") or "") for r in rs), key=_ip_key)
        scope_opts = _options(info.get("options"))
        resv = reserved_by_net.get(net, [])
        reservations = []
        if leases_complete:
            for fa in sorted(resv, key=lambda x: _ip_key(str(x.get("ipv4addr")))):
                ip = str(fa.get("ipv4addr") or "")
                le = lease_by_ip.get(ip)
                reservations.append({
                    "ip": ip,
                    "mac": _mac(fa.get("mac")) if fa.get("match_client") in (None, "MAC_ADDRESS") else "",
                    "name": str(fa.get("name") or ""),
                    "active": le is not None,
                    "client_mac": _mac(le.get("hardware")) if le else "",
                    "lease_expiry": str(le.get("ends")) if le and le.get("ends") else None,
                    "bad_address": False,
                })
        scopes.append({
            "scope_id": scope_id,
            "name": str(info.get("comment") or "") or None,
            "state": "Active" if active else "Inactive",
            "start_range": starts[0] if starts else None,
            "end_range": ends[-1] if ends else None,
            "subnet_mask": mask,
            "lease_duration_sec": _lease_seconds(_overlay(server_options, scope_opts)),
            "addresses_in_use": in_use,
            "addresses_free": max(total - in_use, 0),
            "percentage_in_use": round(100.0 * in_use / total, 1) if total else None,
            "reserved": len(resv),
            "reservations": reservations,
            "options": scope_opts,
        })

    failover = [
        {"name": name, "partner": fo["partner"], "mode": None, "state": fo["state"],
         "scope_ids": sorted(fo_scopes.get(name, set()), key=_ip_key)}
        for name, fo in sorted(mine_fo.items())
    ]

    return {
        "hostname": host_name or None,
        "is_authorized": None,
        "is_domain_joined": None,
        "server_stats": {
            "total_scopes": len(scopes),
            "total_addresses": tot_total,
            "addresses_in_use": tot_in_use,
            "addresses_available": max(tot_total - tot_in_use, 0),
            "percentage_in_use": round(100.0 * tot_in_use / tot_total, 1) if tot_total else None,
            "dhcp_enabled": member.get("enable_dhcp"),
            "ranges_complete": ranges_complete,
            "reservation_leases": (
                "complete" if leases_complete else "none" if not reserved_by_net else "partial"
            ),
        },
        "failover": failover,
        "server_options": server_options,
        "scopes": scopes,
    }


# ---------------------------------------------------------------------------
# One target
# ---------------------------------------------------------------------------


def collect_one(target: dict[str, Any], base: dict[str, Any], *, timeout: int) -> dict[str, Any]:
    """Query one Infoblox member through its Grid Master. Never raises."""
    server_ip = str(base.get("server_ip") or "")
    api_host = str(target.get("api_host") or "").strip() or server_ip
    try:
        port = int(target.get("api_port") or 443)
    except (TypeError, ValueError):
        port = 443
    user = str(target.get("api_user") or "")
    password = str(target.get("api_password") or "")
    pin_key = f"{api_host}:{port}"
    base = {**base, "api_host": api_host}

    try:
        import requests  # noqa: F401 — lazy: only when an Infoblox target is collected
    except Exception as exc:  # pragma: no cover
        return _fail(base, "dependency_missing", transport="wapi", detail=f"requests: {exc}")

    pushed = _norm_fp(target.get("tls_fingerprint"))
    expected = pushed or _load_pins().get(pin_key, "")
    try:
        observed = _observed_fingerprint(api_host, port, timeout)
    except Exception as exc:  # noqa: BLE001
        return _fail(base, _classify(str(exc), "unreachable"), transport="wapi",
                     detail=str(exc), secret=password)
    if expected and observed != expected:
        return {**_fail(base, "cert_changed", transport="wapi",
                        detail=f"expected {expected}, got {observed}"),
                "tls_fingerprint_seen": observed}
    fp = expected or observed
    # The dashboard's pin wins; mirror it locally so a later run without one (a
    # sync that hasn't reached this box yet) still checks against it.
    _save_pin(pin_key, fp)

    session = _pinned_session(fp, user, password)
    host = f"[{api_host}]" if ":" in api_host else api_host
    wapi = _Wapi(session, f"https://{host}:{port}/wapi/{WAPI_VERSION}", timeout)
    try:
        report = collect_wapi(wapi, server_ip)
    except _WapiError as exc:
        entry = _fail(base, exc.code, transport="wapi", detail=exc.detail, secret=password)
        if exc.code == "cert_changed":
            entry["tls_fingerprint_seen"] = _safe_observed(api_host, port, timeout)
        return entry
    except Exception as exc:  # noqa: BLE001 — never crash the pass
        return _fail(base, "collect_failed", transport="wapi", detail=str(exc), secret=password)
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
    return {**_ok(base, "wapi", report), "tls_fingerprint": fp}


def _safe_observed(host: str, port: int, timeout: int) -> str | None:
    try:
        return _observed_fingerprint(host, port, timeout)
    except Exception:  # noqa: BLE001
        return None

