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
    whether its DHCP service is on. No match means the address is not a DHCP
    member of this grid; service off is reported as an error, not as scopes.
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
  * ``lease`` (STATIC and ACTIVE) — only to tell whether a reserved address is in
    use and by whom. WAPI cannot filter leases by serving member, so the sensor
    filters.

**Network views.** Infoblox lets the same CIDR exist in several network views
(overlapping address space). Every join below is keyed by (view, network) or
(view, address), and the network / fixed-address / lease reads are filtered to
the views the member's ranges are in — never a bare CIDR, which would attach
another view's options, reservations and leases to this member's scope.

**Reservations are only reported when lease activity is known.** If the lease
read was cut short, or no reserved address matched any lease at all (a grid that
does not record fixed-address leases looks exactly like that), reservations are
left out (count kept) rather than every one reported as unused.

**Option inheritance** follows the grid: grid → member → network → range. At the
member/network/range levels an option whose ``use_option`` is False is an
inherited placeholder and is skipped; at the grid level (the top) it is the
effective value. Options in a vendor space other than standard DHCP are skipped
(a vendor option 3 is not a router). Range-level options apply to the scope when
every range of the member in that network agrees; when they differ, the option
lists every value and says so in its name.

Output: the same entry shape the Windows probe produces (see dhcp_server.py), so
the dashboard ingests it unchanged; ``transport`` is ``"wapi"``.

TLS: Infoblox ships a self-signed certificate, so ordinary verification fails on
most installs. The owner's choice (2026-11-12) is **pin on first use**: the
first connection records the certificate's SHA-256 fingerprint and every later
connection must present the same one. The dashboard holds the pin of record and
pushes it as ``tls_fingerprint``; until it arrives, the sensor keeps its own in
``PINS_FILE``. Credentials are only ever sent over a connection pinned to the
expected fingerprint: environment proxies are ignored (a proxy connection would
not carry the pin), redirects are not followed, and an unreadable pin file or a
first-use pin that cannot be saved stops the collection instead of trusting
whatever answers. A changed certificate is the ``cert_changed`` error, carrying
the new fingerprint (``tls_fingerprint_seen``) for a person to compare and accept.

Time: one target is bounded by an absolute deadline (the pass budget's remainder,
capped), checked before every request; each request's timeout is the smaller of
the per-request timeout and the time left.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from .dhcp_server import _CODE_SIGNS, _fail, _ok

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
# One Infoblox target never runs longer than this, whatever budget is left.
_MAX_TARGET_SECONDS = 90.0

# The read worker per endpoint ("host:port"). A worker abandoned at the deadline
# keeps its slot until it ends, so at most one is ever outstanding per endpoint.
_WORKERS: dict[str, threading.Thread] = {}
_WORKERS_LOCK = threading.Lock()


class _WapiError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def _classify_net(detail: str, default: str) -> str:
    """Map a transport exception's text to a code. Unlike dhcp_server._classify
    this never reads it as a rejected password: a real 401 is an HTTP status,
    handled explicitly, and exception text carries the URL (page ids can contain
    "401")."""
    low = (detail or "").lower()
    for code, signs in _CODE_SIGNS:
        if code in ("wmi_denied", "module_missing"):
            continue
        if any(sign in low for sign in signs):
            return code
    return default


# ---------------------------------------------------------------------------
# Certificate pinning
# ---------------------------------------------------------------------------


class _PinStoreError(Exception):
    pass


def _norm_fp(fp: Any) -> str:
    """Lowercase hex, no separators — 'AB:CD:..' and 'abcd..' compare equal."""
    return "".join(ch for ch in str(fp or "").lower() if ch in "0123456789abcdef")


_FP_SYNTAX = re.compile(r"^[0-9A-Fa-f:\s-]+$")


def _strict_fp(v: Any) -> str | None:
    """A full SHA-256 in hex (separators allowed), normalized — else None. Used for
    every SUPPLIED pin, so junk can never normalize to "" and read as "no pin"."""
    if not isinstance(v, str) or not _FP_SYNTAX.match(v):
        return None
    fp = _norm_fp(v)
    return fp if len(fp) == 64 else None


def _observed_fingerprint(host: str, port: int, timeout: float) -> str:
    """SHA-256 of the certificate the server presents right now (no trust check —
    this is only ever compared against a pin or recorded as one)."""
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def _load_pins() -> dict[str, str]:
    """The local pins. A missing file is "no pins yet"; an unreadable or corrupt
    one raises — treating it as empty would trust whatever answers next."""
    try:
        data = json.loads(PINS_FILE.read_text())
    except FileNotFoundError:
        return {}
    except Exception as exc:  # noqa: BLE001
        raise _PinStoreError(f"could not read {PINS_FILE}: {exc}") from exc
    if not isinstance(data, dict):
        raise _PinStoreError(f"{PINS_FILE} is not a JSON object")
    pins: dict[str, str] = {}
    for k, v in data.items():
        fp = _strict_fp(v)
        # Anything but a full SHA-256 is damage, not "no pin": reading it as empty
        # would trust whatever answers next.
        if fp is None:
            raise _PinStoreError(f"{PINS_FILE} holds an invalid pin for {k!r}")
        pins[str(k)] = fp
    return pins


def _save_pin(key: str, fp: str) -> None:
    """Record a pin; raises _PinStoreError when it cannot be saved."""
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
        raise _PinStoreError(f"could not write {PINS_FILE}: {exc}") from exc


def _pinned_session(fingerprint: str, user: str, password: str) -> Any:
    """A requests session that only completes a TLS handshake with a certificate
    whose SHA-256 matches `fingerprint` (urllib3 checks it after the handshake,
    before any request bytes — so the Authorization header never reaches another
    certificate). Chain/hostname validation is off: the pin replaces it.

    trust_env is off: with an HTTPS_PROXY in the environment requests would use a
    separate proxy manager that never received the pin."""
    import requests
    from requests.adapters import HTTPAdapter

    class _PinnedAdapter(HTTPAdapter):
        def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
            kwargs["assert_fingerprint"] = fingerprint
            kwargs["cert_reqs"] = "CERT_NONE"
            kwargs["assert_hostname"] = False
            super().init_poolmanager(*args, **kwargs)

        def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("proxies are not used for a pinned WAPI session")

    s = requests.Session()
    s.trust_env = False
    s.proxies = {}
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
    def __init__(self, session: Any, base: str, timeout: float, deadline: float) -> None:
        self.session = session
        self.base = base
        self.timeout = timeout
        self.deadline = deadline

    def _get(self, obj: str, params: dict[str, Any]) -> Any:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise _WapiError("timeout", f"time budget used up before {obj}")
        try:
            r = self.session.get(
                f"{self.base}/{obj}", params=params, timeout=min(self.timeout, left),
                allow_redirects=False, stream=True,
            )
        except Exception as exc:  # noqa: BLE001
            if _is_fingerprint_mismatch(exc):
                raise _WapiError("cert_changed", str(exc)) from exc
            raise _WapiError(_classify_net(str(exc), "unreachable"), str(exc)) from exc
        try:
            if r.status_code == 401:
                raise _WapiError("auth_failed", f"HTTP 401 on {obj}")
            if r.status_code == 403:
                raise _WapiError("access_denied", f"HTTP 403 on {obj}")
            if r.status_code >= 300:
                # WAPI's error body names the object/field; it goes to the local log
                # only, and only its first bytes (one bounded read, not r.text).
                head = next(r.iter_content(512), b"")
                raise _WapiError("probe_failed", f"HTTP {r.status_code} on {obj}: {head[:300]!r}")
            body = bytearray()
            for chunk in r.iter_content(16 * 1024):
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise _WapiError("response_too_large", f"over {_MAX_RESPONSE_BYTES} bytes from {obj}")
                if time.monotonic() > self.deadline:
                    raise _WapiError("timeout", f"time budget used up reading {obj}")
        except _WapiError:
            raise
        except Exception as exc:  # noqa: BLE001 — a read error mid-body
            raise _WapiError(_classify_net(str(exc), "unreachable"), str(exc)) from exc
        finally:
            r.close()
        try:
            return json.loads(bytes(body))
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


def _options(raw: Any, *, top: bool = False) -> list[dict[str, Any]]:
    """WAPI dhcpoption structs -> [{id, name, value: [...]}].

    Below the grid (top=False) an option whose `use_option` is explicitly False is
    an inherited placeholder, not a value set there, so it is left out; at the grid
    it is the effective value. Vendor-space options are skipped. List-valued
    options come comma-joined."""
    out: list[dict[str, Any]] = []
    for o in raw if isinstance(raw, list) else []:
        if not isinstance(o, dict):
            continue
        if not top and o.get("use_option") is False:
            continue
        vc = o.get("vendor_class")
        if vc not in (None, "", "DHCP"):
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


def _range_options(rs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Options set on the member's ranges in one network. An option every range
    sets to the same value applies to the scope; one the ranges disagree on (or
    only some set) lists every value, named so a reader sees it varies."""
    per = [{o["id"]: o for o in _options(r.get("options"))} for r in rs]
    ids = sorted({i for p in per for i in p})
    out: list[dict[str, Any]] = []
    for i in ids:
        vals = [p.get(i) for p in per]
        present = [v for v in vals if v is not None]
        if len(present) == len(vals) and all(v["value"] == present[0]["value"] for v in present):
            out.append(present[0])
        else:
            merged: list[str] = []
            for v in present:
                merged.extend(x for x in v["value"] if x not in merged)
            name = present[0]["name"] or f"Option {i}"
            out.append({"id": i, "name": f"{name} (varies by range)", "value": merged})
    return out


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


def _iso(ts: Any) -> str | None:
    """WAPI timestamps are epoch seconds; the Windows path sends ISO 8601."""
    if ts in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(ts), UTC).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _view(obj: dict[str, Any]) -> str:
    return str(obj.get("network_view") or "default")


def collect_wapi(wapi: _Wapi, server_ip: str) -> dict[str, Any]:
    """Read the member's DHCP state and shape it like the Windows report."""
    members = wapi.one("member:dhcpproperties", "host_name,ipv4addr,options,enable_dhcp",
                       ipv4addr=server_ip)
    if not members:
        raise _WapiError("member_not_found", f"no member:dhcpproperties for {server_ip}")
    member = members[0]
    if member.get("enable_dhcp") is False:
        raise _WapiError("service_disabled", f"member {server_ip} has DHCP turned off")
    host_name = str(member.get("host_name") or "")
    me = {server_ip, host_name} - {""}

    grid = wapi.one("grid:dhcpproperties", "options")
    server_options = _overlay(_options(grid[0].get("options") if grid else None, top=True),
                              _options(member.get("options")))

    failovers, _ = wapi.paged("dhcpfailover", "name,primary,secondary,primary_state,secondary_state")
    mine_fo: dict[str, dict[str, Any]] = {}
    for f in failovers:
        primary, secondary = str(f.get("primary") or ""), str(f.get("secondary") or "")
        if primary in me:
            mine_fo[str(f.get("name"))] = {"partner": secondary, "state": f.get("primary_state")}
        elif secondary in me:
            mine_fo[str(f.get("name"))] = {"partner": primary, "state": f.get("secondary_state")}

    ranges, ranges_complete = wapi.paged(
        "range",
        "network,network_view,start_addr,end_addr,disable,member,failover_association,"
        "dynamic_hosts,total_hosts,options",
    )
    by_net: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in ranges:
        if _member_ip(r.get("member")) == server_ip or str(r.get("failover_association") or "") in mine_fo:
            net = str(r.get("network") or "")
            if net:
                by_net.setdefault((_view(r), net), []).append(r)
    views = sorted({v for v, _ in by_net})

    net_info: dict[tuple[str, str], dict[str, Any]] = {}
    reserved_by_net: dict[tuple[str, str], list[dict[str, Any]]] = {}
    lease_by_addr: dict[tuple[str, str], dict[str, Any]] = {}
    networks_complete = fixed_complete = leases_complete = True
    for view in views:
        networks, ok = wapi.paged("network", "network,network_view,comment,disable,options",
                                  network_view=view)
        networks_complete &= ok
        for n in networks:
            key = (_view(n), str(n.get("network") or ""))
            if key in by_net:
                net_info[key] = n
        fixed, ok = wapi.paged("fixedaddress", "ipv4addr,mac,name,network,network_view,match_client",
                               network_view=view)
        fixed_complete &= ok
        for fa in fixed:
            key = (_view(fa), str(fa.get("network") or ""))
            if key in by_net:
                reserved_by_net.setdefault(key, []).append(fa)

    reserved = {(v, str(fa.get("ipv4addr"))) for (v, _), lst in reserved_by_net.items() for fa in lst}
    if reserved:
        # STATIC first, so an ACTIVE lease on a reserved address (who really holds
        # it) wins over the reservation's own STATIC record.
        for state in ("STATIC", "ACTIVE"):
            for view in sorted({v for v, _ in reserved}):
                rows, ok = wapi.paged("lease", "address,hardware,binding_state,ends,network_view",
                                      binding_state=state, network_view=view)
                leases_complete &= ok
                for le in rows:
                    key = (_view(le), str(le.get("address") or ""))
                    if key in reserved:
                        lease_by_addr[key] = le
    # A grid that does not record fixed-address leases returns none for any reserved
    # address; that is "unknown", not "every reservation unused".
    leases_known = bool(reserved) and leases_complete and fixed_complete and bool(lease_by_addr)

    scopes: list[dict[str, Any]] = []
    fo_scopes: dict[str, set[str]] = {}
    tot_in_use = tot_total = 0
    multi_view = len(views) > 1
    for (view, net), rs in sorted(by_net.items(), key=lambda kv: (_ip_key(kv[0][1].split("/")[0]), kv[0][0])):
        info = net_info.get((view, net), {})
        try:
            iface = ipaddress.IPv4Network(net, strict=False)
            scope_id, mask = str(iface.network_address), str(iface.netmask)
        except ValueError:
            scope_id, mask = net.split("/")[0], None
        if multi_view:
            scope_id = f"{scope_id} ({view})"
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
        scope_opts = _overlay(_options(info.get("options")), _range_options(rs))
        resv = reserved_by_net.get((view, net), [])
        reservations = []
        if leases_known:
            for fa in sorted(resv, key=lambda x: _ip_key(str(x.get("ipv4addr")))):
                ip = str(fa.get("ipv4addr") or "")
                le = lease_by_addr.get((view, ip))
                reservations.append({
                    "ip": ip,
                    "mac": _mac(fa.get("mac")) if fa.get("match_client") in (None, "MAC_ADDRESS") else "",
                    "name": str(fa.get("name") or ""),
                    "active": le is not None,
                    "client_mac": _mac(le.get("hardware")) if le else "",
                    "lease_expiry": _iso(le.get("ends")) if le else None,
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
         "scope_ids": sorted(fo_scopes.get(name, set()))}
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
            "network_views": views,
            "ranges_complete": ranges_complete,
            "networks_complete": networks_complete,
            "reservation_leases": (
                "none" if not reserved else "complete" if leases_known
                else "partial" if not (leases_complete and fixed_complete) else "unavailable"
            ),
        },
        "failover": failover,
        "server_options": server_options,
        "scopes": scopes,
    }


# ---------------------------------------------------------------------------
# One target
# ---------------------------------------------------------------------------


def collect_one(
    target: dict[str, Any], base: dict[str, Any], *, timeout: float, deadline: float | None = None,
) -> dict[str, Any]:
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
    cap = time.monotonic() + _MAX_TARGET_SECONDS
    deadline = min(deadline, cap) if deadline is not None else cap

    try:
        import requests  # noqa: F401 — lazy: only when an Infoblox target is collected
    except Exception as exc:  # pragma: no cover
        return _fail(base, "dependency_missing", transport="wapi", detail=f"requests: {exc}")

    try:
        raw_pin = target.get("tls_fingerprint")
        pushed = ""
        # Absent (None/missing/"") means the dashboard has no pin yet; ANY other value
        # must be a full SHA-256, or the target is refused.
        if raw_pin not in (None, ""):
            strict = _strict_fp(raw_pin)
            if strict is None:
                raise _PinStoreError("the pushed tls_fingerprint is not a SHA-256")
            pushed = strict
        expected = pushed or _load_pins().get(pin_key, "")
    except _PinStoreError as exc:
        return _fail(base, "pin_store_failed", transport="wapi", detail=str(exc))
    left = deadline - time.monotonic()
    if left <= 0:
        return _fail(base, "timeout", transport="wapi", detail="no time left for this target")
    try:
        observed = _observed_fingerprint(api_host, port, min(timeout, left))
    except Exception as exc:  # noqa: BLE001
        return _fail(base, _classify_net(str(exc), "unreachable"), transport="wapi",
                     detail=str(exc), secret=password)
    if expected and observed != expected:
        return {**_fail(base, "cert_changed", transport="wapi",
                        detail=f"expected {expected}, got {observed}"),
                "tls_fingerprint_seen": observed}
    fp = expected or observed
    # The dashboard's pin wins; mirror it locally so a later run without one (a
    # sync that hasn't reached this box yet) still checks against it. A first-use
    # pin that cannot be saved must not be used to send credentials.
    try:
        _save_pin(pin_key, fp)
    except _PinStoreError as exc:
        if not pushed:
            return _fail(base, "pin_store_failed", transport="wapi", detail=str(exc))
        log.warning("could not mirror pushed dhcp tls pin", error=str(exc))

    session = _pinned_session(fp, user, password)
    host = f"[{api_host}]" if ":" in api_host else api_host
    wapi = _Wapi(session, f"https://{host}:{port}/wapi/{WAPI_VERSION}", timeout, deadline)
    # The deadline checks inside _Wapi run between reads; a server trickling bytes
    # can hold one read open far longer. So the reads run in a worker and this
    # target ends at the deadline whatever they are doing: the worker's session is
    # closed and its result, if it ever comes, is dropped. Every read still has its
    # own socket timeout, so the worker itself always finishes.
    box: dict[str, Any] = {}
    with _WORKERS_LOCK:
        prev = _WORKERS.get(pin_key)
        if prev is not None and prev.is_alive():
            # A read abandoned on an earlier pass is still stuck on this endpoint:
            # never stack a second one behind it.
            session.close()
            return _fail(base, "timeout", transport="wapi",
                         detail="an earlier read of this endpoint is still running")

    def _work() -> None:
        try:
            box["report"] = collect_wapi(wapi, server_ip)
        except BaseException as exc:  # noqa: BLE001 — handed back to the caller
            box["error"] = exc

    worker = threading.Thread(target=_work, name="dhcp-infoblox", daemon=True)
    with _WORKERS_LOCK:
        _WORKERS[pin_key] = worker
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()) + 1.0)
    try:
        if worker.is_alive():
            return _fail(base, "timeout", transport="wapi",
                         detail="time budget used up mid-read; abandoned")
        exc = box.get("error")
        if isinstance(exc, _WapiError):
            entry = _fail(base, exc.code, transport="wapi", detail=exc.detail, secret=password)
            if exc.code == "cert_changed":
                left = deadline - time.monotonic()
                entry["tls_fingerprint_seen"] = (
                    _safe_observed(api_host, port, min(timeout, left)) if left > 0 else None
                )
            return entry
        if exc is not None:
            return _fail(base, "collect_failed", transport="wapi", detail=str(exc), secret=password)
        return {**_ok(base, "wapi", box["report"]), "tls_fingerprint": fp}
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def _safe_observed(host: str, port: int, timeout: float) -> str | None:
    try:
        return _observed_fingerprint(host, port, timeout)
    except Exception:  # noqa: BLE001
        return None
