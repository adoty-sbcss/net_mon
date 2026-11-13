"""Unit tests for the Infoblox (WAPI) DHCP collector (DHCP-7).

No network: the certificate read and the HTTP session are the two chokepoints,
both faked. The fake WAPI answers from a small grid: one member (10.0.0.20,
"ibx-m1") serving two networks — one directly, one through a failover
association with a second member — plus a network served by someone else.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from collector.discovery import dhcp_infoblox as ib
from collector.discovery import dhcp_server as dh

FP = "ab" * 32
OTHER_FP = "cd" * 32

GRID: dict[str, Any] = {
    "member:dhcpproperties": [{
        "host_name": "ibx-m1.example.org", "ipv4addr": "10.0.0.20", "enable_dhcp": True,
        "options": [
            {"name": "domain-name-servers", "num": 6, "value": "10.0.0.53,10.0.0.54", "use_option": True},
            {"name": "dhcp-lease-time", "num": 51, "value": "28800", "use_option": True},
        ],
    }],
    "grid:dhcpproperties": [{
        "options": [
            {"name": "domain-name", "num": 15, "value": "example.org", "use_option": True},
            {"name": "dhcp-lease-time", "num": 51, "value": "43200", "use_option": False},
        ],
    }],
    "dhcpfailover": [
        {"name": "m1-m2", "primary": "ibx-m1.example.org", "secondary": "ibx-m2.example.org",
         "primary_state": "PARTNER_DOWN", "secondary_state": "COMMUNICATIONS_INTERRUPTED"},
        {"name": "x-y", "primary": "x", "secondary": "y",
         "primary_state": "NORMAL", "secondary_state": "NORMAL"},
    ],
    "range": [
        {"network": "10.1.0.0/24", "start_addr": "10.1.0.100", "end_addr": "10.1.0.199",
         "member": {"ipv4addr": "10.0.0.20", "name": "ibx-m1.example.org"},
         "dynamic_hosts": 92, "total_hosts": 100, "disable": False},
        {"network": "10.2.0.0/23", "start_addr": "10.2.0.10", "end_addr": "10.2.1.250",
         "failover_association": "m1-m2", "dynamic_hosts": 50, "total_hosts": 500, "disable": False},
        {"network": "10.9.0.0/24", "start_addr": "10.9.0.10", "end_addr": "10.9.0.20",
         "member": {"ipv4addr": "10.0.0.99"}, "dynamic_hosts": 1, "total_hosts": 11},
    ],
    "network": [
        {"network": "10.1.0.0/24", "comment": "Lincoln ES staff", "disable": False,
         "options": [{"name": "routers", "num": 3, "value": "10.1.0.1", "use_option": True}]},
        {"network": "10.2.0.0/23", "comment": "", "disable": False, "options": []},
        {"network": "10.9.0.0/24", "comment": "not ours", "options": []},
    ],
    "fixedaddress": [
        {"ipv4addr": "10.1.0.50", "mac": "AA:BB:CC:00:00:01", "name": "printer", "network": "10.1.0.0/24"},
        {"ipv4addr": "10.1.0.51", "mac": "aa:bb:cc:00:00:02", "name": "copier", "network": "10.1.0.0/24"},
        {"ipv4addr": "10.9.0.5", "mac": "aa:bb:cc:00:00:09", "network": "10.9.0.0/24"},
    ],
    "lease:ACTIVE": [
        {"address": "10.1.0.50", "hardware": "aa:bb:cc:00:00:99", "binding_state": "ACTIVE",
         "ends": 1762992000},
    ],
    "lease:STATIC": [
        {"address": "10.1.0.51", "hardware": "aa:bb:cc:00:00:02", "binding_state": "STATIC"},
    ],
}


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()

    def json(self) -> Any:
        return self._body

    def iter_content(self, n: int) -> Any:
        yield self.content

    def close(self) -> None:
        pass


class _FakeSession:
    def __init__(self, grid: dict[str, Any], status: int = 200, page: int = 1000) -> None:
        self.grid = grid
        self.status = status
        self.page = page
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False
        self._cursor: dict[str, tuple[str, int]] = {}
        self._views: dict[str, str] = {}

    def get(self, url: str, params: dict[str, Any], timeout: float,
            allow_redirects: bool = True, stream: bool = False) -> _Resp:
        assert allow_redirects is False
        obj = url.rsplit("/", 1)[1]
        self.calls.append((obj, dict(params)))
        if self.status != 200:
            return _Resp(self.status, {"Error": "nope"})
        if "_page_id" in params:
            key, start = self._cursor.pop(params["_page_id"])
        else:
            key = obj
            if obj == "member:dhcpproperties":
                rows = [m for m in self.grid[obj] if m["ipv4addr"] == params.get("ipv4addr")]
                return _Resp(200, rows)
            if obj == "lease":
                key = f"lease:{params['binding_state']}"
            if "_paging" not in params:
                return _Resp(200, self.grid.get(key, []))
            start = 0
        rows = self.grid.get(key, [])
        view = params.get("network_view")
        if view is not None and start == 0:
            self._views[key] = view
        view = self._views.get(key) if view is None else view
        if view is not None:
            rows = [x for x in rows if x.get("network_view", "default") == view]
        chunk = rows[start:start + self.page]
        body: dict[str, Any] = {"result": chunk}
        if start + self.page < len(rows):
            pid = f"p{len(self.calls)}"
            self._cursor[pid] = (key, start + self.page)
            body["next_page_id"] = pid
        return _Resp(200, body)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> dict[str, Any]:
    state: dict[str, Any] = {"observed": FP, "session": _FakeSession(GRID), "pinned_with": None}
    monkeypatch.setattr(ib, "PINS_FILE", tmp_path / "pins.json")
    monkeypatch.setattr(ib, "_observed_fingerprint", lambda h, p, t: state["observed"])

    def _session(fp: str, user: str, password: str) -> _FakeSession:
        state["pinned_with"] = (fp, user, password)
        return state["session"]

    monkeypatch.setattr(ib, "_pinned_session", _session)
    return state


TARGET = {"server_ip": "10.0.0.20", "server_type": "infoblox", "api_host": "10.0.0.5",
          "api_user": "netmon-ro", "api_password": "s3cret!", "label": "Grid"}


def _scope(out: dict[str, Any], sid: str) -> dict[str, Any]:
    return next(s for s in out["scopes"] if s["scope_id"] == sid)


def test_happy_path_shapes_like_windows(fake: dict[str, Any]) -> None:
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["status"] == "ok" and out["transport"] == "wapi"
    assert out["server_ip"] == "10.0.0.20" and out["api_host"] == "10.0.0.5"
    assert out["server_type"] == "infoblox" and out["label"] == "Grid"
    assert out["hostname"] == "ibx-m1.example.org"
    assert out["tls_fingerprint"] == FP
    # Only the member's two networks; 10.9.0.0 belongs to another member.
    assert [s["scope_id"] for s in out["scopes"]] == ["10.1.0.0", "10.2.0.0"]
    s1 = _scope(out, "10.1.0.0")
    assert (s1["addresses_in_use"], s1["addresses_free"], s1["percentage_in_use"]) == (92, 8, 92.0)
    assert s1["subnet_mask"] == "255.255.255.0" and s1["name"] == "Lincoln ES staff"
    assert s1["state"] == "Active" and s1["lease_duration_sec"] == 28800
    assert {o["id"]: o["value"] for o in s1["options"]} == {3: ["10.1.0.1"]}
    assert _scope(out, "10.2.0.0")["subnet_mask"] == "255.255.254.0"
    # Server options: grid's domain-name + member's DNS and lease time; the grid's
    # use_option=False lease time is a placeholder and must not win.
    so = {o["id"]: o["value"] for o in out["server_options"]}
    assert so == {6: ["10.0.0.53", "10.0.0.54"], 15: ["example.org"], 51: ["28800"]}
    assert out["server_stats"]["total_addresses"] == 600
    assert out["server_stats"]["addresses_in_use"] == 142
    assert out["failover"] == [{"name": "m1-m2", "partner": "ibx-m2.example.org", "mode": None,
                                "state": "PARTNER_DOWN", "scope_ids": ["10.2.0.0"]}]


def test_reservations_conflict_and_active(fake: dict[str, Any]) -> None:
    out = dh._collect_one(TARGET, winrm_timeout=10)
    resv = {r["ip"]: r for r in _scope(out, "10.1.0.0")["reservations"]}
    assert set(resv) == {"10.1.0.50", "10.1.0.51"}
    assert resv["10.1.0.50"]["mac"] == "aa:bb:cc:00:00:01"  # canonical lowercase
    assert resv["10.1.0.50"]["active"] and resv["10.1.0.50"]["client_mac"] == "aa:bb:cc:00:00:99"
    assert resv["10.1.0.51"]["active"] and resv["10.1.0.51"]["client_mac"] == "aa:bb:cc:00:00:02"
    assert _scope(out, "10.1.0.0")["reserved"] == 2
    assert out["server_stats"]["reservation_leases"] == "complete"


def test_paging_follows_next_page_id(fake: dict[str, Any]) -> None:
    fake["session"] = _FakeSession(GRID, page=1)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert [s["scope_id"] for s in out["scopes"]] == ["10.1.0.0", "10.2.0.0"]
    follow = [p for o, p in fake["session"].calls if "_page_id" in p]
    assert follow and all(set(p) == {"_page_id"} for p in follow)


def test_truncated_leases_drop_reservations_not_mark_unused(
    fake: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    grid = {**GRID, "lease:ACTIVE": GRID["lease:ACTIVE"] * 3}
    fake["session"] = _FakeSession(grid, page=1)
    monkeypatch.setattr(ib, "_MAX_PAGES", 2)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    s1 = _scope(out, "10.1.0.0")
    assert s1["reservations"] == [] and s1["reserved"] == 2
    assert out["server_stats"]["reservation_leases"] == "partial"


def test_first_use_pins_locally_then_enforces(fake: dict[str, Any]) -> None:
    assert dh._collect_one(TARGET, winrm_timeout=10)["status"] == "ok"
    assert json.loads(ib.PINS_FILE.read_text()) == {"10.0.0.5:443": FP}
    assert fake["pinned_with"] == (FP, "netmon-ro", "s3cret!")
    fake["observed"] = OTHER_FP
    fake["pinned_with"] = None
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["status"] == "error" and out["code"] == "cert_changed"
    assert out["tls_fingerprint_seen"] == OTHER_FP
    assert fake["pinned_with"] is None  # credentials never sent to the new cert


def test_dashboard_pin_wins_over_local(fake: dict[str, Any]) -> None:
    ib._save_pin("10.0.0.5:443", FP)
    fake["observed"] = OTHER_FP
    out = dh._collect_one({**TARGET, "tls_fingerprint": OTHER_FP.upper()}, winrm_timeout=10)
    assert out["status"] == "ok" and out["tls_fingerprint"] == OTHER_FP
    assert json.loads(ib.PINS_FILE.read_text())["10.0.0.5:443"] == OTHER_FP


def test_dashboard_pin_mismatch_is_cert_changed(fake: dict[str, Any]) -> None:
    out = dh._collect_one({**TARGET, "tls_fingerprint": "AB:" * 31 + "CD"}, winrm_timeout=10)
    assert out["code"] == "cert_changed" and out["tls_fingerprint_seen"] == FP


@pytest.mark.parametrize(("status", "code"), [(401, "auth_failed"), (403, "access_denied"),
                                               (500, "probe_failed")])
def test_http_errors_map_to_codes_without_raw_text(
    fake: dict[str, Any], status: int, code: str,
) -> None:
    fake["session"] = _FakeSession(GRID, status=status)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["status"] == "error" and out["code"] == code
    assert out["error"] == dh._ERROR_TEXT[code]
    assert "s3cret" not in json.dumps(out) and "netmon-ro" not in json.dumps(out)
    assert fake["session"].closed


def test_unknown_member(fake: dict[str, Any]) -> None:
    out = dh._collect_one({**TARGET, "server_ip": "10.0.0.77"}, winrm_timeout=10)
    assert out["code"] == "member_not_found"


def test_unreachable_cert_read(fake: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(h: str, p: int, t: int) -> str:
        raise ConnectionRefusedError("[Errno 111] Connection refused")

    monkeypatch.setattr(ib, "_observed_fingerprint", boom)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["code"] == "unreachable" and fake["pinned_with"] is None


def test_api_host_defaults_to_server_ip(fake: dict[str, Any]) -> None:
    t = {k: v for k, v in TARGET.items() if k != "api_host"}
    out = dh._collect_one(t, winrm_timeout=10)
    assert out["api_host"] == "10.0.0.20"
    assert "10.0.0.20:443" in json.loads(ib.PINS_FILE.read_text())


def test_options_parsing() -> None:
    raw = [{"num": 3, "value": "10.0.0.1", "use_option": True},
           {"num": "6", "value": " 1.1.1.1 , 8.8.8.8 "},
           {"num": 66, "value": "x", "use_option": False},
           {"name": "bad"}, "junk"]
    assert ib._options(raw) == [
        {"id": 3, "name": None, "value": ["10.0.0.1"]},
        {"id": 6, "name": None, "value": ["1.1.1.1", "8.8.8.8"]},
    ]
    assert ib._norm_fp("AB:cd:EF") == "abcdef"


# ---- review fixes (DHCP-7 round 1) -------------------------------------------


def _grid(**over: Any) -> dict[str, Any]:
    g = json.loads(json.dumps(GRID))
    g.update(over)
    return g


def test_same_cidr_in_another_view_never_leaks_in(fake: dict[str, Any]) -> None:
    g = _grid()
    # Another view reuses 10.1.0.0/24 with its own comment, router, reservation, lease.
    g["network"].append({"network": "10.1.0.0/24", "network_view": "guest", "comment": "OTHER VIEW",
                         "options": [{"num": 3, "value": "192.0.2.1", "use_option": True}]})
    g["fixedaddress"].append({"ipv4addr": "10.1.0.60", "mac": "aa:bb:cc:00:00:60",
                              "network": "10.1.0.0/24", "network_view": "guest"})
    g["lease:ACTIVE"].append({"address": "10.1.0.51", "hardware": "aa:bb:cc:99:99:99",
                              "network_view": "guest"})
    fake["session"] = _FakeSession(g)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    s1 = _scope(out, "10.1.0.0")
    assert s1["name"] == "Lincoln ES staff"
    assert {o["id"]: o["value"] for o in s1["options"]} == {3: ["10.1.0.1"]}
    assert {r["ip"] for r in s1["reservations"]} == {"10.1.0.50", "10.1.0.51"}
    assert next(r for r in s1["reservations"] if r["ip"] == "10.1.0.51")["client_mac"] == "aa:bb:cc:00:00:02"
    for obj in ("network", "fixedaddress", "lease"):
        assert all(p.get("network_view") == "default" for o, p in fake["session"].calls
                   if o == obj and "_page_id" not in p)


def test_member_serving_two_views_keeps_scopes_apart(fake: dict[str, Any]) -> None:
    g = _grid()
    g["range"].append({"network": "10.1.0.0/24", "network_view": "guest", "start_addr": "10.1.0.10",
                       "end_addr": "10.1.0.20", "member": {"ipv4addr": "10.0.0.20"},
                       "dynamic_hosts": 1, "total_hosts": 11})
    g["network"].append({"network": "10.1.0.0/24", "network_view": "guest", "comment": "Guest"})
    fake["session"] = _FakeSession(g)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    ids = {s["scope_id"]: s for s in out["scopes"]}
    assert ids["10.1.0.0 (default)"]["addresses_in_use"] == 92
    assert ids["10.1.0.0 (guest)"]["addresses_in_use"] == 1
    assert ids["10.1.0.0 (guest)"]["name"] == "Guest"


def test_range_options_apply_and_disagreement_is_visible(fake: dict[str, Any]) -> None:
    g = _grid()
    g["range"][0]["options"] = [{"num": 6, "value": "10.1.0.53", "use_option": True}]
    g["range"].append({"network": "10.1.0.0/24", "start_addr": "10.1.0.200", "end_addr": "10.1.0.210",
                       "member": {"ipv4addr": "10.0.0.20"}, "dynamic_hosts": 0, "total_hosts": 11,
                       "options": [{"num": 6, "value": "10.1.0.54", "use_option": True}]})
    g["range"][1]["options"] = [{"num": 3, "value": "10.2.0.1", "use_option": True}]
    fake["session"] = _FakeSession(g)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    o1 = {o["id"]: o for o in _scope(out, "10.1.0.0")["options"]}
    assert o1[6]["value"] == ["10.1.0.53", "10.1.0.54"] and "varies" in o1[6]["name"]
    assert {o["id"]: o["value"] for o in _scope(out, "10.2.0.0")["options"]} == {3: ["10.2.0.1"]}


def test_grid_default_lease_time_counts_and_vendor_options_do_not(fake: dict[str, Any]) -> None:
    g = _grid()
    g["member:dhcpproperties"][0]["options"] = [
        {"num": 3, "value": "203.0.113.9", "vendor_class": "MSFT", "use_option": True},
    ]
    fake["session"] = _FakeSession(g)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    so = {o["id"]: o["value"] for o in out["server_options"]}
    assert so == {15: ["example.org"], 51: ["43200"]}
    assert _scope(out, "10.2.0.0")["lease_duration_sec"] == 43200


def test_dhcp_service_off_is_an_error(fake: dict[str, Any]) -> None:
    g = _grid()
    g["member:dhcpproperties"][0]["enable_dhcp"] = False
    fake["session"] = _FakeSession(g)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["status"] == "error" and out["code"] == "service_disabled"


def test_no_lease_records_means_unknown_not_unused(fake: dict[str, Any]) -> None:
    fake["session"] = _FakeSession(_grid(**{"lease:ACTIVE": [], "lease:STATIC": []}))
    out = dh._collect_one(TARGET, winrm_timeout=10)
    s1 = _scope(out, "10.1.0.0")
    assert s1["reservations"] == [] and s1["reserved"] == 2
    assert out["server_stats"]["reservation_leases"] == "unavailable"


def test_active_lease_beats_static_record(fake: dict[str, Any]) -> None:
    g = _grid()
    g["lease:STATIC"].append({"address": "10.1.0.50", "hardware": "aa:bb:cc:00:00:01"})
    fake["session"] = _FakeSession(g)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    r = next(x for x in _scope(out, "10.1.0.0")["reservations"] if x["ip"] == "10.1.0.50")
    assert r["client_mac"] == "aa:bb:cc:00:00:99"
    assert r["lease_expiry"] == "2025-11-13T00:00:00+00:00"


def test_corrupt_pin_file_fails_closed(fake: dict[str, Any]) -> None:
    ib.PINS_FILE.write_text("{not json")
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["code"] == "pin_store_failed" and fake["pinned_with"] is None


def test_unsavable_first_use_pin_fails_closed(fake: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def nope(key: str, fp: str) -> None:
        raise ib._PinStoreError("disk full")

    monkeypatch.setattr(ib, "_save_pin", nope)
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["code"] == "pin_store_failed" and fake["pinned_with"] is None
    # ...but with the dashboard's pin pushed, the pin is known: collection goes on.
    out = dh._collect_one({**TARGET, "tls_fingerprint": FP}, winrm_timeout=10)
    assert out["status"] == "ok"


def test_deadline_stops_paging(fake: dict[str, Any]) -> None:
    fake["session"] = _FakeSession(GRID, page=1)
    out = ib.collect_one(TARGET, {"server_ip": "10.0.0.20", "label": None, "server_type": "infoblox"},
                         timeout=10, deadline=__import__("time").monotonic() - 1)
    assert out["code"] == "timeout"


def test_exception_text_with_401_is_not_a_rejected_password() -> None:
    detail = "HTTPSConnectionPool(host='gm', port=443): Read timed out. (url=/wapi/v2.7/lease?_page_id=789401abc)"
    assert ib._classify_net(detail, "unreachable") == "timeout"
    assert ib._classify_net("Max retries exceeded ... _page_id=x401", "unreachable") == "unreachable"


def test_pinned_session_ignores_environment_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("requests")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    s = ib._pinned_session(FP, "u", "p")
    assert s.trust_env is False
    settings = s.merge_environment_settings("https://gm/wapi", {}, None, None, None)
    assert not settings.get("proxies")


# ---- review fixes (DHCP-7 round 2) -------------------------------------------


@pytest.mark.parametrize("bad", [None, "", "zzzz", "ab" * 31, 42])
def test_invalid_value_in_pin_file_fails_closed(fake: dict[str, Any], bad: Any) -> None:
    ib.PINS_FILE.write_text(json.dumps({"10.0.0.5:443": bad}))
    out = dh._collect_one(TARGET, winrm_timeout=10)
    assert out["code"] == "pin_store_failed" and fake["pinned_with"] is None


def test_malformed_pushed_pin_fails_closed(fake: dict[str, Any]) -> None:
    out = dh._collect_one({**TARGET, "tls_fingerprint": "abcd"}, winrm_timeout=10)
    assert out["code"] == "pin_store_failed" and fake["pinned_with"] is None


def test_a_read_that_hangs_past_the_deadline_is_abandoned(
    fake: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import time as _t

    release = threading.Event()

    class _Slow(_FakeSession):
        def get(self, *a: Any, **k: Any) -> _Resp:
            release.wait(5)  # a trickling server: no timeout fires inside the read
            return super().get(*a, **k)

    fake["session"] = _Slow(GRID)
    monkeypatch.setattr(ib, "_MAX_TARGET_SECONDS", 0.3)
    t0 = _t.monotonic()
    out = dh._collect_one(TARGET, winrm_timeout=10)
    release.set()
    assert out["code"] == "timeout" and _t.monotonic() - t0 < 3
    assert fake["session"].closed


# ---- review fixes (DHCP-7 round 3) -------------------------------------------


@pytest.mark.parametrize("bad", ["zzzz", "---", "  ", 42, ["ab"], "ab" * 31, "g" * 64])
def test_any_supplied_invalid_pushed_pin_fails_closed(fake: dict[str, Any], bad: Any) -> None:
    out = dh._collect_one({**TARGET, "tls_fingerprint": bad}, winrm_timeout=10)
    assert out["code"] == "pin_store_failed" and fake["pinned_with"] is None


def test_absent_pushed_pin_is_first_use(fake: dict[str, Any]) -> None:
    for none in (None, ""):
        out = dh._collect_one({**TARGET, "tls_fingerprint": none}, winrm_timeout=10)
        assert out["status"] == "ok"


def test_only_one_abandoned_read_per_endpoint(
    fake: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    release = threading.Event()
    started = []

    class _Stuck(_FakeSession):
        def get(self, *a: Any, **k: Any) -> _Resp:
            started.append(1)
            release.wait(10)
            return super().get(*a, **k)

    fake["session"] = _Stuck(GRID)
    monkeypatch.setattr(ib, "_MAX_TARGET_SECONDS", 0.2)
    try:
        first = dh._collect_one(TARGET, winrm_timeout=10)
        second = dh._collect_one(TARGET, winrm_timeout=10)
        third = dh._collect_one(TARGET, winrm_timeout=10)
        assert first["code"] == second["code"] == third["code"] == "timeout"
        assert len(started) == 1  # passes 2 and 3 started no new read
        alive = [t for t in threading.enumerate() if t.name == "dhcp-infoblox" and t.is_alive()]
        assert len(alive) == 1
    finally:
        release.set()
