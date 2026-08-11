"""Per-device SNMP credential overrides (dashboard `snmp_credential_overrides`).

The contract these pin, and why each one matters:

  * the override is tried BEFORE the cache. The cache holds whatever answered
    last time and is only invalidated by failing, so checking it first would
    make a freshly-pushed override inert forever on a device that already works;
  * a failing override FALLS BACK to the shared ladder rather than blacking the
    device out — a stale override should degrade, not break monitoring;
  * an override is a credential source on its own, so a box with an empty shared
    community list still polls the devices that have one;
  * parsing splits on the FIRST '=' so a community containing '=' survives, and
    junk entries are skipped rather than raising.
"""
from types import SimpleNamespace

from collector.config import Settings
from collector.discovery import snmp


def _no_cache(monkeypatch):
    """No cached credential, and record the writes the selector makes."""
    writes: list[tuple[str, str]] = []
    monkeypatch.setattr(snmp, "get_snmp_credential", lambda ip: None)
    monkeypatch.setattr(
        snmp, "record_snmp_success", lambda ip, c, v="2c": writes.append((ip, c))
    )
    monkeypatch.setattr(snmp, "record_snmp_failure", lambda ip: writes.append((ip, "")))
    return writes


# ---- parsing --------------------------------------------------------------


def test_override_map_parses_pairs() -> None:
    s = Settings(NETMON_SNMP_CREDENTIAL_OVERRIDES="10.0.0.1=alpha,10.0.0.2=beta")
    assert s.snmp_credential_override_map == {"10.0.0.1": "alpha", "10.0.0.2": "beta"}


def test_override_map_tolerates_whitespace() -> None:
    s = Settings(NETMON_SNMP_CREDENTIAL_OVERRIDES=" 10.0.0.1 = alpha , 10.0.0.2=beta ")
    assert s.snmp_credential_override_map == {"10.0.0.1": "alpha", "10.0.0.2": "beta"}


def test_override_community_may_contain_equals() -> None:
    """Split on the FIRST '=' only — base64-ish communities keep their padding."""
    s = Settings(NETMON_SNMP_CREDENTIAL_OVERRIDES="10.0.0.1=a=b=c")
    assert s.snmp_credential_override_map == {"10.0.0.1": "a=b=c"}


def test_override_map_skips_malformed_entries() -> None:
    """One bad pair must not take SNMP down for the whole box."""
    s = Settings(
        NETMON_SNMP_CREDENTIAL_OVERRIDES="garbage,10.0.0.1=alpha,=orphan,10.0.0.3=,"
    )
    assert s.snmp_credential_override_map == {"10.0.0.1": "alpha"}


def test_override_map_empty_by_default() -> None:
    assert Settings().snmp_credential_override_map == {}


# ---- selection ------------------------------------------------------------


def test_override_wins_over_the_shared_list(monkeypatch) -> None:
    writes = _no_cache(monkeypatch)
    tried: list[str] = []

    def probe(ip, community):
        tried.append(community)
        return True  # everything answers; order is what's under test

    monkeypatch.setattr(snmp, "_probe", probe)

    got = snmp._select_community(
        "10.0.0.1", ["districtro"], overrides={"10.0.0.1": "special"}
    )

    assert got == "special"
    assert tried == ["special"], "the shared list must not be tried first"
    assert writes == [("10.0.0.1", "special")]


def test_override_beats_a_working_cached_community(monkeypatch) -> None:
    """THE regression: a cache hit must not shadow a newly-pushed override."""
    monkeypatch.setattr(
        snmp,
        "get_snmp_credential",
        lambda ip: {"community": "cached", "version": "2c", "failure_count": 0},
    )
    monkeypatch.setattr(snmp, "record_snmp_success", lambda ip, c, v="2c": None)
    tried: list[str] = []

    def probe(ip, community):
        tried.append(community)
        return True

    monkeypatch.setattr(snmp, "_probe", probe)

    got = snmp._select_community(
        "10.0.0.1", ["districtro"], overrides={"10.0.0.1": "special"}
    )

    assert got == "special"
    assert tried == ["special"], f"cache was consulted first: {tried}"


def test_failing_override_falls_back_to_the_ladder(monkeypatch) -> None:
    """A stale override degrades to the district ladder; it doesn't black out."""
    writes = _no_cache(monkeypatch)
    tried: list[str] = []

    def probe(ip, community):
        tried.append(community)
        return community == "districtro"

    monkeypatch.setattr(snmp, "_probe", probe)

    got = snmp._select_community(
        "10.0.0.1", ["districtro"], overrides={"10.0.0.1": "wrong"}
    )

    assert got == "districtro"
    assert tried == ["wrong", "districtro"]
    assert writes == [("10.0.0.1", "districtro")]


def test_failed_override_is_not_retried_in_the_ladder(monkeypatch) -> None:
    """It already failed — probing the same string again is wasted round-trips."""
    _no_cache(monkeypatch)
    tried: list[str] = []

    def probe(ip, community):
        tried.append(community)
        return False

    monkeypatch.setattr(snmp, "_probe", probe)

    got = snmp._select_community(
        "10.0.0.1", ["shared", "dup"], overrides={"10.0.0.1": "dup"}
    )

    assert got is None
    assert tried == ["dup", "shared"], f"duplicate probe: {tried}"


def test_override_applies_only_to_its_own_device(monkeypatch) -> None:
    _no_cache(monkeypatch)
    tried: list[str] = []

    def probe(ip, community):
        tried.append(community)
        return True

    monkeypatch.setattr(snmp, "_probe", probe)

    got = snmp._select_community(
        "10.0.0.9", ["districtro"], overrides={"10.0.0.1": "special"}
    )

    assert got == "districtro"
    assert tried == ["districtro"]


def _in_backoff(monkeypatch):
    """A device that has failed enough times to be in the 24h backoff window."""
    from datetime import UTC, datetime

    monkeypatch.setattr(
        snmp,
        "get_snmp_credential",
        lambda ip: {
            "community": None,
            "failure_count": snmp.MAX_FAILURES_BEFORE_BACKOFF + 1,
            "last_attempt_at": datetime.now(UTC),
        },
    )


def test_an_override_bypasses_failure_backoff(monkeypatch) -> None:
    """A device stuck in backoff is EXACTLY the device an operator overrides.

    Backoff lives in the box's own cache and is not reset by a config push, so
    honouring it here would leave a freshly-pushed override inert for up to 24
    hours — looking identical to a wrong credential.
    """
    _in_backoff(monkeypatch)
    monkeypatch.setattr(snmp, "record_snmp_success", lambda ip, c, v="2c": None)
    probed: list[str] = []

    def probe(ip, community):
        probed.append(community)
        return community == "special"

    monkeypatch.setattr(snmp, "_probe", probe)

    got = snmp._select_community(
        "10.0.0.1", ["districtro"], overrides={"10.0.0.1": "special"}
    )

    assert got == "special"
    assert probed == ["special"]


def test_backoff_still_skips_a_device_with_no_override(monkeypatch) -> None:
    """The bypass is scoped to overridden devices — everything else still backs
    off, or a dead subnet costs a full trial on every scan."""
    _in_backoff(monkeypatch)
    probed: list[str] = []
    monkeypatch.setattr(snmp, "_probe", lambda ip, c: probed.append(c) or True)

    got = snmp._select_community(
        "10.0.0.9", ["districtro"], overrides={"10.0.0.1": "special"}
    )

    assert got is None
    assert probed == []


# ---- the poll entry point -------------------------------------------------


def test_poll_runs_with_overrides_and_no_shared_communities(monkeypatch) -> None:
    """An override is a credential source on its own — the early return that
    bails on an empty community list must not skip a device that has one."""
    settings = SimpleNamespace(
        snmp_enabled=True,
        snmp_community_list=(),
        snmp_credential_override_map={"192.0.2.1": "special"},
        snmp_poll_max_candidates=10,
        snmp_poll_time_budget=120,
    )
    monkeypatch.setattr(snmp, "get_settings", lambda: settings)
    monkeypatch.setattr(snmp.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    seen: list[dict[str, str] | None] = []

    def select(ip, communities, deadline=float("inf"), overrides=None):
        seen.append(overrides)
        return (overrides or {}).get(ip)

    monkeypatch.setattr(snmp, "_select_community", select)
    monkeypatch.setattr(
        snmp,
        "_poll_oids",
        lambda ip, community, include_bulk=True, deadline=float("inf"): [
            {"ip": ip, "community": community}
        ],
    )

    rows = snmp.poll(["192.0.2.1"])

    assert rows == [{"ip": "192.0.2.1", "community": "special"}]
    assert seen == [{"192.0.2.1": "special"}]


def test_poll_still_returns_early_with_nothing_configured(monkeypatch) -> None:
    settings = SimpleNamespace(
        snmp_enabled=True,
        snmp_community_list=(),
        snmp_credential_override_map={},
        snmp_poll_max_candidates=10,
        snmp_poll_time_budget=120,
    )
    monkeypatch.setattr(snmp, "get_settings", lambda: settings)

    assert snmp.poll(["192.0.2.1"]) == []
