"""PoE (group.port) -> ifIndex join: it must never place a row it cannot prove.

There is no standard pethPsePort->ifIndex OID, so `_attach_poe` joins
structurally. Getting it wrong is worse than collecting nothing: PoE rendered
against the wrong port looks measured. These tests pin the behaviour that
matters — a row is either placed correctly or dropped and counted.

The two REAL fixtures in `fixtures/poe_aruba_cx_walks.json` are verbatim
snmpwalk output (ifName / ifType / pethPsePortTable), captured through the
Monitor1 sensor on 2026-08-20:

  rch_idf_n_stk  Aruba 6200M, 4-member ArubaOS-CX VSF stack. 212 interfaces,
                 192 PSE rows. ifIndex == (member-1)*64 + port, and the PSE
                 index space uses the SAME numbering (group 1: 1..48,
                 group 2: 65..112, group 3: 129..176, group 4: 193..240),
                 so on this chassis pethPsePortIndex IS the ifIndex.
  rch_idf_n      the same model with a single member — 56 interfaces, 48 rows.
"""

import json
import re
from pathlib import Path

import pytest

from collector.discovery.snmp_topology import _attach_poe

FIXTURE = Path(__file__).parent / "fixtures" / "poe_aruba_cx_walks.json"
PHYSICAL_IFTYPE = "6"  # ethernetCsmacd


def _load(name: str) -> tuple[dict[str, dict], set[str], list[str]]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))[name]
    interfaces = {i: {"name": n} for i, (n, _t) in data["interfaces"].items()}
    physical = {i for i, (_n, t) in data["interfaces"].items() if t == PHYSICAL_IFTYPE}
    return interfaces, physical, list(data["pse_keys"])


def _run(interfaces, physical, keys):
    work = {i: dict(r) for i, r in interfaces.items()}
    poe = {k: {"key": k} for k in keys}
    dropped = _attach_poe(work, poe, physical)
    landed = {i: r["poe"]["key"] for i, r in work.items() if "poe" in r}
    return work, landed, dropped


# --------------------------------------------------------------- real hardware
@pytest.mark.parametrize("fixture", ["rch_idf_n_stk", "rch_idf_n"])
def test_arubaos_cx_every_row_lands_on_its_own_ifindex(fixture: str) -> None:
    """On ArubaOS-CX the PSE index IS the ifIndex, measured on the real stack."""
    interfaces, physical, keys = _load(fixture)
    work, landed, dropped = _run(interfaces, physical, keys)

    assert dropped == 0, "no row on this chassis is ambiguous"
    assert len(landed) == len(keys), "every PSE row must be placed"
    for ifidx, key in landed.items():
        assert ifidx == key.split(".")[1], (
            f"pethPsePort {key} landed on ifIndex {ifidx} "
            f"({work[ifidx]['name']!r}); PSE index is the ifIndex on this chassis"
        )


def test_stack_join_does_not_depend_on_walk_order() -> None:
    """The slot digit in "2/1/12" is also 1, so PoE group 1 satisfies a naive
    name match against EVERY member. First-match-wins was therefore correct only
    because snmpwalk happens to ascend by ifIndex: reversing the order used to
    mis-attach 22 rows and silently lose 48."""
    interfaces, physical, keys = _load("rch_idf_n_stk")
    reversed_walk = {i: interfaces[i] for i in sorted(interfaces, key=lambda x: -int(x))}

    _work, landed, dropped = _run(reversed_walk, physical, keys)

    assert dropped == 0
    assert len(landed) == len(keys)
    assert all(i == k.split(".")[1] for i, k in landed.items()), (
        "enumeration order must not change which port a PoE reading belongs to"
    )


def test_no_reading_ever_lands_on_a_non_physical_interface() -> None:
    """An SVI/LAG/loopback can never be a PSE port."""
    for fixture in ("rch_idf_n_stk", "rch_idf_n"):
        interfaces, physical, keys = _load(fixture)
        work, landed, _dropped = _run(interfaces, physical, keys)
        stray = {i: work[i]["name"] for i in landed if i not in physical}
        assert not stray, f"{fixture}: PoE attached to non-physical {stray}"


# ------------------------------------------------------------------ regressions
def _stack(members: int, ports: int, name: str) -> tuple[dict, set, list, dict]:
    interfaces, physical, keys, truth = {}, set(), [], {}
    for m in range(1, members + 1):
        for p in range(1, ports + 1):
            ifidx = str(m * 1000 + p)
            interfaces[ifidx] = {"name": name.format(m=m, p=p)}
            physical.add(ifidx)
            keys.append(f"{m}.{p}")
            truth[f"{m}.{p}"] = ifidx
    return interfaces, physical, keys, truth


def test_cisco_stack_still_joins_by_name() -> None:
    """Cisco names ports member/0/port, so the group digit disambiguates."""
    interfaces, physical, keys, truth = _stack(3, 48, "GigabitEthernet{m}/0/{p}")
    _work, landed, dropped = _run(interfaces, physical, keys)
    assert dropped == 0
    assert {k: i for i, k in landed.items()} == truth


def test_orphan_row_is_dropped_rather_than_shown_on_an_svi() -> None:
    """Reproduces what production showed on the Cucamonga 2930M stacks: a PSE
    row whose index matched nothing but the VLAN100 SVI (the only interface
    whose ifName ended in 100) was rendered as that SVI's PoE status."""
    interfaces, physical, keys, truth = _stack(3, 48, "{m}/{p}")
    interfaces["9100"] = {"name": "VLAN100"}  # SVI: absent from `physical`
    keys.append("1.100")  # the orphan row

    work, landed, dropped = _run(interfaces, physical, keys)

    assert "poe" not in work["9100"], "an SVI must never carry a PoE reading"
    assert dropped == 1, "the unplaceable row must be dropped AND counted"
    assert {k: i for i, k in landed.items()} == truth


def test_single_pse_group_with_stack_global_index_keeps_its_readings() -> None:
    """The other plausible ArubaOS-Switch scheme: ONE PSE group whose port index
    runs stack-global (member 2 -> 101..148). The group carries no member
    information, so requiring a member token here would throw away every reading
    past member 1. Only the unplaceable orphan may be dropped.

    This chassis shape could not be walked directly — the Cucamonga stacks are
    not reachable from the sensor we have shell on — so it is pinned as the
    conservative boundary rather than as measured fact.
    """
    interfaces, physical, keys, truth = {}, set(), [], {}
    for m in (1, 2, 3):
        for p in range(1, 49):
            ifidx = str((m - 1) * 100 + p)
            interfaces[ifidx] = {"name": f"{m}/{p}"}
            physical.add(ifidx)
            key = f"1.{(m - 1) * 100 + p}"
            keys.append(key)
            truth[key] = ifidx
    interfaces["9100"] = {"name": "VLAN100"}
    keys.append("1.100")

    work, landed, dropped = _run(interfaces, physical, keys)

    assert "poe" not in work["9100"]
    assert dropped == 1, "only the orphan row is unplaceable"
    assert {k: i for i, k in landed.items()} == truth


def test_truncated_interface_list_drops_rather_than_reassigns() -> None:
    """_IFACE_CAP can cut ports while the PSE table is still walked whole. The
    orphaned rows must not fall onto whatever interface shares their number."""
    interfaces, physical, keys, truth = _stack(5, 48, "{m}/1/{p}")
    svis = {str(v): {"name": f"vlan{v}"} for v in range(1, 201)}
    walked = {**svis, **interfaces}
    kept = dict(list(walked.items())[:400])  # emulate the cap

    work, landed, dropped = _run(kept, physical & set(kept), keys)

    assert not [i for i in landed if not re.match(r"^\d+/1/\d+$", work[i]["name"])]
    assert dropped == len(keys) - len(landed) > 0
    for ifidx, key in landed.items():
        assert truth[key] == ifidx
