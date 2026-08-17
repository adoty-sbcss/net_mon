"""INV-8: fold `cdp:`/`ip:` placeholder nodes onto the real device in one crawl.

The fixtures here are COPIED from what production actually emitted, not invented —
Cucamonga SD carried 356 duplicate pairs in exactly three shapes, and one of them
(`D0 3D 52 0D 28 BC` against `d0:3d:52:0d:28:bc`) is the same MAC written two ways,
which is the kind of outlier a hand-typed fixture smooths away.

Charter, same as the dashboard matcher: a WRONG fold is worse than a duplicate. Every
"folds" test is paired with a near-miss that must NOT fold.
"""
from collector.discovery.snmp_topology import _fold_synthetic_nodes, _identity_key


def node(chassis, *, name=None, descr=None, ips=None, caps=None, source="snmp"):
    return {
        "chassis_id": chassis,
        "system_name": name,
        "system_description": descr,
        "mgmt_ips": list(ips or []),
        "discovered_via_ip": (ips or ["10.0.0.1"])[0],
        "source": source,
        "capabilities": caps,
    }


def edge(local, remote, *, lport="1", rport="2", via="lldp"):
    return {
        "local_chassis_id": local,
        "local_port_id": lport,
        "local_port_desc": None,
        "remote_chassis_id": remote,
        "remote_port_id": rport,
        "remote_port_desc": None,
        "via": via,
        "discovered_via_ip": "10.0.0.1",
    }


# ---------------------------------------------------------------- identity key


def test_identity_key_collapses_mac_spellings():
    assert _identity_key("D0 3D 52 0D 28 BC") == _identity_key("d0:3d:52:0d:28:bc")
    assert _identity_key("T34W44DBD28A3B6A") == _identity_key("t34w-44db-d28a-3b6a")


# ---------------------------------------------------------------- the 3 shapes


def test_cdp_named_for_the_chassis_id_verbatim_folds():
    """135 of Cucamonga's pairs: the CDP device-id IS the chassis id."""
    nodes = {
        "T34W44DBD28A3B6A": node("T34W44DBD28A3B6A", name="T34W", ips=["192.168.130.45"]),
        "cdp:T34W44DBD28A3B6A": node("cdp:T34W44DBD28A3B6A", name="T34W44DBD28A3B6A", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 1
    assert set(nodes) == {"T34W44DBD28A3B6A"}
    # the real node's own sysName is never overwritten by the placeholder's
    assert nodes["T34W44DBD28A3B6A"]["system_name"] == "T34W"


def test_same_mac_with_spaces_instead_of_colons_folds():
    """88 of the pairs: the same MAC, rejected downstream purely over formatting."""
    nodes = {
        "d0:3d:52:0d:28:bc": node("d0:3d:52:0d:28:bc", name="avacam-abhi-u3x2-i4sa", ips=["10.52.33.147"]),
        "cdp:D0 3D 52 0D 28 BC": node("cdp:D0 3D 52 0D 28 BC", name="D0 3D 52 0D 28 BC", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 1
    assert set(nodes) == {"d0:3d:52:0d:28:bc"}


def test_ip_placeholder_sharing_a_mgmt_address_folds():
    """133 of the pairs: the placeholder is named for the address it already shares.

    The dashboard leaves these to a human because months may separate the two rows.
    Here both came out of ONE crawl minutes apart, so the address cannot have changed
    hands and folding is safe.
    """
    nodes = {
        "ec:fc:c6:c7:e1:3a": node("ec:fc:c6:c7:e1:3a", name="RCH-Outdoor-North", ips=["10.10.0.66"]),
        "ip:10.10.0.66": node("ip:10.10.0.66", name="10.10.0.66", ips=["10.10.0.66"]),
    }
    assert _fold_synthetic_nodes(nodes, []) == 1
    assert set(nodes) == {"ec:fc:c6:c7:e1:3a"}
    assert nodes["ec:fc:c6:c7:e1:3a"]["system_name"] == "RCH-Outdoor-North"


def test_cdp_placeholder_matching_a_sysname_folds():
    nodes = {
        "aa:bb:cc:00:00:01": node("aa:bb:cc:00:00:01", name="RCH-IDF-N", ips=["10.10.0.5"]),
        "cdp:RCH-IDF-N": node("cdp:RCH-IDF-N", name="RCH-IDF-N", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 1
    assert set(nodes) == {"aa:bb:cc:00:00:01"}


# ---------------------------------------------------------------- refusals


def test_shared_virtual_address_never_folds():
    """HSRP/VRRP: two real routers behind one VIP. Guessing which is a wrong merge."""
    nodes = {
        "aa:bb:cc:00:00:01": node("aa:bb:cc:00:00:01", name="core-a", ips=["10.0.0.1"]),
        "aa:bb:cc:00:00:02": node("aa:bb:cc:00:00:02", name="core-b", ips=["10.0.0.1"]),
        "ip:10.0.0.1": node("ip:10.0.0.1", name="10.0.0.1", ips=["10.0.0.1"]),
    }
    assert _fold_synthetic_nodes(nodes, []) == 0
    assert "ip:10.0.0.1" in nodes


def test_ambiguous_sysname_never_folds():
    nodes = {
        "aa:bb:cc:00:00:01": node("aa:bb:cc:00:00:01", name="switch", ips=["10.0.0.1"]),
        "aa:bb:cc:00:00:02": node("aa:bb:cc:00:00:02", name="switch", ips=["10.0.0.2"]),
        "cdp:switch": node("cdp:switch", name="switch", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 0


def test_placeholder_with_no_match_is_kept():
    """A device only a neighbour ever saw is REAL inventory, not a duplicate."""
    nodes = {
        "aa:bb:cc:00:00:01": node("aa:bb:cc:00:00:01", name="core", ips=["10.0.0.1"]),
        "cdp:far-away-switch": node("cdp:far-away-switch", name="far-away-switch", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 0
    assert len(nodes) == 2


def test_address_shaped_name_is_not_treated_as_an_identity():
    """A placeholder named for an address must not match a chassis id by digits.

    A normalized IPv4 tops out at 12 characters — exactly a MAC's length — so an
    all-decimal MAC could collide with one.
    """
    nodes = {
        "25:52:55:25:52:55": node("25:52:55:25:52:55", name="edge", ips=["10.9.9.9"]),
        "ip:255.255.255.255": node("ip:255.255.255.255", name="255.255.255.255", ips=["255.255.255.255"]),
    }
    assert _fold_synthetic_nodes(nodes, []) == 0


def test_short_identity_is_not_trusted():
    nodes = {
        "sw-1": node("sw-1", name="alpha", ips=["10.0.0.9"]),
        "cdp:SW1": node("cdp:SW1", name="SW1", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 0


def test_mac_differing_by_one_digit_never_folds():
    nodes = {
        "d0:3d:52:0d:28:bc": node("d0:3d:52:0d:28:bc", name="cam-a", ips=["10.52.33.147"]),
        "cdp:D0 3D 52 0D 28 BD": node("cdp:D0 3D 52 0D 28 BD", name="D0 3D 52 0D 28 BD", source="cdp"),
    }
    assert _fold_synthetic_nodes(nodes, []) == 0


def test_a_crawl_with_no_real_nodes_folds_nothing():
    nodes = {"cdp:a-switch": node("cdp:a-switch", name="a-switch", source="cdp")}
    assert _fold_synthetic_nodes(nodes, []) == 0
    assert len(nodes) == 1


# ---------------------------------------------------------------- edges


def test_edges_repoint_and_self_loops_drop():
    nodes = {
        "ec:fc:c6:c7:e1:3a": node("ec:fc:c6:c7:e1:3a", name="leaf", ips=["10.10.0.66"]),
        "ip:10.10.0.66": node("ip:10.10.0.66", name="10.10.0.66", ips=["10.10.0.66"]),
        "aa:bb:cc:00:00:09": node("aa:bb:cc:00:00:09", name="core", ips=["10.10.0.1"]),
    }
    edges = [
        edge("aa:bb:cc:00:00:09", "ip:10.10.0.66"),        # -> real leaf
        edge("ec:fc:c6:c7:e1:3a", "ip:10.10.0.66"),        # the device facing ITSELF
        edge("aa:bb:cc:00:00:09", "ec:fc:c6:c7:e1:3a"),    # already correct == dupe of #1
    ]
    assert _fold_synthetic_nodes(nodes, edges) == 1
    assert len(edges) == 1
    assert edges[0]["local_chassis_id"] == "aa:bb:cc:00:00:09"
    assert edges[0]["remote_chassis_id"] == "ec:fc:c6:c7:e1:3a"


def test_fold_fills_only_missing_fields():
    nodes = {
        "aa:bb:cc:00:00:01": node("aa:bb:cc:00:00:01", name="core", ips=["10.0.0.1"]),
        "ip:10.0.0.1": node(
            "ip:10.0.0.1", name="10.0.0.1", descr="Cisco IOS 15.2", ips=["10.0.0.1", "10.0.0.2"],
            caps=["bridge"],
        ),
    }
    assert _fold_synthetic_nodes(nodes, []) == 1
    keeper = nodes["aa:bb:cc:00:00:01"]
    assert keeper["system_name"] == "core"                     # not overwritten
    assert keeper["system_description"] == "Cisco IOS 15.2"    # filled in
    assert keeper["capabilities"] == ["bridge"]                # filled in
    assert sorted(keeper["mgmt_ips"]) == ["10.0.0.1", "10.0.0.2"]  # unioned


def test_fold_is_idempotent():
    nodes = {
        "ec:fc:c6:c7:e1:3a": node("ec:fc:c6:c7:e1:3a", name="leaf", ips=["10.10.0.66"]),
        "ip:10.10.0.66": node("ip:10.10.0.66", name="10.10.0.66", ips=["10.10.0.66"]),
    }
    edges = [edge("ip:10.10.0.66", "aa:bb:cc:00:00:09")]
    assert _fold_synthetic_nodes(nodes, edges) == 1
    snapshot = ({k: dict(v) for k, v in nodes.items()}, [dict(e) for e in edges])
    assert _fold_synthetic_nodes(nodes, edges) == 0
    assert ({k: dict(v) for k, v in nodes.items()}, [dict(e) for e in edges]) == snapshot


def test_a_real_node_is_never_removed():
    nodes = {
        "aa:bb:cc:00:00:01": node("aa:bb:cc:00:00:01", name="core", ips=["10.0.0.1"]),
        "bb:bb:cc:00:00:02": node("bb:bb:cc:00:00:02", name="core", ips=["10.0.0.1"]),
    }
    before = set(nodes)
    _fold_synthetic_nodes(nodes, [])
    assert set(nodes) == before
