"""lib/trunk.sh: VLAN sub-interface naming, clearing, and migration.

Two defects, both of the "quietly does nothing" kind:

1. A 15-character parent NIC (a USB `enx001122334455`) made `<parent>.<vid>` longer
   than Linux's 15-byte interface-name limit. nmcli/networkd refused the name, the
   `|| true` swallowed it, and the apply still reported success.
2. Clearing the VLAN list removed nothing: host-apply-vlan refuses an empty set and
   there was no other path, so NetMon's sub-interfaces stayed up.

These tests source the REAL lib/trunk.sh in bash, with `ip`, `nmcli`, `netplan` and
`systemctl` replaced by stubs over a small on-disk model of the kernel's link table
that enforces the two kernel rules that matter here: names are at most 15 bytes,
and one parent cannot carry two devices for the same VLAN id. The stubs model the
WORST case for leftovers — deleting an NM connection or dropping a netplan stanza
does not remove the link — so every link that disappears was removed by trunk.sh.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TRUNK = REPO_ROOT / "lib" / "trunk.sh"
HOST_ACTION = REPO_ROOT / "scripts" / "host-action.sh"

LONG = "enx001122334455"  # 15 chars: a USB NIC named from its MAC
LONG2 = "enx00aabbccddee"


def _bash() -> str:
    if sys.platform == "win32":
        git = shutil.which("git")
        candidates = [d / "bin" / "bash.exe" for d in Path(git).parents] if git else []
        found = next((str(c) for c in candidates if c.exists()), None)
    else:
        found = shutil.which("bash")
    if not found:
        pytest.skip("bash is required")
    return found


# State files (all under $ST):
#   links  "name kind vid parent"   kind is vlan|eth; vid/parent "-" for eth
#   cons   "con ifname parent vid addrs [type]"   "-" = empty; type defaults to vlan
#   noroute    present => no default route
#   route-back-after   N: the route comes back after N one-second sleeps
#   calls      every mutating stub call, for assertions
STUBS = r'''
set -uo pipefail
SUDO=""
log()  { printf 'LOG %s\n' "$*"; }
ok()   { printf 'OK %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
sleep() {
    local n
    if [[ -e "$ST/route-back-after" ]]; then
        n=$(( $(cat "$ST/route-back-after") - 1 ))
        if (( n <= 0 )); then rm -f "$ST/route-back-after" "$ST/noroute"; else echo "$n" > "$ST/route-back-after"; fi
    fi
}
install() {  # install -m 600 -o root -g root SRC DST
    local a=("$@"); cp "${a[-2]}" "${a[-1]}"
}
systemctl() {  # systemctl is-active --quiet <unit>
    local unit="${*: -1}"
    case "$BACKEND:$unit" in
        nm:NetworkManager|networkd:systemd-networkd) return 0 ;;
        *) return 1 ;;
    esac
}
_has_link() { awk -v n="$1" '$1==n {f=1} END {exit !f}' "$ST/links"; }
_add_vlan_link() {  # name vid parent -> 0 created/exists-identical, 1 refused
    local name="$1" vid="$2" parent="$3"
    (( ${#name} <= 15 )) || { echo "kernel: name too long: $name" >> "$ST/calls"; return 1; }
    _has_link "$parent" || return 1
    if _has_link "$name"; then return 0; fi   # existing netdev is never modified
    if awk -v v="$vid" -v p="$parent" '$2=="vlan" && $3==v && $4==p {f=1} END {exit !f}' "$ST/links"; then
        echo "kernel: vid $vid already on $parent" >> "$ST/calls"; return 1
    fi
    echo "$name vlan $vid $parent" >> "$ST/links"
}
ip() {
    case "$*" in
        "route show default")
            [[ -e "$ST/noroute" ]] || echo "default via 192.0.2.1 dev $UPLINK proto dhcp" ;;
        "-d -o link show dev "*)
            local n="${*: -1}" kind vid par
            read -r _ kind vid par < <(awk -v n="$n" '$1==n' "$ST/links") || return 1
            if [[ "$kind" == vlan ]]; then
                echo "9: ${n}@${par}: <BROADCAST,UP> mtu 1500 \\    vlan protocol 802.1Q id ${vid} <REORDER_HDR> addrgenmode eui64"
            else
                echo "2: ${n}: <BROADCAST,UP> mtu 1500 \\    link/ether 00:11:22:33:44:55"
            fi ;;
        "link show dev "*) _has_link "${*: -1}" ;;
        "link delete "*)
            local n="${*: -1}"
            echo "ip link delete $n" >> "$ST/calls"
            awk -v n="$n" '$1!=n' "$ST/links" > "$ST/links.tmp" && mv "$ST/links.tmp" "$ST/links" ;;
        *) echo "unexpected ip $*" >> "$ST/calls"; return 1 ;;
    esac
}
netplan() {
    echo "netplan $*" >> "$ST/calls"
    case "$1" in
        generate)
            # networkd rejects an over-long netdev name.
            [[ -f "$NETMON_VLAN_NETPLAN" ]] || return 0
            ! _vlan_netplan_children "$NETMON_VLAN_NETPLAN" | awk 'length($1) > 15 {f=1} END {exit !f}' ;;
        apply)
            [[ -e "$ST/apply-drops-route" ]] && touch "$ST/noroute"
            [[ -f "$NETMON_VLAN_NETPLAN" ]] || return 0
            local name id link
            while read -r name id link; do
                [[ -n "$name" ]] && _add_vlan_link "$name" "$id" "$link"
            done < <(_vlan_netplan_children "$NETMON_VLAN_NETPLAN")
            return 0 ;;
    esac
}
nmcli() {
    case "$*" in
        "-g NAME con show") awk '{print $1}' "$ST/cons" ;;
        "-g connection.type,connection.interface-name,vlan.parent,vlan.id,ipv4.addresses con show "*)
            local c="${*: -1}" ifn par vid adr typ v
            read -r _ ifn par vid adr typ < <(awk -v c="$c" '$1==c' "$ST/cons") || return 10
            for v in ifn par vid adr; do [[ "${!v}" == "-" ]] && printf -v "$v" '%s' ''; done
            printf '%s\n%s\n%s\n%s\n%s\n' "${typ:-vlan}" "$ifn" "$par" "$vid" "$adr" ;;
        "con delete "*)
            local c="${*: -1}"
            [[ -e "$ST/delete-fails" ]] && return 1
            echo "nmcli con delete $c" >> "$ST/calls"
            [[ -e "$ST/delete-drops-route" ]] && touch "$ST/noroute"
            awk -v c="$c" '$1!=c' "$ST/cons" > "$ST/cons.tmp" && mv "$ST/cons.tmp" "$ST/cons" ;;
        "con add type vlan "*)
            local a=("$@") i con="" ifn="" dev="" vid="" adr="-"
            for ((i = 0; i < ${#a[@]}; i++)); do
                case "${a[$i]}" in
                    con-name) con="${a[$((i+1))]}" ;;
                    ifname) ifn="${a[$((i+1))]}" ;;
                    dev) dev="${a[$((i+1))]}" ;;
                    id) vid="${a[$((i+1))]}" ;;
                    ipv4.addresses) adr="${a[$((i+1))]}" ;;
                esac
            done
            echo "nmcli con add $con $ifn $dev $vid $adr" >> "$ST/calls"
            # nmcli validates interface-name: > 15 bytes is refused.
            (( ${#ifn} <= 15 )) || return 2
            echo "$con $ifn $dev $vid $adr" >> "$ST/cons" ;;
        "con up "*)
            local c="$3" ifn par vid
            read -r _ ifn par vid _ < <(awk -v c="$c" '$1==c' "$ST/cons") || return 10
            _add_vlan_link "$ifn" "$vid" "$par" || return 4 ;;
        *) echo "unexpected nmcli $*" >> "$ST/calls"; return 1 ;;
    esac
}
'''


def _run(tmp_path: Path, body: str, *, backend: str, links: str = "",
         cons: str = "", netplan_file: str | None = None, uplink: str = "eth0",
         flags: tuple[str, ...] = ()) -> tuple[str, dict[str, str]]:
    st = tmp_path / "st"
    st.mkdir()
    base = f"eth0 eth - -\n{LONG} eth - -\n{LONG2} eth - -\neth1 eth - -\n"
    (st / "links").write_text(base + links, encoding="utf-8", newline="\n")
    (st / "cons").write_text(cons, encoding="utf-8", newline="\n")
    (st / "calls").write_text("", encoding="utf-8")
    for f in flags:
        (st / f).write_text("", encoding="utf-8")
    plan = tmp_path / "60-netmon-vlans.yaml"
    if netplan_file is not None:
        plan.write_text(netplan_file, encoding="utf-8", newline="\n")
    script = tmp_path / "t.sh"
    script.write_text(
        f'ST="{st.as_posix()}"\nBACKEND="{backend}"\nUPLINK="{uplink}"\n'
        f'NETMON_VLAN_NETPLAN="{plan.as_posix()}"\n'
        + STUBS
        + f'. "{TRUNK.as_posix()}"\n'
        + body + "\n",
        encoding="utf-8", newline="\n",
    )
    proc = subprocess.run([_bash(), script.as_posix()], capture_output=True, text=True)
    state = {
        "links": (st / "links").read_text(encoding="utf-8"),
        "cons": (st / "cons").read_text(encoding="utf-8"),
        "calls": (st / "calls").read_text(encoding="utf-8"),
        "plan": plan.read_text(encoding="utf-8") if plan.exists() else "",
        "plan_exists": "yes" if plan.exists() else "",
        "stderr": proc.stderr,
    }
    return proc.stdout, state


def _vlan_links(state: dict[str, str]) -> set[tuple[str, str, str]]:
    out = set()
    for line in state["links"].splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[1] == "vlan":
            out.add((parts[0], parts[2], parts[3]))
    return out


def _netplan_old(children: list[tuple[str, int, str]]) -> str:
    lines = ["network:", "  version: 2", "  vlans:"]
    for name, vid, link in children:
        lines += [f"    {name}:", f"      id: {vid}", f"      link: {link}",
                  "      dhcp4: true", "      dhcp4-overrides:", "        use-routes: false"]
    return "\n".join(lines) + "\n"


# --- naming -----------------------------------------------------------------


@pytest.mark.parametrize(("parent", "vid", "expected"), [
    ("eth0", 10, "eth0.10"),
    ("enp0s31f6", 4094, "enp0s31f6.4094"),
    ("enp0s20f0u1", 100, "enp0s20f0u1.100"),   # exactly 15: unchanged
    ("enp0s20f0u1", 1000, "vlan1000"),         # 16 would be refused
    (LONG, 10, "vlan10"),
    (LONG, 4094, "vlan4094"),
])
def test_child_name_keeps_the_dotted_name_when_it_fits(tmp_path, parent, vid, expected) -> None:
    out, _ = _run(tmp_path, f'vlan_child_name "{parent}" {vid}; echo', backend="networkd")
    assert out.strip() == expected
    assert len(out.strip()) <= 15


# --- fix 2: long parent -------------------------------------------------------


def test_netplan_long_parent_creates_bounded_names_on_the_full_parent(tmp_path) -> None:
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG} 10,4094 "4094:10.0.40.9/24"; echo "RC=$?"',
                   backend="networkd")
    assert "RC=0" in out, out + st["calls"]
    assert _vlan_links(st) == {("vlan10", "10", LONG), ("vlan4094", "4094", LONG)}
    assert f"link: {LONG}" in st["plan"]
    assert "    vlan4094:\n      id: 4094\n      link: enx001122334455\n      addresses: [10.0.40.9/24]" in st["plan"]


def test_nmcli_long_parent_creates_bounded_names_on_the_full_parent(tmp_path) -> None:
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG} 10,20 "20:10.0.20.9/24"; echo "RC=$?"',
                   backend="nm")
    assert "RC=0" in out, out + st["calls"]
    assert _vlan_links(st) == {("vlan10", "10", LONG), ("vlan20", "20", LONG)}
    assert f"netmon-vlan20 vlan20 {LONG} 20 10.0.20.9/24" in st["cons"]


def test_a_sub_interface_that_never_appears_is_a_failure_not_success(tmp_path) -> None:
    # The old code `|| true`-ed a refused add and still printed "VLAN sub-interfaces
    # up". Model a refusal (VLAN 10 already held on the parent by a foreign device).
    out, st = _run(tmp_path, 'apply_vlan_netplan_headless eth0 10; echo "RC=$?"',
                   backend="nm", links="office10 vlan 10 eth0\n")
    assert "RC=1" in out
    assert "did not come up: eth0.10" in out
    assert ("office10", "10", "eth0") in _vlan_links(st)  # foreign device untouched


def test_short_parent_names_are_unchanged(tmp_path) -> None:
    out, st = _run(tmp_path, 'apply_vlan_netplan_headless eth0 10,20; echo "RC=$?"', backend="networkd")
    assert "RC=0" in out
    assert _vlan_links(st) == {("eth0.10", "10", "eth0"), ("eth0.20", "20", "eth0")}
    assert "ip link delete" not in st["calls"]


def test_invalid_parent_is_refused_before_anything_is_written(tmp_path) -> None:
    out, st = _run(tmp_path, 'apply_vlan_netplan_headless "eth0: {}" 10; echo "RC=$?"', backend="networkd")
    assert "RC=1" in out
    assert not st["plan_exists"]
    assert st["calls"] == ""


# --- migration: old names, parent changes -------------------------------------


def test_netplan_reapply_onto_a_long_parent_removes_the_old_link_first(tmp_path) -> None:
    # Box configured on eth0 (eth0.10, eth0.20), operator moves the trunk to a USB NIC.
    old = _netplan_old([("eth0.10", 10, "eth0"), ("eth0.20", 20, "eth0")])
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG} 10; echo "RC=$?"', backend="networkd",
                   netplan_file=old, links="eth0.10 vlan 10 eth0\neth0.20 vlan 20 eth0\n")
    assert "RC=0" in out, out + st["calls"]
    assert _vlan_links(st) == {("vlan10", "10", LONG)}


def test_netplan_parent_change_between_long_parents_recreates_the_same_name(tmp_path) -> None:
    # vlan10 on LONG -> vlan10 on LONG2: networkd would leave the old netdev in
    # place under the same name, so it must be deleted before the apply.
    old = _netplan_old([("vlan10", 10, LONG)])
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG2} 10; echo "RC=$?"', backend="networkd",
                   netplan_file=old, links=f"vlan10 vlan 10 {LONG}\n")
    assert "RC=0" in out, out + st["calls"]
    assert _vlan_links(st) == {("vlan10", "10", LONG2)}


def test_netplan_unchanged_children_are_not_bounced(tmp_path) -> None:
    old = _netplan_old([("eth0.10", 10, "eth0"), ("eth0.20", 20, "eth0")])
    out, st = _run(tmp_path, 'apply_vlan_netplan_headless eth0 10; echo "RC=$?"', backend="networkd",
                   netplan_file=old, links="eth0.10 vlan 10 eth0\neth0.20 vlan 20 eth0\n")
    assert "RC=0" in out
    assert "ip link delete eth0.10" not in st["calls"]
    assert "ip link delete eth0.20" in st["calls"]
    assert _vlan_links(st) == {("eth0.10", "10", "eth0")}


def test_nmcli_reapply_onto_a_long_parent_migrates_old_names(tmp_path) -> None:
    cons = "netmon-vlan10 eth0.10 eth0 10 -\nnetmon-vlan20 eth0.20 eth0 20 -\n"
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG} 10; echo "RC=$?"', backend="nm",
                   cons=cons, links="eth0.10 vlan 10 eth0\neth0.20 vlan 20 eth0\n")
    assert "RC=0" in out, out + st["calls"]
    assert _vlan_links(st) == {("vlan10", "10", LONG)}
    assert st["cons"].split("\n")[0:1] == [f"netmon-vlan10 vlan10 {LONG} 10 -"]


def test_nmcli_stale_removal_uses_the_recorded_name_not_a_guess(tmp_path) -> None:
    # The old code deleted "${parent}.${vid}" for a stale VLAN — the wrong name for a
    # vlan<id> sub-interface, so the link stayed up.
    cons = f"netmon-vlan10 vlan10 {LONG} 10 -\nnetmon-vlan20 vlan20 {LONG} 20 -\n"
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG} 10; echo "RC=$?"', backend="nm",
                   cons=cons, links=f"vlan10 vlan 10 {LONG}\nvlan20 vlan 20 {LONG}\n")
    assert "RC=0" in out
    assert _vlan_links(st) == {("vlan10", "10", LONG)}
    assert "netmon-vlan20" not in st["cons"]


# --- fix 1: clearing ----------------------------------------------------------


def test_remove_on_networkd_removes_only_what_our_file_defines(tmp_path) -> None:
    old = _netplan_old([("eth0.10", 10, "eth0"), ("vlan20", 20, LONG)])
    links = f"eth0.10 vlan 10 eth0\nvlan20 vlan 20 {LONG}\neth0.99 vlan 99 eth0\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="networkd",
                   netplan_file=old, links=links, cons="office eth0.99 eth0 99 -\n")
    assert "RC=0" in out, out + st["calls"]
    assert not st["plan_exists"]
    assert _vlan_links(st) == {("eth0.99", "99", "eth0")}   # the admin's own VLAN stays
    assert st["cons"] == "office eth0.99 eth0 99 -\n"       # and its NM connection
    assert "netplan apply" in st["calls"]
    for base in ("eth0", LONG, LONG2, "eth1"):
        assert f"ip link delete {base}\n" not in st["calls"]


def test_remove_on_nm_removes_only_netmon_connections(tmp_path) -> None:
    cons = (f"netmon-vlan10 vlan10 {LONG} 10 -\nnetmon-vlan20 eth0.20 eth0 20 10.0.20.9/24\n"
            "office-vlan eth0.30 eth0 30 -\nnetmon-vlanx eth0.40 eth0 40 -\n")
    links = f"vlan10 vlan 10 {LONG}\neth0.20 vlan 20 eth0\neth0.30 vlan 30 eth0\neth0.40 vlan 40 eth0\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm",
                   cons=cons, links=links)
    assert "RC=0" in out, out + st["calls"]
    assert _vlan_links(st) == {("eth0.30", "30", "eth0"), ("eth0.40", "40", "eth0")}
    assert st["cons"] == "office-vlan eth0.30 eth0 30 -\nnetmon-vlanx eth0.40 eth0 40 -\n"
    assert "netplan" not in st["calls"]


def test_remove_with_nothing_to_remove_succeeds_and_touches_nothing(tmp_path) -> None:
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="networkd",
                   links="eth0.99 vlan 99 eth0\n")
    assert "RC=0" in out
    assert st["calls"] == ""
    assert _vlan_links(st) == {("eth0.99", "99", "eth0")}


def test_remove_never_deletes_a_non_vlan_or_mismatched_or_uplink_device(tmp_path) -> None:
    # A hand-edited (or corrupt) netplan file naming the parent, a VLAN with a
    # different id, and the uplink itself: none of them is deleted.
    old = _netplan_old([("eth1", 10, "eth0"), ("eth0.20", 21, "eth0"), ("eth0.5", 5, "eth0")])
    links = "eth0.20 vlan 20 eth0\neth0.5 vlan 5 eth0\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="networkd",
                   netplan_file=old, links=links, uplink="eth0.5")
    assert "ip link delete" not in st["calls"]
    assert "RC=1" in out   # still present -> reported, not claimed clean
    assert "still present after removal" in out


def test_remove_leaves_a_netmon_named_profile_that_is_not_a_netmon_vlan(tmp_path) -> None:
    # The name prefix alone is not ownership: an admin's ethernet profile that
    # happens to be called netmon-vlan10 (here the uplink), and a VLAN profile whose
    # id disagrees with its name, are both left alone — profile AND device.
    cons = "netmon-vlan10 eth0 - - - 802-3-ethernet\nnetmon-vlan50 eth0.51 eth0 51 -\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm",
                   cons=cons, links="eth0.51 vlan 51 eth0\n")
    assert "nmcli con delete" not in st["calls"]
    assert "ip link delete" not in st["calls"]
    assert st["cons"] == cons
    assert "RC=1" in out


def test_remove_restores_the_netplan_file_when_the_default_route_is_lost(tmp_path) -> None:
    old = _netplan_old([("eth0.10", 10, "eth0")])
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="networkd",
                   netplan_file=old, links="eth0.10 vlan 10 eth0\n", flags=("apply-drops-route",))
    assert "RC=1" in out
    assert "RESTORING" in out
    assert st["plan"] == old


def test_remove_recreates_nm_connections_when_the_default_route_is_lost(tmp_path) -> None:
    cons = f"netmon-vlan10 vlan10 {LONG} 10 -\nnetmon-vlan20 eth0.20 eth0 20 10.0.20.9/24\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm",
                   cons=cons, links=f"vlan10 vlan 10 {LONG}\neth0.20 vlan 20 eth0\n",
                   flags=("delete-drops-route",))
    assert "RC=1" in out
    assert f"netmon-vlan10 vlan10 {LONG} 10 -" in st["cons"]
    assert "netmon-vlan20 eth0.20 eth0 20 10.0.20.9/24" in st["cons"]


# --- host action wiring -------------------------------------------------------


def test_remove_vlan_is_allow_listed_on_both_sides() -> None:
    from collector import checkin

    assert "host-remove-vlan" in checkin._HOST_ACTIONS
    text = HOST_ACTION.read_text(encoding="utf-8")
    assert "remove-vlan|host-remove-vlan)" in text
    arm = text[text.index("remove-vlan|host-remove-vlan)"):]
    arm = arm[: arm.index(";;")]
    assert "remove_vlan_interfaces_headless" in arm


def test_apply_vlan_still_refuses_an_empty_list() -> None:
    # An unreadable env file reads back empty too; empty must never mean "remove".
    text = HOST_ACTION.read_text(encoding="utf-8")
    arm = text[text.index("apply-vlan|host-apply-vlan)"):]
    arm = arm[: arm.index(";;")]
    assert '[ -z "$t_vlans" ] && {' in arm and "exit 1" in arm
    assert "remove_vlan_interfaces_headless" not in arm


# --- collector: VLAN attribution comes from the kernel, not the name ------------

PROC = (
    "VLAN Dev name\t | VLAN ID\n"
    "Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"
    f"vlan10         | 10  | {LONG}\n"
    "eth0.20        | 20  | eth0\n"
)


def test_vlan_of_reads_the_kernel_table_for_bounded_names(monkeypatch, tmp_path) -> None:
    from collector import scan
    from collector.discovery import interfaces

    proc = tmp_path / "config"
    proc.write_text(PROC, encoding="utf-8")
    monkeypatch.setattr(interfaces, "PROC_VLAN_CONFIG", proc)
    assert interfaces.vlan_of("vlan10") == (10, LONG)
    assert scan._vlan_of("vlan10") == (10, LONG)
    assert interfaces.vlan_of("eth0.20") == (20, "eth0")
    assert interfaces.vlan_of("eth0") == (None, None)
    assert interfaces.vlan_of("vlan30") == (None, None)  # not a VLAN device


def test_vlan_of_falls_back_to_the_dotted_name(monkeypatch, tmp_path) -> None:
    from collector.discovery import interfaces

    monkeypatch.setattr(interfaces, "PROC_VLAN_CONFIG", tmp_path / "missing")
    assert interfaces.vlan_of("eth0.10") == (10, "eth0")
    assert interfaces.vlan_of("enp0s31f6.4094") == (4094, "enp0s31f6")
    assert interfaces.vlan_of("eth0.4095") == (None, None)
    assert interfaces.vlan_of("eth0") == (None, None)


def test_checkin_interface_list_tags_bounded_names_with_their_vlan(monkeypatch, tmp_path) -> None:
    from collector import checkin
    from collector.discovery import interfaces
    from collector.models import InterfaceState

    proc = tmp_path / "config"
    proc.write_text(PROC, encoding="utf-8")
    monkeypatch.setattr(interfaces, "PROC_VLAN_CONFIG", proc)
    states = [
        InterfaceState(name=LONG, is_up=True, has_carrier=True, mac=None, ipv4_addrs=["192.0.2.5/24"]),
        InterfaceState(name="vlan10", is_up=True, has_carrier=True, mac=None, ipv4_addrs=[]),
        InterfaceState(name="eth0.20", is_up=True, has_carrier=True, mac=None, ipv4_addrs=[]),
    ]
    monkeypatch.setattr(interfaces, "snapshot", lambda **_: states)
    monkeypatch.setattr(interfaces, "primary_interface", lambda: LONG)
    got = {i["name"]: i["vlan"] for i in checkin._interfaces()}
    assert got == {LONG: None, "vlan10": 10, "eth0.20": 20}


# --- review round 1: identity, empty-ish lists, route timing, fail-closed backup ----


def test_remove_does_not_delete_a_same_named_device_on_another_parent(tmp_path) -> None:
    # Our records: vlan10 (VLAN 10) on LONG, vlan20 on LONG. The kernel: an admin's
    # vlan10 / vlan20 with the same ids on other parents. Not ours.
    old = _netplan_old([("vlan10", 10, LONG)])
    cons = f"netmon-vlan20 vlan20 {LONG} 20 -\n"
    links = "vlan10 vlan 10 eth0\nvlan20 vlan 20 eth1\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm",
                   netplan_file=old, cons=cons, links=links)
    assert "ip link delete" not in st["calls"]
    assert _vlan_links(st) == {("vlan10", "10", "eth0"), ("vlan20", "20", "eth1")}
    assert "RC=0" in out, out   # ours are gone; the others were never ours


def test_apply_does_not_count_a_foreign_same_named_device_as_up(tmp_path) -> None:
    # An admin's vlan10 on eth0 blocks NetMon's vlan10 on LONG; the old name-only
    # presence check reported that as success.
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless {LONG} 10; echo "RC=$?"', backend="nm",
                   links="vlan10 vlan 10 eth0\n")
    assert "RC=1" in out
    assert "did not come up: vlan10" in out
    assert ("vlan10", "10", "eth0") in _vlan_links(st)


@pytest.mark.parametrize("vlans", [",", "0", "4095", ",,0,"])
@pytest.mark.parametrize("backend", ["nm", "networkd"])
def test_a_list_with_no_valid_vlan_id_is_refused_not_applied_as_empty(tmp_path, vlans, backend) -> None:
    old = _netplan_old([("eth0.10", 10, "eth0")])
    cons = "netmon-vlan20 eth0.20 eth0 20 -\n"
    out, st = _run(tmp_path, f'apply_vlan_netplan_headless eth0 "{vlans}"; echo "RC=$?"', backend=backend,
                   netplan_file=old, cons=cons, links="eth0.10 vlan 10 eth0\neth0.20 vlan 20 eth0\n")
    assert "RC=1" in out
    assert st["calls"] == ""
    assert st["plan"] == old and st["cons"] == cons


def test_a_slow_dhcp_lease_on_the_uplink_is_not_a_lost_route(tmp_path) -> None:
    # netplan apply re-runs DHCP on the uplink; the route is back after 5 s.
    old = _netplan_old([("eth0.10", 10, "eth0")])
    body = 'echo 5 > "$ST/route-back-after"; remove_vlan_interfaces_headless; echo "RC=$?"'
    out, st = _run(tmp_path, body, backend="networkd", netplan_file=old,
                   links="eth0.10 vlan 10 eth0\n", flags=("apply-drops-route",))
    assert "RC=0" in out, out
    assert "RESTORING" not in out
    assert not st["plan_exists"]


def test_apply_reverts_to_no_netmon_vlans_when_the_route_is_lost(tmp_path) -> None:
    out, st = _run(tmp_path, 'apply_vlan_netplan_headless eth0 10,20; echo "RC=$?"', backend="networkd",
                   flags=("apply-drops-route",))
    assert "RC=1" in out
    assert "REVERTING" in out
    assert not st["plan_exists"]
    assert _vlan_links(st) == set()


def test_apply_reverts_nm_vlans_when_the_route_is_lost(tmp_path) -> None:
    body = 'touch "$ST/delete-drops-route"; apply_vlan_netplan_headless eth0 10; echo "RC=$?"'
    out, st = _run(tmp_path, body, backend="nm", cons="netmon-vlan20 eth0.20 eth0 20 -\n",
                   links="eth0.20 vlan 20 eth0\n")
    assert "RC=1" in out
    assert "REVERTING" in out
    assert "netmon-vlan10" not in st["cons"]
    assert _vlan_links(st) == set()


def test_remove_fails_closed_when_the_backup_cannot_be_made(tmp_path) -> None:
    old = _netplan_old([("eth0.10", 10, "eth0")])
    out, st = _run(tmp_path, 'mktemp() { return 1; }; remove_vlan_interfaces_headless; echo "RC=$?"',
                   backend="networkd", netplan_file=old, links="eth0.10 vlan 10 eth0\n")
    assert "RC=1" in out
    assert st["plan"] == old
    assert st["calls"] == ""
    assert _vlan_links(st) == {("eth0.10", "10", "eth0")}


def test_remove_leaves_a_netmon_vlan_profile_whose_device_is_the_uplink(tmp_path) -> None:
    # A genuine VLAN profile, id matching its name — but its device carries the
    # default route. Deleting the profile would deactivate the uplink.
    cons = "netmon-vlan5 eth0.5 eth0 5 -\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm",
                   cons=cons, links="eth0.5 vlan 5 eth0\n", uplink="eth0.5")
    assert "nmcli con delete" not in st["calls"]
    assert st["cons"] == cons
    assert "RC=1" in out


# --- review round 2 -----------------------------------------------------------------


def test_remove_leaves_a_vlan_profile_with_no_interface_name(tmp_path) -> None:
    # NetMon always sets one; without it the device (and whether it is the uplink)
    # is unknown, so the profile is not provably ours.
    cons = "netmon-vlan10 - eth0 10 -\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm", cons=cons)
    assert "nmcli con delete" not in st["calls"]
    assert st["cons"] == cons
    assert "RC=1" in out


def test_apply_stops_when_a_foreign_profile_holds_a_netmon_name(tmp_path) -> None:
    # The add for VLAN 10 is refused (foreign ethernet profile named netmon-vlan10);
    # even with an identity-matching link present, that is a failure — and the
    # stale NetMon VLAN 20 is not reconciled away on a half-apply.
    cons = "netmon-vlan10 eth0.10 - - - 802-3-ethernet\nnetmon-vlan20 eth0.20 eth0 20 -\n"
    out, st = _run(tmp_path, 'apply_vlan_netplan_headless eth0 10; echo "RC=$?"', backend="nm",
                   cons=cons, links="eth0.10 vlan 10 eth0\neth0.20 vlan 20 eth0\n")
    assert "RC=1" in out
    assert "non-NetMon NM profile holds the name: 10" in out
    assert st["cons"] == cons
    assert "nmcli con delete" not in st["calls"]


def test_remove_reports_a_profile_networkmanager_would_not_delete(tmp_path) -> None:
    cons = "netmon-vlan20 eth0.20 eth0 20 -\n"
    out, st = _run(tmp_path, 'remove_vlan_interfaces_headless; echo "RC=$?"', backend="nm",
                   cons=cons, links="eth0.20 vlan 20 eth0\n", flags=("delete-fails",))
    assert "RC=1" in out
    assert "refused to delete netmon-vlan20" in out
    assert st["cons"] == cons
    assert ("eth0.20", "20", "eth0") in _vlan_links(st)   # left consistent with its profile


@pytest.mark.parametrize("wait", ["abc", "-1", "99999"])
def test_a_malformed_route_wait_does_not_break_the_guard(tmp_path, wait) -> None:
    old = _netplan_old([("eth0.10", 10, "eth0")])
    out, st = _run(tmp_path, f'NETMON_ROUTE_WAIT="{wait}"; remove_vlan_interfaces_headless; echo "RC=$?"',
                   backend="networkd", netplan_file=old, links="eth0.10 vlan 10 eth0\n",
                   flags=("apply-drops-route",))
    assert "RC=1" in out, out + st["stderr"]
    assert "RESTORING" in out
    assert st["plan"] == old
