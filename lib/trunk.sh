# lib/trunk.sh — 802.1Q VLAN trunk monitoring setup.
#
# Plug the sensor into a switch TRUNK port and monitor many VLANs from one box.
# We add a VLAN sub-interface (eth0.<id>, see vlan_child_name) per VLAN via
# netplan or nmcli; the collector poller then scans each like any NIC and tags the
# data with its VLAN (the scan's vlan_id/parent_interface, see scan.py _vlan_of).
#
# Hybrid detect-then-edit: sniff the 802.1Q tags on the trunk (in the collector
# container, which has tshark + host networking), propose the VLANs seen, let the
# operator add/remove. DHCP per VLAN by default — crucially with routes OFF so a
# monitoring VLAN can NEVER steal the box's uplink/default route — plus optional
# static IPs for VLANs with no DHCP.
#
# Source AFTER common.sh, paths.sh, envfile.sh.

[[ -n "${_NETMON_TRUNK_SH:-}" ]] && return 0
_NETMON_TRUNK_SH=1

NETMON_VLAN_NETPLAN="${NETMON_VLAN_NETPLAN:-/etc/netplan/60-netmon-vlans.yaml}"

# A Linux interface name: at most 15 bytes (IFNAMSIZ-1), no '/', ':' or space.
# Same grammar the dashboard enforces on the parent (src/lib/vlan-config.ts).
_TRUNK_IFNAME_RE='^[A-Za-z0-9_][A-Za-z0-9._-]{0,14}$'

# Name of the sub-interface for VLAN <vid> on <parent>. Keeps the historical
# <parent>.<vid> whenever it fits in 15 bytes — every box configured so far uses
# it and the dashboard's ingest derives the VLAN from it — and falls back to
# vlan<vid> (at most 8 bytes) when a long parent would overflow, e.g. a USB NIC
# enx001122334455 (15 chars) for which the kernel refuses enx001122334455.10.
# The full parent always goes in link:/dev, and the collector reads the VLAN id
# and parent from the kernel (/proc/net/vlan/config), not from this name.
vlan_child_name() {
    local parent="$1" vid="$2"
    local name="${parent}.${vid}"
    if (( ${#name} <= 15 )); then
        printf '%s' "$name"
    else
        printf 'vlan%s' "$vid"
    fi
}

# Delete one VLAN sub-interface NetMon created. Callers pass only names taken from
# NetMon's own records (our netplan file, our netmon-vlan<id> NM connections); this
# also refuses anything that is not a valid name, not an 802.1Q device in the
# kernel, carries a different VLAN id than recorded, or carries the default route.
_vlan_delete_link() {
    local name="$1" vid="${2:-}" info
    [[ "$name" =~ $_TRUNK_IFNAME_RE ]] || return 0
    info="$(ip -d -o link show dev "$name" 2>/dev/null)" || return 0
    [[ "$info" == *"vlan protocol 802.1"* ]] || return 0
    if [[ -n "$vid" ]]; then
        local id_re="vlan protocol 802\\.1[Qq]([Aa][Dd])? id ${vid}([^0-9]|$)"
        [[ "$info" =~ $id_re ]] || return 0
    fi
    if _trunk_is_uplink "$name"; then
        warn "not deleting ${name}: it carries the default route"
        return 0
    fi
    $SUDO ip link delete "$name" >/dev/null 2>&1 || true
}

# The sub-interfaces our generated netplan file defines, one "name id link" line
# each. Reads only the fixed layout generate_vlan_netplan writes.
_vlan_netplan_children() {
    local f="${1:-$NETMON_VLAN_NETPLAN}"
    $SUDO cat "$f" 2>/dev/null | awk '
        /^    [^ #][^ :]*:[[:space:]]*$/ {
            if (n != "") print n, id, link
            n = $1; sub(/:$/, "", n); id = ""; link = ""; next
        }
        /^      id:/   { id = $2 }
        /^      link:/ { link = $2 }
        END { if (n != "") print n, id, link }'
}

# docker compose invocation (mirrors scripts/netmon-checkin.sh).
_trunk_dc() {
    if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        docker compose "$@"
    else
        $SUDO docker compose "$@"
    fi
}

# A sensible default parent NIC: the interface owning the default route, else the
# first non-loopback/virtual NIC.
_trunk_default_parent() {
    local dev
    dev="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -z "$dev" ]]; then
        dev="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
            | grep -vE '^(lo|docker|br-|veth|virbr|tun|tap)' | head -1)"
    fi
    printf '%s' "$dev"
}

# Does the default route ride this interface (i.e. it's the box's uplink)?
_trunk_is_uplink() {
    local parent="$1"
    ip route show default 2>/dev/null | grep -qE "dev[[:space:]]+${parent}([[:space:]]|$)"
}

# Sniff VLAN tags on the parent via the collector container; echo comma-sep ids.
# Returns non-zero (no output) if the collector container isn't running.
_trunk_detect() {
    local parent="$1"
    if ! _trunk_dc ps --status running 2>/dev/null | grep -q netmon-collector; then
        return 1
    fi
    _trunk_dc exec -T collector python -m collector detect-vlans "$parent" --seconds 8 \
        2>/dev/null | tr -d '\r'
}

# Write the netplan vlans: stanza from a VLAN list + optional statics map.
# statics: "30:10.0.30.5/24,40:10.0.40.5/24" (vlan:cidr; DHCP for the rest).
# Defines ONLY the VLAN sub-interfaces — never the parent — so the box's existing
# uplink config is left completely untouched. Echoes the file path.
generate_vlan_netplan() {
    local parent="$1" vlans="$2" statics="${3:-}"
    local f="$NETMON_VLAN_NETPLAN"
    local tmp; tmp="$(mktemp)"
    {
        echo "# Generated by 'netmon-wizard trunk' — VLAN monitoring sub-interfaces."
        echo "# Each sub-if gets an address (DHCP or static) but installs NO routes, so"
        echo "# a monitored VLAN can never hijack the box's real uplink/default route."
        echo "# Edit via the wizard, not by hand:  sudo netmon-wizard trunk"
        echo "network:"
        echo "  version: 2"
        echo "  vlans:"
        local vid cidr pair
        for vid in ${vlans//,/ }; do
            [[ "$vid" =~ ^[0-9]+$ ]] || continue
            vid=$((10#$vid))   # strip leading zeros (avoid bash octal parsing)
            (( vid >= 1 && vid <= 4094 )) || continue
            cidr=""
            for pair in ${statics//,/ }; do
                if [[ "$pair" == "${vid}:"* ]]; then cidr="${pair#"${vid}":}"; fi
            done
            echo "    $(vlan_child_name "$parent" "$vid"):"
            echo "      id: ${vid}"
            echo "      link: ${parent}"
            if [[ -n "$cidr" ]]; then
                echo "      addresses: [${cidr}]"
            else
                echo "      dhcp4: true"
                echo "      dhcp4-overrides:"
                echo "        use-routes: false"
            fi
        done
    } > "$tmp"
    $SUDO install -m 600 -o root -g root "$tmp" "$f"
    rm -f "$tmp"
    printf '%s' "$f"
}

# Which backend manages this box's networking? VLAN sub-interfaces render very
# differently: under systemd-networkd our netplan `vlans:` stanza works, but under
# NetworkManager `netplan generate` CRASHES (nm.c `vlan_link` assertion) because we
# deliberately never declare the parent ethernet. So on an NM box we build the VLANs
# with nmcli (NM-native) instead. Echoes "nm" or "networkd". Same heuristic the
# wizard already warns on (NetworkManager active, systemd-networkd not).
_vlan_backend() {
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet NetworkManager 2>/dev/null \
        && ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        printf 'nm'
    else
        printf 'networkd'
    fi
}

# One NetMon VLAN connection's "ifname parent vid cidr" (cidr "-" for DHCP), read
# back from NetworkManager so removal and revert never guess the interface name.
_nmcli_vlan_con_info() {
    local con="$1" ifname="" vparent="" vid="" addrs=""
    { read -r ifname; read -r vparent; read -r vid; read -r addrs; } < <(
        $SUDO nmcli -g connection.interface-name,vlan.parent,vlan.id,ipv4.addresses \
            con show "$con" 2>/dev/null)
    [[ -n "$ifname" ]] || return 1
    addrs="${addrs%%,*}"
    printf '%s %s %s %s\n' "$ifname" "${vparent:--}" "${vid:--}" "${addrs:--}"
}

# Delete one NetMon VLAN connection and the sub-interface it names (whatever its
# naming scheme), so the VLAN id is free on the parent before anything re-adds it.
_nmcli_remove_vlan_con() {
    local con="$1" info ifname _p vid _a
    info="$(_nmcli_vlan_con_info "$con" || true)"
    $SUDO nmcli con delete "$con" >/dev/null 2>&1 || true
    if [[ -n "$info" ]]; then
        read -r ifname _p vid _a <<< "$info"
        [[ "$vid" =~ ^[0-9]+$ ]] || vid=""
        _vlan_delete_link "$ifname" "$vid"
    fi
}

# (Re)create one NetMon VLAN connection `netmon-vlan<vid>` on <parent>.
_nmcli_add_vlan() {
    local parent="$1" vid="$2" cidr="${3:-}"
    local conname="netmon-vlan${vid}" ifname
    ifname="$(vlan_child_name "$parent" "$vid")"
    # Recreate idempotently: drop any same-name connection AND its old link (an
    # older name or another parent would otherwise hold this VLAN id), then add.
    _nmcli_remove_vlan_con "$conname"
    if [[ -n "$cidr" ]]; then
        $SUDO nmcli con add type vlan con-name "$conname" ifname "$ifname" \
            dev "$parent" id "$vid" ipv4.method manual ipv4.addresses "$cidr" \
            ipv4.never-default yes ipv4.ignore-auto-routes yes ipv6.method ignore \
            connection.autoconnect yes >/dev/null 2>&1 || true
    else
        # may-fail:yes so the sub-interface comes up immediately and DHCP runs in
        # the BACKGROUND — a VLAN with no DHCP server must not block the apply
        # (it just gets no lease, surfaced as "no data" on the dashboard).
        $SUDO nmcli con add type vlan con-name "$conname" ifname "$ifname" \
            dev "$parent" id "$vid" ipv4.method auto ipv4.may-fail yes \
            ipv4.never-default yes ipv4.ignore-auto-routes yes ipv6.method ignore \
            connection.autoconnect yes >/dev/null 2>&1 || true
    fi
    # --wait caps activation so even a DHCP-less VLAN returns promptly.
    $SUDO nmcli con up "$conname" --wait 10 >/dev/null 2>&1 || true
    log "nmcli VLAN ${vid} on ${parent} as ${ifname} (${cidr:-dhcp}, routes off)"
}

# Which of these "name ..." sub-interfaces did not come up? Echoes the missing
# names. Without this a refused name (or a refused add) still reported success.
_vlan_missing_links() {
    local name _rest missing=""
    while read -r name _rest; do
        [[ -n "$name" ]] || continue
        ip link show dev "$name" >/dev/null 2>&1 || missing+="${name} "
    done
    printf '%s' "${missing% }"
}

# ...and which of them are (still) present.
_vlan_present_links() {
    local name _rest present=""
    while read -r name _rest; do
        [[ -n "$name" ]] || continue
        ip link show dev "$name" >/dev/null 2>&1 && present+="${name} "
    done
    printf '%s' "${present% }"
}

# Create/refresh VLAN sub-interfaces via NetworkManager (nmcli) — the native path on
# an NM-managed box, where the netplan vlans: renderer crashes. Each VLAN is its own
# NM connection `netmon-vlan<id>` on vlan_child_name (<parent>.<id>), DHCP (or a
# static), with NO default route and DHCP-pushed routes ignored (routes-off,
# mirroring netplan's use-routes:false) so a monitored VLAN can never hijack the
# box's uplink. Idempotent: reconciles the set — (re)creates the wanted VLANs,
# removes our stale ones. Guarded: reverts if the default route disappears.
# Validated on the verification sensor (NM box) 2026-06-24.
_apply_vlan_nmcli() {
    local parent="$1" vlans="$2" statics="${3:-}"
    if ! command -v nmcli >/dev/null 2>&1; then
        warn "nmcli not found — cannot configure VLANs on this NetworkManager box."
        return 1
    fi

    local before_default after_default
    before_default="$(ip route show default 2>/dev/null | head -1)"

    local want=" " vid cidr pair names=""
    for vid in ${vlans//,/ }; do
        [[ "$vid" =~ ^[0-9]+$ ]] || continue
        vid=$((10#$vid))   # strip leading zeros (avoid octal parsing)
        (( vid >= 1 && vid <= 4094 )) || continue
        want+="$vid "
        cidr=""
        for pair in ${statics//,/ }; do
            [[ "$pair" == "${vid}:"* ]] && cidr="${pair#"${vid}":}"
        done
        _nmcli_add_vlan "$parent" "$vid" "$cidr"
        names+="$(vlan_child_name "$parent" "$vid")"$'\n'
    done

    # Remove netmon-vlan<digits> connections we own that are no longer wanted.
    local existing evid
    while IFS= read -r existing; do
        [[ "$existing" =~ ^netmon-vlan[0-9]+$ ]] || continue
        evid="${existing#netmon-vlan}"
        if [[ " $want " != *" $evid "* ]]; then
            _nmcli_remove_vlan_con "$existing"
            log "removed stale VLAN connection ${existing}"
        fi
    done < <($SUDO nmcli -g NAME con show 2>/dev/null)

    # Connectivity guard (belt-and-suspenders; never-default already blocks hijack).
    after_default="$(ip route show default 2>/dev/null | head -1)"
    if [[ -n "$before_default" && -z "$after_default" ]]; then
        warn "default route lost after VLAN apply — REVERTING the nmcli VLANs."
        for vid in $want; do
            _nmcli_remove_vlan_con "netmon-vlan${vid}"
        done
        return 1
    fi

    local missing
    missing="$(_vlan_missing_links <<< "$names")"
    if [[ -n "$missing" ]]; then
        warn "VLAN sub-interface(s) did not come up: ${missing}"
        return 1
    fi
    ok "VLAN sub-interfaces up via NetworkManager on ${parent} (${vlans}); the collector scans them within a poll tick (~30s)."
    return 0
}

# Non-interactive VLAN netplan apply with a connectivity guard — the headless
# counterpart to prompt_trunk_config's `netplan try` (which needs a TTY). Writes
# the sub-interface config, validates it, applies, and AUTO-REVERTS if the box's
# default route disappears. Safe because we only ever ADD sub-interfaces (routes
# off) and never touch the parent, so the uplink + SSH stay up. Used by install.sh
# (install-time) and the dashboard apply-vlan host action (runtime push).
# Args: parent vlans [statics]. Returns 0 on success, non-zero on any problem.
apply_vlan_netplan_headless() {
    local parent="$1" vlans="$2" statics="${3:-}"
    local f="$NETMON_VLAN_NETPLAN"

    if [[ -z "$parent" || -z "$vlans" ]]; then
        warn "VLAN setup: missing parent interface or VLAN list — skipping."
        return 1
    fi
    if [[ ! "$parent" =~ $_TRUNK_IFNAME_RE ]]; then
        warn "VLAN setup: '${parent}' is not a valid interface name — skipping."
        return 1
    fi

    # Backend-aware: a NetworkManager-managed box CANNOT use our netplan vlans:
    # stanza — `netplan generate` crashes (nm.c vlan_link assertion) because we
    # never declare the parent. Build the VLANs with nmcli (NM-native) there.
    if [[ "$(_vlan_backend)" == "nm" ]]; then
        log "NetworkManager backend — configuring VLANs via nmcli instead of netplan."
        _apply_vlan_nmcli "$parent" "$vlans" "$statics"
        return $?
    fi

    if ! command -v netplan >/dev/null 2>&1; then
        warn "netplan not found — cannot configure VLAN sub-interfaces on this box."
        return 1
    fi

    # Snapshot the default route so we can detect (and undo) connectivity loss.
    local before_default after_default
    before_default="$(ip route show default 2>/dev/null | head -1)"

    # What our previous file defined, so links it no longer defines identically
    # can be dropped below.
    local old_children new_children
    old_children="$(_vlan_netplan_children "$f")"

    generate_vlan_netplan "$parent" "$vlans" "$statics" >/dev/null
    log "wrote ${f} (VLANs ${vlans} on ${parent}, routes off)"

    if ! $SUDO netplan generate 2>/tmp/netmon-netplan.err; then
        warn "netplan validation failed — removing our file so it can't break netplan:"
        $SUDO sed 's/^/    /' /tmp/netmon-netplan.err 2>/dev/null || true
        $SUDO rm -f "$f"
        $SUDO netplan generate >/dev/null 2>&1 || true
        return 1
    fi

    # networkd never changes an existing netdev, and the kernel refuses a second
    # device for the same VLAN id on one parent. So a sub-interface our old file
    # defined that the new one renames, re-parents, re-ids or drops is deleted
    # BEFORE the apply, or the new one cannot be created (a rename to vlan<id>, a
    # parent change) or the old one lingers (a dropped VLAN).
    new_children="$(_vlan_netplan_children "$f")"
    local line name id
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if ! grep -qxF -- "$line" <<< "$new_children"; then
            read -r name id _ <<< "$line"
            _vlan_delete_link "$name" "$id"
        fi
    done <<< "$old_children"

    $SUDO netplan apply 2>/dev/null || true
    sleep 3

    after_default="$(ip route show default 2>/dev/null | head -1)"
    if [[ -n "$before_default" && -z "$after_default" ]]; then
        warn "default route lost after VLAN apply — REVERTING (removing ${f})."
        $SUDO rm -f "$f"
        $SUDO netplan apply 2>/dev/null || true
        while read -r name id _; do
            [[ -n "$name" ]] && _vlan_delete_link "$name" "$id"
        done <<< "$new_children"
        return 1
    fi

    local missing
    missing="$(_vlan_missing_links <<< "$new_children")"
    if [[ -n "$missing" ]]; then
        warn "VLAN sub-interface(s) did not come up: ${missing}"
        return 1
    fi
    ok "VLAN sub-interfaces up on ${parent} (${vlans}); the collector scans them within a poll tick (~30s)."
    return 0
}

# Remove every VLAN sub-interface NetMon created, and nothing else — the clear
# path for an emptied VLAN list (host action host-remove-vlan). Ownership is what
# NetMon wrote: our netplan file (networkd) and our netmon-vlan<id> NM connections;
# both are checked whatever the current backend, so a box that changed backends is
# still cleaned. A link is deleted only when one of those names it (see
# _vlan_delete_link for the further checks). The parent and every other netplan
# file and NM connection are left alone. Guarded like the apply: if the default
# route disappears, the removed config is put back. Returns 0 on success
# (including "nothing to remove"), non-zero on any problem.
remove_vlan_interfaces_headless() {
    local f="$NETMON_VLAN_NETPLAN"
    local before_default after_default
    before_default="$(ip route show default 2>/dev/null | head -1)"

    # networkd / netplan side.
    local children="" backup="" name id
    if $SUDO test -f "$f"; then
        children="$(_vlan_netplan_children "$f")"
        backup="$(mktemp)"
        $SUDO cat "$f" > "$backup" 2>/dev/null || true
        $SUDO rm -f "$f"
        log "removed ${f}"
        if command -v netplan >/dev/null 2>&1; then
            $SUDO netplan generate >/dev/null 2>&1 || true
            # Only a networkd box applies netplan here; our file is never live on an
            # NM box (the nmcli path below owns that), so don't bounce NM for it.
            if [[ "$(_vlan_backend)" == "networkd" ]]; then
                $SUDO netplan apply 2>/dev/null || true
                sleep 3
            fi
        fi
        while read -r name id _; do
            [[ -n "$name" ]] && _vlan_delete_link "$name" "$id"
        done <<< "$children"
    fi

    # NetworkManager side: our netmon-vlan<digits> connections only.
    local con saved=()
    if command -v nmcli >/dev/null 2>&1; then
        local info
        while IFS= read -r con; do
            [[ "$con" =~ ^netmon-vlan[0-9]+$ ]] || continue
            info="$(_nmcli_vlan_con_info "$con" || true)"
            [[ -n "$info" ]] && saved+=("$info")
            _nmcli_remove_vlan_con "$con"
            log "removed VLAN connection ${con}"
        done < <($SUDO nmcli -g NAME con show 2>/dev/null)
    fi

    after_default="$(ip route show default 2>/dev/null | head -1)"
    if [[ -n "$before_default" && -z "$after_default" ]]; then
        warn "default route lost after VLAN removal — RESTORING the previous VLAN config."
        if [[ -n "$backup" ]]; then
            $SUDO install -m 600 -o root -g root "$backup" "$f"
            if command -v netplan >/dev/null 2>&1 && [[ "$(_vlan_backend)" == "networkd" ]]; then
                $SUDO netplan apply 2>/dev/null || true
            fi
        fi
        local entry ifname vparent vid addrs
        for entry in "${saved[@]}"; do
            read -r ifname vparent vid addrs <<< "$entry"
            [[ "$vid" =~ ^[0-9]+$ && "$vparent" =~ $_TRUNK_IFNAME_RE ]] || continue
            [[ "$addrs" == "-" || -z "$addrs" ]] && addrs=""
            _nmcli_add_vlan "$vparent" "$vid" "$addrs"
        done
        rm -f "$backup"
        return 1
    fi
    [[ -n "$backup" ]] && rm -f "$backup"

    # Anything our records named that is still there? (A link _vlan_delete_link
    # refused — not a VLAN, or carrying the default route — lands here too.)
    local left
    left="$(_vlan_present_links < <(printf '%s\n' "$children"; printf '%s\n' "${saved[@]}"))"
    if [[ -n "$left" ]]; then
        warn "VLAN sub-interface(s) still present after removal: ${left}"
        return 1
    fi
    ok "NetMon VLAN sub-interfaces removed; the box's own interfaces are untouched."
    return 0
}

prompt_trunk_config() {
    echo ""
    echo "${C_INFO}=== VLAN trunk monitoring ===${C_OFF}"
    echo "Plug this sensor into a switch TRUNK port (802.1Q) and monitor many"
    echo "VLANs from one box. We add a VLAN sub-interface per VLAN; the collector"
    echo "scans each and tags the data with its VLAN."
    echo ""
    echo "The switch port must already be a trunk that allows those VLANs — the"
    echo "sensor can't reconfigure the switch."
    echo ""

    # 1. Parent interface
    local default_parent parent
    default_parent="$(current_value NETMON_TRUNK_PARENT)"
    [[ -z "$default_parent" ]] && default_parent="$(_trunk_default_parent)"
    read -r -p "Trunk parent interface [${default_parent}]: " parent || parent=""
    parent="${parent:-$default_parent}"
    if [[ -z "$parent" ]]; then warn "No interface given — trunk setup cancelled."; return 0; fi

    # 2. Uplink protection note
    echo ""
    if _trunk_is_uplink "$parent"; then
        echo "${C_WARN}Note:${C_OFF} ${parent} carries this box's default route (its uplink)."
        echo "We leave ${parent} untouched and only ADD VLAN sub-interfaces that take no"
        echo "routes, so your connection stays up. Native/untagged traffic on ${parent}"
        echo "keeps working as the management connection."
    else
        echo "${parent} is not the box's uplink, so the trunk is monitoring-only."
    fi

    # 2b. Renderer sanity. VLAN sub-interfaces are reliable under systemd-networkd
    # (the Ubuntu Server default). On a NetworkManager-managed box the apply can
    # bounce the connection and the VLANs may not attach — warn, don't block.
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet NetworkManager 2>/dev/null \
        && ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        echo ""
        warn "This box appears to use NetworkManager, not systemd-networkd."
        warn "VLAN sub-interfaces are most reliable under networkd — they may not come"
        warn "up cleanly here. Consider moving the parent to netplan/networkd first."
    fi

    # 3. Detect VLANs on the trunk
    local detected=""
    echo ""
    if prompt_yesno "Sniff the trunk to detect which VLANs are present (~8s)?" "Y"; then
        echo "  listening for 802.1Q tags on ${parent}…"
        detected="$(_trunk_detect "$parent" || true)"
        if [[ -n "$detected" ]]; then
            ok "detected VLANs: ${detected}"
        else
            warn "no tagged VLANs detected — a quiet trunk, an access port, or the collector"
            warn "isn't running yet (normal during first-boot, before setup starts it)."
            warn "Enter the VLANs manually now; re-run 'sudo netmon-wizard trunk' after the"
            warn "box is up to use auto-detect."
        fi
    fi

    # 4. Final VLAN list (prefilled with detected, else the current value)
    local cur_vlans default_vlans vlans
    cur_vlans="$(current_value NETMON_TRUNK_VLANS)"
    default_vlans="${detected:-$cur_vlans}"
    read -r -p "VLAN IDs to monitor (comma-separated) [${default_vlans}]: " vlans || vlans=""
    vlans="${vlans:-$default_vlans}"
    vlans="$(printf '%s' "$vlans" | tr -cd '0-9,')"   # keep only digits + commas
    if [[ -z "$vlans" ]]; then warn "No VLANs given — trunk setup cancelled."; return 0; fi

    # 5. Optional static IPs
    local statics statics_in
    statics="$(current_value NETMON_TRUNK_STATICS)"
    echo ""
    echo "Every VLAN gets an address via DHCP (no routes) by default. For VLANs with"
    echo "no DHCP, set a static IP as vlan:cidr, comma-separated"
    echo "  e.g.  30:10.0.30.9/24,40:10.0.40.9/24"
    echo "Leave blank for all-DHCP."
    read -r -p "Static IPs [${statics}]: " statics_in || statics_in=""
    statics="${statics_in:-$statics}"

    # 6. Persist for re-runs + reference
    set_value NETMON_TRUNK_PARENT  "$parent"
    set_value NETMON_TRUNK_VLANS   "$vlans"
    set_value NETMON_TRUNK_STATICS "$statics"

    # 7. Generate the netplan file
    local f
    f="$(generate_vlan_netplan "$parent" "$vlans" "$statics")"
    ok "wrote ${f}"
    echo ""
    echo "Preview:"
    $SUDO sed 's/^/    /' "$f"

    # 8. Validate + apply
    echo ""
    if ! command -v netplan >/dev/null 2>&1; then
        warn "netplan not found — config written to ${f}; apply it with your network manager."
        return 0
    fi
    if $SUDO netplan generate 2>/tmp/netmon-netplan.err; then
        ok "netplan config is valid"
    else
        warn "netplan validation failed:"; $SUDO sed 's/^/    /' /tmp/netmon-netplan.err
        warn "This can also be a PRE-EXISTING error elsewhere in /etc/netplan, or the"
        warn "parent (${parent}) not being netplan-managed. Fix, then: sudo netmon-wizard trunk"
        return 0
    fi
    # netplan try needs an interactive terminal (it waits for ENTER to keep the
    # change). If we're not on a TTY, write the file but don't apply.
    if [[ ! -t 0 ]]; then
        warn "not an interactive terminal — wrote ${f} but did NOT apply it."
        echo "  Apply it yourself with:  sudo netplan try   (safe; auto-reverts)"
        return 0
    fi
    if prompt_yesno "Apply now? (uses 'netplan try' — auto-reverts if it can't reach the network)" "Y"; then
        echo "  applying… your SSH/console should stay up. Press ENTER at the netplan"
        echo "  prompt to KEEP it; if anything breaks, do nothing and it auto-reverts."
        # `netplan try` is the safe path for remote boxes: it applies, then reverts
        # to the prior config on timeout or if the network can't be reached — so a
        # bad VLAN change can never strand the box.
        if $SUDO netplan try --timeout 120; then
            ok "applied + kept — VLAN sub-interfaces are up"
            echo "  the collector discovers + scans them within a poll tick (~30s)."
        else
            warn "netplan reverted — nothing kept (timeout, or it couldn't reach the network)."
            warn "Your previous config is intact. Re-run 'sudo netmon-wizard trunk' when ready."
        fi
    else
        echo "  (not applied — the file is written; run 'sudo netplan try' when ready)"
    fi

    echo ""
    echo "Verify with:  ./netmon interfaces     (or  ip -br addr )"
}
