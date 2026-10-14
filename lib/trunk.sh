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
NETMON_NM_CONN_DIR="${NETMON_NM_CONN_DIR:-/etc/NetworkManager/system-connections}"

# A Linux interface name: at most 15 bytes (IFNAMSIZ-1), no '/', ':' or space.
# Same grammar the dashboard's VLAN form enforces on the parent (PROV-7).
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

# The valid VLAN ids in a comma list, space-separated, leading zeros stripped,
# de-duplicated. Empty when none survive — "," or "0" is NOT a VLAN list.
_trunk_vids() {
    local vid out=" "
    for vid in ${1//,/ }; do
        [[ "$vid" =~ ^[0-9]{1,4}$ ]] || continue
        vid=$((10#$vid))   # strip leading zeros (avoid bash octal parsing)
        (( vid >= 1 && vid <= 4094 )) || continue
        [[ "$out" == *" $vid "* ]] || out+="$vid "
    done
    out="${out# }"
    printf '%s' "${out% }"
}

# Is <name> the 802.1Q sub-interface for VLAN <vid> on <parent>? An empty vid or
# parent is not checked. Identity, not just the name: an admin's own vlan10 on
# another parent (or a non-VLAN device with that name) is not ours.
_vlan_link_is() {
    local name="$1" vid="${2:-}" parent="${3:-}" info
    [[ "$name" =~ $_TRUNK_IFNAME_RE ]] || return 1
    info="$(ip -d -o link show dev "$name" 2>/dev/null)" || return 1
    [[ "$info" == *"vlan protocol 802.1Q id "* ]] || return 1
    if [[ -n "$vid" ]]; then
        local id_re="vlan protocol 802\\.1Q id ${vid}([^0-9]|$)"
        [[ "$info" =~ $id_re ]] || return 1
    fi
    if [[ -n "$parent" ]]; then
        [[ "$info" == *": $name@$parent: <"* ]] || return 1
    fi
    return 0
}

# Delete one VLAN sub-interface NetMon created. Callers pass only "name vid parent"
# taken from NetMon's own records (our netplan file, our netmon-vlan<id> NM
# connections); it is deleted only if the kernel agrees on all three and it does
# not carry the default route.
_vlan_delete_link() {
    local name="$1" vid="${2:-}" parent="${3:-}"
    _vlan_link_is "$name" "$vid" "$parent" || return 0
    if _trunk_is_uplink "$name"; then
        warn "not deleting ${name}: it carries the default route"
        return 0
    fi
    $SUDO ip link delete "$name" >/dev/null 2>&1 || true
}

# Which of these "name vid parent" sub-interfaces is not up as specified? Echoes
# the names. Without this a refused name (or a refused add) reported success.
_vlan_missing_links() {
    local name vid parent _rest missing=""
    while read -r name vid parent _rest; do
        [[ -n "$name" ]] || continue
        [[ "$vid" =~ ^[0-9]+$ ]] || vid=""
        [[ "$parent" == "-" ]] && parent=""
        _vlan_link_is "$name" "$vid" "$parent" || missing+="${name} "
    done
    printf '%s' "${missing% }"
}

# ...and which of them are (still) there.
_vlan_present_links() {
    local name vid parent _rest present=""
    while read -r name vid parent _rest; do
        [[ -n "$name" ]] || continue
        [[ "$vid" =~ ^[0-9]+$ ]] || vid=""
        [[ "$parent" == "-" ]] && parent=""
        _vlan_link_is "$name" "$vid" "$parent" && present+="${name} "
    done
    printf '%s' "${present% }"
}

# Was the default route lost? <before> is `ip route show default` from before the
# change; nothing to lose if it was empty. netplan apply re-runs DHCP on the uplink
# (networkctl reconfigure, or a networkd restart on older netplan), so poll for up
# to NETMON_ROUTE_WAIT seconds before calling it lost — one early sample turned a
# slow lease into a false revert.
_trunk_route_lost() {
    local before="$1" i wait="${NETMON_ROUTE_WAIT:-20}"
    [[ -n "$before" ]] || return 1
    [[ "$wait" =~ ^[0-9]{1,3}$ ]] || wait=20
    (( wait <= 120 )) || wait=120
    for (( i = 0; i < wait; i++ )); do
        [[ -n "$(ip route show default 2>/dev/null | head -1)" ]] && return 1
        sleep 1
    done
    [[ -n "$(ip route show default 2>/dev/null | head -1)" ]] && return 1
    return 0
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

# Delete each sub-interface the OLD file defined that the NEW one does not define
# identically ("name id link"). networkd never changes an existing netdev, and the
# kernel refuses a second 802.1Q device for one VLAN id on a parent, so a renamed,
# re-parented, re-id'd or dropped child must go BEFORE the apply — or the new one
# cannot be created (a rename to vlan<id>, a parent change) or the old one lingers.
_vlan_drop_changed_children() {
    local old="$1" new="$2" line name id link
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if ! grep -qxF -- "$line" <<< "$new"; then
            read -r name id link <<< "$line"
            _vlan_delete_link "$name" "$id" "$link"
        fi
    done <<< "$old"
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

# One NetMon VLAN connection's "type ifname parent vid cidr" ("-" for an empty
# field; cidr "-" means DHCP), read back from NetworkManager so removal and revert
# never guess the interface name.
_nmcli_vlan_con_info() {
    local con="$1" ctype="" ifname="" vparent="" vid="" addrs=""
    { read -r ctype; read -r ifname; read -r vparent; read -r vid; read -r addrs; } < <(
        $SUDO nmcli -g connection.type,connection.interface-name,vlan.parent,vlan.id,ipv4.addresses \
            con show "$con" 2>/dev/null)
    [[ -n "$ctype" ]] || return 1
    addrs="${addrs%%,*}"
    printf '%s %s %s %s %s\n' "$ctype" "${ifname:--}" "${vparent:--}" "${vid:--}" "${addrs:--}"
}

# Delete one NetMon VLAN connection and the sub-interface it names (whatever its
# naming scheme), so the VLAN id is free on the parent before anything re-adds it.
# The netmon-vlan<id> name alone is not proof of ownership: a profile that is not a
# VLAN, carries another VLAN id, has no interface name (NetMon always sets one, and
# without it the device — and whether it is the uplink — cannot be known), or
# whose interface carries the default route is left alone (returns 1), as is one
# NetworkManager refuses to delete. An absent profile returns 0.
_nmcli_remove_vlan_con() {
    local con="$1" info ctype ifname vparent vid _a
    info="$(_nmcli_vlan_con_info "$con")" || return 0
    read -r ctype ifname vparent vid _a <<< "$info"
    if [[ "$ctype" != "vlan" || "$vid" != "${con#netmon-vlan}" || "$ifname" == "-" ]]; then
        warn "not touching NM connection ${con}: not a NetMon VLAN profile (type ${ctype}, id ${vid}, interface ${ifname})"
        return 1
    fi
    if _trunk_is_uplink "$ifname"; then
        warn "not touching NM connection ${con}: ${ifname} carries the default route"
        return 1
    fi
    if ! $SUDO nmcli con delete "$con" >/dev/null 2>&1; then
        warn "NetworkManager refused to delete ${con}"
        return 1
    fi
    [[ "$vparent" == "-" ]] && vparent=""
    _vlan_delete_link "$ifname" "$vid" "$vparent"
    return 0
}

# (Re)create one NetMon VLAN connection `netmon-vlan<vid>` on <parent>.
_nmcli_add_vlan() {
    local parent="$1" vid="$2" cidr="${3:-}"
    local conname="netmon-vlan${vid}" ifname
    ifname="$(vlan_child_name "$parent" "$vid")"
    # Recreate idempotently: drop any same-name connection AND its old link (an
    # older name or another parent would otherwise hold this VLAN id), then add.
    _nmcli_remove_vlan_con "$conname" || return 1
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

# Create/refresh VLAN sub-interfaces via NetworkManager (nmcli) — the native path on
# an NM-managed box, where the netplan vlans: renderer crashes. Each VLAN is its own
# NM connection `netmon-vlan<id>` on vlan_child_name (<parent>.<id>), DHCP (or a
# static), with NO default route and DHCP-pushed routes ignored (routes-off,
# mirroring netplan's use-routes:false) so a monitored VLAN can never hijack the
# box's uplink. Idempotent: reconciles the set — (re)creates the wanted VLANs,
# removes our stale ones. Guarded: reverts if the default route disappears.
# Validated on the verification sensor (NM box) 2026-06-24.
# Args: parent vids (validated, space-separated — see _trunk_vids) [statics].
_apply_vlan_nmcli() {
    local parent="$1" vids="$2" statics="${3:-}"
    if ! command -v nmcli >/dev/null 2>&1; then
        warn "nmcli not found — cannot configure VLANs on this NetworkManager box."
        return 1
    fi

    local before_default
    before_default="$(ip route show default 2>/dev/null | head -1)"

    local vid cidr pair wanted="" refused=""
    for vid in $vids; do
        cidr=""
        for pair in ${statics//,/ }; do
            [[ "$pair" == "${vid}:"* ]] && cidr="${pair#"${vid}":}"
        done
        _nmcli_add_vlan "$parent" "$vid" "$cidr" || refused+="${vid} "
        wanted+="$(vlan_child_name "$parent" "$vid") ${vid} ${parent}"$'\n'
    done

    # Remove netmon-vlan<digits> connections we own that are no longer wanted —
    # unless an add was refused: a foreign profile holds one of our names, so
    # stop reconciling and report it rather than half-apply.
    local existing evid listing stale_left=""
    if [[ -z "$refused" ]]; then
        if listing="$($SUDO nmcli -g NAME con show 2>/dev/null)"; then
            while IFS= read -r existing; do
                [[ "$existing" =~ ^netmon-vlan[0-9]+$ ]] || continue
                evid="${existing#netmon-vlan}"
                [[ " $vids " == *" $evid "* ]] && continue
                if _nmcli_remove_vlan_con "$existing"; then
                    log "removed stale VLAN connection ${existing}"
                else
                    stale_left+="${existing} "
                fi
            done <<< "$listing"
        else
            stale_left="(could not list NetworkManager connections) "
        fi
    fi

    # Connectivity guard (belt-and-suspenders; never-default already blocks hijack).
    # The safe end state is "no NetMon VLANs": routes-off sub-interfaces cannot be
    # what took the route, so removing them is the conservative undo.
    if _trunk_route_lost "$before_default"; then
        warn "default route lost after VLAN apply — REVERTING the nmcli VLANs."
        for vid in $vids; do
            _nmcli_remove_vlan_con "netmon-vlan${vid}" || true
        done
        _trunk_route_lost "$before_default" \
            && warn "default route is STILL missing after the revert — check the uplink."
        return 1
    fi

    if [[ -n "$refused" ]]; then
        warn "VLAN(s) not configured — a non-NetMon NM profile holds the name: ${refused% }"
        return 1
    fi
    if [[ -n "$stale_left" ]]; then
        warn "stale NetMon VLAN connection(s) not removed: ${stale_left% }"
        return 1
    fi
    local missing
    missing="$(_vlan_missing_links <<< "$wanted")"
    if [[ -n "$missing" ]]; then
        warn "VLAN sub-interface(s) did not come up: ${missing} (a parent with no link yet comes up when it is cabled)"
        return 1
    fi
    ok "VLAN sub-interfaces up via NetworkManager on ${parent} (${vids// /,}); the collector scans them within a poll tick (~30s)."
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
    local f="$NETMON_VLAN_NETPLAN" vids

    # Validate BEFORE choosing a backend or touching anything: a list with no valid
    # VLAN id ("," or "0") would otherwise reconcile to empty — an implicit clear.
    # Clearing is remove_vlan_interfaces_headless, explicitly.
    vids="$(_trunk_vids "$vlans")"
    if [[ -z "$parent" || -z "$vids" ]]; then
        warn "VLAN setup: missing parent interface or no valid VLAN id in '${vlans}' — skipping."
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
        _apply_vlan_nmcli "$parent" "$vids" "$statics"
        return $?
    fi

    if ! command -v netplan >/dev/null 2>&1; then
        warn "netplan not found — cannot configure VLAN sub-interfaces on this box."
        return 1
    fi

    # Snapshot the default route so we can detect (and undo) connectivity loss.
    local before_default
    before_default="$(ip route show default 2>/dev/null | head -1)"

    # What our previous file defined, so links it no longer defines identically
    # can be dropped before the apply.
    local old_children new_children
    old_children="$(_vlan_netplan_children "$f")"

    generate_vlan_netplan "$parent" "${vids// /,}" "$statics" >/dev/null
    log "wrote ${f} (VLANs ${vids// /,} on ${parent}, routes off)"

    if ! $SUDO netplan generate 2>/tmp/netmon-netplan.err; then
        warn "netplan validation failed — removing our file so it can't break netplan:"
        $SUDO sed 's/^/    /' /tmp/netmon-netplan.err 2>/dev/null || true
        $SUDO rm -f "$f"
        $SUDO netplan generate >/dev/null 2>&1 || true
        return 1
    fi

    new_children="$(_vlan_netplan_children "$f")"
    _vlan_drop_changed_children "$old_children" "$new_children"

    $SUDO netplan apply 2>/dev/null || true
    sleep 3

    # Same conservative undo as the nmcli path: back to no NetMon VLANs.
    local name id link
    if _trunk_route_lost "$before_default"; then
        warn "default route lost after VLAN apply — REVERTING (removing ${f})."
        $SUDO rm -f "$f"
        $SUDO netplan apply 2>/dev/null || true
        while read -r name id link; do
            [[ -n "$name" ]] && _vlan_delete_link "$name" "$id" "$link"
        done <<< "$new_children"
        _trunk_route_lost "$before_default" \
            && warn "default route is STILL missing after the revert — check the uplink."
        return 1
    fi

    local missing
    missing="$(_vlan_missing_links <<< "$new_children")"
    if [[ -n "$missing" ]]; then
        warn "VLAN sub-interface(s) did not come up: ${missing}"
        return 1
    fi
    ok "VLAN sub-interfaces up on ${parent} (${vids// /,}); the collector scans them within a poll tick (~30s)."
    return 0
}

# Remove every VLAN sub-interface NetMon created, and nothing else — the clear
# path for an emptied VLAN list (host action host-remove-vlan). Ownership is what
# NetMon wrote: our netplan file (networkd) and our netmon-vlan<id> NM connections
# (VLAN-typed, id matching the name); both are checked whatever the current
# backend, so a box that changed backends is still cleaned. A link is deleted only
# when one of those records names it and the kernel agrees on name, VLAN id and
# parent (see _vlan_delete_link). The parent and every other netplan file and NM
# connection are left alone. Guarded like the apply: if the default route
# disappears, the removed config is put back. Returns 0 on success (including
# "nothing to remove"), non-zero on any problem.
remove_vlan_interfaces_headless() {
    local f="$NETMON_VLAN_NETPLAN"
    local before_default rc=0
    before_default="$(ip route show default 2>/dev/null | head -1)"

    # networkd / netplan side. Fail closed: no verified backup, no removal.
    local children="" backup="" name id link
    if $SUDO test -f "$f"; then
        children="$(_vlan_netplan_children "$f")"
        if ! backup="$(mktemp)"; then
            warn "could not create a backup of ${f} — leaving it in place."
            return 1
        fi
        if ! $SUDO cat "$f" > "$backup" 2>/dev/null || [[ ! -s "$backup" ]]; then
            rm -f "$backup"
            warn "could not back up ${f} — leaving it in place."
            return 1
        fi
        $SUDO rm -f "$f"
        if $SUDO test -f "$f"; then
            rm -f "$backup"
            warn "could not remove ${f}."
            return 1
        fi
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
        while read -r name id link; do
            [[ -n "$name" ]] && _vlan_delete_link "$name" "$id" "$link"
        done <<< "$children"
    fi

    # NetworkManager side: our netmon-vlan<digits> VLAN connections only.
    local con info ctype ifname vparent vid addrs saved=() nm_links="" cons=""
    if command -v nmcli >/dev/null 2>&1; then
        if ! cons="$($SUDO nmcli -g NAME con show 2>/dev/null)"; then
            cons=""
            # Running and failing is a failure. Stopped is fine only if no NetMon
            # profile is saved to come back when NetworkManager starts.
            if command -v systemctl >/dev/null 2>&1 \
                && systemctl is-active --quiet NetworkManager 2>/dev/null; then
                warn "could not list NetworkManager connections."
                rc=1
            elif $SUDO ls "$NETMON_NM_CONN_DIR" 2>/dev/null \
                    | grep -qE '^netmon-vlan[0-9]+\.nmconnection$'; then
                warn "NetworkManager is not running but NetMon VLAN profiles are saved in ${NETMON_NM_CONN_DIR} — start it and retry."
                rc=1
            fi
        fi
        while IFS= read -r con; do
            [[ "$con" =~ ^netmon-vlan[0-9]+$ ]] || continue
            if ! info="$(_nmcli_vlan_con_info "$con")"; then
                if $SUDO nmcli -g NAME con show 2>/dev/null | grep -qxF -- "$con"; then
                    warn "could not inspect NM connection ${con}."
                    rc=1
                fi
                continue
            fi
            if _nmcli_remove_vlan_con "$con"; then
                saved+=("$info")
                read -r ctype ifname vparent vid addrs <<< "$info"
                nm_links+="${ifname} ${vid} ${vparent}"$'\n'
                log "removed VLAN connection ${con}"
            else
                rc=1
            fi
        done <<< "$cons"
    fi

    if _trunk_route_lost "$before_default"; then
        warn "default route lost after VLAN removal — RESTORING the previous VLAN config."
        if [[ -n "$backup" ]]; then
            if $SUDO install -m 600 -o root -g root "$backup" "$f"; then
                if command -v netplan >/dev/null 2>&1 && [[ "$(_vlan_backend)" == "networkd" ]]; then
                    $SUDO netplan apply 2>/dev/null || true
                fi
            else
                warn "could not restore ${f} (backup kept at ${backup})."
                backup=""
            fi
        fi
        local entry
        for entry in "${saved[@]}"; do
            read -r ctype ifname vparent vid addrs <<< "$entry"
            [[ "$vid" =~ ^[0-9]+$ && "$vparent" =~ $_TRUNK_IFNAME_RE ]] || continue
            [[ "$addrs" == "-" ]] && addrs=""
            _nmcli_add_vlan "$vparent" "$vid" "$addrs" || true
        done
        [[ -n "$backup" ]] && rm -f "$backup"
        _trunk_route_lost "$before_default" \
            && warn "default route is STILL missing after the restore — check the uplink."
        return 1
    fi
    [[ -n "$backup" ]] && rm -f "$backup"

    # Anything of ours still there? (A link _vlan_delete_link refused because it
    # carries the default route lands here; a stale record now naming someone
    # else's device does not — that device is not ours.)
    local left
    left="$(_vlan_present_links < <(printf '%s\n' "$children"; printf '%s' "$nm_links"))"
    if [[ -n "$left" ]]; then
        warn "VLAN sub-interface(s) still present after removal: ${left}"
        return 1
    fi
    if (( rc != 0 )); then
        warn "NetMon's VLAN state could not be fully removed (see above)."
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
    vlans="$(_trunk_vids "$vlans")"; vlans="${vlans// /,}"   # valid ids only, canonical
    if [[ -z "$vlans" ]]; then warn "No valid VLAN ids (1-4094) given — trunk setup cancelled."; return 0; fi

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
