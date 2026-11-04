# lib/wifi.sh — WIFI-1: backend-aware Wi-Fi association for an ANALYSIS radio.
#
# Join a sensor's spare Wi-Fi NIC to a network so the collector can analyze it
# (the poller scans any interface that gets an IP). Built as a near-mirror of
# lib/trunk.sh (VLAN trunk): backend-aware (nmcli on NetworkManager, wpa_supplicant
# +netplan on systemd-networkd) and — crucially — the joined connection takes NO
# default route (ipv4.never-default + ipv4.ignore-auto-routes), so the analysis
# radio can NEVER hijack the box's real uplink / upload path. Same routes-off guard
# the VLAN apply uses, with the same auto-revert-on-default-route-loss safety.
#
# Supported auth (v1): open, WPA2-PSK, WPA2-Enterprise PEAP/TTLS (username+password).
# EAP-TLS (client certs) is intentionally NOT here — it needs a secure cert-delivery
# path + a SEC-* review (a stolen sensor cert pivots onto the staff net). See the
# feature registry WIFI-3 / SEC follow-up.
#
# Secrets (PSK / 802.1X password) are written to a 0600 NetworkManager keyfile, NOT
# passed on the nmcli command line, so they never appear in argv / `ps`.
#
# On systemd-networkd boxes the join is our own wpa_supplicant instance on the radio
# (0600 config under /run, so nothing survives a reboot) plus a runtime .network file
# that takes DHCP but no gateway, routes or DNS from it — the same routes-off contract.
#
# Routes-off still leaves the address's own connected route, in the MAIN table, so a
# destination inside the joined subnet that the box normally reaches over the wired
# uplink (a resolver or server that happens to sit in that range) is diverted onto the
# Wi-Fi. A caller that only needs the radio for its own source-bound probes (the
# experience battery) passes a route table: the connected route then goes there instead
# (NM ipv4.route-table and networkd [DHCPv4] RouteTable= both cover the prefix route),
# and the main table gets nothing from the radio.
#
# Source AFTER common.sh, paths.sh, envfile.sh.

[[ -n "${_NETMON_WIFI_SH:-}" ]] && return 0
_NETMON_WIFI_SH=1

NETMON_NM_KEYFILE_DIR="${NETMON_NM_KEYFILE_DIR:-/etc/NetworkManager/system-connections}"
# networkd backend: wpa_supplicant config/pid/iface per connection (root 0700 tmpfs),
# and the runtime .network directory (a /run file outranks nothing persistent and is
# gone after a reboot, so a box can never come back up still joined).
NETMON_WPA_RUN_DIR="${NETMON_WPA_RUN_DIR:-/run/netmon-wifi}"
NETMON_NETWORKD_RUN_DIR="${NETMON_NETWORKD_RUN_DIR:-/run/systemd/network}"
NETMON_NETWORKD_LEASE_DIR="${NETMON_NETWORKD_LEASE_DIR:-/run/systemd/netif/leases}"

# Which backend manages this box's networking? Identical heuristic to
# lib/trunk.sh _vlan_backend so Wi-Fi and VLAN agree on a box.
_wifi_backend() {
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet NetworkManager 2>/dev/null \
        && ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        printf 'nm'
    else
        printf 'networkd'
    fi
}

# A route table a join may put its connected route in: numeric, and not one of the
# kernel's reserved tables (253 default, 254 main, 255 local).
_wifi_table_ok() {
    [[ "${1:-}" =~ ^[1-9][0-9]{0,8}$ ]] && (( $1 < 253 || $1 > 255 ))
}

# A stable NM connection-id / keyfile basename for an SSID (filesystem-safe, capped).
_wifi_conname() {
    local ssid="$1" slug
    slug="$(printf '%s' "$ssid" | tr -c 'A-Za-z0-9' '_' | cut -c1-32)"
    printf 'netmon-wifi-%s' "${slug:-x}"
}

# Read-only inventory of Wi-Fi interfaces: "<name>\t<mac>\t<is_uplink>\t<has_carrier>".
# A netdev is wireless iff /sys/class/net/<dev>/phy80211 exists. is_uplink=1 if it
# owns the default route (we must never reconfigure the box's uplink radio).
wifi_list_interfaces() {
    local uplink d iface mac carrier is_uplink
    uplink="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    for d in /sys/class/net/*/phy80211; do
        [[ -e "$d" ]] || continue
        iface="$(basename "$(dirname "$d")")"
        [[ "$iface" == p2p-* ]] && continue
        mac="$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo '')"
        carrier="$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo 0)"
        is_uplink=0; [[ "$iface" == "$uplink" ]] && is_uplink=1
        printf '%s\t%s\t%s\t%s\n' "$iface" "$mac" "$is_uplink" "$carrier"
    done
}

# Pick the analysis radio: the first Wi-Fi NIC that is NOT the box's uplink. Returns
# empty if the only Wi-Fi NIC owns the default route (never repoint the uplink).
wifi_analysis_iface() {
    local explicit="${1:-}"
    if [[ -n "$explicit" ]]; then printf '%s' "$explicit"; return 0; fi
    local line iface is_uplink
    while IFS=$'\t' read -r iface _ is_uplink _; do
        [[ "$is_uplink" == "1" ]] && continue
        printf '%s' "$iface"; return 0
    done < <(wifi_list_interfaces)
    return 0
}

# PURE function: emit a NetworkManager keyfile (INI) for one network. No I/O, no
# secrets-in-argv — unit-testable. The [ipv4] block is the safety contract: a joined
# analysis network installs NO default route and ignores DHCP-pushed routes, so it
# cannot become the box's uplink. With a route table, its connected route goes there
# too, so the main table gets nothing from the radio.
#   args: iface ssid auth identity secret [route_table]
#   auth: open | psk | peap | ttls   (peap/ttls => 802.1X username+password)
wifi_keyfile_content() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}" table="${6:-}" conname
    conname="$(_wifi_conname "$ssid")"
    printf '[connection]\n'
    printf 'id=%s\n' "$conname"
    printf 'type=wifi\n'
    printf 'interface-name=%s\n' "$iface"
    # The scheduler brings connections up/down explicitly; never auto-reconnect
    # (it would fight the SSID-hopping scheduler and could grab the radio).
    printf 'autoconnect=false\n\n'
    printf '[wifi]\n'
    printf 'mode=infrastructure\n'
    printf 'ssid=%s\n\n' "$ssid"
    case "$auth" in
        psk)
            printf '[wifi-security]\n'
            printf 'key-mgmt=wpa-psk\n'
            printf 'psk=%s\n\n' "$secret"
            ;;
        peap|ttls)
            printf '[wifi-security]\n'
            printf 'key-mgmt=wpa-eap\n\n'
            printf '[802-1x]\n'
            printf 'eap=%s\n' "$auth"
            printf 'identity=%s\n' "$identity"
            printf 'password=%s\n' "$secret"
            printf 'phase2-auth=mschapv2\n'
            # v1 analysis join sets NO ca-cert, so wpa_supplicant does NOT validate
            # the RADIUS server cert — intentional for characterization (we are not
            # trusting the network). A real deployment MUST pin the CA; EAP-TLS + CA
            # pinning is the SEC follow-up. (Some NM builds warn about the missing CA;
            # `system-ca-certs=false` does NOT disable validation, so it's omitted.)
            printf '\n'
            ;;
        open|*)
            printf '\n'
            ;;
    esac
    printf '[ipv4]\n'
    printf 'method=auto\n'
    printf 'never-default=true\n'
    printf 'ignore-auto-routes=true\n'
    [[ -n "$table" ]] && printf 'route-table=%s\n' "$table"
    printf 'may-fail=true\n\n'
    printf '[ipv6]\n'
    printf 'method=ignore\n'
}

# Join one network on the analysis radio (NM backend). Writes the 0600 keyfile,
# reloads NM, brings the connection up, and GUARDS the box's uplink: snapshots the
# default route and reverts the join if the default route disappears. Mirrors
# lib/trunk.sh _apply_vlan_nmcli. Returns 0 on a usable association.
#   args: iface ssid auth [identity] [secret] [route_table]
_wifi_join_nm() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}" table="${6:-}"
    command -v nmcli >/dev/null 2>&1 || { warn "nmcli not found — cannot join Wi-Fi on this NM box."; return 1; }
    local conname keyfile before_default after_default tmp
    conname="$(_wifi_conname "$ssid")"
    keyfile="${NETMON_NM_KEYFILE_DIR}/${conname}.nmconnection"
    before_default="$(ip route show default 2>/dev/null | head -1)"

    tmp="$(mktemp)"
    wifi_keyfile_content "$iface" "$ssid" "$auth" "$identity" "$secret" "$table" > "$tmp"
    $SUDO install -m 600 -o root -g root "$tmp" "$keyfile"
    rm -f "$tmp"
    $SUDO nmcli con reload >/dev/null 2>&1 || true
    # --wait is a GLOBAL option and MUST precede the subcommand (`nmcli --wait N con
    # up`); placed after, nmcli errors "invalid extra argument '--wait'" and the
    # connection never activates (the VLAN path hid this with autoconnect=yes — we
    # use autoconnect=false). Caps activation so a failing auth/DHCP returns promptly.
    $SUDO nmcli --wait 25 con up "$conname" >/dev/null 2>&1 || true

    after_default="$(ip route show default 2>/dev/null | head -1)"
    if [[ -n "$before_default" && -z "$after_default" ]]; then
        warn "default route lost after Wi-Fi join — REVERTING (${ssid})."
        _wifi_leave_nm "$ssid"
        return 1
    fi
    # Associated iff the device reports this connection active.
    if $SUDO nmcli -t -f GENERAL.STATE device show "$iface" 2>/dev/null | grep -q '^GENERAL.STATE:100 '; then
        ok "joined ${ssid} on ${iface} (routes-off; uplink untouched)"
        return 0
    fi
    warn "Wi-Fi join did not associate (${ssid}) — auth/range/DHCP. Leaving it clean."
    _wifi_leave_nm "$ssid"
    return 1
}

# Tear down a joined network (NM backend): bring it down, delete the connection and
# its keyfile. Idempotent.
_wifi_leave_nm() {
    local ssid="$1" conname
    conname="$(_wifi_conname "$ssid")"
    $SUDO nmcli con down "$conname" >/dev/null 2>&1 || true
    $SUDO nmcli con delete "$conname" >/dev/null 2>&1 || true
    $SUDO rm -f "${NETMON_NM_KEYFILE_DIR}/${conname}.nmconnection" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------------
# systemd-networkd backend (wpa_supplicant + a runtime .network file)
# ---------------------------------------------------------------------------------

# A netdev name we are willing to put in a file name and a [Match] line.
_wifi_iface_ok() { [[ "${1:-}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; }

# Does this interface carry a default route, IPv4 or IPv6, in any table, including as
# one nexthop of a multipath default? (Never reconfigure the uplink, even when it was
# named explicitly.) Not `ip route show default dev X`: before iproute2 6.10 that
# filter ignores multipath nexthops.
_wifi_is_uplink() {
    { ip -4 route show default table all; ip -6 route show default table all; } 2>/dev/null \
        | grep -qE "[[:space:]]dev ${1//./\\.}([[:space:]]|$)"
}

_wifi_is_radio() { [[ -e "/sys/class/net/${1}/phy80211" ]]; }

# networkctl only while networkd is already running: the call is D-Bus-activated, so
# on a box where networkd is enabled but stopped it would START networkd, which would
# then manage every link any .network file matches.
_wifi_networkd_running() { systemctl is-active --quiet systemd-networkd 2>/dev/null; }
_wifi_networkd_reload() { _wifi_networkd_running && $SUDO networkctl reload >/dev/null 2>&1; }

# Lower-case hex of a string, no separators. wpa_supplicant reads an unquoted string
# value as hex, so SSID / identity / password reach it with no quoting to get wrong.
_wifi_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }

_wifi_networkd_file() { printf '%s/05-netmon-wifi-%s.network' "$NETMON_NETWORKD_RUN_DIR" "$1"; }

# PURE function: the wpa_supplicant config for one network. Fails (rc 1, partial output
# for the caller to discard) on a secret wpa_supplicant cannot take as given, rather than
# writing a config that silently means something else.
#   args: ssid auth identity secret       auth: open | psk | peap | ttls
wifi_wpa_conf_content() {
    local ssid="$1" auth="$2" identity="${3:-}" secret="${4:-}" LC_ALL=C
    printf 'ctrl_interface=%s/ctrl\n' "$NETMON_WPA_RUN_DIR"
    printf 'update_config=0\n'
    printf 'network={\n'
    printf '\tssid=%s\n' "$(_wifi_hex "$ssid")"
    printf '\tscan_ssid=1\n'
    case "$auth" in
        psk)
            printf '\tkey_mgmt=WPA-PSK\n'
            # A raw 64-hex PSK goes in bare; a passphrase must be 8-63 printable ASCII
            # (802.11i), quoted. wpa_supplicant takes everything up to the LAST quote, so
            # a quote inside the passphrase is fine; a newline is not, and is refused here.
            # So is a '#' anywhere after a quote: the config reader pairs quotes from the
            # first one and reads a '#' outside a pair as a comment, which would cut the
            # passphrase short and join with the wrong key.
            if [[ "$secret" =~ ^[0-9A-Fa-f]{64}$ ]]; then
                printf '\tpsk=%s\n' "$secret"
            elif [[ "$secret" == *\"*#* ]]; then
                return 1
            elif [[ "$secret" =~ ^[\ -~]{8,63}$ ]]; then
                printf '\tpsk="%s"\n' "$secret"
            else
                return 1
            fi
            ;;
        peap|ttls)
            [[ -n "$identity" && -n "$secret" ]] || return 1
            printf '\tkey_mgmt=WPA-EAP\n'
            printf '\teap=%s\n' "${auth^^}"
            printf '\tidentity=%s\n' "$(_wifi_hex "$identity")"
            printf '\tpassword=%s\n' "$(_wifi_hex "$secret")"
            printf '\tphase2="auth=MSCHAPV2"\n'
            # No ca_cert, as on the NM path: characterization, not trust. CA pinning
            # arrives with EAP-TLS (SEC-11).
            ;;
        open|*)
            printf '\tkey_mgmt=NONE\n'
            ;;
    esac
    printf '}\n'
}

# PURE function: the runtime .network file. The safety contract is the [DHCPv4] block:
# a lease gives the radio an address and nothing else — no gateway, no routes (incl.
# option 121), no DNS or search domains, no MTU — so it cannot become the box's uplink
# or change how the box resolves names. The address's own connected route is the one
# route it does get: in the main table, or in route_table when one is given (networkd
# then adds the address without a kernel prefix route and installs that route in the
# table itself — systemd 249 and 255 alike, whatever UseRoutes= says). The box's
# hostname is not sent either.
#   args: iface [route_table]
wifi_networkd_unit_content() {
    local iface="$1" table="${2:-}"
    printf '[Match]\nName=%s\n\n' "$iface"
    printf '[Link]\nRequiredForOnline=no\n\n'
    printf '[Network]\n'
    printf 'DHCP=ipv4\n'
    printf 'LinkLocalAddressing=no\n'
    printf 'IPv6AcceptRA=no\n'
    printf 'LLMNR=no\n'
    printf 'MulticastDNS=no\n'
    printf 'DNSDefaultRoute=no\n\n'
    printf '[DHCPv4]\n'
    printf 'UseGateway=no\n'
    printf 'UseRoutes=no\n'
    printf 'UseDNS=no\n'
    printf 'UseDomains=no\n'
    printf 'UseNTP=no\n'
    printf 'UseHostname=no\n'
    printf 'UseMTU=no\n'
    printf 'SendHostname=no\n'
    [[ -n "$table" ]] && printf 'RouteTable=%s\n' "$table"
    return 0
}

# wpa_supplicant + networkctl present? Install wpasupplicant once if not (the same
# one-time, best-effort apt path the survey uses for iw on these boxes).
_wifi_networkd_tools() {
    if ! command -v networkctl >/dev/null 2>&1; then
        warn "networkctl not found — cannot join Wi-Fi on this box."; return 1
    fi
    if ! _wifi_networkd_running; then
        warn "neither NetworkManager nor systemd-networkd is running — not joining Wi-Fi."; return 1
    fi
    if ! command -v wpa_supplicant >/dev/null 2>&1 || ! command -v wpa_cli >/dev/null 2>&1; then
        warn "wpa_supplicant not found; attempting one-time install"
        $SUDO apt-get update -qq >/dev/null 2>&1 || true
        $SUDO apt-get install -y -qq wpasupplicant >/dev/null 2>&1 || true
        if ! command -v wpa_supplicant >/dev/null 2>&1 || ! command -v wpa_cli >/dev/null 2>&1; then
            warn "could not install wpasupplicant (needs passwordless sudo + network)."; return 1
        fi
    fi
}

# Is the radio already driven by the box's own config (netplan `wifis:`, or a
# wpa_supplicant@ unit)? Then it is not ours to take.
_wifi_networkd_radio_owned() {
    local iface="$1" unit
    for unit in "netplan-wpa-${iface}" "wpa_supplicant@${iface}" "wpa_supplicant-nl80211@${iface}"; do
        systemctl is-active --quiet "${unit}.service" 2>/dev/null && return 0
    done
    # NetworkManager running beside networkd (the backend heuristic picks networkd
    # then) and managing this radio: two supplicants on one radio fight.
    if systemctl is-active --quiet NetworkManager 2>/dev/null && command -v nmcli >/dev/null 2>&1; then
        nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -q "^${iface}:" \
            && ! nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -qx "${iface}:unmanaged" \
            && return 0
    fi
    [[ -e "/run/wpa_supplicant/${iface}" ]]
}

_wifi_wpa_cli() { $SUDO wpa_cli -p "${NETMON_WPA_RUN_DIR}/ctrl" "$@" 2>/dev/null; }

_wifi_wpa_state() {
    _wifi_wpa_cli -i "$1" status | sed -n 's/^wpa_state=//p' | head -1
}

# Wait up to $2 half-seconds for the supplicant to report a completed association.
_wifi_wpa_wait_completed() {
    local iface="$1" n="${2:-50}" i
    for (( i = 0; i < n; i++ )); do
        [[ "$(_wifi_wpa_state "$iface")" == "COMPLETED" ]] && return 0
        sleep 0.5
    done
    return 1
}

# Is <pid> OUR supplicant for this connection (its command line names our config)?
# A stale pidfile must not kill some unrelated process, nor the box's own supplicant.
_wifi_pid_is_ours() {
    local pid="$1" conf="$2"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    # $SUDO cat: /proc may be mounted hidepid, hiding root's processes from a sudoer.
    $SUDO cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' '\n' | grep -qxF -- "$conf"
}

# Every live supplicant started with this config: the pidfile's pid AND any process
# whose command line names the config, so a missing or stale pidfile hides none.
_wifi_our_pids() {
    local conf="$1" p
    { $SUDO cat "${conf%.conf}.pid" 2>/dev/null; echo; pgrep -f -- "$conf" 2>/dev/null; } \
        | sort -u | while read -r p; do
            _wifi_pid_is_ours "$p" "$conf" && printf '%s\n' "$p"
        done
}

# Stop one connection's supplicant and remove its files. First through our own control
# socket (only our instance listens there), then by signal to whatever is still ours.
# A terminate reply comes before the process is gone, so wait for the process itself.
#   args: base (run-dir path without extension) [iface, if the .iface record is missing]
_wifi_networkd_stop() {
    local base="$1" iface pid i left
    iface="$($SUDO cat "${base}.iface" 2>/dev/null || true)"
    [[ -z "$iface" ]] && iface="${2:-}"
    if _wifi_iface_ok "$iface"; then
        _wifi_wpa_cli -i "$iface" terminate >/dev/null || true
    fi
    for (( i = 0; i < 10; i++ )); do
        [[ -z "$(_wifi_our_pids "${base}.conf")" ]] && break
        sleep 0.3
    done
    for pid in $(_wifi_our_pids "${base}.conf"); do
        $SUDO kill "$pid" 2>/dev/null || true
    done
    for (( i = 0; i < 10; i++ )); do
        [[ -z "$(_wifi_our_pids "${base}.conf")" ]] && break
        sleep 0.3
    done
    for pid in $(_wifi_our_pids "${base}.conf"); do
        $SUDO kill -9 "$pid" 2>/dev/null || true
    done
    sleep 0.2
    left="$(_wifi_our_pids "${base}.conf")"
    if [[ -n "$left" ]]; then
        # Keep the records so the next leave/leave_all tries again; the routes-off
        # .network file stays on the link while the supplicant does.
        warn "wpa_supplicant for ${base##*/} would not stop (pid ${left//$'\n'/ }) — keeping its records."
        return 1
    fi
    $SUDO rm -f "${base}.conf" "${base}.pid" "${base}.iface" 2>/dev/null || true
    if _wifi_iface_ok "$iface"; then
        $SUDO rm -f "$(_wifi_networkd_file "$iface")" 2>/dev/null || true
        _wifi_networkd_reload || true
        # Carrier loss already drops the lease; this catches a networkd that kept it.
        # Never on the uplink (an explicitly configured iface could be one).
        _wifi_is_uplink "$iface" || $SUDO ip -4 addr flush dev "$iface" scope global 2>/dev/null || true
    fi
}

# Join one network on the analysis radio (networkd backend). Same contract as
# _wifi_join_nm: 0600 secrets, no default route, revert if the uplink's default route
# disappears. Waits up to 25 s to associate, then up to 15 s for the lease (NM's
# `con up` covers both, so time-to-associate means the same on either backend).
#   args: iface ssid auth [identity] [secret] [route_table]
_wifi_join_networkd() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}" table="${6:-}"
    local base before_default after_default tmp i netfile
    _wifi_iface_ok "$iface" || { warn "Wi-Fi join: bad interface name '${iface}'."; return 1; }
    # An explicitly configured iface skips wifi_analysis_iface's choice, so check here,
    # before anything is written: a radio, and not the uplink.
    _wifi_is_radio "$iface" || { warn "${iface} is not a Wi-Fi radio — not joining."; return 1; }
    if _wifi_is_uplink "$iface"; then
        warn "${iface} carries a default route (the uplink) — not joining."; return 1
    fi
    _wifi_networkd_tools || return 1
    if _wifi_networkd_radio_owned "$iface"; then
        warn "${iface} is driven by this box's own Wi-Fi config — not using it as an analysis radio."; return 1
    fi
    base="${NETMON_WPA_RUN_DIR}/$(_wifi_conname "$ssid")"
    netfile="$(_wifi_networkd_file "$iface")"
    before_default="$(ip route show default 2>/dev/null | head -1)"

    $SUDO install -d -m 700 -o root -g root "$NETMON_WPA_RUN_DIR" || return 1
    tmp="$(mktemp)" || return 1
    if ! wifi_wpa_conf_content "$ssid" "$auth" "$identity" "$secret" > "$tmp"; then
        rm -f "$tmp"
        warn "Wi-Fi join: ${auth} credentials for ${ssid} are not usable (a passphrase must be 8-63 printable characters, with no '#' after a quote; 802.1X needs a username and password)."
        return 1
    fi
    # Every step must land; any failure undoes what was written and joins nothing.
    if ! { $SUDO install -m 600 -o root -g root "$tmp" "${base}.conf" \
            && printf '%s\n' "$iface" > "$tmp" \
            && $SUDO install -m 600 -o root -g root "$tmp" "${base}.iface" \
            && wifi_networkd_unit_content "$iface" "$table" > "$tmp" \
            && $SUDO install -d -m 755 "$NETMON_NETWORKD_RUN_DIR" \
            && $SUDO install -m 644 -o root -g root "$tmp" "$netfile"; }; then
        rm -f "$tmp"
        warn "Wi-Fi join: could not write the join files — not joining ${ssid}."
        _wifi_networkd_stop "$base" "$iface"; return 1
    fi
    rm -f "$tmp"
    # reload picks up the new file; reconfigure applies it to a link that had none.
    if ! _wifi_networkd_reload; then
        warn "networkctl reload failed — not joining ${ssid}."
        _wifi_networkd_stop "$base" "$iface"; return 1
    fi
    $SUDO networkctl reconfigure "$iface" >/dev/null 2>&1 || true
    # Associate only once networkd has put OUR file (the routes-off one) on the link;
    # anything else matching it (a netplan stanza, a catch-all) could take a gateway.
    for (( i = 0; i < 20; i++ )); do
        networkctl status "$iface" --no-pager 2>/dev/null | grep -qF "Network File: ${netfile}" && break
        sleep 0.5
    done
    if ! networkctl status "$iface" --no-pager 2>/dev/null | grep -qF "Network File: ${netfile}"; then
        warn "networkd did not apply the routes-off config to ${iface} — not joining ${ssid}."
        _wifi_networkd_stop "$base" "$iface"; return 1
    fi
    if command -v rfkill >/dev/null 2>&1; then $SUDO rfkill unblock wifi 2>/dev/null || true; fi
    $SUDO ip link set dev "$iface" up 2>/dev/null || true
    if ! $SUDO wpa_supplicant -B -i "$iface" -c "${base}.conf" -P "${base}.pid" -D nl80211 >/dev/null 2>&1; then
        warn "wpa_supplicant would not start on ${iface}."
        _wifi_networkd_stop "$base" "$iface"; return 1
    fi
    if ! _wifi_wpa_wait_completed "$iface" 50; then
        warn "Wi-Fi join did not associate (${ssid}) — auth/range. Leaving it clean."
        _wifi_networkd_stop "$base" "$iface"; return 1
    fi
    for (( i = 0; i < 30; i++ )); do
        [[ -n "$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null)" ]] && break
        sleep 0.5
    done

    after_default="$(ip route show default 2>/dev/null | head -1)"
    if [[ -n "$before_default" && -z "$after_default" ]] || _wifi_is_uplink "$iface"; then
        warn "default route changed after Wi-Fi join — REVERTING (${ssid})."
        _wifi_networkd_stop "$base" "$iface"; return 1
    fi
    ok "joined ${ssid} on ${iface} (routes-off; uplink untouched)"
    return 0
}

_wifi_leave_networkd() {
    _wifi_networkd_stop "${NETMON_WPA_RUN_DIR}/$(_wifi_conname "$1")"
}

_wifi_leave_all_networkd() {
    local f
    for f in $($SUDO sh -c "ls '${NETMON_WPA_RUN_DIR}' 2>/dev/null" | sed -n 's/^\(netmon-wifi-.*\)\.\(conf\|pid\|iface\)$/\1/p' | sort -u); do
        _wifi_networkd_stop "${NETMON_WPA_RUN_DIR}/${f}"
    done
    # A .network file whose run-dir record is already gone (killed mid-join).
    if compgen -G "${NETMON_NETWORKD_RUN_DIR}/05-netmon-wifi-*.network" >/dev/null; then
        $SUDO rm -f "${NETMON_NETWORKD_RUN_DIR}"/05-netmon-wifi-*.network 2>/dev/null || true
        _wifi_networkd_reload || true
    fi
}

# Drop and re-make the association on the same supplicant (the captive-portal rejoin).
# networkd drops the lease on carrier loss and asks again on carrier, as NM's down/up does.
wifi_networkd_reassociate() {
    local iface="$1"
    _wifi_wpa_cli -i "$iface" disconnect >/dev/null || return 1
    sleep 1
    _wifi_wpa_cli -i "$iface" reconnect >/dev/null || return 1
    _wifi_wpa_wait_completed "$iface" 50
}

# One value from the radio's DHCP lease as networkd recorded it (the first, for
# multi-valued keys like ROUTER / DNS). The lease keeps the router and resolvers even
# though the .network file tells networkd not to use them.
#   args: iface key
wifi_networkd_lease() {
    local iface="$1" key="$2" idx
    idx="$(cat "/sys/class/net/${iface}/ifindex" 2>/dev/null || true)"
    [[ "$idx" =~ ^[0-9]+$ ]] || return 0
    $SUDO sed -n "s/^${key}=//p" "${NETMON_NETWORKD_LEASE_DIR}/${idx}" 2>/dev/null | head -1 | awk '{print $1}'
}

# Signal (dBm), BSSID, frequency (MHz) and link rate (Mbit/s) of the current
# association, tab-separated, from the supplicant itself (no iw needed).
wifi_networkd_link() {
    local iface="$1" poll st rssi freq rate bssid
    poll="$(_wifi_wpa_cli -i "$iface" signal_poll)"
    st="$(_wifi_wpa_cli -i "$iface" status)"
    rssi="$(printf '%s\n' "$poll" | sed -n 's/^RSSI=\(-\{0,1\}[0-9]\{1,3\}\)$/\1/p' | head -1)"
    rate="$(printf '%s\n' "$poll" | sed -n 's/^LINKSPEED=\([0-9]\{1,5\}\)$/\1/p' | head -1)"
    freq="$(printf '%s\n' "$poll" | sed -n 's/^FREQUENCY=\([0-9]\{3,5\}\)$/\1/p' | head -1)"
    bssid="$(printf '%s\n' "$st" | sed -n 's/^bssid=//p' | grep -ioE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' | head -1)"
    printf '%s\t%s\t%s\t%s' "$rssi" "$bssid" "$freq" "$rate"
}

# ---------------------------------------------------------------------------------
# Backend-aware public entry points
# ---------------------------------------------------------------------------------
# route_table (optional): keep the joined address's connected route out of the main
# table (see the header). Without one, the join behaves as it always has.
#   args: iface ssid auth [identity] [secret] [route_table]
wifi_join() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}" table="${6:-}"
    if [[ -z "$iface" || -z "$ssid" ]]; then warn "wifi_join: need iface + ssid"; return 1; fi
    if [[ -n "$table" ]] && ! _wifi_table_ok "$table"; then
        warn "wifi_join: route table '${table}' is not usable — not joining."; return 1
    fi
    case "$(_wifi_backend)" in
        nm) _wifi_join_nm "$iface" "$ssid" "$auth" "$identity" "$secret" "$table" ;;
        *)  _wifi_join_networkd "$iface" "$ssid" "$auth" "$identity" "$secret" "$table" ;;
    esac
}

wifi_leave() {
    local ssid="$1"
    case "$(_wifi_backend)" in
        nm) _wifi_leave_nm "$ssid" ;;
        *)  _wifi_leave_networkd "$ssid" ;;
    esac
}

# Remove every connection/keyfile we own (cleanup; e.g. when the feature is disabled).
wifi_leave_all() {
    local existing
    case "$(_wifi_backend)" in
        nm) ;;
        *)  _wifi_leave_all_networkd; return 0 ;;
    esac
    while IFS= read -r existing; do
        [[ "$existing" == netmon-wifi-* ]] || continue
        $SUDO nmcli con down "$existing" >/dev/null 2>&1 || true
        $SUDO nmcli con delete "$existing" >/dev/null 2>&1 || true
    done < <($SUDO nmcli -g NAME con show 2>/dev/null || true)
    $SUDO rm -f "${NETMON_NM_KEYFILE_DIR}"/netmon-wifi-*.nmconnection >/dev/null 2>&1 || true
}
