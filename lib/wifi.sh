# lib/wifi.sh — WIFI-1: backend-aware Wi-Fi association for an ANALYSIS radio.
#
# Join a sensor's spare Wi-Fi NIC to a network so the collector can analyze it
# (the poller scans any interface that gets an IP). Built as a near-mirror of
# lib/trunk.sh (VLAN trunk): backend-aware (nmcli on NetworkManager, wpa_supplicant
# +netplan on systemd-networkd) and — crucially — the joined connection takes NO
# default route (ipv4.never-default + ipv4.ignore-auto-routes), so the analysis
# radio can NEVER hijack the box's real uplink / SFTP path. Same routes-off guard
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
# Source AFTER common.sh, paths.sh, envfile.sh.

[[ -n "${_NETMON_WIFI_SH:-}" ]] && return 0
_NETMON_WIFI_SH=1

NETMON_NM_KEYFILE_DIR="${NETMON_NM_KEYFILE_DIR:-/etc/NetworkManager/system-connections}"

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
# cannot become the box's uplink.
#   args: iface ssid auth identity secret
#   auth: open | psk | peap | ttls   (peap/ttls => 802.1X username+password)
wifi_keyfile_content() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}" conname
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
    printf 'may-fail=true\n\n'
    printf '[ipv6]\n'
    printf 'method=ignore\n'
}

# Join one network on the analysis radio (NM backend). Writes the 0600 keyfile,
# reloads NM, brings the connection up, and GUARDS the box's uplink: snapshots the
# default route and reverts the join if the default route disappears. Mirrors
# lib/trunk.sh _apply_vlan_nmcli. Returns 0 on a usable association.
#   args: iface ssid auth [identity] [secret]
_wifi_join_nm() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}"
    command -v nmcli >/dev/null 2>&1 || { warn "nmcli not found — cannot join Wi-Fi on this NM box."; return 1; }
    local conname keyfile before_default after_default tmp
    conname="$(_wifi_conname "$ssid")"
    keyfile="${NETMON_NM_KEYFILE_DIR}/${conname}.nmconnection"
    before_default="$(ip route show default 2>/dev/null | head -1)"

    tmp="$(mktemp)"
    wifi_keyfile_content "$iface" "$ssid" "$auth" "$identity" "$secret" > "$tmp"
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

# Backend-aware public entry points. networkd/wpa_supplicant is not implemented in
# v1 (the fleet's Wi-Fi boxes are NM); fail loud rather than silently no-op.
wifi_join() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}"
    if [[ -z "$iface" || -z "$ssid" ]]; then warn "wifi_join: need iface + ssid"; return 1; fi
    case "$(_wifi_backend)" in
        nm) _wifi_join_nm "$iface" "$ssid" "$auth" "$identity" "$secret" ;;
        *)  warn "Wi-Fi join on systemd-networkd boxes is not implemented yet (WIFI-1 v1 is NM-only)."; return 2 ;;
    esac
}

wifi_leave() {
    local ssid="$1"
    case "$(_wifi_backend)" in
        nm) _wifi_leave_nm "$ssid" ;;
        *)  return 0 ;;
    esac
}

# Remove every connection/keyfile we own (cleanup; e.g. when the feature is disabled).
wifi_leave_all() {
    local existing
    while IFS= read -r existing; do
        [[ "$existing" == netmon-wifi-* ]] || continue
        $SUDO nmcli con down "$existing" >/dev/null 2>&1 || true
        $SUDO nmcli con delete "$existing" >/dev/null 2>&1 || true
    done < <($SUDO nmcli -g NAME con show 2>/dev/null || true)
    $SUDO rm -f "${NETMON_NM_KEYFILE_DIR}"/netmon-wifi-*.nmconnection >/dev/null 2>&1 || true
}
