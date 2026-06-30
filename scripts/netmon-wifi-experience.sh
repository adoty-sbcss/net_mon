#!/usr/bin/env bash
# scripts/netmon-wifi-experience.sh — WIFI-3: client-experience battery.
#
# Joins the configured network on the analysis radio (lib/wifi.sh, routes-off),
# then measures what a real client experiences ON THAT network and tears down.
# Emits /var/lib/netmon/wifi_experience.json for the collector to bundle.
#
# Battery: time-to-associate, time-to-DHCP, RSSI, captive-portal characterization,
# DNS, internet reachability, and a guest->internal ISOLATION probe.
#
# SOURCE ROUTING — the crux: the analysis radio is routes-off (never-default), so
# by default traffic would leave via the WIRED uplink, not the Wi-Fi we want to
# test. We install a dedicated policy-routing table (from the Wi-Fi source IP ->
# default via the Wi-Fi gateway) for the duration of the battery, so the probes
# actually traverse the joined network, then remove it. The box's real uplink/
# default route is never touched.
#
# ⚠️ NOT yet hardware-validated (built static-only per scoping; the policy-routing
# + per-interface probes need a live association to confirm). Single network in v1;
# the SSID-hopping scheduler is a loop over a configured list — a later increment.
#
# Source AFTER common.sh, paths.sh, envfile.sh, wifi.sh (the host-action does this).

set -uo pipefail

# Self-contained: source the libs we use (current_value, wifi_join/leave, …).
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
for _lib in common.sh paths.sh envfile.sh wifi.sh; do
    # shellcheck source=/dev/null
    [ -f "$REPO_DIR/lib/$_lib" ] && . "$REPO_DIR/lib/$_lib"
done

STATE_DIR="${NETMON_STATE_DIR:-/var/lib/netmon}"
OUT="${STATE_DIR}/wifi_experience.json"
RT_TABLE=51                       # dedicated policy-routing table for the analysis radio
# Rule priority MUST be below the main-table rule (prio 32766), or the main table
# matches first and the wifi-sourced probe leaves via the wired uplink. Validated
# on Monitor1: at 5100 `ip route get <dst> from <wifi-ip>` routes via the wifi.
RT_RULE_PRIO=5100

# Cleanup targets for the EXIT trap. These MUST be globals: the trap fires after
# main() returns, when main's `local iface`/`ssid` are out of scope — referencing
# them there is an "unbound variable" under `set -u`, which aborts the trap before
# the Wi-Fi is torn down (leaving the radio joined). Globals survive main's return.
_TRAP_IFACE=""
_TRAP_SSID=""

# common.sh provides $SUDO; fall back if it wasn't sourced.
if [ -z "${SUDO+x}" ]; then SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"; fi

_now_ms() { date +%s%3N 2>/dev/null || echo 0; }
_ts()     { date -u +%Y-%m-%dT%H:%M:%SZ; }
b64()     { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }

# Tear down our policy route + rules (idempotent). Always run on exit.
_routing_teardown() {
    local iface="$1"
    $SUDO ip rule del prio "$RT_RULE_PRIO" 2>/dev/null || true
    $SUDO ip rule del prio "$((RT_RULE_PRIO + 1))" 2>/dev/null || true
    $SUDO ip route flush table "$RT_TABLE" 2>/dev/null || true
}

# Route probe traffic out via the Wi-Fi gateway (so it traverses the joined network,
# not the wired uplink). Two rules: `from <wifi-ip>` (matches probes bound by source
# IP) AND `oif <iface>` (matches anything egress-bound to the radio) — belt-and-
# suspenders since SO_BINDTODEVICE sets the oif but NOT the source IP. Reversible;
# the box's real default route is untouched.
_routing_setup() {
    local iface="$1" ip="$2" gw="$3"
    [[ -z "$ip" || -z "$gw" ]] && return 1
    $SUDO ip route replace default via "$gw" dev "$iface" table "$RT_TABLE" 2>/dev/null || return 1
    $SUDO ip rule add from "$ip" table "$RT_TABLE" prio "$RT_RULE_PRIO" 2>/dev/null || true
    $SUDO ip rule add oif "$iface" table "$RT_TABLE" prio "$((RT_RULE_PRIO + 1))" 2>/dev/null || true
    return 0
}

# Classify a captive portal from a curl probe of a known generate_204 endpoint.
# Echoes "state<TAB>http_code<TAB>redirect_url". PURE-ish (only runs curl) — the
# state logic is unit-tested via wifi_experience.py.
#   open    : 204 (direct internet, no portal)
#   portal  : 3xx or a 200 with a body (intercepted -> redirect_url is the portal)
#   blocked : no response (timeout/refused)
_captive_probe() {
    local bind="$1" out code redir   # bind = Wi-Fi source IP (curl --interface takes an address)
    out="$($SUDO curl -s -m 8 --interface "$bind" -o /dev/null \
            -w '%{http_code} %{redirect_url}' \
            http://connectivitycheck.gstatic.com/generate_204 2>/dev/null || true)"
    code="${out%% *}"; redir="${out#* }"
    [[ "$redir" == "$out" ]] && redir=""
    local state="blocked"
    if [[ "$code" == "204" ]]; then state="open"
    elif [[ "$code" =~ ^3[0-9][0-9]$ ]]; then state="portal"
    elif [[ "$code" == "200" ]]; then state="portal"   # 204 expected; a 200 body = interception
    elif [[ -z "$code" || "$code" == "000" ]]; then state="blocked"
    else state="other"; fi
    printf '%s\t%s\t%s' "$state" "${code:-000}" "$redir"
}

# ---- main ----------------------------------------------------------------

main() {
    command -v ip >/dev/null 2>&1 || { echo "ip(8) missing"; exit 1; }

    local enabled iface ssid auth identity secret
    enabled="$(current_value NETMON_WIFI_JOIN_ENABLED 2>/dev/null || true)"
    case "${enabled,,}" in true|1|yes) ;; *) echo "NETMON_WIFI_JOIN_ENABLED not true — skipping"; exit 0 ;; esac
    ssid="$(current_value NETMON_WIFI_JOIN_SSID 2>/dev/null || true)"
    [[ -z "$ssid" ]] && { echo "no NETMON_WIFI_JOIN_SSID — nothing to test"; exit 0; }
    iface="$(current_value NETMON_WIFI_JOIN_IFACE 2>/dev/null || true)"
    [[ -z "$iface" ]] && iface="$(wifi_analysis_iface)"
    [[ -z "$iface" ]] && { echo "no spare Wi-Fi NIC — refusing"; exit 1; }
    auth="$(current_value NETMON_WIFI_JOIN_AUTH 2>/dev/null || echo open)"
    identity="$(current_value NETMON_WIFI_JOIN_IDENTITY 2>/dev/null || true)"
    secret="$(current_value NETMON_WIFI_JOIN_SECRET 2>/dev/null || true)"

    # Hand the cleanup targets to the trap via globals (main's locals vanish before
    # the EXIT trap runs — see _TRAP_IFACE/_TRAP_SSID above).
    _TRAP_IFACE="$iface"; _TRAP_SSID="$ssid"
    trap '_routing_teardown "$_TRAP_IFACE"; [ -n "$_TRAP_SSID" ] && wifi_leave "$_TRAP_SSID" >/dev/null 2>&1 || true' EXIT

    # 1. Associate (timed).
    local t0 assoc_ms associated=false
    t0="$(_now_ms)"
    if wifi_join "$iface" "$ssid" "${auth:-open}" "$identity" "$secret" >/dev/null 2>&1; then
        associated=true
    fi
    assoc_ms=$(( $(_now_ms) - t0 ))

    # 2. Wait for a DHCP lease (timed, ~15s cap).
    local dhcp_ms=-1 ip4="" gw="" tries=0
    if $associated; then
        local d0; d0="$(_now_ms)"
        while (( tries < 30 )); do
            ip4="$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4; exit}')"
            [[ -n "$ip4" ]] && break
            sleep 0.5; tries=$((tries+1))
        done
        [[ -n "$ip4" ]] && dhcp_ms=$(( $(_now_ms) - d0 ))
        # Gateway: ignore-auto-routes suppresses IP4.GATEWAY AND installs no default
        # route, so the gateway comes from the DHCP lease's `routers` option (the
        # only reliable source on a routes-off connection; validated on Monitor1).
        gw="$($SUDO nmcli -g DHCP4.OPTION dev show "$iface" 2>/dev/null | tr ',' '\n' | sed -n 's/.*routers = \([0-9.]*\).*/\1/p' | head -1)"
        [[ -z "$gw" ]] && gw="$($SUDO nmcli -g IP4.GATEWAY dev show "$iface" 2>/dev/null | head -1)"
    fi

    # 3. Signal quality (nmcli SIGNAL is 0-100 link quality, NOT dBm — same unit the
    #    WIFI-2 survey reports; tagged signal_unit="quality" in the artifact).
    local rssi=""
    rssi="$($SUDO nmcli -t -f IN-USE,SIGNAL,SSID dev wifi list ifname "$iface" 2>/dev/null \
            | awk -F: '/^\*/{print $2; exit}')"

    # 4. Battery (only if we got an IP). Probes traverse the joined net via the
    #    dedicated route table.
    local cap_state="n/a" cap_code="" cap_redir_b64="" ping_ok=false rtt="" loss=""
    local dns_ok=false iso_tested="" iso_reachable=""
    if [[ -n "$ip4" && -n "$gw" ]]; then
        local srcip="${ip4%/*}"
        _routing_setup "$iface" "$srcip" "$gw" || true
        # Probes bind by SOURCE IP (not device): SO_BINDTODEVICE sets the oif but not
        # the source, so binding to the Wi-Fi IP is what makes the `from <ip>` policy
        # rule route them via the Wi-Fi gateway (the oif rule is the fallback).
        # captive portal
        local cap; cap="$(_captive_probe "$srcip")"
        cap_state="$(printf '%s' "$cap" | cut -f1)"
        cap_code="$(printf '%s' "$cap" | cut -f2)"
        cap_redir_b64="$(printf '%s' "$cap" | cut -f3 | b64)"
        # internet reachability via the Wi-Fi
        local png; png="$($SUDO ping -I "$srcip" -c 3 -W 2 1.1.1.1 2>/dev/null || true)"
        printf '%s' "$png" | grep -q ' 0% packet loss' && ping_ok=true
        rtt="$(printf '%s' "$png" | awk -F'/' '/rtt|round-trip/{print $5; exit}')"
        loss="$(printf '%s' "$png" | grep -oE '[0-9]+% packet loss' | grep -oE '[0-9]+' | head -1)"
        # DNS resolves through the Wi-Fi
        $SUDO curl -s -m 6 --interface "$srcip" -o /dev/null https://dns.google/resolve?name=example.com 2>/dev/null && dns_ok=true
        # ISOLATION: from the guest/Wi-Fi, can we reach an INTERNAL host (the wired
        # uplink's gateway)? A properly isolated guest network should NOT.
        iso_tested="$(ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}')"
        if [[ -n "$iso_tested" ]]; then
            if $SUDO ping -I "$srcip" -c 1 -W 2 "$iso_tested" >/dev/null 2>&1; then iso_reachable=true; else iso_reachable=false; fi
        fi
        _routing_teardown "$iface"
    fi

    # 5. Emit the artifact (single-network result list; scheduler will append).
    local tmp; tmp="$(mktemp)"
    {
        printf '{"schema":1,"generated_at":"%s","interface":"%s","results":[' "$(_ts)" "$iface"
        printf '{"ssid":"%s","auth":"%s","associated":%s,"assoc_ms":%s,"dhcp_ms":%s,' \
            "$(printf '%s' "$ssid" | tr -d '\000-\037\042\134')" "${auth:-open}" "$associated" "$assoc_ms" "$dhcp_ms"
        printf '"ip":"%s","gateway":"%s","signal":%s,"signal_unit":"quality",' "${ip4:-}" "${gw:-}" "${rssi:-null}"
        printf '"captive_portal":{"state":"%s","http_code":"%s","redirect_b64":"%s"},' \
            "$cap_state" "${cap_code:-}" "$cap_redir_b64"
        printf '"internet":{"ping_ok":%s,"rtt_ms":"%s","loss_pct":"%s"},' "$ping_ok" "${rtt:-}" "${loss:-}"
        printf '"dns_ok":%s,' "$dns_ok"
        printf '"isolation":{"internal_target":"%s","internal_reachable":%s}}' \
            "${iso_tested:-}" "${iso_reachable:-null}"
        printf ']}\n'
    } > "$tmp"
    $SUDO install -m 0644 "$tmp" "$OUT"
    rm -f "$tmp"
    echo "wrote $OUT (ssid=$ssid associated=$associated portal=$cap_state)"
}

main "$@"
