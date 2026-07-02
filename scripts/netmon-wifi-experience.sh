#!/usr/bin/env bash
# scripts/netmon-wifi-experience.sh — WIFI-3/WIFI-6: client-experience battery.
#
# For EACH configured network profile, join it on the analysis radio (lib/wifi.sh,
# routes-off), measure what a real client experiences ON THAT network, then leave —
# serialized (one radio = one association at a time). Emits
# /var/lib/netmon/wifi_experience.json (a results[] array, one object per profile)
# for the collector to bundle.
#
# Profiles come from the dashboard-pushed 0600 JSON file
# (checkin.WIFI_PROFILES_FILE = /var/lib/netmon/wifi-profiles.json), each:
#   {"ssid","auth","identity","secret","captive_auto_accept"}
# If that file is ABSENT we fall back to the single NETMON_WIFI_JOIN_* env keys as
# one profile (legacy / pre-portal boxes). A present-but-empty file means "no
# profiles" (feature stays gated by NETMON_WIFI_JOIN_ENABLED).
#
# Battery per profile: time-to-associate, time-to-DHCP, RSSI, captive-portal
# characterization (+ optional best-effort click-through accept), DNS, internet
# reachability, and a guest->internal ISOLATION probe.
#
# SOURCE ROUTING — the crux: the analysis radio is routes-off (never-default), so
# by default traffic would leave via the WIRED uplink, not the Wi-Fi we want to
# test. For the duration of each profile's battery we install a dedicated policy-
# routing table (from the Wi-Fi source IP -> default via the Wi-Fi gateway) so the
# probes actually traverse the joined network, then remove it. The box's real
# uplink / default route is never touched.
#
# Validated live on Monitor1 2026-06-30 (PSK sbcss-mpsk): join, DHCP, gateway (from
# the DHCP `routers` option), source-routed probes, and clean teardown all confirmed.
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
PROFILES_FILE="${STATE_DIR}/wifi-profiles.json"   # dashboard-pushed profiles (0600)
WEBPERF_URLS_FILE="${STATE_DIR}/webperf-urls.json"   # dashboard-pushed district URL list (PERF-5)
# curl -w timing (mirrors collector/webperf.py _CURL_FMT); all times cumulative seconds.
WEBPERF_FMT='%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_code} %{size_download} %{speed_download}'
RT_TABLE=51                       # dedicated policy-routing table for the analysis radio
# Rule priority MUST be below the main-table rule (prio 32766), or the main table
# matches first and the wifi-sourced probe leaves via the wired uplink. Validated
# on Monitor1: at 5100 `ip route get <dst> from <wifi-ip>` routes via the wifi.
RT_RULE_PRIO=5100

# Cleanup target for the EXIT trap. MUST be a global: the trap fires after main()
# returns, when main's locals are out of scope — referencing them there is an
# "unbound variable" under `set -u`, which aborts the trap before cleanup runs.
# The trap tears down routing + leaves EVERY netmon-owned Wi-Fi connection
# (wifi_leave_all), so it needs no per-profile SSID state even though each profile
# is measured inside a command-substitution subshell.
_TRAP_IFACE=""

# common.sh provides $SUDO; fall back if it wasn't sourced.
if [ -z "${SUDO+x}" ]; then SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"; fi

_now_ms() { date +%s%3N 2>/dev/null || echo 0; }
_ts()     { date -u +%Y-%m-%dT%H:%M:%SZ; }
b64()     { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }

# Tear down our policy route + rules (idempotent). Always run on exit.
_routing_teardown() {
    local iface="${1:-}"
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

# --- Captive-portal auto-accept (vendor-aware) -----------------------------------------
# Many K-12 guest nets gate internet behind a single click-through AUP. We identify the
# portal VENDOR (its login flow differs per platform) and run a tailored accept; the
# caller re-probes generate_204 to confirm internet opened. All fetches are source-bound
# + http(s)-pinned (the portal URL is the joined network's redirect — refuse file://,
# gopher://, etc.). NOTE on validation: the Aruba Central flow was reverse-engineered live
# on SBCSS-Guest 2026-07-01; the Cisco/Meraki routines follow each vendor's DOCUMENTED
# web-auth pattern but are not yet hardware-validated (no test gear) — best-effort, and a
# failed accept is harmless (the portal simply stays up and we record it blocked).
_UA_BROWSER='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
# How long to hold the association after a captive accept, polling for the gateway to
# open. Aruba Central grants the MAC ASYNC — seconds to a minute+ AFTER the AUP POST — so
# a fast re-probe misses it. Bounded so a guest profile can't stall the battery forever;
# tune per-deploy via NETMON_WIFI_CAPTIVE_POLL_SEC. If the grant lands AFTER this budget,
# the NEXT battery run still measures it (Aruba's guest MAC grant persists across runs), so
# the accept is worthwhile even when this run records the portal. Default 45s.
CAPTIVE_ACCEPT_POLL_SEC="$(current_value NETMON_WIFI_CAPTIVE_POLL_SEC 2>/dev/null || echo 45)"
[[ "$CAPTIVE_ACCEPT_POLL_SEC" =~ ^[0-9]+$ ]] || CAPTIVE_ACCEPT_POLL_SEC=45

# Classify the portal vendor from the redirect host, then (if inconclusive) the page body.
# Echoes: aruba_central | aruba | cisco_wlc | cisco_ise | meraki | generic
_captive_vendor() {
    local srcip="$1" redir="$2" page=""
    case "$redir" in
        *cloudguest*.arubanetworks.com*|*cloudguest.central.*) echo "aruba_central"; return;;
        *securelogin.arubanetworks.com*|*securelogin.hpe.com*|*arubanetworks.com*) echo "aruba"; return;;
        *network-auth.com*) echo "meraki"; return;;
    esac
    [[ -z "$redir" ]] && { echo "generic"; return; }
    page="$($SUDO curl -s -m 8 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" "$redir" 2>/dev/null || true)"
    case "$page" in
        *portal_login_page_config*|*cloudguest*) echo "aruba_central";;
        *network-auth.com*|*"Cisco Meraki"*|*meraki*) echo "meraki";;
        *ClearPass*|*arubanetworks*|*Aruba*) echo "aruba";;
        *buttonClicked*|*"/login.html"*|*Cisco*Systems*) echo "cisco_wlc";;
        *_eventId*|*"self-registration"*|*ISE*|*sponsor*) echo "cisco_ise";;
        *) echo "generic";;
    esac
}

# Aruba Central Cloud Guest (Svelte SPA): generate_204 -> capture -> JS/META bounce to a
# /login SPA -> anonymous "I accept" AUP. Replicate the accept POST (capture + csrf +
# cmd=authenticate), then POLL up to CAPTIVE_ACCEPT_POLL_SEC — the AP opens the gateway
# ASYNC (seconds to a minute+) after the POST. Reverse-engineered live on SBCSS-Guest;
# grant timing is being measured to tune the budget. If the grant lands after the budget,
# the next battery run measures it (grant persists). Returns 0 iff internet opened here.
_accept_aruba_central() {
    local srcip="$1" cap_url="$2" cj bounce login host page csrf capture code waited
    cj="$(mktemp 2>/dev/null || echo /tmp/nm-cj.$$)"
    bounce="$($SUDO curl -s -m 12 -L --interface "$srcip" -A "$_UA_BROWSER" -c "$cj" -b "$cj" "$cap_url" 2>/dev/null || true)"
    login="$(printf '%s' "$bounce" | grep -oiE 'window\.top\.location\.href *= *"[^"]+"' | head -1 | sed -E 's/.*href *= *"([^"]+)".*/\1/')"
    login="${login//&amp;/&}"; login="${login// /%20}"
    [[ -z "$login" ]] && { rm -f "$cj"; return 1; }
    host="$(printf '%s' "$login" | sed -E 's#^(https?://[^/]+).*#\1#')"
    page="$($SUDO curl -s -m 12 -L --interface "$srcip" -A "$_UA_BROWSER" -c "$cj" -b "$cj" "$login" 2>/dev/null || true)"
    csrf="$(printf '%s' "$page" | grep -oE '"csrf_token":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]*)"$/\1/')"
    capture="$(printf '%s' "$page" | grep -oE '"capture":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]*)"$/\1/')"
    [[ -z "$capture" ]] && capture="$(printf '%s' "$login" | sed -E 's/.*[?&]capture=([^&]*).*/\1/')"
    $SUDO curl -s -m 15 -L --interface "$srcip" -A "$_UA_BROWSER" -c "$cj" -b "$cj" \
        -H "Referer: $login" -H "Origin: $host" \
        --data-urlencode "csrf_token=$csrf" --data-urlencode "capture=$capture" --data 'cmd=authenticate' \
        -o /dev/null "$login" 2>/dev/null || true
    rm -f "$cj"
    waited=0
    while (( waited < CAPTIVE_ACCEPT_POLL_SEC )); do   # poll for the async gateway open
        code="$($SUDO curl -s -m 5 --interface "$srcip" -o /dev/null -w '%{http_code}' http://connectivitycheck.gstatic.com/generate_204 2>/dev/null || echo 000)"
        [[ "$code" == "204" ]] && return 0
        sleep 3; waited=$((waited + 3))
    done
    return 1
}

# Cisco WLC internal web-auth (login.html): a consent/AUP page submits buttonClicked=4
# (the "accept/continue" button) with the original redirect_url. Documented pattern.
_accept_cisco_wlc() {
    local srcip="$1" url="$2" host
    host="$(printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*#\1#')"
    $SUDO curl -s -m 10 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" -o /dev/null \
        --data-urlencode 'buttonClicked=4' \
        --data-urlencode 'redirect_url=http://connectivitycheck.gstatic.com/generate_204' \
        --data 'err_flag=0&username=&password=' "${host}/login.html" 2>/dev/null && return 0
    return 1
}

# Meraki click-through splash: the "Continue" control grants access via a form POST that
# carries a success/continue URL. Documented pattern (network-auth.com splash).
_accept_meraki() {
    local srcip="$1" url="$2" page action base
    page="$($SUDO curl -s -m 10 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" "$url" 2>/dev/null || true)"
    action="$(printf '%s' "$page" | grep -oiE '<form[^>]*action="[^"]*"' | head -1 | sed -E 's/.*[Aa]ction="([^"]*)".*/\1/')"
    [[ -z "$action" ]] && return 1
    base="$(printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*#\1#')"
    case "$action" in http://*|https://*) : ;; /*) action="${base}${action}";; *) action="${url%/*}/${action}";; esac
    $SUDO curl -s -m 10 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" -o /dev/null \
        --data-urlencode 'success_url=http://connectivitycheck.gstatic.com/generate_204' \
        --data 'answer=1&accept=Accept' "$action" 2>/dev/null && return 0
    return 1
}

# Generic click-through: fetch the portal, submit the first <form> with the usual accept
# fields (+ cmd=authenticate, which many Aruba/Cisco on-prem AUP forms expect). Handles
# aruba (on-prem/Instant), cisco_ise, and unknown portals.
_accept_generic() {
    local srcip="$1" url="$2" page action method origin proto rest host
    [[ -z "$url" ]] && url="http://connectivitycheck.gstatic.com/generate_204"
    page="$($SUDO curl -s -m 8 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" "$url" 2>/dev/null || true)"
    [[ -z "$page" ]] && return 1
    action="$(printf '%s' "$page" | grep -oiE '<form[^>]*action="[^"]*"' | head -1 | sed -E 's/.*[Aa]ction="([^"]*)".*/\1/')"
    method="$(printf '%s' "$page" | grep -oiE '<form[^>]*method="[^"]*"' | head -1 | sed -E 's/.*[Mm]ethod="([^"]*)".*/\1/' | tr 'A-Z' 'a-z')"
    [[ -z "$action" ]] && return 0   # no form — some portals accept on the GET we followed
    proto="${url%%://*}"; rest="${url#*://}"; host="${rest%%/*}"; origin="${proto}://${host}"
    case "$action" in
        http://*|https://*) : ;;
        /*) action="${origin}${action}" ;;
        *)  action="${url%/*}/${action}" ;;
    esac
    local fields='accept=1&submit=Continue&agree=on&terms=agree&cmd=authenticate&buttonClicked=4'
    if [[ "$method" == "post" ]]; then
        $SUDO curl -s -m 8 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" -o /dev/null --data "$fields" "$action" 2>/dev/null && return 0
    else
        $SUDO curl -s -m 8 -L --proto '=http,https' --proto-redir '=http,https' --interface "$srcip" -A "$_UA_BROWSER" -o /dev/null --get --data "$fields" "$action" 2>/dev/null && return 0
    fi
    return 1
}

# Dispatch the accept to the vendor routine. Returns 0 if the accept HTTP-succeeded (the
# caller re-probes generate_204 for the real proof).
_captive_try_accept() {
    local srcip="$1" url="$2" vendor="${3:-generic}"
    [[ -z "$url" ]] && url="http://connectivitycheck.gstatic.com/generate_204"
    case "$vendor" in
        aruba_central) _accept_aruba_central "$srcip" "$url" ;;
        cisco_wlc)     _accept_cisco_wlc "$srcip" "$url" ;;
        meraki)        _accept_meraki "$srcip" "$url" ;;
        *)             _accept_generic "$srcip" "$url" ;;   # aruba on-prem, cisco_ise, generic
    esac
}

# Probe ONE URL's load waterfall source-bound over the Wi-Fi (curl --interface), and
# emit a single JSON object matching collector/webperf.py's shape so the wired (live
# POST) and Wi-Fi (bundle) runs are the SAME measurement. Cumulative curl seconds -> ms.
_webperf_one() {
    local srcip="$1" url="$2" out u
    out="$($SUDO curl -sS -o /dev/null -L --proto '=http,https' --proto-redir '=http,https' \
           --max-time 15 --interface "$srcip" -w "$WEBPERF_FMT" "$url" 2>/dev/null || true)"
    u="$(printf '%s' "$url" | tr -d '\000-\037\042\134')"
    awk -v url="$u" -v raw="$out" 'BEGIN{
        n=split(raw, p, " ");
        if (n < 8) { printf "{\"url\":\"%s\",\"ok\":false,\"error\":\"no timing\"}", url; exit }
        code=p[6]+0; ok=(code>=200 && code<400)?"true":"false";
        tls=(p[3]+0>0)?sprintf("%.1f", p[3]*1000):"null";
        errf=(ok=="true")?"null":((code>0)?sprintf("\"HTTP %d\"", code):"\"no response\"");
        printf "{\"url\":\"%s\",\"ok\":%s,\"dns_ms\":%.1f,\"tcp_ms\":%.1f,\"tls_ms\":%s,\"ttfb_ms\":%.1f,\"total_ms\":%.1f,\"http_status\":%d,\"size_bytes\":%d,\"speed_mbps\":%.2f,\"error\":%s}", \
            url, ok, p[1]*1000, p[2]*1000, tls, p[4]*1000, p[5]*1000, code, p[7]+0, p[8]*8/1000000, errf;
    }'
}

# Emit the join profiles as TSV rows: ssid \t auth \t identity \t secret \t cap_accept.
# Source: the dashboard-pushed 0600 JSON file; if that file is ABSENT, fall back to the
# single NETMON_WIFI_JOIN_* env keys as one profile. A present-but-empty file ([]) means
# "no profiles" (an authoritative empty list, NOT a fallback trigger).
_wifi_profiles_tsv() {
    local raw=""
    [[ -f "$PROFILES_FILE" ]] && raw="$($SUDO cat "$PROFILES_FILE" 2>/dev/null || true)"
    if [[ -n "$raw" ]]; then
        if command -v python3 >/dev/null 2>&1; then
            # Pass the JSON (with secrets) via ENV, never argv (keeps it out of `ps`).
            NETMON_WJP="$raw" python3 - <<'PY' 2>/dev/null
import json, os, sys
try:
    profs = json.loads(os.environ.get("NETMON_WJP") or "[]")
except Exception:
    sys.exit(0)
if not isinstance(profs, list):
    sys.exit(0)
rows = []
for p in profs:
    if not isinstance(p, dict):
        continue
    ssid = str(p.get("ssid") or "").strip()
    if not ssid:
        continue
    auth = str(p.get("auth") or "open").strip() or "open"
    ident = str(p.get("identity") or "")
    secret = str(p.get("secret") or "")
    cap = "1" if p.get("captive_auto_accept") else "0"
    st = "1" if (p.get("speedtest") or p.get("primary")) else "0"
    fields = [ssid, auth, ident, secret, cap, st]
    # Field sep = US (0x1f), NOT tab: tab is an IFS-whitespace char, so bash `read`
    # COLLAPSES consecutive tabs and an empty field (e.g. a blank identity) vanishes,
    # shifting every later field left (the PSK would land in `identity`). US never
    # collapses and can't occur in an SSID/secret. Records get a trailing newline so
    # `read` doesn't drop the last one.
    rows.append([
        f.replace("\t", " ").replace("\n", " ").replace("\r", " ").replace("\x1f", " ")
        for f in fields])
# Default: if the dashboard didn't designate a speed-test primary, the FIRST network is
# it — so a school gets the internet speed test without anyone picking one. The dashboard
# overrides by flagging a specific profile (which then wins here).
if rows and not any(r[5] == "1" for r in rows):
    rows[0][5] = "1"
sys.stdout.write("".join("\x1f".join(r) + "\n" for r in rows))
PY
            return 0
        fi
        echo "python3 missing — cannot parse ${PROFILES_FILE}; single-config fallback" >&2
    fi
    # Single-config fallback (file absent, or python3 unavailable). US-separated to
    # match the parser (\037 = 0x1f), trailing newline so `read` keeps the row.
    local ssid; ssid="$(current_value NETMON_WIFI_JOIN_SSID 2>/dev/null || true)"
    [[ -z "$ssid" ]] && return 0
    local auth ident secret
    auth="$(current_value NETMON_WIFI_JOIN_AUTH 2>/dev/null || echo open)"
    ident="$(current_value NETMON_WIFI_JOIN_IDENTITY 2>/dev/null || true)"
    secret="$(current_value NETMON_WIFI_JOIN_SECRET 2>/dev/null || true)"
    # Single-config box = one network, so it IS the speed-test primary (6th field = 1).
    printf '%s\037%s\037%s\037%s\0370\0371\n' "$ssid" "${auth:-open}" "$ident" "$secret"
}

# Join + measure + leave ONE profile; echo a single result JSON object. Runs the
# battery through the dedicated route table so probes traverse the joined network.
# Called in a command-substitution subshell (its stdout is the JSON); the NM
# connection it creates/removes is system state, so the EXIT trap's wifi_leave_all
# still cleans up if we're killed mid-profile.
#   args: iface ssid auth [identity] [secret] [cap_accept]
_run_profile() {
    local iface="$1" ssid="$2" auth="$3" identity="${4:-}" secret="${5:-}" cap_accept="${6:-0}" speedtest="${7:-0}"

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
        # grep-gate to `routers` at a word boundary so a dhclient box's
        # `requested_routers = 1` option can't be captured as gw="1".
        gw="$($SUDO nmcli -g DHCP4.OPTION dev show "$iface" 2>/dev/null | tr ',' '\n' | grep -E '(^|[[:space:]])routers = ' | sed -n 's/.*routers = \([0-9.]*\).*/\1/p' | head -1)"
        [[ -z "$gw" ]] && gw="$($SUDO nmcli -g IP4.GATEWAY dev show "$iface" 2>/dev/null | head -1)"
    fi

    # 3. Signal quality (nmcli SIGNAL is 0-100 link quality, NOT dBm — same unit the
    #    WIFI-2 survey reports; tagged signal_unit="quality" in the artifact).
    local rssi=""
    rssi="$($SUDO nmcli -t -f IN-USE,SIGNAL,SSID dev wifi list ifname "$iface" 2>/dev/null \
            | awk -F: '/^\*/{print $2; exit}')"

    # 3b. Which AP (BSSID), band, and link rate the client got — e.g. "shoved onto
    #     2.4GHz at a low rate" is a real finding, and the BSSID ties the experience to
    #     a specific AP. Read from the SAME in-use (*) nmcli row the signal came from
    #     (iw is not installed on every box; nmcli is a hard dependency we already use).
    #     RATE here is the AP's advertised link rate, not the negotiated PHY rate.
    local bssid="" band="" rx_rate="" apline freq
    apline="$($SUDO nmcli -t -f IN-USE,BSSID,FREQ,RATE dev wifi list ifname "$iface" 2>/dev/null \
              | awk '/^\*/{print; exit}')"
    if [[ -n "$apline" ]]; then
        # terse mode escapes value-internal colons as '\:'; unescape, then pattern-pull
        # each piece (MAC / "NNNN MHz" / "NNN Mbit/s") rather than split on ':'.
        apline="${apline//\\:/:}"
        bssid="$(printf '%s' "$apline" | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)"
        freq="$(printf '%s' "$apline" | grep -oE '[0-9]{3,5} MHz' | grep -oE '^[0-9]+' | head -1)"
        rx_rate="$(printf '%s' "$apline" | grep -oE '[0-9]+ Mbit/s' | grep -oE '^[0-9]+' | head -1)"
        if [[ "$freq" =~ ^[0-9]+$ ]]; then
            if (( freq < 2500 )); then band="2.4GHz"
            elif (( freq < 5900 )); then band="5GHz"
            else band="6GHz"; fi
        fi
    fi

    # 4. Battery (only if we got an IP). Probes traverse the joined net via the
    #    dedicated route table.
    local cap_state="n/a" cap_code="" cap_redir="" cap_redir_b64="" cap_accepted="null" cap_vendor=""
    local ping_ok=false http_ok=false rtt="" loss="" dns_ok=false iso_tested="" iso_reachable=""
    local dl_mbps="" tgt_json="" wp_json="" st_json=""
    if [[ -n "$ip4" && -n "$gw" ]]; then
        local srcip="${ip4%/*}"
        _routing_setup "$iface" "$srcip" "$gw" || true
        # captive portal (probes bind by SOURCE IP so the `from <ip>` rule routes them
        # via the Wi-Fi gateway; SO_BINDTODEVICE would set oif but not the source IP).
        local cap; cap="$(_captive_probe "$srcip")"
        cap_state="$(printf '%s' "$cap" | cut -f1)"
        cap_code="$(printf '%s' "$cap" | cut -f2)"
        cap_redir="$(printf '%s' "$cap" | cut -f3)"
        # identify the portal platform (Aruba/Cisco/Meraki/…) whenever one intercepts —
        # useful telemetry even when we don't attempt (or can't) accept.
        [[ "$cap_state" == "portal" ]] && cap_vendor="$(_captive_vendor "$srcip" "$cap_redir")"
        # optional best-effort click-through accept (vendor-tailored), then re-probe.
        if [[ "$cap_accept" == "1" && "$cap_state" == "portal" ]]; then
            if _captive_try_accept "$srcip" "$cap_redir" "$cap_vendor"; then cap_accepted=true; else cap_accepted=false; fi
            cap="$(_captive_probe "$srcip")"
            cap_state="$(printf '%s' "$cap" | cut -f1)"
            cap_code="$(printf '%s' "$cap" | cut -f2)"
            cap_redir="$(printf '%s' "$cap" | cut -f3)"
        fi
        cap_redir_b64="$(printf '%s' "$cap_redir" | b64)"
        # internet reachability via the Wi-Fi. TWO signals: ICMP (ping_ok) AND HTTP
        # (http_ok). Guest networks commonly BLOCK ICMP but pass HTTP/DNS, so ping alone
        # gives a false "unreachable" — http_ok (a 204 from the connectivity endpoint, the
        # same one the captive probe used) is the reliable "internet actually works" signal.
        local png; png="$($SUDO ping -I "$srcip" -c 3 -W 2 1.1.1.1 2>/dev/null || true)"
        printf '%s' "$png" | grep -q ' 0% packet loss' && ping_ok=true
        rtt="$(printf '%s' "$png" | awk -F'/' '/rtt|round-trip/{print $5; exit}')"
        loss="$(printf '%s' "$png" | grep -oE '[0-9]+% packet loss' | grep -oE '[0-9]+' | head -1)"
        [[ "$cap_state" == "open" ]] && http_ok=true
        # DNS resolves through the Wi-Fi
        $SUDO curl -s -m 6 --interface "$srcip" -o /dev/null https://dns.google/resolve?name=example.com 2>/dev/null && dns_ok=true
        # throughput: a short source-bound download over the Wi-Fi (Cloudflare speed
        # endpoint, capped at 12s); the analysis radio only, never the uplink.
        local dl
        dl="$($SUDO curl -s -m 12 --proto '=https' --interface "$srcip" -o /dev/null -w '%{speed_download}' 'https://speed.cloudflare.com/__down?bytes=25000000' 2>/dev/null || true)"
        [[ "$dl" =~ ^[0-9.]+$ ]] && dl_mbps="$(awk "BEGIN{printf \"%.2f\", ($dl*8)/1000000}")"
        # instructional-target latency over the Wi-Fi ("internet's fine but Google /
        # M365 is slow" is a distinct, real signal). RTT is source-routed over the radio.
        local _t _tp _trtt
        for _t in www.google.com www.office.com; do
            _tp="$($SUDO ping -I "$srcip" -c 2 -W 2 "$_t" 2>/dev/null || true)"
            _trtt="$(printf '%s' "$_tp" | awk -F'/' '/rtt|round-trip/{print $5; exit}')"
            [[ -n "$tgt_json" ]] && tgt_json="${tgt_json},"
            tgt_json="${tgt_json}{\"host\":\"${_t}\",\"rtt_ms\":${_trtt:-null}}"
        done
        # webperf: run the district URL waterfall source-bound over the Wi-Fi, so each
        # site's DNS/TCP/TLS/TTFB/total is comparable to the WIRED run (same probe, both
        # paths). Only when the district enabled web monitoring + pushed a URL list.
        local webperf_on="0" _wpurl
        case "$(current_value NETMON_WEBPERF_ENABLED 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
            true|1|yes) webperf_on=1 ;;
        esac
        if [[ "$webperf_on" == "1" && -s "$WEBPERF_URLS_FILE" ]]; then
            while IFS= read -r _wpurl; do
                [[ -z "$_wpurl" ]] && continue
                [[ -n "$wp_json" ]] && wp_json="${wp_json},"
                wp_json="${wp_json}$(_webperf_one "$srcip" "$_wpurl")"
            done < <($SUDO grep -oE 'https?://[^"]+' "$WEBPERF_URLS_FILE" 2>/dev/null)
        fi
        # Internet SPEED TEST — only for the PRIMARY network (saturating up/down is
        # airtime-expensive on a live AP, so we designate ONE SSID per school for it).
        # Download reuses the throughput pull above; add a source-bound upload + a longer
        # ping burst for latency/jitter(mdev)/loss. Teams/Zoom/online-testing pain is
        # upload- and jitter-bound, so a download-only number would hide the real problem.
        if [[ "$speedtest" == "1" ]]; then
            local up ul_mbps="" zf stp st_lat="" st_jit="" st_loss=""
            zf="$(mktemp 2>/dev/null || echo /tmp/netmon-ul.$$)"
            head -c 10000000 /dev/zero > "$zf" 2>/dev/null
            up="$($SUDO curl -s -m 15 --proto '=https' --interface "$srcip" -o /dev/null \
                  -w '%{speed_upload}' --data-binary "@$zf" 'https://speed.cloudflare.com/__up' 2>/dev/null || true)"
            rm -f "$zf"
            [[ "$up" =~ ^[0-9.]+$ ]] && ul_mbps="$(awk "BEGIN{printf \"%.2f\", ($up*8)/1000000}")"
            stp="$($SUDO ping -I "$srcip" -c 10 -W 2 1.1.1.1 2>/dev/null || true)"
            st_lat="$(printf '%s' "$stp" | awk -F'/' '/rtt|round-trip/{print $5; exit}')"
            st_jit="$(printf '%s' "$stp" | awk -F'/' '/rtt|round-trip/{split($7,a," "); print a[1]; exit}')"
            st_loss="$(printf '%s' "$stp" | grep -oE '[0-9]+% packet loss' | grep -oE '[0-9]+' | head -1)"
            st_json="{\"download_mbps\":${dl_mbps:-null},\"upload_mbps\":${ul_mbps:-null},\"latency_ms\":${st_lat:-null},\"jitter_ms\":${st_jit:-null},\"loss_pct\":${st_loss:-null}}"
        fi
        # ISOLATION: from the guest/Wi-Fi, can we reach an INTERNAL host (the wired
        # uplink's gateway)? A properly isolated guest network should NOT.
        iso_tested="$(ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}')"
        if [[ -n "$iso_tested" ]]; then
            if $SUDO ping -I "$srcip" -c 1 -W 2 "$iso_tested" >/dev/null 2>&1; then iso_reachable=true; else iso_reachable=false; fi
        fi
        _routing_teardown "$iface"
    fi

    # 5. Leave THIS network so the next profile can take the radio.
    wifi_leave "$ssid" >/dev/null 2>&1 || true

    # 6. Echo the single result object (SSID stripped of control chars + " and \).
    printf '{"ssid":"%s","auth":"%s","associated":%s,"assoc_ms":%s,"dhcp_ms":%s,' \
        "$(printf '%s' "$ssid" | tr -d '\000-\037\042\134')" "${auth:-open}" "$associated" "$assoc_ms" "$dhcp_ms"
    printf '"ip":"%s","gateway":"%s","signal":%s,"signal_unit":"quality",' "${ip4:-}" "${gw:-}" "${rssi:-null}"
    printf '"captive_portal":{"state":"%s","http_code":"%s","redirect_b64":"%s","auto_accepted":%s,"vendor":"%s"},' \
        "$cap_state" "${cap_code:-}" "$cap_redir_b64" "$cap_accepted" "${cap_vendor:-}"
    printf '"internet":{"ping_ok":%s,"http_ok":%s,"rtt_ms":"%s","loss_pct":"%s"},' "$ping_ok" "$http_ok" "${rtt:-}" "${loss:-}"
    printf '"link":{"bssid":"%s","band":"%s","rx_rate_mbps":%s},' "${bssid:-}" "${band:-}" "${rx_rate:-null}"
    printf '"throughput":{"download_mbps":%s},' "${dl_mbps:-null}"
    printf '"speedtest":%s,' "${st_json:-null}"
    printf '"targets":[%s],' "${tgt_json:-}"
    printf '"webperf":[%s],' "${wp_json:-}"
    printf '"dns_ok":%s,' "$dns_ok"
    printf '"isolation":{"internal_target":"%s","internal_reachable":%s}}' \
        "${iso_tested:-}" "${iso_reachable:-null}"
}

# ---- main ----------------------------------------------------------------

main() {
    command -v ip >/dev/null 2>&1 || { echo "ip(8) missing"; exit 1; }

    local enabled
    enabled="$(current_value NETMON_WIFI_JOIN_ENABLED 2>/dev/null || true)"
    case "${enabled,,}" in true|1|yes) ;; *) echo "NETMON_WIFI_JOIN_ENABLED not true — skipping"; exit 0 ;; esac

    # One analysis radio per box (never the uplink). Profiles are the networks to test
    # on it; the iface is box-level, not per-profile.
    local iface
    iface="$(current_value NETMON_WIFI_JOIN_IFACE 2>/dev/null || true)"
    [[ -z "$iface" ]] && iface="$(wifi_analysis_iface)"
    [[ -z "$iface" ]] && { echo "no spare Wi-Fi NIC — refusing"; exit 1; }

    # The EXIT trap tears down routing + leaves EVERY netmon-owned Wi-Fi connection,
    # so a mid-run death (even inside a profile subshell) can't strand the radio.
    _TRAP_IFACE="$iface"
    trap '_routing_teardown "$_TRAP_IFACE"; wifi_leave_all >/dev/null 2>&1 || true' EXIT

    # Run each profile serialized (one radio = one association at a time), appending a
    # result object. Empty results[] if there are no profiles / none associated.
    local results="" n=0 obj
    while IFS=$'\037' read -r p_ssid p_auth p_ident p_secret p_cap p_st; do
        [[ -z "${p_ssid:-}" ]] && continue
        obj="$(_run_profile "$iface" "$p_ssid" "${p_auth:-open}" "${p_ident:-}" "${p_secret:-}" "${p_cap:-0}" "${p_st:-0}")"
        [[ -z "$obj" ]] && continue
        [[ -n "$results" ]] && results="${results},"
        results="${results}${obj}"
        n=$((n+1))
    done < <(_wifi_profiles_tsv)

    # Emit the artifact (single JSON, results[] with one object per profile).
    local tmp; tmp="$(mktemp)"
    printf '{"schema":1,"generated_at":"%s","interface":"%s","results":[%s]}\n' \
        "$(_ts)" "$iface" "$results" > "$tmp"
    $SUDO install -m 0644 "$tmp" "$OUT"
    rm -f "$tmp"
    echo "wrote $OUT (interface=$iface profiles=$n)"
}

main "$@"
