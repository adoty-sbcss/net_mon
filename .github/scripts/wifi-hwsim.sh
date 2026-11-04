#!/usr/bin/env bash
# WIFI-1 networkd backend, exercised for real: simulated radios (mac80211_hwsim) on a
# GitHub Ubuntu runner, whose own networking is systemd-networkd — i.e. the runner IS
# a networkd box. Three access points (open, WPA2-PSK, WPA2-Enterprise PEAP via
# hostapd's built-in EAP server) live in their own network namespace, so traffic to
# them crosses the simulated air instead of short-circuiting locally. The station
# radio stays in the root namespace and is joined by lib/wifi.sh and the real battery.
# A fourth namespace is a WIRED host inside the open AP's subnet: the battery must not
# pull it onto the Wi-Fi while it runs.
#
# Run as root on a disposable runner only: it loads a kernel module and writes
# /etc/netmon/netmon.env.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
NS=apns
FAILS=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local what="$1"; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
# eventually <tries> <cmd...>: retry every 0.5 s (networkd applies routes after the lease).
eventually() { local n="$1"; shift; while (( n-- > 0 )); do "$@" && return 0; sleep 0.5; done; "$@"; }

systemctl is-active --quiet systemd-networkd || { echo "runner is not a networkd box"; exit 2; }
if systemctl is-active --quiet NetworkManager; then echo "NetworkManager is running; this test wants networkd"; exit 2; fi

modprobe mac80211_hwsim radios=4
sleep 2
mapfile -t RADIOS < <(for d in /sys/class/net/*/phy80211; do basename "$(dirname "$d")"; done | sort)
(( ${#RADIOS[@]} == 4 )) || { echo "expected 4 hwsim radios, got: ${RADIOS[*]}"; exit 2; }
STA="${RADIOS[3]}"
echo "station radio: $STA; APs: ${RADIOS[*]:0:3}"

# --- access points, in their own namespace -------------------------------------
ip netns add "$NS"
WORK="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=radius.test" \
    -keyout "$WORK/server.key" -out "$WORK/server.crt" >/dev/null 2>&1
# hostapd's user file has no quote escaping, so this password tests a space, not a
# quote (the PSK below carries the quotes).
printf '"netmon-svc"\tPEAP\n"netmon-svc"\tMSCHAPV2\t"pass word q!"\t[2]\n' > "$WORK/eap_users"

ap() {   # ap <index> <ssid> <subnet-octet> <security block>
    local i="$1" ssid="$2" net="$3" sec="$4" ifc phy
    ifc="${RADIOS[$i]}"
    phy="$(cat "/sys/class/net/${ifc}/phy80211/name")"
    iw phy "$phy" set netns name "$NS"
    ip netns exec "$NS" ip link set "$ifc" up
    ip netns exec "$NS" ip addr add "192.168.${net}.1/24" dev "$ifc"
    printf 'interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=%s\n%s\n' \
        "$ifc" "$ssid" "$(( (i * 5) + 1 ))" "$sec" > "$WORK/hostapd-$i.conf"
    ip netns exec "$NS" hostapd -B -P "$WORK/hostapd-$i.pid" "$WORK/hostapd-$i.conf" >/dev/null
    ip netns exec "$NS" dnsmasq --interface="$ifc" --bind-interfaces --except-interface=lo \
        --port=0 --no-resolv --no-hosts --user=root --pid-file="$WORK/dnsmasq-$i.pid" \
        --dhcp-leasefile="$WORK/leases-$i" --dhcp-range="192.168.${net}.50,192.168.${net}.99,1h" \
        --dhcp-option=3,"192.168.${net}.1" --dhcp-option=6,"192.168.${net}.53,192.168.${net}.54"
}
ap 0 "NetmonTest Open" 71 ""
ap 1 'NetmonTest "PSK"' 72 $'wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase=correct horse "battery"'
ap 2 "NetmonTest PEAP" 73 "$(printf 'wpa=2\nwpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\nieee8021x=1\neap_server=1\neap_user_file=%s\nca_cert=%s\nserver_cert=%s\nprivate_key=%s' \
    "$WORK/eap_users" "$WORK/server.crt" "$WORK/server.crt" "$WORK/server.key")"
# An address OFF every AP subnet, answered inside the AP namespace: reaching it from a
# Wi-Fi source address proves a probe really went out the radio via the battery's
# default route in table 51 (nothing else routes it).
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add 10.71.0.1/32 dev lo
sleep 3

# --- a wired host inside the open AP's subnet ------------------------------------
# A resolver or server that happens to sit in the Wi-Fi's range but that the box
# reaches over its wired side, through a broader route. A Wi-Fi connected route in the
# main table is more specific, so it would divert this host onto the radio.
WIRED_NS=wiredns
WIRED_DST=192.168.71.200
ip netns add "$WIRED_NS"
ip link add vwired type veth peer name vwired-ns
ip link set vwired-ns netns "$WIRED_NS"
ip addr add 10.99.0.1/30 dev vwired
ip link set vwired up
ip netns exec "$WIRED_NS" ip link set lo up
ip netns exec "$WIRED_NS" ip addr add 10.99.0.2/30 dev vwired-ns
ip netns exec "$WIRED_NS" ip addr add "$WIRED_DST/32" dev lo
ip netns exec "$WIRED_NS" ip link set vwired-ns up
ip netns exec "$WIRED_NS" ip route add default via 10.99.0.1
ip route add 192.168.64.0/18 via 10.99.0.2 dev vwired
wired_dev() { ip -4 route get "$WIRED_DST" | grep -oE ' dev [^ ]+' | head -1 | cut -d' ' -f3; }
wired_reachable() { ping -c 1 -W 2 "$WIRED_DST" >/dev/null; }
main_clear() { [[ -z "$(ip -4 route show table main dev "$STA")" ]]; }
wired_untouched() {
    if [[ "$(wired_dev)" == vwired ]] && wired_reachable && main_clear; then return 0; fi
    ip -4 route get "$WIRED_DST" || true
    ip -4 route show table main dev "$STA" || true
    return 1
}
check "wired host reachable before any join" wired_untouched

# --- the libraries, as host-action.sh sources them -------------------------------
for lib in common.sh paths.sh envfile.sh wifi.sh; do
    # shellcheck source=/dev/null
    . "$REPO_DIR/lib/$lib"
done
check "backend is networkd" test "$(_wifi_backend)" = networkd
# The uplink, compared on its own: its default route and its resolvers. A resolvectl
# that errors is a failed check, not an empty answer that happens to differ.
UPLINK="$(ip route show default | awk '{print $5; exit}')"
uplink_state() {
    ip route show default dev "$UPLINK"
    resolvectl dns "$UPLINK" || echo "RESOLVECTL-ERROR"
}
UPLINK_BEFORE="$(uplink_state)"
echo "uplink: $UPLINK"; echo "$UPLINK_BEFORE"
# Otherwise two identical error markers would compare equal and observe nothing.
[[ "$UPLINK_BEFORE" == *RESOLVECTL-ERROR* ]] && { echo "cannot read the uplink's resolvers"; exit 2; }
uplink_untouched() {
    local now
    now="$(uplink_state)"
    if [[ "$now" == "$UPLINK_BEFORE" && -z "$(ip route show default dev "$STA")" ]]; then
        return 0
    fi
    diff <(printf '%s\n' "$UPLINK_BEFORE") <(printf '%s\n' "$now") || true
    ip route show default dev "$STA" || true
    networkctl status "$STA" --no-pager || true
    journalctl -u systemd-networkd --since -5min --no-pager | tail -40 || true
    return 1
}
nothing_left() {
    [[ -z "$(pgrep -a wpa_supplicant | grep -- "-i *$STA" || true)" ]] \
        && ! compgen -G "/run/netmon-wifi/netmon-wifi-*" >/dev/null \
        && ! compgen -G "/run/systemd/network/05-netmon-wifi-*" >/dev/null \
        && [[ -z "$(ip -4 -o addr show dev "$STA" scope global)" ]]
}

# --- lib/wifi.sh directly --------------------------------------------------------
check "join open" wifi_join "$STA" "NetmonTest Open" open
check "lease address on the open AP's subnet" bash -c "ip -4 -o addr show dev $STA | grep -q 'inet 192.168.71.'"
check "lease gateway read from networkd's lease" test "$(wifi_networkd_lease "$STA" ROUTER)" = 192.168.71.1
check "first lease resolver" test "$(wifi_networkd_lease "$STA" DNS)" = 192.168.71.53
LINK="$(wifi_networkd_link "$STA")"
echo "link: $LINK"
check "link: dBm signal" bash -c "[[ '$(cut -f1 <<<"$LINK")' =~ ^-[0-9]+$ ]]"
check "link: AP BSSID" test "$(cut -f2 <<<"$LINK")" = "$(ip netns exec "$NS" cat "/sys/class/net/${RADIOS[0]}/address")"
check "link: frequency" test "$(cut -f3 <<<"$LINK")" = 2412
check "uplink untouched while joined" uplink_untouched
# Positive control: a join with no route table (the persistent wifi-join host action)
# keeps the connected route in main, and that route does capture the wired host. If
# this ever stops being true, the checks below that it does NOT move prove nothing.
check "without a route table the Wi-Fi /24 captures the wired host" test "$(wired_dev)" = "$STA"
check "reassociate" wifi_networkd_reassociate "$STA"
sleep 3
check "lease back after reassociate" bash -c "ip -4 -o addr show dev $STA | grep -q 'inet 192.168.71.'"
wifi_leave "NetmonTest Open" || true
check "leave cleans up everything" nothing_left

# The battery's join: the connected route goes to table 51 (networkd puts it there
# itself, as RouteTable= says) and the main table gets nothing from the radio.
check "join open with route table 51" wifi_join "$STA" "NetmonTest Open" open "" "" 51
check "lease address on the open AP's subnet (table join)" bash -c "ip -4 -o addr show dev $STA | grep -q 'inet 192.168.71.'"
ip -4 route show table all dev "$STA" | grep -v '^local \|^broadcast ' || true
check "networkd put the joined subnet in table 51" eventually 20 bash -c "ip -4 route show table 51 dev $STA | grep -q '^192.168.71.0/24 '"
check "main table has nothing via the radio" main_clear
check "wired host stays wired while joined" wired_untouched
check "reassociate (table join)" wifi_networkd_reassociate "$STA"
check "lease back in table 51 after reassociate" eventually 30 bash -c "ip -4 route show table 51 dev $STA | grep -q '^192.168.71.0/24 '"
check "main table still clear after reassociate" main_clear
wifi_leave "NetmonTest Open" || true
check "table join leave cleans up everything" nothing_left
check "table 51 empty after leave" test -z "$(ip -4 route show table 51)"

check "join open again" wifi_join "$STA" "NetmonTest Open" open
rm -f /run/netmon-wifi/netmon-wifi-*.pid
wifi_leave "NetmonTest Open" || true
check "leave without a pidfile still stops the supplicant" nothing_left

check "wrong PSK does not associate" bash -c "! (for l in common.sh paths.sh envfile.sh wifi.sh; do . '$REPO_DIR/lib/'\$l; done; wifi_join '$STA' 'NetmonTest \"PSK\"' psk '' 'wrong passphrase')"
check "a failed join leaves nothing behind" nothing_left
check "unusable passphrase refused before touching the radio" bash -c "! (for l in common.sh paths.sh envfile.sh wifi.sh; do . '$REPO_DIR/lib/'\$l; done; wifi_join '$STA' 'NetmonTest \"PSK\"' psk '' \$'two\\nlines!!')"
LIBS="for l in common.sh paths.sh envfile.sh wifi.sh; do . '$REPO_DIR/lib/'\$l; done"
check "the uplink, named explicitly, is refused" bash -c "! ($LIBS; wifi_join '$UPLINK' 'NetmonTest Open' open)"
check "a non-radio is refused" bash -c "! ($LIBS; wifi_join lo 'NetmonTest Open' open)"
# The uplink guard on a RADIO (the two above stop at the radio check): give the station
# a default route in a side table, then as one nexthop of a multipath default.
ip route add default dev "$STA" table 77
check "a radio carrying a default route (side table) is refused" bash -c "! ($LIBS; wifi_join '$STA' 'NetmonTest Open' open)"
ip route del default dev "$STA" table 77
ip route add default table 78 nexthop dev "$UPLINK" nexthop dev "$STA"
check "a radio in a multipath default is refused" bash -c "! ($LIBS; wifi_join '$STA' 'NetmonTest Open' open)"
ip route del default table 78
check "nothing written for a refused interface" bash -c "! compgen -G '/run/systemd/network/05-netmon-wifi-*' >/dev/null"
check "uplink untouched after failures" uplink_untouched

# --- the real battery over all three networks -------------------------------------
STATE="$(mktemp -d)"
mkdir -p /etc/netmon
printf 'NETMON_WIFI_JOIN_ENABLED=true\nNETMON_WIFI_JOIN_IFACE=%s\n' "$STA" > /etc/netmon/netmon.env
python3 - "$STATE/wifi-profiles.json" <<'PY'
import json, sys
json.dump([
    {"ssid": "NetmonTest Open", "auth": "open"},
    {"ssid": 'NetmonTest "PSK"', "auth": "psk", "secret": 'correct horse "battery"'},
    {"ssid": "NetmonTest PEAP", "auth": "peap", "identity": "netmon-svc", "secret": "pass word q!"},
], open(sys.argv[1], "w"))
PY
chmod 600 "$STATE/wifi-profiles.json"
# Sample the wired host's path for as long as the battery runs: one line per sample,
# "<joined-71> <wired-dev> <wired-ping> <wifi-ping> <main-table routes via the radio>".
# wifi-ping: while the battery's policy routing is up on the open AP, a ping from the
# Wi-Fi address to the AP's gateway (on-link, table 51 prefix) and to 10.71.0.1 (off
# every subnet, table 51 default) both answer; "-" when there was nothing to try.
# A failed read is recorded as a failing sample, never allowed to end the watcher (set -e).
watch_wired() {
    local joined dev ping wifi main wip
    while [[ ! -e "$STATE/battery-done" ]]; do
        wip="$(ip -4 -o addr show dev "$STA" | grep -oE 'inet 192\.168\.71\.[0-9]+' | cut -d' ' -f2)" || wip=""
        joined=0; [[ -n "$wip" ]] && joined=1
        dev="$(wired_dev)" || dev=""
        ping=0; wired_reachable && ping=1
        wifi=-
        if [[ -n "$wip" ]] && ip rule show | grep -qE "^5100:[[:space:]]+from ${wip}[[:space:]]"; then
            wifi=0
            ping -c 1 -W 1 -I "$wip" 192.168.71.1 >/dev/null 2>&1 \
                && ping -c 1 -W 1 -I "$wip" 10.71.0.1 >/dev/null 2>&1 && wifi=1
        fi
        main="$(ip -4 route show table main dev "$STA" | tr ' \n' '_;')" || main="read-error"
        printf '%s %s %s %s %s\n' "$joined" "${dev:-none}" "$ping" "$wifi" "${main:-clear}"
        sleep 0.3
    done
}
# What a battery SIGKILLed mid-profile leaves behind: its default via the radio in
# table 51 and its source rule. The networkd join refuses a radio that carries a default
# route in any table, so the battery must clear this before its first join (the three
# networks below must still associate).
ip route add default dev "$STA" table 51
ip rule add from 192.0.2.9 table 51 prio 5100
watch_wired > "$STATE/wired-watch.log" &
WATCH_PID=$!
NETMON_STATE_DIR="$STATE" timeout 900 bash "$REPO_DIR/scripts/netmon-wifi-experience.sh" 2> "$STATE/battery.err" \
    || fail "battery exited $?"
touch "$STATE/battery-done"
wait "$WATCH_PID" || true
echo "--- battery stderr"
cat "$STATE/battery.err"
echo "--- wifi_experience.json"
cat "$STATE/wifi_experience.json"
echo "--- wired host while the battery ran ($(wc -l < "$STATE/wired-watch.log") samples)"
sort "$STATE/wired-watch.log" | uniq -c
# The battery joined the open AP while it was being watched (else the rest is vacuous).
check "watcher saw the battery on the open AP's subnet" \
    test "$(grep -c '^1 ' "$STATE/wired-watch.log")" -ge 3
check "main table never routed via the radio during the battery" \
    bash -c "! grep -qv ' clear\$' '$STATE/wired-watch.log'"
check "wired host stayed on the wired link, reachable, during the battery" \
    bash -c "! grep -qv '^[01] vwired 1 ' '$STATE/wired-watch.log'"
check "probes from the Wi-Fi address crossed the radio during the battery" \
    test "$(grep -c '^1 [^ ]* [01] 1 ' "$STATE/wired-watch.log")" -ge 1
# One _routing_setup per network: no captive portal here, so no rejoin (which sets up twice).
check "battery reported a clear main table for each network" \
    test "$(grep -c '^routing: main table has no route via ' "$STATE/battery.err")" -eq 3
python3 - "$STATE/wifi_experience.json" <<'PY' || FAILS=$((FAILS + 1))
import json, sys
doc = json.load(open(sys.argv[1]))
res = {r["ssid"]: r for r in doc["results"]}
bad = []
for ssid, net in (("NetmonTest Open", 71), ('NetmonTest "PSK"', 72), ("NetmonTest PEAP", 73)):
    key = ssid.replace('"', "")  # the battery strips quotes from the reported SSID
    r = res.get(key)
    if not r:
        bad.append(f"{key}: no result"); continue
    want = {
        "associated": True,
        "gateway": f"192.168.{net}.1",
        "signal_unit": "dbm",
        "dns_server": f"192.168.{net}.53",
        "routing_ok": True,
    }
    for k, v in want.items():
        if r.get(k) != v:
            bad.append(f"{key}: {k}={r.get(k)!r}, want {v!r}")
    if not str(r.get("ip", "")).startswith(f"192.168.{net}."):
        bad.append(f"{key}: ip={r.get('ip')!r}")
    if not isinstance(r.get("signal"), int) or r["signal"] >= 0:
        bad.append(f"{key}: signal={r.get('signal')!r}")
    if r.get("dhcp_ms", -1) < 0:
        bad.append(f"{key}: dhcp_ms={r.get('dhcp_ms')!r}")
    if (r.get("link") or {}).get("band") != "2.4GHz":
        bad.append(f"{key}: link={r.get('link')!r}")
for b in bad:
    print("FAIL battery", b)
print("PASS battery: 3 networks" if not bad else "")
sys.exit(1 if bad else 0)
PY
check "battery left nothing behind" nothing_left
check "battery left no policy routing behind" \
    bash -c "[[ -z \"\$(ip -4 route show table 51)\" ]] && ! ip rule show | grep -qE '^510[01]:'"
check "uplink untouched after the battery" uplink_untouched
check "wired host reachable after the battery" wired_untouched

echo "failures: $FAILS"
exit $(( FAILS > 0 ))
