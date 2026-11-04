#!/usr/bin/env bash
# WIFI-1 networkd backend, exercised for real: simulated radios (mac80211_hwsim) on a
# GitHub Ubuntu runner, whose own networking is systemd-networkd — i.e. the runner IS
# a networkd box. Three access points (open, WPA2-PSK, WPA2-Enterprise PEAP via
# hostapd's built-in EAP server) live in their own network namespace, so traffic to
# them crosses the simulated air instead of short-circuiting locally. The station
# radio stays in the root namespace and is joined by lib/wifi.sh and the real battery.
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
sleep 3

# --- the libraries, as host-action.sh sources them -------------------------------
for lib in common.sh paths.sh envfile.sh wifi.sh; do
    # shellcheck source=/dev/null
    . "$REPO_DIR/lib/$lib"
done
check "backend is networkd" test "$(_wifi_backend)" = networkd
DEFAULT_BEFORE="$(ip route show default)"
DNS_BEFORE="$(resolvectl dns 2>/dev/null | grep -v "$STA" || true)"
uplink_untouched() {
    [[ "$(ip route show default)" == "$DEFAULT_BEFORE" ]] \
        && [[ "$(resolvectl dns 2>/dev/null | grep -v "$STA" || true)" == "$DNS_BEFORE" ]] \
        && [[ -z "$(ip route show default dev "$STA")" ]]
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
check "reassociate" wifi_networkd_reassociate "$STA"
sleep 3
check "lease back after reassociate" bash -c "ip -4 -o addr show dev $STA | grep -q 'inet 192.168.71.'"
wifi_leave "NetmonTest Open" || true
check "leave cleans up everything" nothing_left

check "wrong PSK does not associate" bash -c "! (for l in common.sh paths.sh envfile.sh wifi.sh; do . '$REPO_DIR/lib/'\$l; done; wifi_join '$STA' 'NetmonTest \"PSK\"' psk '' 'wrong passphrase')"
check "a failed join leaves nothing behind" nothing_left
check "unusable passphrase refused before touching the radio" bash -c "! (for l in common.sh paths.sh envfile.sh wifi.sh; do . '$REPO_DIR/lib/'\$l; done; wifi_join '$STA' 'NetmonTest \"PSK\"' psk '' \$'two\\nlines!!')"
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
NETMON_STATE_DIR="$STATE" timeout 900 bash "$REPO_DIR/scripts/netmon-wifi-experience.sh" || fail "battery exited $?"
echo "--- wifi_experience.json"
cat "$STATE/wifi_experience.json"
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
check "uplink untouched after the battery" uplink_untouched

echo "failures: $FAILS"
exit $(( FAILS > 0 ))
