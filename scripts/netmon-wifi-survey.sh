#!/usr/bin/env bash
# scripts/netmon-wifi-survey.sh — host-side, backend-aware Wi-Fi RF/AP survey (WIFI-2).
#
# Why host-side: the collector container ships neither `iw` nor `nmcli`, and on a
# NetworkManager-managed box NM OWNS the radio — having the container issue its
# own scans would contend with NM. (The network backend, networkd vs NM, is the
# exact thing that breaks wireless/VLAN features — see lib/trunk.sh _vlan_backend.)
# So we survey on the HOST with whatever owns the radio and drop a small JSON
# envelope in the shared state dir; the in-container `discovery/wifi.py` reads +
# normalizes it.
#
# Passive scan: enumerates nearby SSIDs / BSSIDs / channels / signal / encryption.
# Never associates, captures no payloads, writes no secrets. So the feature can be
# turned on from the dashboard with no host access, it will (best-effort, guarded)
# install `iw` and bring the analysis radio up so a scan can run — but it never
# joins a network or writes persistent network config. Safe to run on a timer.
#
# Output: ${NETMON_STATE_DIR:-/var/lib/netmon}/wifi_survey.json (atomic write).
# The raw tool output is base64'd into the envelope so this script stays dumb (no
# JSON-escaping of colons/quotes/newlines in bash); ALL parsing + normalization
# lives in the testable Python module.

set -euo pipefail

# Opt-in gate: the timer is installed fleet-wide, but the survey stays inert
# until NETMON_WIFI_SURVEY_ENABLED is set true in the env file — the SAME flag
# the collector reads to decide whether to ship the result. So "default OFF"
# means the host genuinely does nothing (no scan, no file) until a sensor is
# explicitly opted in (locally or via a dashboard desired-config push).
ENV_FILE="${NETMON_ENV_FILE:-/etc/netmon/netmon.env}"
# `|| true` so a NO-MATCH grep (the default state of every box that hasn't opted
# in) doesn't trip `set -e`/`pipefail` and fail the oneshot service.
_enabled="$( { grep -E '^[[:space:]]*NETMON_WIFI_SURVEY_ENABLED[[:space:]]*=' "$ENV_FILE" 2>/dev/null \
    | tail -1 | cut -d= -f2- \
    | tr -d '[:space:]' | tr -d '\042\047' | tr '[:upper:]' '[:lower:]'; } || true)"   # \042=" \047='
if [[ "$_enabled" != "true" && "$_enabled" != "1" && "$_enabled" != "yes" ]]; then
    echo "wifi survey disabled (NETMON_WIFI_SURVEY_ENABLED not true in ${ENV_FILE}) — skipping"
    exit 0
fi

STATE_DIR="${NETMON_STATE_DIR:-/var/lib/netmon}"
OUT="${STATE_DIR}/wifi_survey.json"
TMP="$(mktemp)"
ERRF="$(mktemp)"
trap 'rm -f "$TMP" "$ERRF"' EXIT

# Use `sudo -n` (never prompt): this runs from a systemd timer with no TTY, so a
# password prompt would hang the oneshot forever instead of failing fast.
SUDO=""
[[ "$(id -u)" -ne 0 ]] && SUDO="sudo -n"

host="$(hostname 2>/dev/null || echo unknown)"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Regulatory domain — a tool-free sysfs read. "00" = world/unset (restrictive:
# caps TX power, makes some 5 GHz/DFS channels passive-only). A real finding.
regdom="$(tr -d '[:space:]' < /sys/module/cfg80211/parameters/ieee80211_regdom 2>/dev/null || true)"
[[ -z "$regdom" ]] && regdom="unknown"

# Network backend — same heuristic as lib/trunk.sh _vlan_backend.
backend="networkd"
if command -v systemctl >/dev/null 2>&1 \
   && systemctl is-active --quiet NetworkManager 2>/dev/null \
   && ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    backend="nm"
fi

# Wi-Fi interfaces: a netdev is wireless iff /sys/class/net/<dev>/phy80211 exists.
# Skip p2p / virtual control interfaces.
wifi_ifaces=()
for d in /sys/class/net/*/phy80211; do
    [[ -e "$d" ]] || continue
    iface="$(basename "$(dirname "$d")")"
    [[ "$iface" == p2p-* ]] && continue
    wifi_ifaces+=("$iface")
done

# --- Provision the radio for scanning (self-heal, best-effort) --------------
# A box that never used its analysis radio ships two blockers the survey can fix
# itself, so enabling Wi-Fi monitoring from the dashboard "just works" with no
# SSH — a console-only operator has no host shell (the Trona 2026-07-03 case: box
# recovered, monitoring enabled, but the survey could never run):
#   1. `iw` may be absent on a networkd box (fresh images don't ship it; NM boxes
#      use nmcli, already present). Install it once, non-interactively.
#   2. The radio is often administratively DOWN — `iw scan` then fails with
#      "Network is down". We bring each wifi iface up in the scan loop below.
# Still passive: we never associate, change persistent config, or write secrets.
# Guarded so the apt path runs at most once (until iw lands), and everything is
# best-effort — a box without passwordless sudo just reports the tool error.
if [[ ${#wifi_ifaces[@]} -gt 0 ]]; then
    if command -v rfkill >/dev/null 2>&1; then
        $SUDO rfkill unblock wifi 2>/dev/null || true
    fi
    if [[ "$backend" != "nm" ]] && ! command -v iw >/dev/null 2>&1; then
        echo "iw not found on a networkd box; attempting one-time install"
        $SUDO apt-get update -qq 2>/dev/null || true
        if $SUDO apt-get install -y -qq iw 2>/dev/null; then
            echo "installed iw"
        else
            echo "WARN: could not install iw (needs passwordless sudo + network); survey will report a tool error until it is present"
        fi
    fi
fi

NMCLI_FIELDS="IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY,WPA-FLAGS,RSN-FLAGS,MODE"

# GNU base64 wraps at 76 cols by default; -w0 keeps it one line. Fallback strips.
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
# JSON-safe a short error string. The error field is injected RAW into the
# envelope (it bypasses the base64 path the rest of the output uses), so it must
# carry no character that breaks strict JSON: drop ALL control bytes U+0000-U+001F
# (incl. TAB, which a tool's stderr can emit), plus the double-quote and backslash.
# (\000-\037 = the control range, \042 = ", \134 = \).
jsan() { tr -d '\000-\037\042\134' | head -c 200; }

ifaces_json=""
sep=""
if [[ ${#wifi_ifaces[@]} -gt 0 ]]; then
    for iface in "${wifi_ifaces[@]}"; do
        tool=""; raw=""; err="null"; fields="null"
        # Bring the radio up so scans don't fail with "Network is down" (idempotent;
        # we never associate, so this can't turn the analysis radio into an uplink).
        $SUDO ip link set "$iface" up 2>/dev/null || true
        if [[ "$backend" == "nm" ]] && command -v nmcli >/dev/null 2>&1; then
            tool="nmcli"; fields="\"$NMCLI_FIELDS\""
            if out="$(nmcli -t -f "$NMCLI_FIELDS" dev wifi list ifname "$iface" --rescan auto 2>"$ERRF")"; then
                raw="$(printf '%s' "$out" | b64)"
            else
                err="\"$(jsan < "$ERRF")\""
            fi
        elif command -v iw >/dev/null 2>&1; then
            tool="iw"
            if out="$($SUDO iw dev "$iface" scan 2>"$ERRF")"; then
                raw="$(printf '%s' "$out" | b64)"
            else
                err="\"$(jsan < "$ERRF")\""
            fi
        else
            err="\"no survey tool (need nmcli on NM, or iw on networkd)\""
        fi
        obj="{\"name\":\"$iface\",\"tool\":\"$tool\",\"fields\":$fields,\"raw_b64\":\"$raw\",\"error\":$err}"
        ifaces_json="${ifaces_json}${sep}${obj}"
        sep=","
    done
fi

printf '{"schema":1,"generated_at":"%s","host":"%s","backend":"%s","regdom":"%s","interfaces":[%s]}\n' \
    "$ts" "$host" "$backend" "$regdom" "$ifaces_json" > "$TMP"

# Atomic publish, world-readable (a passive survey carries no secrets).
$SUDO install -m 0644 "$TMP" "$OUT"
echo "wrote $OUT (backend=$backend, ifaces=${#wifi_ifaces[@]}, regdom=$regdom)"
