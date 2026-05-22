#!/usr/bin/env bash
set -euo pipefail

# Start lldpd in the background so we accumulate neighbor info as soon as
# the container comes up. -cfs allows snmp/lldp/cdp; -k disables kernel netlink
# fast-path which we don't need; -L disables logging to syslog (we don't have one).
if command -v lldpd >/dev/null 2>&1; then
    # Run as root inside the container; bind to all interfaces by default.
    lldpd -cfs 2>/dev/null || lldpd 2>/dev/null || true
fi

exec python -m collector "$@"
