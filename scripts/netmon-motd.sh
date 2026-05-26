#!/bin/sh
# /etc/update-motd.d/99-netmon — login banner showing NetMon status.
#
# Installed by setup.sh with mode 755. The Ubuntu update-motd machinery
# concatenates everything in /etc/update-motd.d/ on each interactive login
# and shows it as the MOTD.
#
# Kept terse: one block, three lines max. The operator sees this every
# SSH login, so noise is expensive.

REPO_DIR="$(ls -d /home/*/NetMon 2>/dev/null | head -1)"
[ -z "$REPO_DIR" ] && [ -d /opt/NetMon ] && REPO_DIR=/opt/NetMon
[ -z "$REPO_DIR" ] && exit 0

# Version
if [ -d "$REPO_DIR/.git" ]; then
    SHA="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    DATE="$(git -C "$REPO_DIR" log -1 --format=%cd --date=short 2>/dev/null || echo unknown)"
    BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
    VERSION="v=${SHA} (${BRANCH} ${DATE})"
else
    VERSION="(no git repo at $REPO_DIR)"
fi

# Identity
IDENTITY=""
if [ -f /etc/netmon/netmon.env ]; then
    DISTRICT="$(sudo -n grep -E '^NETMON_DISTRICT=' /etc/netmon/netmon.env 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//')"
    SCHOOL="$(sudo -n grep -E '^NETMON_SCHOOL=' /etc/netmon/netmon.env 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//')"
    DEVICE="$(sudo -n grep -E '^NETMON_DEVICE=' /etc/netmon/netmon.env 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//')"
    if [ -n "$DISTRICT" ] && [ -n "$SCHOOL" ] && [ -n "$DEVICE" ]; then
        IDENTITY="${DISTRICT} / ${SCHOOL} / ${DEVICE}"
    fi
fi

# Container health (cheap — just check if collector container is "running")
HEALTH="unknown"
if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}} {{.State}}' 2>/dev/null | grep -q '^netmon-collector running'; then
        HEALTH="containers up"
    else
        HEALTH="containers DOWN"
    fi
fi

# Last successful upload (from bundle_uploads if postgres is reachable)
LAST_UP="unknown"
if [ "$HEALTH" = "containers up" ]; then
    LAST_UP="$(docker exec netmon-postgres psql -U netmon -d netmon -t -c \
        "SELECT to_char(MAX(uploaded_at), 'YYYY-MM-DD HH24:MI') FROM bundle_uploads WHERE uploaded_at IS NOT NULL;" \
        2>/dev/null | tr -d ' ')"
    [ -z "$LAST_UP" ] && LAST_UP="never"
fi

# Wizard status
WIZARD_STATE="not run"
[ -f /var/lib/netmon/.wizard-done ] && WIZARD_STATE="ok"

printf '\n'
printf '\033[1;36m NetMon\033[0m  %s\n' "$VERSION"
[ -n "$IDENTITY" ] && printf '         %s\n' "$IDENTITY"
printf '         %s  •  wizard: %s  •  last upload: %s\n' "$HEALTH" "$WIZARD_STATE" "$LAST_UP"
printf '\n'
