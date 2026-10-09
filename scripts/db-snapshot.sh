#!/usr/bin/env bash
# db-snapshot.sh — pg_dump the NetMon database to /var/lib/netmon/db-snapshots/
# and prune older than RETENTION_DAYS (default 7).
#
# Called from scripts/auto-update.sh BEFORE every git pull + rebuild so a
# failed update can roll back to the pre-update DB state via scripts/rollback.sh.
# Also callable by hand:  ./scripts/db-snapshot.sh
#
# Exit 0 on success, 1 on failure. Failures are loud — auto-update.sh treats
# a snapshot failure as a reason to skip the update entirely.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SNAP_DIR="/var/lib/netmon/db-snapshots"
RETENTION_DAYS="${NETMON_SNAPSHOT_RETENTION_DAYS:-7}"

LOG_TAG="netmon-db-snapshot"
log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$*"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

# Pick the right docker invocation (sudo if not in docker group).
if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    DC=(docker compose)
else
    DC=(sudo docker compose)
fi

cd "$REPO_DIR"

# A snapshot is a full copy of the database, which holds the SNMP communities,
# so neither the directory nor the dumps may be readable by other local users.
# install -d also tightens a directory an older release created 0755, and the
# sweep tightens dumps an older release wrote 0644 — this script runs before
# every update, so existing boxes are corrected on their next one.
umask 077
SNAP_OWNER="${SUDO_USER:-${USER:-root}}"
sudo install -d -m 700 -o "$SNAP_OWNER" -g "$SNAP_OWNER" "$SNAP_DIR"
sudo find "$SNAP_DIR" -maxdepth 1 -type f -name 'netmon_*.sql.gz' \
    -exec chown "$SNAP_OWNER:$SNAP_OWNER" {} + -exec chmod 600 {} +

# Container has to be up. If it's not, bail clean — no snapshot, no harm.
if ! "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-postgres; then
    log "postgres container not running; skipping snapshot"
    exit 0
fi

# Read the role and database name from netmon.env so pg_dump uses the same ones
# the collector does. The password is deliberately NOT read here — see below.
ENV_FILE="/etc/netmon/netmon.env"
PG_USER="netmon"
PG_DB="netmon"
if [[ -r "$ENV_FILE" ]] || sudo test -r "$ENV_FILE"; then
    PG_USER="$(sudo grep -E '^POSTGRES_USER=' "$ENV_FILE" 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//' || echo netmon)"
    PG_DB="$(sudo grep -E '^POSTGRES_DB=' "$ENV_FILE" 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//' || echo netmon)"
fi
[[ -n "$PG_USER" ]] || PG_USER="netmon"
[[ -n "$PG_DB" ]] || PG_DB="netmon"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$SNAP_DIR/netmon_${STAMP}.sql.gz"

log "taking snapshot -> $TARGET"
# The password never appears on a command line: `exec -e PGPASSWORD=<value>`
# put it in the argv of docker compose (and of sudo), readable by every local
# user via ps. The postgres container already holds it as POSTGRES_PASSWORD, so
# the shell INSIDE the container hands it to pg_dump through the environment;
# the single-quoted script below is all that any argv ever carries.
# shellcheck disable=SC2016  # expanded by the container's shell, not this one
if ! "${DC[@]}" exec -T postgres sh -c \
        'PGPASSWORD="${POSTGRES_PASSWORD:-}" exec pg_dump --no-owner --no-privileges -U "$1" -d "$2"' \
        pg_dump "$PG_USER" "$PG_DB" \
        | gzip > "$TARGET"; then
    log "ERROR: pg_dump failed"
    rm -f "$TARGET"
    exit 1
fi

SIZE="$(stat -c %s "$TARGET" 2>/dev/null || echo 0)"
log "snapshot done: $(basename "$TARGET") ($SIZE bytes)"

# Pruning: delete snapshots older than RETENTION_DAYS, keep at least 1 most recent.
KEEP_LIST="$(ls -1t "$SNAP_DIR"/netmon_*.sql.gz 2>/dev/null | head -1 || true)"
PRUNED=0
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # Always keep the most recent regardless of age.
    [[ "$f" == "$KEEP_LIST" ]] && continue
    age_days=$(( ( $(date +%s) - $(stat -c %Y "$f") ) / 86400 ))
    if (( age_days > RETENTION_DAYS )); then
        rm -f "$f"
        log "pruned $(basename "$f") (age ${age_days}d)"
        PRUNED=$((PRUNED + 1))
    fi
done < <(ls -1 "$SNAP_DIR"/netmon_*.sql.gz 2>/dev/null || true)

if (( PRUNED > 0 )); then
    log "pruned $PRUNED old snapshot(s); kept $(ls "$SNAP_DIR"/netmon_*.sql.gz 2>/dev/null | wc -l)"
fi

# Update the "latest snapshot" symlink for rollback.sh to find easily.
ln -sfn "$(basename "$TARGET")" "$SNAP_DIR/latest.sql.gz"

exit 0
