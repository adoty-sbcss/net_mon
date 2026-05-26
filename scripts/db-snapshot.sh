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

# Ensure the snapshot directory exists with proper ownership.
sudo install -d -m 755 -o "${SUDO_USER:-${USER:-root}}" -g "${SUDO_USER:-${USER:-root}}" "$SNAP_DIR"

# Container has to be up. If it's not, bail clean — no snapshot, no harm.
if ! "${DC[@]}" ps --status running 2>/dev/null | grep -q netmon-postgres; then
    log "postgres container not running; skipping snapshot"
    exit 0
fi

# Read credentials from netmon.env so pg_dump uses the same user/db the
# collector does. POSTGRES_PASSWORD also goes in the env via PGPASSWORD.
ENV_FILE="/etc/netmon/netmon.env"
PG_USER="netmon"
PG_DB="netmon"
PG_PW=""
if [[ -r "$ENV_FILE" ]] || sudo test -r "$ENV_FILE"; then
    PG_USER="$(sudo grep -E '^POSTGRES_USER=' "$ENV_FILE" 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//' || echo netmon)"
    PG_DB="$(sudo grep -E '^POSTGRES_DB=' "$ENV_FILE" 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//' || echo netmon)"
    PG_PW="$(sudo grep -E '^POSTGRES_PASSWORD=' "$ENV_FILE" 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//')"
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$SNAP_DIR/netmon_${STAMP}.sql.gz"

log "taking snapshot -> $TARGET"
if ! "${DC[@]}" exec -T -e "PGPASSWORD=$PG_PW" postgres \
        pg_dump --no-owner --no-privileges -U "$PG_USER" -d "$PG_DB" \
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
