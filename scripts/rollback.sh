#!/usr/bin/env bash
# rollback.sh — restore the box to the last known-good state.
#
# Three components get rolled back together:
#   1. Git: reset --hard to the SHA saved in /var/lib/netmon/last-known-good-sha
#   2. Docker image: retag netmon/collector:previous -> :latest
#   3. Database: restore from /var/lib/netmon/db-snapshots/latest.sql.gz
#
# Called from:
#   - scripts/auto-update.sh on a failed post-update healthcheck (automatic)
#   - sudo netmon-rollback (manual, via ./netmon -> System -> Rollback)
#
# Exits 0 on success, non-zero on failure (and leaves the box in whatever
# state we reached — at worst, you re-run setup.sh).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SNAP_DIR="/var/lib/netmon/db-snapshots"
SHA_FILE="/var/lib/netmon/last-known-good-sha"
LATEST_SNAP="$SNAP_DIR/latest.sql.gz"
ENV_FILE="/etc/netmon/netmon.env"

LOG_TAG="netmon-rollback"
log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$*"
    fi
    printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    DC=(docker compose)
else
    DC=(sudo docker compose)
fi

# Self-heal a root-owned netmon.env before the first compose call (mirrors
# ensure_env_readable in scripts/auto-update.sh): compose reads the env_file
# while building its project model, so an unprivileged rollback would fail on
# `down`/`up` with "permission denied" — i.e. the exact drift that broke the
# update would break its safety net too. chown never touches the 0600 mode.
ensure_env_readable() {
    [[ -e "$ENV_FILE" ]] || return 0    # pre-setup box: nothing to heal
    [[ -r "$ENV_FILE" ]] && return 0    # already readable: silent no-op
    local me grp owner
    me="$(id -un)"; grp="$(id -gn)"; owner="$(stat -c %U "$ENV_FILE" 2>/dev/null || echo '?')"
    log "env file $ENV_FILE is owned by '$owner' and unreadable by '$me' — docker compose would fail with 'permission denied'. Self-healing."
    if sudo -n chown "$me:$grp" "$ENV_FILE" 2>/dev/null; then
        log "self-healed: chowned $ENV_FILE back to $me:$grp (root-owned env drift from a root-run config apply; mode stays 0600)"
    else
        log "WARN: could not chown $ENV_FILE (no passwordless sudo). If compose fails with 'permission denied', run:  sudo chown $me:$grp $ENV_FILE"
    fi
}
ensure_env_readable

cd "$REPO_DIR"

log "=== NetMon rollback starting ==="

# --- 1. Validate we have something to roll back to ----------------------

if [[ ! -f "$SHA_FILE" ]]; then
    log "FATAL: no last-known-good SHA at $SHA_FILE — has auto-update ever succeeded?"
    log "       Manual recovery: git log; git reset --hard <sha>; ./netmon restart"
    exit 1
fi
TARGET_SHA="$(cat "$SHA_FILE")"
if [[ -z "$TARGET_SHA" ]]; then
    log "FATAL: $SHA_FILE is empty"
    exit 1
fi

CURRENT_SHA="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
log "current SHA: $CURRENT_SHA"
log "target  SHA: $TARGET_SHA"

if [[ "$CURRENT_SHA" == "$TARGET_SHA" ]]; then
    log "already on the last-known-good SHA — nothing to roll back"
    log "(if the box is actually broken, the rollback target is itself broken;"
    log " run: ./netmon factory-reset and re-run the wizard from a backup)"
    exit 0
fi

# --- 2. Stop containers (they hold the DB and the current image) --------

log "stopping containers..."
"${DC[@]}" down >/dev/null 2>&1 || true

# --- 3. Select the rolled-back image (REL-3) -----------------------------
# CI publishes an immutable :<sha> image for every main commit, and compose
# reads the tag from the repo-root .env. Point it at the rollback target's SHA;
# step 6 pulls it (usually a cache hit, so offline-safe) or falls back to a local
# build. If TARGET_SHA predates REL-3, its compose uses the old build path and
# the pull simply falls through to a build — still correct.
ENV_DOTFILE="$REPO_DIR/.env"
if [[ -f "$ENV_DOTFILE" ]] && grep -q '^NETMON_IMAGE_TAG=' "$ENV_DOTFILE"; then
    sed -i "s|^NETMON_IMAGE_TAG=.*|NETMON_IMAGE_TAG=${TARGET_SHA}|" "$ENV_DOTFILE"
else
    echo "NETMON_IMAGE_TAG=${TARGET_SHA}" >> "$ENV_DOTFILE"
fi
log "rollback image tag set to :${TARGET_SHA:0:8}"

# --- 4. Git rollback ----------------------------------------------------

log "git reset --hard $TARGET_SHA"
git -C "$REPO_DIR" reset --hard "$TARGET_SHA" >/dev/null 2>&1 || {
    log "FATAL: git reset failed"
    exit 1
}

# --- 5. Start postgres only, restore from snapshot ---------------------

if [[ -e "$LATEST_SNAP" ]]; then
    log "starting postgres for snapshot restore..."
    "${DC[@]}" up -d postgres >/dev/null
    # Wait for postgres health
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if "${DC[@]}" exec -T postgres pg_isready -U netmon -d netmon >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done

    log "restoring DB snapshot: $(readlink "$LATEST_SNAP")"
    # Reset the schema, then load, in ONE transaction. The plain pg_dump carries
    # no DROP statements, so loading it into the current (post-update) schema used
    # to collide on the first CREATE and abort under ON_ERROR_STOP — a silent
    # no-op restore that left old code running on the new schema. Prepending
    # "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" clears the target so the
    # dump loads cleanly; --single-transaction makes the whole thing atomic, so a
    # bad/truncated snapshot rolls back and leaves the DB exactly as it was (never
    # half-restored, never emptied). netmon is the DB superuser/owner so the reset
    # is permitted, and the collector is down (compose down, above) so nothing
    # else is connected.
    PG_PW="$(sudo grep -E '^POSTGRES_PASSWORD=' /etc/netmon/netmon.env 2>/dev/null | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//')"
    if { printf 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;\n'; gunzip -c "$LATEST_SNAP"; } \
            | "${DC[@]}" exec -T -e "PGPASSWORD=$PG_PW" postgres \
              psql -U netmon -d netmon --single-transaction -v ON_ERROR_STOP=1 >/dev/null; then
        log "snapshot restored (schema reset + reload, atomic)"
    else
        log "WARN: snapshot restore failed and was rolled back — DB left on the"
        log "      post-update schema unchanged; investigate the snapshot before retrying"
    fi
else
    log "no snapshot at $LATEST_SNAP — DB will continue with current state"
fi

# --- 6. Pull the rolled-back image (or rebuild), then bring everything up -

log "pulling rolled-back collector image :${TARGET_SHA:0:8} (or building if unreachable)..."
if ! "${DC[@]}" pull collector >/dev/null 2>&1; then
    log "  pull failed (registry unreachable / tag missing); building locally"
    "${DC[@]}" build --pull collector >/dev/null 2>&1 || log "  WARN: local build also failed"
fi

log "starting all containers..."
"${DC[@]}" up -d >/dev/null

# Wait for collector to be reachable
log "waiting for collector to come up..."
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if "${DC[@]}" exec -T collector python -m collector --version >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

log "=== rollback complete; now on $(git -C "$REPO_DIR" rev-parse --short HEAD) ==="
exit 0
