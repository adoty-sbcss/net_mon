#!/usr/bin/env bash
# auto-update.sh — pull latest NetMon from main and apply, with rollback safety.
#
# Designed for nightly systemd timer execution. Safe to run by hand too.
# Logs to syslog via `logger` so journalctl picks it up; also echoes to stdout
# for interactive runs.
#
# Behavior:
#   1. git fetch — bail clean if remote is unreachable
#   2. Resolve the target commit and immutable image for the configured channel
#   3. Pre-update safety when the target changed:
#        - pg_dump current DB to /var/lib/netmon/db-snapshots/
#        - Save current SHA to /var/lib/netmon/last-known-good-sha
#   4. Reset the checkout to the resolved target
#   5. Pull the immutable image (or build it locally as a fallback)
#   6. docker compose up -d  (applies migrations on collector startup)
#   7. Post-update healthcheck (wait 2min, run the blocking readiness command)
#   8. On healthcheck failure: invoke scripts/rollback.sh automatically
#
# Exit codes:
#   0 — successful reconciliation/update, or successful auto-rollback
#   1 — recoverable failure (network, git, docker, healthcheck) — try again next run
#   2 — non-recoverable (working tree dirty, fast-forward not possible)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

SHA_FILE="/var/lib/netmon/last-known-good-sha"
CURRENT_SHA_FILE="/var/lib/netmon/current-sha"   # reported to the dashboard at check-in
ENV_FILE="/etc/netmon/netmon.env"
HEALTHCHECK_WAIT_SECONDS="${NETMON_HEALTHCHECK_WAIT:-120}"

# Update observability: the update runs host-side and async, so its outcome never
# reached the dashboard (fire-and-forget) and its log only went to syslog (no SSH
# = no way to read it). Fix both:
#   - RESULT_FILE: a one-line JSON outcome the next check-in reports back, so the
#     dashboard shows "last update: failed (dubious ownership)" instead of nothing.
#   - UPDATE_LOG: a copy of this run's log under /var/log/netmon (a host<->container
#     bind mount) so `collect-logs` can retrieve it without SSH.
# Both live on bind mounts the collector container can read.
RESULT_FILE="/var/lib/netmon/last-update-result"
UPDATE_LOG="/var/log/netmon/auto-update.log"

# Record the terminal outcome for the dashboard. Driven by an EXIT trap so EVERY
# exit path (including an unexpected set -e abort) reports something — the trap
# writes whatever RESULT_STATUS/RESULT_REASON were last set to. LOCAL/NEW_HEAD may
# be unset at early exits (set -u), hence the :- defaults.
RESULT_STATUS="failed"
RESULT_REASON="update did not complete"
record_result() {
    local at; at="$(date -Iseconds 2>/dev/null || echo unknown)"
    local from="${LOCAL:-}" to="${NEW_HEAD:-${LOCAL:-}}" chan="${UPDATE_CHANNEL:-stable}"
    local json
    json="{\"status\":\"${RESULT_STATUS}\",\"reason\":\"${RESULT_REASON}\",\"from\":\"${from:0:12}\",\"to\":\"${to:0:12}\",\"channel\":\"${chan:-stable}\",\"at\":\"${at}\"}"
    { printf '%s\n' "$json" >"$RESULT_FILE"; } 2>/dev/null \
        || { printf '%s\n' "$json" | sudo -n tee "$RESULT_FILE" >/dev/null 2>&1; } \
        || true
}
trap record_result EXIT

# Keep the retrievable log from growing without bound (best-effort).
if [[ -f "$UPDATE_LOG" ]]; then
    log_lines="$(wc -l <"$UPDATE_LOG" 2>/dev/null || echo 0)"
    if [[ "${log_lines:-0}" -gt 1000 ]]; then
        { tail -n 500 "$UPDATE_LOG" >"${UPDATE_LOG}.tmp" && mv "${UPDATE_LOG}.tmp" "$UPDATE_LOG"; } 2>/dev/null || true
    fi
fi

# Read a NETMON_* key from the env file (root-owned 0600). Empty if absent.
read_env() {
    sudo grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true
}
# Persist the live commit SHA so the dashboard can show exactly which release a
# box is on (release-channel rollout view). Best-effort.
record_current_sha() {
    sudo install -d -m 755 /var/lib/netmon 2>/dev/null || true
    git rev-parse HEAD 2>/dev/null | sudo tee "$CURRENT_SHA_FILE" >/dev/null 2>&1 || true
}

# REL-3: persist the image tag compose should run, in the repo-root .env that
# `docker compose` auto-reads — so EVERY compose invocation (auto-update, the
# netmon CLI, rollback) selects the same image. .env is gitignored, so git
# reset --hard never clobbers it. Preserves any other keys already in .env.
ENV_DOTFILE="$REPO_DIR/.env"
write_image_tag_env() {
    local tag="$1"
    if [[ -f "$ENV_DOTFILE" ]] && grep -q '^NETMON_IMAGE_TAG=' "$ENV_DOTFILE"; then
        sed -i "s|^NETMON_IMAGE_TAG=.*|NETMON_IMAGE_TAG=${tag}|" "$ENV_DOTFILE"
    else
        echo "NETMON_IMAGE_TAG=${tag}" >> "$ENV_DOTFILE"
    fi
}

LOG_TAG="netmon-update"
log() {
    local msg="$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" "$msg"
    fi
    local line; line="[$(date -Iseconds)] $msg"
    printf '%s\n' "$line"
    # Mirror to the bind-mounted log so `collect-logs` can retrieve it (best-effort).
    { printf '%s\n' "$line" >>"$UPDATE_LOG"; } 2>/dev/null || true
}

# Source paths.sh so we can run ensure_paths after the git pull lands new
# code. Migrating from the old in-repo layout to /etc/netmon + /var/lib/netmon
# happens on the next call. Older clones won't have lib/, so guard the source.
ensure_paths_if_available() {
    if [[ -f "$REPO_DIR/lib/common.sh" ]] && [[ -f "$REPO_DIR/lib/paths.sh" ]]; then
        # shellcheck source=/dev/null
        . "$REPO_DIR/lib/common.sh"
        # shellcheck source=/dev/null
        . "$REPO_DIR/lib/paths.sh"
        ensure_paths
    fi
}

# REL-2: a repo cloned/owned by a different user than the one running this script
# (the classic "cloned as root, but netmon-update.service runs as the service
# user" case) makes EVERY git command fail with "fatal: detected dubious
# ownership". That used to surface as the misleading "git fetch failed (network
# down?)" and silently froze the box dozens of commits behind. Detect it up front
# and self-heal: chown the repo back to us (preferred), else trust it via
# safe.directory so at least reads work and log a loud, actionable warning.
ensure_repo_ownership() {
    local repo_uid me_uid me grp owner
    repo_uid="$(stat -c %u "$REPO_DIR/.git" 2>/dev/null || stat -c %u "$REPO_DIR" 2>/dev/null || echo -1)"
    me_uid="$(id -u)"
    [[ "$repo_uid" == "$me_uid" ]] && return 0
    me="$(id -un)"; grp="$(id -gn)"; owner="$(stat -c %U "$REPO_DIR" 2>/dev/null || echo '?')"
    log "repo $REPO_DIR is owned by '$owner' (uid $repo_uid) but auto-update runs as '$me' (uid $me_uid) — git would refuse with 'dubious ownership'. Self-healing."
    if sudo -n chown -R "$me:$grp" "$REPO_DIR" 2>/dev/null; then
        log "self-healed: chowned $REPO_DIR to $me:$grp (root-clone bug; see lesson_autoupdate_root_clone)"
    else
        git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true
        log "WARN: could not chown $REPO_DIR (no passwordless sudo). Added git safe.directory so fetch/status work, but 'git pull' may still fail on write until an admin runs:  sudo chown -R $me:$grp $REPO_DIR"
    fi
}
ensure_repo_ownership

# The companion self-heal for /etc/netmon/netmon.env: the collector container
# runs as root with /etc/netmon bind-mounted, and (before the collector-side
# ownership fix in checkin.py) any dashboard config push rewrote netmon.env as
# root:root 0600. docker compose reads that env_file while building its project
# model, so EVERY unprivileged compose command then failed with "permission
# denied" — the nightly update failed, the pre-update DB snapshot silently
# skipped, and the rollback path (also compose) failed the same way, leaving
# the box down until a human logged in (Monitor1 lost ~1.3 days to this).
# Heal it up front, before anything reads the env or touches compose, exactly
# like the repo-ownership self-heal above. chown never touches the 0600 mode.
ensure_env_readable() {
    [[ -e "$ENV_FILE" ]] || return 0    # pre-setup box: nothing to heal
    [[ -r "$ENV_FILE" ]] && return 0    # already readable: silent no-op
    local me grp owner
    me="$(id -un)"; grp="$(id -gn)"; owner="$(stat -c %U "$ENV_FILE" 2>/dev/null || echo '?')"
    log "env file $ENV_FILE is owned by '$owner' and unreadable by '$me' — every docker compose command (update AND rollback) would fail with 'permission denied'. Self-healing."
    if sudo -n chown "$me:$grp" "$ENV_FILE" 2>/dev/null; then
        log "self-healed: chowned $ENV_FILE back to $me:$grp (root-owned env drift from a root-run config apply; mode stays 0600)"
    else
        log "WARN: could not chown $ENV_FILE (no passwordless sudo). docker compose will keep failing with 'permission denied' until an admin runs:  sudo chown $me:$grp $ENV_FILE"
    fi
}
ensure_env_readable

# REL-3/REL-2 last-resort self-heal: if git is wedged by ownership and we couldn't
# chown (a locked-down box with no passwordless sudo — exactly what stranded a
# field box on old code), re-clone the repo FRESH to a dir we own and swap it in.
# SAFE: all config/state lives OUTSIDE the repo (/etc/netmon, /var/lib/netmon), so
# the repo is pure code — re-cloning loses nothing. CONSERVATIVE: only the
# dubious-ownership fetch failure below calls this; the broken repo is moved aside
# (never deleted) and restored if the swap fails; a marker prevents loops. On
# success it re-execs the fresh script (forcing an image refresh) and never returns.
selfheal_reclone() {
    [[ -n "${NETMON_RECLONED:-}" ]] && { log "self-heal: already re-cloned this run; not looping"; return 1; }
    # Never operate on a data/system dir, even if REPO_DIR is somehow misset.
    case "$REPO_DIR" in
        /|/etc|/etc/netmon|/var|/var/lib|/var/lib/netmon|"$HOME")
            log "self-heal: refusing to re-clone suspicious REPO_DIR=$REPO_DIR"; return 1 ;;
    esac
    git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true
    local url; url="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
    [[ -z "$url" ]] && { log "self-heal: cannot read origin URL; not re-cloning"; return 1; }
    local parent; parent="$(dirname "$REPO_DIR")"
    [[ -w "$parent" ]] || { log "self-heal: parent dir $parent not writable; can't re-clone (needs an admin chown)"; return 1; }

    local fresh="${REPO_DIR}.fresh.$$"
    rm -rf "$fresh" 2>/dev/null || true
    log "self-heal: re-cloning $url -> fresh tree owned by $(id -un)"
    if ! git clone --quiet "$url" "$fresh"; then
        log "self-heal: fresh clone failed (registry/network?); leaving existing repo untouched"
        rm -rf "$fresh" 2>/dev/null || true
        return 1
    fi
    if [[ ! -f "$fresh/docker-compose.yml" || ! -x "$fresh/scripts/auto-update.sh" ]]; then
        log "self-heal: fresh clone failed validation; discarding"
        rm -rf "$fresh" 2>/dev/null || true
        return 1
    fi
    # Preserve the gitignored repo-root .env (image-tag selection) if present.
    if [[ -f "$REPO_DIR/.env" ]]; then cp -p "$REPO_DIR/.env" "$fresh/.env" 2>/dev/null || true; fi

    local aside="${REPO_DIR}.broken.$(date +%s 2>/dev/null || echo old)"
    if ! mv "$REPO_DIR" "$aside" 2>/dev/null; then
        log "self-heal: could not move old repo aside; aborting (repo untouched)"
        rm -rf "$fresh" 2>/dev/null || true
        return 1
    fi
    if ! mv "$fresh" "$REPO_DIR" 2>/dev/null; then
        log "self-heal: CRITICAL: could not move fresh repo into place; restoring original"
        mv "$aside" "$REPO_DIR" 2>/dev/null || true
        rm -rf "$fresh" 2>/dev/null || true
        return 1
    fi
    log "self-heal: re-clone complete (old repo saved at $aside); re-executing auto-update with fresh code"
    export NETMON_RECLONED=1 NETMON_FORCE_REFRESH=1
    exec "$REPO_DIR/scripts/auto-update.sh"
}

# Refuse to run on a dirty working tree — we'd lose local changes.
if [[ -n "$(git status --porcelain)" ]]; then
    log "FATAL: working tree has uncommitted changes; refusing to auto-update"
    log "Resolve manually:  cd $REPO_DIR && git status"
    RESULT_STATUS="failed"; RESULT_REASON="working tree has uncommitted changes; refusing to auto-update"
    exit 2
fi

# 1. Fetch latest refs. Distinguish a genuine network failure from a lingering
# ownership problem (REL-2) so the journal says something actionable.
if ! fetch_err="$(git fetch --quiet origin main 2>&1)"; then
    if printf '%s' "$fetch_err" | grep -qi "dubious ownership"; then
        log "git fetch failed: dubious repo ownership persists after self-heal. Run:  sudo chown -R $(id -un):$(id -gn) $REPO_DIR"
        # Last-resort: re-clone fresh + re-exec. exec's away on success; returns
        # here only if it couldn't (then we record a clear, actionable failure).
        selfheal_reclone || true
        RESULT_STATUS="failed"; RESULT_REASON="git fetch failed: dubious repo ownership; auto re-clone unavailable (needs an admin: sudo chown -R the repo to the service user)"
    else
        log "git fetch failed (network down?); will retry next run"
        RESULT_STATUS="failed"; RESULT_REASON="git fetch failed (registry/network unreachable)"
    fi
    exit 1
fi

LOCAL=$(git rev-parse HEAD)

# 1b. Release channel: resolve the TARGET this box should converge to. Default
# (unset/unknown channel) == 'stable' with no pin == track origin/main, i.e. the
# historical behavior — so shipping this is a no-op until channels are set from
# the dashboard. 'canary' tracks origin/main (latest); 'hold' pauses updates;
# 'stable' with a pin (NETMON_UPDATE_REF) converges to that exact commit.
UPDATE_CHANNEL="$(read_env NETMON_UPDATE_CHANNEL)"
UPDATE_REF="$(read_env NETMON_UPDATE_REF)"
case "$UPDATE_CHANNEL" in
    hold)
        log "update channel=hold; skipping auto-update"
        RESULT_STATUS="skipped"; RESULT_REASON="update channel=hold (updates paused)"
        exit 0
        ;;
    canary)
        REMOTE=$(git rev-parse origin/main)
        IMAGE_TAG="$REMOTE"
        log "update channel=canary -> origin/main ${REMOTE:0:8} (immutable image :${REMOTE:0:8})"
        ;;
    stable|"")
        if [[ -n "$UPDATE_REF" ]] && REMOTE=$(git rev-parse --verify "${UPDATE_REF}^{commit}" 2>/dev/null); then
            # Pinned to an exact commit -> the immutable per-commit image tag.
            IMAGE_TAG="$REMOTE"
            log "update channel=stable; pinned ${UPDATE_REF} -> ${REMOTE:0:8} (image :${REMOTE:0:8})"
        else
            [[ -n "$UPDATE_REF" ]] && log "WARN: pinned ref '${UPDATE_REF}' not found after fetch; tracking origin/main"
            REMOTE=$(git rev-parse origin/main)
            IMAGE_TAG="$REMOTE"
            log "update channel=stable -> origin/main ${REMOTE:0:8} (immutable image :${REMOTE:0:8})"
        fi
        ;;
    *)
        REMOTE=$(git rev-parse origin/main)
        IMAGE_TAG="$REMOTE"
        log "WARN: unknown update channel '${UPDATE_CHANNEL}'; tracking origin/main (immutable image :${REMOTE:0:8})"
        ;;
esac

# Reconcile image and container state even when Git is already current. This is
# what lets the next timer run recover after a prior pull/build/recreate failure.
TARGET_CHANGED=1
if [[ "$LOCAL" == "$REMOTE" ]]; then
    TARGET_CHANGED=0
    log "source is current at ${LOCAL:0:8}; reconciling image and container state"
else
    log "update available: ${LOCAL:0:8} -> ${REMOTE:0:8} (channel=${UPDATE_CHANNEL:-stable})"
fi

# 2. Inspect what changed.
CHANGED=$(git diff --name-only "$LOCAL" "$REMOTE")
log "files changed:"
echo "$CHANGED" | while read -r f; do log "  $f"; done

# REL-3: code changes ship IN the prebuilt image now, so we no longer decide
# whether to build from the diff — we always pull the resolved tag (and fall
# back to a local build only if the registry is unreachable). The container is
# recreated automatically by `up -d` when the pulled image digest changes.

NEEDS_RECREATE=0
if echo "$CHANGED" | grep -qE '^docker-compose\.yml$'; then
    NEEDS_RECREATE=1
fi

# 3. Pre-update snapshot. We want a fresh DB dump and a saved image tag
# BEFORE we change anything so rollback has something to restore from.
log "pre-update: saving rollback state"

# 3a. Save current SHA as the rollback target.
if [[ "$TARGET_CHANGED" -eq 1 ]]; then
    sudo install -d -m 755 /var/lib/netmon
    echo "$LOCAL" | sudo tee "$SHA_FILE" >/dev/null
    log "  saved current SHA $LOCAL as rollback target"
else
    log "  preserving existing rollback target during reconciliation"
fi

# 3b. pg_dump. Skip silently if the script isn't present (very old clones).
if [[ "$TARGET_CHANGED" -eq 1 && -x "$REPO_DIR/scripts/db-snapshot.sh" ]]; then
    log "  taking pre-update DB snapshot"
    if ! "$REPO_DIR/scripts/db-snapshot.sh" 2>&1 | while read -r ln; do log "    $ln"; done; then
        log "WARN: pre-update snapshot failed; rollback will lose any new DB state"
    fi
fi

# 3c. Rollback target = the immutable per-commit image tag :<LOCAL>. CI publishes
# a :<sha> tag for every main commit, and the image is almost always still in the
# local docker cache, so rollback.sh can restore it (pull or cached) without a
# fragile local :previous tag. The SHA itself is already saved to $SHA_FILE above.

# 4. Move to the resolved target (channel-aware). reset --hard is safe here: the
# dirty-tree guard at the top already refused to run with local changes, and
# REMOTE is always a fetched commit (origin/main or a verified pin). This handles
# pinned downgrades and canary-ahead alike, where a plain --ff-only could not.
if ! git reset --hard --quiet "$REMOTE"; then
    log "FATAL: git reset to ${REMOTE:0:8} failed; manual intervention needed"
    RESULT_STATUS="failed"; RESULT_REASON="git reset to ${REMOTE:0:8} failed (repo not writable?)"
    exit 2
fi
NEW_HEAD=$(git rev-parse HEAD)
log "updated to ${NEW_HEAD:0:8}"

# 4b. Run path migration with the freshly-pulled code.
log "ensuring canonical paths (and migrating legacy layout if needed)"
ensure_paths_if_available 2>&1 | while read -r ln; do log "  $ln"; done

# 4c. If install-auto-update.sh or any systemd unit file changed in this
# pull AND the boxes' update timer is already installed (i.e. setup.sh has
# been run at least once), re-run the installer so any NEW timers added
# in this release land on the box automatically. Skips if the user never
# enabled the timers in the first place.
if systemctl list-unit-files netmon-update.timer 2>/dev/null | grep -q netmon-update; then
    if echo "$CHANGED" | grep -qE '^(scripts/install-auto-update\.sh|systemd/)'; then
        log "systemd units or installer changed; re-running install-auto-update.sh"
        if [[ -x "$REPO_DIR/scripts/install-auto-update.sh" ]]; then
            "$REPO_DIR/scripts/install-auto-update.sh" 2>&1 \
                | while read -r ln; do log "  $ln"; done || \
                log "WARN: installer re-run reported errors"
        fi
    fi
fi

# 5. REL-3: pull the prebuilt image for the resolved tag. Fall back to a local
# build only if the registry is unreachable (e.g. a school that blocks ghcr.io)
# — the build is reliable again now that the Ookla install was removed.
log "pulling collector image (ghcr.io/adoty-sbcss/netmon-collector:${IMAGE_TAG})"
if NETMON_IMAGE_TAG="$IMAGE_TAG" docker compose pull collector >/dev/null 2>&1; then
    log "  image pulled"
else
    log "WARN: image pull failed (registry unreachable?); building collector locally"
    if ! NETMON_IMAGE_TAG="$IMAGE_TAG" docker compose build --pull --quiet collector 2>&1 | while read -r ln; do log "  $ln"; done; then
        log "ERROR: image pull AND local build both failed"
        RESULT_STATUS="failed"; RESULT_REASON="image pull AND local build both failed (registry + build deps unreachable — egress filtering?)"
        exit 1
    fi
fi

# Persist the target only after the image exists locally. A failed pull/build
# must not leave future compose invocations pointing at an unavailable image.
write_image_tag_env "$IMAGE_TAG"

# 6. Bring containers up.
COMPOSE_ARGS="up -d --remove-orphans"
if [[ $NEEDS_RECREATE -eq 1 ]]; then
    COMPOSE_ARGS="up -d --force-recreate --remove-orphans"
fi
log "docker compose $COMPOSE_ARGS"
if ! docker compose $COMPOSE_ARGS 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "ERROR: docker compose up failed — invoking rollback"
    if [[ -x "$REPO_DIR/scripts/rollback.sh" ]]; then
        "$REPO_DIR/scripts/rollback.sh" 2>&1 | while read -r ln; do log "  $ln"; done || true
    fi
    RESULT_STATUS="failed"; RESULT_REASON="docker compose up failed; attempted rollback"
    exit 1
fi

# Collector applies any pending db/migrations/*.sql at startup.
if echo "$CHANGED" | grep -q '^db/migrations/'; then
    log "new schema migrations included; collector will apply on startup"
fi

# 7. Post-update healthcheck. Wait HEALTHCHECK_WAIT_SECONDS for the collector
# to settle, then run the blocking readiness command. If it fails, the release is broken —
# auto-rollback to the saved SHA + :previous image + latest snapshot.
log "post-update healthcheck: waiting ${HEALTHCHECK_WAIT_SECONDS}s for collector to settle"
sleep "$HEALTHCHECK_WAIT_SECONDS"

if docker compose exec -T collector python -m collector healthcheck --verbose >/dev/null 2>&1; then
    record_current_sha
    log "healthcheck passed; update complete at ${NEW_HEAD:0:8}"
    RESULT_STATUS="ok"; RESULT_REASON="updated ${LOCAL:0:8} -> ${NEW_HEAD:0:8}; healthcheck passed"
    exit 0
fi

# Healthcheck failed.
log "CRITICAL: post-update healthcheck failed — invoking auto-rollback"
log "  failed update was ${LOCAL:0:8} -> ${NEW_HEAD:0:8}"
log "  rollback target: ${LOCAL:0:8}"

if [[ ! -x "$REPO_DIR/scripts/rollback.sh" ]]; then
    log "FATAL: scripts/rollback.sh missing — box is stuck on ${NEW_HEAD:0:8}"
    log "       manual recovery: git reset --hard $LOCAL && docker compose up -d --force-recreate"
    RESULT_STATUS="failed"; RESULT_REASON="healthcheck failed after update to ${NEW_HEAD:0:8}; rollback.sh missing (box stuck on new build)"
    exit 1
fi

if "$REPO_DIR/scripts/rollback.sh" 2>&1 | while read -r ln; do log "  $ln"; done; then
    log "auto-rollback completed; box is back on ${LOCAL:0:8}"
    RESULT_STATUS="rolled_back"; RESULT_REASON="healthcheck failed after update to ${NEW_HEAD:0:8}; auto-rolled-back to ${LOCAL:0:8}"
    exit 0
else
    log "FATAL: auto-rollback also failed — manual intervention required"
    RESULT_STATUS="failed"; RESULT_REASON="healthcheck failed after update to ${NEW_HEAD:0:8}; auto-rollback ALSO failed (manual intervention needed)"
    exit 1
fi
