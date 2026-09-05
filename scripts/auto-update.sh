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

# The account netmon-update.service actually runs as. EVERY ownership decision
# in this script must target this user, never `id -un`: the documented manual
# force update (`sudo bash scripts/auto-update.sh`) makes `id -un` return root,
# and the self-heal below used to chown the whole checkout to root:root while
# the unit stays User=<service account> - manufacturing the exact "dubious
# ownership" freeze it exists to prevent (hit on Monitor1, 2026-09-04).
# Resolution order: the installed unit (authoritative) -> the sudo invoker ->
# the repo's current owner -> ourselves.
UPDATE_UNIT="/etc/systemd/system/netmon-update.service"
netmon_service_user() {
    local u=""
    if [[ -r "$UPDATE_UNIT" ]]; then
        u="$(sed -n 's/^[[:space:]]*User[[:space:]]*=[[:space:]]*//p' "$UPDATE_UNIT" | tail -1)"
        u="${u%%[[:space:]]*}"            # drop trailing CR/whitespace
        u="${u#\"}"; u="${u%\"}"          # drop optional quoting
    fi
    [[ -n "$u" ]] || u="${SUDO_USER:-}"
    [[ -n "$u" ]] || u="$(stat -c %U "$REPO_DIR" 2>/dev/null || true)"
    if [[ -z "$u" ]] || ! id -u "$u" >/dev/null 2>&1; then u="$(id -un)"; fi
    printf '%s' "$u"
}
SERVICE_USER="$(netmon_service_user)"
SERVICE_GROUP="$(id -gn "$SERVICE_USER" 2>/dev/null || printf '%s' "$SERVICE_USER")"

# Run a privileged command: directly when already root, else via the
# passwordless sudo that install-auto-update.sh's sudoers drop-in provides.
priv() {
    if [[ "$(id -u)" -eq 0 ]]; then "$@"; else sudo -n "$@"; fi
}

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
# Guard for every recursive chown below. REPO_DIR is derived from $0, so a run
# launched by an unexpected path can resolve it to / or /etc - and `chown -R`
# there, as root, would be far more destructive than anything it is meant to
# repair. selfheal_reclone already refuses to operate on such a path for the
# same reason; a real checkout always has a .git entry.
repo_dir_is_sane() {
    [[ -n "${REPO_DIR:-}" && -e "$REPO_DIR/.git" ]] || return 1
    case "$REPO_DIR" in
        /|/etc|/etc/netmon|/var|/var/lib|/var/lib/netmon|/usr|/home|/root|"${HOME:-}") return 1 ;;
    esac
    return 0
}

# A root-run update writes as root throughout: git creates new objects, replaces
# .git/index via lock+rename, and `reset --hard` re-creates every changed
# working-tree file - all owned by root:root, even once the top-level chown
# below targets the right user. Left alone the checkout drifts out of the
# service user's hands one manual run at a time, which is how the freeze starts.
# Put it back on the way out, on every exit path.
restore_repo_ownership() {
    [[ "$(id -u)" -eq 0 ]] || return 0
    [[ -n "${SERVICE_USER:-}" && "$SERVICE_USER" != "root" ]] || return 0
    repo_dir_is_sane || return 0
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$REPO_DIR" 2>/dev/null || true
    # Same trap for the retrievable log: a root run that creates it first leaves
    # it root-owned, and every later unprivileged run silently fails to append
    # (that write is best-effort), so `collect-logs` quietly goes stale.
    if [[ -e "$UPDATE_LOG" ]]; then
        chown "$SERVICE_USER:$SERVICE_GROUP" "$UPDATE_LOG" 2>/dev/null || true
    fi
    return 0
}

# Both run on EVERY exit path; ownership first, so even a box left mid-failure
# is handed back to the service user.
on_exit() { restore_repo_ownership; record_result; }
trap on_exit EXIT

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

# REL-2: a repo owned by a different user than the one netmon-update.service
# runs as makes EVERY git command fail with "fatal: detected dubious ownership".
# That used to surface as the misleading "git fetch failed (network down?)" and
# silently froze the box dozens of commits behind.
#
# The invariant is "the checkout belongs to $SERVICE_USER", NOT "the checkout
# belongs to whoever is running me". Those diverge exactly when an operator runs
# the documented manual force update, `sudo bash scripts/auto-update.sh`: this
# used to chown the whole tree to root:root, which satisfied the root process it
# was running under while handing the next nightly run (User=<service account>)
# the very freeze this function exists to prevent. Monitor1 hit it 2026-09-04.
ensure_repo_ownership() {
    local repo_uid want_uid owner
    repo_uid="$(stat -c %u "$REPO_DIR/.git" 2>/dev/null || stat -c %u "$REPO_DIR" 2>/dev/null || echo -1)"
    want_uid="$(id -u "$SERVICE_USER" 2>/dev/null || echo -1)"
    [[ "$repo_uid" == "$want_uid" ]] && return 0
    if ! repo_dir_is_sane; then
        log "WARN: refusing to touch ownership of '$REPO_DIR' - it does not look like the NetMon checkout (no .git, or a system directory)"
        return 0
    fi
    owner="$(stat -c %U "$REPO_DIR" 2>/dev/null || echo '?')"
    log "repo $REPO_DIR is owned by '$owner' (uid $repo_uid) but netmon-update.service runs as '$SERVICE_USER' (uid $want_uid); git would refuse with 'dubious ownership'. Self-healing."
    if priv chown -R "$SERVICE_USER:$SERVICE_GROUP" "$REPO_DIR" 2>/dev/null; then
        log "self-healed: chowned $REPO_DIR to $SERVICE_USER:$SERVICE_GROUP (root-clone bug; see lesson_autoupdate_root_clone)"
    else
        log "WARN: could not chown $REPO_DIR (no passwordless sudo). Trusting the path for this process so fetch/status work, but 'git pull' may still fail on write until an admin runs:  sudo chown -R $SERVICE_USER:$SERVICE_GROUP $REPO_DIR"
    fi
    return 0
}
ensure_repo_ownership

# git refuses to touch a repo owned by anyone but the caller. Under `sudo` it
# makes an exception for the invoking user (it matches $SUDO_UID), which is why
# the manual force update still works with the tree owned by $SERVICE_USER - but
# a root cron or `su -` has no SUDO_UID and WOULD be refused, driving the fetch
# failure below into selfheal_reclone for no reason. Trust the path for THIS
# PROCESS only (inherited by every child git), leaving no safe.directory entry
# behind in whichever ~/.gitconfig root happened to be pointed at.
ensure_git_trusts_repo() {
    local repo_uid
    repo_uid="$(stat -c %u "$REPO_DIR/.git" 2>/dev/null || stat -c %u "$REPO_DIR" 2>/dev/null || echo -1)"
    [[ "$repo_uid" == "$(id -u)" ]] && return 0
    export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="safe.directory" GIT_CONFIG_VALUE_0="$REPO_DIR"
    return 0
}
ensure_git_trusts_repo

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
    # A privileged run can read this file no matter who owns it, so the check
    # below returns "fine" while the unprivileged nightly still cannot read it:
    # a manual `sudo` validation reporting green on a box that is still broken.
    # Say so rather than heal it - this is the file whose ownership caused a P0,
    # so a root run warns and deliberately leaves ownership alone.
    local env_owner
    env_owner="$(stat -c %U "$ENV_FILE" 2>/dev/null || echo '?')"
    if [[ "$(id -u)" -eq 0 && "$env_owner" != "$SERVICE_USER" && "$env_owner" != '?' ]]; then
        log "WARN: $ENV_FILE is owned by '$env_owner', not the service user '$SERVICE_USER'. THIS run can read it only because it is privileged; netmon-update.service and netmon-checkin.service cannot, and their docker compose calls will fail with 'permission denied'. Fix with:  sudo chown $SERVICE_USER:$SERVICE_GROUP $ENV_FILE"
    fi
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
    log "self-heal: re-cloning $url -> fresh tree for $SERVICE_USER"
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
    # The clone inherits the ownership of whoever is running us; a root-run
    # re-clone left root-owned would swap one dubious-ownership freeze for
    # another. The exec below skips the EXIT trap, so settle it here.
    if [[ "$(id -u)" -eq 0 && "$SERVICE_USER" != "root" ]]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$fresh" 2>/dev/null || true
    fi

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

# A dirty working tree used to be an unconditional refusal ("we'd lose local
# changes"). On a sensor APPLIANCE that default is wrong and strands the box on
# old code forever: there are no legitimate local edits (all config lives in
# /etc/netmon + /var/lib/netmon — the checkout is pure code), yet a repo cloned
# by a different user than the one running this script leaves permanent exec-bit
# / filemode drift that git reports as modified. That "dirt" is never real, but
# the guard refused every nightly run (Cucamonga elem-mdf + datacenter sat 16h+
# stuck on 2026-07-29, "No version reported"). Self-heal instead of refusing —
# this is exactly what docs/help/recover-stuck-sensor tells an admin to do by
# hand, done automatically:
#   1. stop counting exec-bit/filemode drift as a change (core.fileMode false)
#   2. if the tree is STILL dirty, hard-reset to HEAD — safe here: pure code,
#      nothing to preserve. `git reset --hard` also re-normalizes file modes.
# Only a tree that survives BOTH steps (e.g. reset failed on a read-only repo)
# still blocks, so a genuinely unwritable repo is surfaced, not silently ignored.
git config core.fileMode false 2>/dev/null || true
if [[ -n "$(git status --porcelain)" ]]; then
    log "working tree dirty after normalizing filemode; restoring to HEAD (appliance checkout is pure code — see docs/help/recover-stuck-sensor)"
    git reset --hard 2>/dev/null || true
    # `reset --hard` does NOT remove UNTRACKED files, so one stray file (nohup.out,
    # a .orig from a failed merge, an operator's scratch copy) would leave the tree
    # permanently dirty and re-wedge the box exactly the way the Cucamonga exec-bit
    # did. -d also clears untracked directories.
    # Deliberately NOT -x: gitignored state must survive — above all the repo-root
    # .env that pins NETMON_IMAGE_TAG, which every later compose call reads.
    git clean -fd 2>/dev/null || true
fi
if [[ -n "$(git status --porcelain)" ]]; then
    log "FATAL: working tree still dirty after self-heal (fileMode + reset + clean); refusing to auto-update"
    log "Resolve manually:  cd $REPO_DIR && git status"
    RESULT_STATUS="failed"; RESULT_REASON="working tree still dirty after self-heal (fileMode+reset+clean); refusing to auto-update"
    exit 2
fi

# 1. Fetch latest refs. Distinguish a genuine network failure from a lingering
# ownership problem (REL-2) so the journal says something actionable.
if ! fetch_err="$(git fetch --quiet origin main 2>&1)"; then
    if printf '%s' "$fetch_err" | grep -qi "dubious ownership"; then
        log "git fetch failed: dubious repo ownership persists after self-heal. Run:  sudo chown -R $SERVICE_USER:$SERVICE_GROUP $REPO_DIR"
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
