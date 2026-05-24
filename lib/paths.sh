# lib/paths.sh — canonical NetMon filesystem paths + migration from the
# old in-repo layout to the new /etc + /var Linux-conventional layout.
#
# Source AFTER common.sh:
#     . "$DIR/lib/common.sh"
#     . "$DIR/lib/paths.sh"
#
# Provides path constants and two entry points:
#   - ensure_paths   — create the canonical directories with correct ownership
#                      and run migrate_from_repo if old in-repo files exist
#   - migrate_from_repo
#                    — one-shot move of legacy in-repo files into the new
#                      layout. Idempotent. Safe to call every invocation.

[[ -n "${_NETMON_PATHS_SH:-}" ]] && return 0
_NETMON_PATHS_SH=1

# Canonical paths. The collector container mounts these as-is.
NETMON_ETC_DIR="/etc/netmon"
NETMON_ENV_FILE="${NETMON_ETC_DIR}/netmon.env"
NETMON_SNMP_FILE="${NETMON_ETC_DIR}/snmp.yaml"

NETMON_VAR_DIR="/var/lib/netmon"
NETMON_BUNDLES_DIR="${NETMON_VAR_DIR}/bundles"
NETMON_DB_SNAPSHOTS_DIR="${NETMON_VAR_DIR}/db-snapshots"

NETMON_LOG_DIR="/var/log/netmon"

# Owner for the config + state trees. We pick the user who invoked the script
# (via SUDO_USER if running under sudo, else $USER). That user must already be
# in the docker group for the container ops in ./netmon to work without sudo.
NETMON_OWNER_USER="${SUDO_USER:-${USER:-$(id -un)}}"

ensure_paths() {
    # Create the canonical directory tree if missing.
    $SUDO install -d -m 750 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" "$NETMON_ETC_DIR"
    $SUDO install -d -m 755 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" "$NETMON_VAR_DIR"
    $SUDO install -d -m 755 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" "$NETMON_BUNDLES_DIR"
    $SUDO install -d -m 755 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" "$NETMON_DB_SNAPSHOTS_DIR"
    $SUDO install -d -m 755 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" "$NETMON_LOG_DIR"

    # Then sweep any legacy in-repo files into place.
    migrate_from_repo
}

migrate_from_repo() {
    # Idempotent: each `mv` is guarded by "src exists AND dst doesn't."
    # Repo root is the caller's CWD (setup.sh and friends cd to it before sourcing).
    local repo_root="${PWD}"
    local moved=0

    # 1. .env -> /etc/netmon/netmon.env
    if [[ -f "${repo_root}/.env" ]] && [[ ! -f "$NETMON_ENV_FILE" ]]; then
        log "migrating: .env -> $NETMON_ENV_FILE"
        $SUDO install -m 600 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" \
            "${repo_root}/.env" "$NETMON_ENV_FILE"
        rm -f "${repo_root}/.env"
        moved=1
    fi

    # 2. config/snmp.yaml -> /etc/netmon/snmp.yaml
    if [[ -f "${repo_root}/config/snmp.yaml" ]] && [[ ! -f "$NETMON_SNMP_FILE" ]]; then
        log "migrating: config/snmp.yaml -> $NETMON_SNMP_FILE"
        $SUDO install -m 644 -o "$NETMON_OWNER_USER" -g "$NETMON_OWNER_USER" \
            "${repo_root}/config/snmp.yaml" "$NETMON_SNMP_FILE"
        rm -f "${repo_root}/config/snmp.yaml"
        moved=1
    fi

    # 3. bundles/ -> /var/lib/netmon/bundles/
    if [[ -d "${repo_root}/bundles" ]] && [[ -n "$(ls -A "${repo_root}/bundles" 2>/dev/null)" ]]; then
        log "migrating: bundles/ contents -> $NETMON_BUNDLES_DIR/"
        # Move file-by-file so a partial move doesn't leave a non-empty src
        # blocking re-run. cp+rm pattern survives cross-filesystem moves too.
        find "${repo_root}/bundles" -mindepth 1 -maxdepth 1 -print0 | \
            while IFS= read -r -d '' f; do
                local base
                base="$(basename "$f")"
                if [[ ! -e "${NETMON_BUNDLES_DIR}/${base}" ]]; then
                    $SUDO mv "$f" "${NETMON_BUNDLES_DIR}/${base}"
                fi
            done
        moved=1
    fi

    # 4. logs/ -> /var/log/netmon/
    if [[ -d "${repo_root}/logs" ]] && [[ -n "$(ls -A "${repo_root}/logs" 2>/dev/null)" ]]; then
        log "migrating: logs/ contents -> $NETMON_LOG_DIR/"
        find "${repo_root}/logs" -mindepth 1 -maxdepth 1 -print0 | \
            while IFS= read -r -d '' f; do
                local base
                base="$(basename "$f")"
                if [[ ! -e "${NETMON_LOG_DIR}/${base}" ]]; then
                    $SUDO mv "$f" "${NETMON_LOG_DIR}/${base}"
                fi
            done
        moved=1
    fi

    # 5. Clean up empty legacy directories so they don't get re-created
    # by accidental relative paths in user shell history.
    for legacy in bundles logs; do
        if [[ -d "${repo_root}/${legacy}" ]] && [[ -z "$(ls -A "${repo_root}/${legacy}" 2>/dev/null)" ]]; then
            rmdir "${repo_root}/${legacy}" 2>/dev/null || true
        fi
    done
    # config/ stays — it still holds snmp.yaml.example as a reference template
    # that's part of the repo, not user state.

    if [[ $moved -eq 1 ]]; then
        ok "legacy in-repo state migrated to /etc/netmon and /var/lib/netmon"
    fi
}
