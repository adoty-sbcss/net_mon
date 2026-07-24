# lib/lifecycle.sh — recovery + maintenance actions:
#   - rollback          (delegates to scripts/rollback.sh)
#   - quick_rebuild     (compose down + rm + build + up; keeps DB + config)
#   - factory_reset     (wipe DB volume + /etc/netmon + /var/lib/netmon)
#
# Sourced by ./netmon. Each function logs what it's doing and asks for
# confirmation before destructive steps. Functions return 0 on success,
# non-zero on cancel or failure.
#
# Source AFTER common.sh, paths.sh.

[[ -n "${_NETMON_LIFECYCLE_SH:-}" ]] && return 0
_NETMON_LIFECYCLE_SH=1

# DC array set by the calling script (./netmon defines it).
_dc() {
    if [[ -n "${DC[*]:-}" ]]; then
        "${DC[@]}" "$@"
    else
        docker compose "$@"
    fi
}

lifecycle_rollback() {
    echo ""
    printf '%s== Rollback ==%s\n' "$C_HEAD" "$C_OFF"
    echo "Reverts the box to the last known-good state:"
    echo "  - git reset --hard to the previous good SHA"
    echo "  - retag docker image :previous -> :latest"
    echo "  - restore DB from the most recent pre-update snapshot"
    echo ""
    local sha_file="/var/lib/netmon/last-known-good-sha"
    if [[ ! -f "$sha_file" ]]; then
        printf '%sNo rollback target available.%s\n' "$C_WARN" "$C_OFF"
        echo "  ($sha_file does not exist — auto-update has never recorded a target)"
        return 1
    fi
    local target
    target="$(cat "$sha_file")"
    echo "Rollback target: $target"
    echo ""
    read -r -p "Type ROLLBACK to confirm: " confirm || confirm=""
    if [[ "$confirm" != "ROLLBACK" ]]; then
        echo "(cancelled)"
        return 1
    fi
    if [[ -x ./scripts/rollback.sh ]]; then
        sudo ./scripts/rollback.sh
    else
        echo "ERROR: scripts/rollback.sh missing or not executable" >&2
        return 1
    fi
}

lifecycle_quick_rebuild() {
    echo ""
    printf '%s== Quick rebuild ==%s\n' "$C_HEAD" "$C_OFF"
    echo "Stops containers, removes the collector image, rebuilds from current"
    echo "source, brings everything back up. Preserves:"
    echo "  - /etc/netmon/netmon.env (SFTP creds, identity, settings)"
    echo "  - postgres volume (all scan history)"
    echo "  - /var/log/netmon/ (audit + collector logs)"
    echo ""
    echo "Use this when the collector container is in a weird state but you"
    echo "don't want to lose any data."
    echo ""
    read -r -p "Type REBUILD to confirm: " confirm || confirm=""
    if [[ "$confirm" != "REBUILD" ]]; then
        echo "(cancelled)"
        return 1
    fi
    printf '%s==>%s stopping containers...\n' "$C_INFO" "$C_OFF"
    _dc down
    printf '%s==>%s removing collector image...\n' "$C_INFO" "$C_OFF"
    docker image rm netmon/collector:latest 2>/dev/null || true
    printf '%s==>%s rebuilding from current source...\n' "$C_INFO" "$C_OFF"
    _dc build --pull collector
    printf '%s==>%s starting containers...\n' "$C_INFO" "$C_OFF"
    _dc up -d
    printf '%s  ok%s rebuild complete\n' "$C_OK" "$C_OFF"
}

lifecycle_factory_reset() {
    echo ""
    printf '%s== Factory reset ==%s\n' "$C_ERR" "$C_OFF"
    echo "This wipes EVERYTHING except the NetMon repo itself:"
    echo "  - postgres volume (all scan history — GONE)"
    echo "  - /etc/netmon/ (SFTP creds, identity, snmp.yaml — GONE)"
    echo "  - /var/lib/netmon/ (bundles, DB snapshots, sentinels — GONE)"
    echo "  - /var/log/netmon/ (audit + collector logs — GONE)"
    echo "  - docker images for netmon/collector (forces fresh rebuild)"
    echo ""
    echo "After this, the first-boot wizard runs again from scratch."
    echo ""
    printf '%sThere is no config restore: /etc/netmon is a materialization of the%s\n' "$C_INFO" "$C_OFF"
    printf '%sdashboard'"'"'s desired config, which is re-pushed on the next check-in.%s\n' "$C_INFO" "$C_OFF"
    echo ""
    read -r -p "Type RESET to confirm: " confirm || confirm=""
    if [[ "$confirm" != "RESET" ]]; then
        echo "(cancelled)"
        return 1
    fi
    printf '%s==>%s stopping containers + removing volumes...\n' "$C_INFO" "$C_OFF"
    _dc down -v
    printf '%s==>%s removing /etc/netmon/, /var/lib/netmon/, /var/log/netmon/...\n' "$C_INFO" "$C_OFF"
    sudo rm -rf /etc/netmon /var/lib/netmon /var/log/netmon
    printf '%s==>%s removing collector images...\n' "$C_INFO" "$C_OFF"
    docker image rm netmon/collector:latest netmon/collector:previous 2>/dev/null || true

    # Recreate the canonical empty dirs so the next setup.sh / wizard run
    # has somewhere to write.
    ensure_paths >/dev/null 2>&1 || true

    printf '%s  ok%s factory reset done\n' "$C_OK" "$C_OFF"
    echo ""
    echo "Next steps:"
    echo "  1. Run: sudo netmon-wizard         # configure identity + SFTP"
    echo "  2. Run: ./setup.sh                 # rebuilds containers + starts them"
    echo "  3. Re-enroll against the dashboard # it re-pushes this box's desired config"
}
