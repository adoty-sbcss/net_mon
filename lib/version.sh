# lib/version.sh — version helpers (git SHA + commit date + branch).
#
# Used by ./netmon version, the MOTD, the watchdog log, and bundle metadata.
#
# Source AFTER common.sh.

[[ -n "${_NETMON_VERSION_SH:-}" ]] && return 0
_NETMON_VERSION_SH=1

# Locate the NetMon repo. Callers usually cd into it first; if not, we look
# up from the script that sourced us. Falls back to "unknown" gracefully.
_netmon_repo_dir() {
    if git -C "$PWD" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$PWD" rev-parse --show-toplevel
        return
    fi
    # Last resort: check common deployment paths.
    for cand in /home/*/NetMon /opt/NetMon /root/NetMon; do
        [[ -d "$cand/.git" ]] && { printf '%s' "$cand"; return; }
    done
    printf 'unknown'
}

netmon_version_sha() {
    local d
    d="$(_netmon_repo_dir)"
    [[ -d "$d/.git" ]] || { printf 'unknown'; return; }
    git -C "$d" rev-parse --short HEAD 2>/dev/null || printf 'unknown'
}

netmon_version_full_sha() {
    local d
    d="$(_netmon_repo_dir)"
    [[ -d "$d/.git" ]] || { printf 'unknown'; return; }
    git -C "$d" rev-parse HEAD 2>/dev/null || printf 'unknown'
}

netmon_version_date() {
    local d
    d="$(_netmon_repo_dir)"
    [[ -d "$d/.git" ]] || { printf 'unknown'; return; }
    git -C "$d" log -1 --format=%cd --date=short 2>/dev/null || printf 'unknown'
}

netmon_version_branch() {
    local d
    d="$(_netmon_repo_dir)"
    [[ -d "$d/.git" ]] || { printf 'unknown'; return; }
    git -C "$d" rev-parse --abbrev-ref HEAD 2>/dev/null || printf 'unknown'
}

# One-line summary suitable for MOTD or status output: "v=74c3248 (main 2026-05-23)"
netmon_version_summary() {
    printf 'v=%s (%s %s)' \
        "$(netmon_version_sha)" \
        "$(netmon_version_branch)" \
        "$(netmon_version_date)"
}
