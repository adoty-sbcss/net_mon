# lib/menu.sh — small helpers for building consistent text menus.
#
# Source AFTER common.sh.
#
# Usage pattern:
#
#     menu_header "NetMon — Configure"
#     menu_item 1 "Edit SFTP destination"
#     menu_item 2 "Edit SNMP communities"
#     menu_footer "b" "Back" "q" "Quit"
#     choice="$(menu_read)"
#     case "$choice" in
#         1) ... ;;
#         b|B) return ;;
#         q|Q) exit 0 ;;
#     esac

[[ -n "${_NETMON_MENU_SH:-}" ]] && return 0
_NETMON_MENU_SH=1

menu_header() {
    local title="$1"
    local width=46
    local padded
    padded="$(printf "%-${width}s" "$title")"
    echo ""
    printf '%s╔══════════════════════════════════════════════╗%s\n' "$C_HEAD" "$C_OFF"
    printf '%s║ %s ║%s\n' "$C_HEAD" "$padded" "$C_OFF"
    printf '%s╠══════════════════════════════════════════════╣%s\n' "$C_HEAD" "$C_OFF"
}

menu_item() {
    local num="$1" label="$2"
    printf '   %3s) %s\n' "$num" "$label"
}

menu_section() {
    local label="$1"
    printf '\n   %s%s%s\n' "$C_DIM" "$label" "$C_OFF"
}

menu_footer() {
    # Args: pairs of (key, label).
    echo ""
    while [[ $# -ge 2 ]]; do
        printf '   %3s) %s\n' "$1" "$2"
        shift 2
    done
    printf '%s╚══════════════════════════════════════════════╝%s\n' "$C_HEAD" "$C_OFF"
}

menu_read() {
    local choice
    read -r -p "Choice: " choice || choice="q"
    printf '%s' "$choice"
}

menu_pause() {
    echo ""
    read -r -p "Press Enter to continue..." _ || true
}
