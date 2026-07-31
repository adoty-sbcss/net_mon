# lib/validate.sh — input validators and slug helpers.
#
# Source AFTER common.sh.

[[ -n "${_NETMON_VALIDATE_SH:-}" ]] && return 0
_NETMON_VALIDATE_SH=1

# slugify "Big Bear Elementary" -> "big-bear-elementary"
# Rules: lowercase, replace non-alphanumeric runs with single dash,
# trim leading/trailing dashes, collapse multiple dashes.
slugify() {
    local input="$*"
    printf '%s' "$input" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-+/-/g'
}

# is_valid_slug — non-empty, only lowercase a-z 0-9 and dashes, no leading/trailing dash.
is_valid_slug() {
    local s="$1"
    [[ -n "$s" ]] || return 1
    [[ "$s" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]
}

# is_valid_hostname — RFC 1123 subset: labels 1-63 chars, alnum + dash,
# total length <= 253, no leading/trailing dash per label.
is_valid_hostname() {
    local h="$1"
    [[ -n "$h" ]] || return 1
    [[ ${#h} -le 253 ]] || return 1
    [[ "$h" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$ ]]
}

# is_valid_ipv4
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    local -a parts=($ip)
    for p in "${parts[@]}"; do
        (( p >= 0 && p <= 255 )) || return 1
    done
    return 0
}

# is_valid_port — integer in 1..65535
is_valid_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p >= 1 && p <= 65535 ))
}
