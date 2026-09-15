#!/bin/sh
# Validate the host-side bind address before Docker sees the Compose project.
set -eu

die() {
    printf '%s\n' "ollama preflight: OLLAMA_LAN_IP must be a literal RFC1918 IPv4 address (10/8, 172.16/12, or 192.168/16)" >&2
    exit 64
}

address=${OLLAMA_LAN_IP:-}

case "$address" in
    '' | .* | *. | *..* | *[!0-9.]*) die ;;
esac

old_ifs=$IFS
IFS=.
set -- $address
IFS=$old_ifs

[ "$#" -eq 4 ] || die

for octet in "$@"; do
    case "$octet" in
        0 | [1-9] | [1-9][0-9] | [1-9][0-9][0-9]) ;;
        *) die ;;
    esac
    [ "$octet" -le 255 ] 2>/dev/null || die
done

case "$1" in
    10) ;;
    172) [ "$2" -ge 16 ] 2>/dev/null && [ "$2" -le 31 ] 2>/dev/null || die ;;
    192) [ "$2" -eq 168 ] 2>/dev/null || die ;;
    *) die ;;
esac

printf '%s\n' "ollama preflight: binding only to private LAN address $address"
