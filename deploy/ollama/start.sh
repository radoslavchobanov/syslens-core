#!/bin/sh
# The only supported startup path: validate the host bind before publishing it.
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$directory"

space=' '
tab=$(printf '\t')
carriage_return=$(printf '\r')

trim_whitespace() {
    value=$1
    while :; do
        case "$value" in
            "$space"* | "$tab"*) value=${value#?} ;;
            *) break ;;
        esac
    done
    while :; do
        case "$value" in
            *"$space" | *"$tab") value=${value%?} ;;
            *) break ;;
        esac
    done
    printf '%s' "$value"
}

parse_env_value() {
    value=$(trim_whitespace "$1")
    [ -n "$value" ] || return 0

    first=${value%"${value#?}"}
    double_quote='"'
    single_quote="'"
    case "$first" in
        "$double_quote" | "$single_quote")
            remainder=${value#?}
            case "$remainder" in
                *"$first"*)
                    value=${remainder%%"$first"*}
                    remainder=${remainder#*"$first"}
                    remainder=$(trim_whitespace "$remainder")
                    case "$remainder" in
                        '' | \#*) ;;
                        *) return 1 ;;
                    esac
                    ;;
                *) return 1 ;;
            esac
            ;;
        *)
            case "$value" in
                *"$space"\#*) value=${value%%"$space"\#*} ;;
                *"$tab"\#*) value=${value%%"$tab"\#*} ;;
            esac
            value=$(trim_whitespace "$value")
            ;;
    esac
    printf '%s' "$value"
}

# Compose reads .env itself. Read only the bind address when it was not supplied
# explicitly, so preflight validates the same value before Docker is invoked.
if [ "${OLLAMA_LAN_IP+x}" != x ]; then
    [ -r .env ] || {
        printf '%s\n' "ollama start: set OLLAMA_LAN_IP or create a readable .env" >&2
        exit 64
    }
    found=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%"$carriage_return"}
        line=$(trim_whitespace "$line")
        case "$line" in
            export"$space"* | export"$tab"*)
                line=${line#export}
                line=$(trim_whitespace "$line")
                ;;
        esac
        case "$line" in
            *=*)
                key=$(trim_whitespace "${line%%=*}")
                [ "$key" = "OLLAMA_LAN_IP" ] || continue
                [ "$found" -eq 0 ] || {
                    printf '%s\n' "ollama start: .env must contain exactly one OLLAMA_LAN_IP entry" >&2
                    exit 64
                }
                OLLAMA_LAN_IP=$(parse_env_value "${line#*=}") || {
                    printf '%s\n' "ollama start: invalid OLLAMA_LAN_IP syntax in .env" >&2
                    exit 64
                }
                export OLLAMA_LAN_IP
                found=1
                ;;
        esac
    done < .env
    [ "$found" -eq 1 ] || {
        printf '%s\n' "ollama start: set OLLAMA_LAN_IP or add it to .env" >&2
        exit 64
    }
fi
./preflight.sh
exec docker compose up -d --wait ollama "$@"
