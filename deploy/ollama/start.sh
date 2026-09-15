#!/bin/sh
# The only supported startup path: validate the host bind before publishing it.
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$directory"

# Compose reads .env itself. Read only the bind address when it was not supplied
# explicitly, so preflight validates the same value before Docker is invoked.
if [ "${OLLAMA_LAN_IP+x}" != x ]; then
    [ -r .env ] || {
        printf '%s\n' "ollama start: set OLLAMA_LAN_IP or create a readable .env" >&2
        exit 64
    }
    found=0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            OLLAMA_LAN_IP=*)
                [ "$found" -eq 0 ] || {
                    printf '%s\n' "ollama start: .env must contain exactly one OLLAMA_LAN_IP entry" >&2
                    exit 64
                }
                OLLAMA_LAN_IP=${line#OLLAMA_LAN_IP=}
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
