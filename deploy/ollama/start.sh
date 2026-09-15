#!/bin/sh
# The only supported startup path: validate the host bind before publishing it.
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$directory"
./preflight.sh
exec docker compose up -d --wait ollama "$@"
