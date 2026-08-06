#!/usr/bin/env bash
set -euo pipefail

SOURCE_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${SOURCE_PATH}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${HOME}/.local/bin"
TARGET_NAME="syslens-core"

if [[ "${1:-}" == "--activate" ]]; then
  TARGET_NAME="syslens"
elif [[ -n "${1:-}" ]]; then
  echo "Usage: $0 [--activate]" >&2
  echo "  default: install as ~/.local/bin/syslens-core" >&2
  echo "  --activate: install as ~/.local/bin/syslens after Plasma migration" >&2
  exit 2
fi

cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml"
mkdir -p "${TARGET_DIR}"
install -m 0755 "${ROOT_DIR}/target/release/syslens" "${TARGET_DIR}/${TARGET_NAME}"
echo "Installed ${TARGET_DIR}/${TARGET_NAME}"
