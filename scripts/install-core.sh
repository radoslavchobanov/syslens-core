#!/usr/bin/env bash
set -euo pipefail

SOURCE_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${SOURCE_PATH}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${HOME}/.local/bin"
TARGET_NAME="syslens"

if [[ -n "${1:-}" && "${1:-}" != "--activate" ]]; then
  echo "Usage: $0 [--activate]" >&2
  echo "  installs ~/.local/bin/syslens" >&2
  echo "  --activate is accepted for compatibility and has no additional effect" >&2
  exit 2
fi

cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml"
mkdir -p "${TARGET_DIR}"
install -m 0755 "${ROOT_DIR}/target/release/syslens" "${TARGET_DIR}/${TARGET_NAME}"
ln -sfn "syslens" "${TARGET_DIR}/syslens-core"
echo "Installed ${TARGET_DIR}/${TARGET_NAME}"
echo "Kept ~/.local/bin/syslens-core as a compatibility alias"
