#!/usr/bin/env bash
set -euo pipefail

# Build a minimal architecture-specific Debian package from an already-built
# SysLens binary. This script deliberately has no cargo dependency so release
# automation can build first and package the exact resulting artifact.

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <binary> <version> <amd64|arm64> <output-directory>" >&2
  exit 2
fi

BINARY="$1"
VERSION="$2"
ARCHITECTURE="$3"
OUTPUT_DIRECTORY="$4"

case "${ARCHITECTURE}" in
  amd64|arm64) ;;
  *)
    echo "Unsupported Debian architecture: ${ARCHITECTURE}" >&2
    exit 2
    ;;
esac

if [[ ! -x "${BINARY}" ]]; then
  echo "Expected an executable SysLens binary at ${BINARY}" >&2
  exit 2
fi

ROOT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DIRECTORY="$(mktemp -d)"
PACKAGE_NAME="syslens-core_${VERSION}_${ARCHITECTURE}.deb"
PACKAGE_PATH="${OUTPUT_DIRECTORY}/${PACKAGE_NAME}"
trap 'rm -rf "${STAGING_DIRECTORY}"' EXIT

mkdir -p \
  "${STAGING_DIRECTORY}/DEBIAN" \
  "${STAGING_DIRECTORY}/usr/bin" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-core"

install -m 0755 "${BINARY}" "${STAGING_DIRECTORY}/usr/bin/syslens"
install -m 0644 "${ROOT_DIRECTORY}/packaging/debian/syslens.service" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user/syslens.service"
install -m 0644 "${ROOT_DIRECTORY}/LICENSE" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-core/copyright"
install -m 0644 "${ROOT_DIRECTORY}/README.md" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-core/README.md"

cat >"${STAGING_DIRECTORY}/DEBIAN/control" <<EOF
Package: syslens-core
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCHITECTURE}
Maintainer: Radoslav Chobanov
Depends: libc6 (>= 2.34)
Homepage: https://github.com/radoslavchobanov/syslens-core
Description: Lightweight Linux telemetry collector for SysLens
 SysLens reads Linux kernel and sysfs telemetry, keeps compact local history,
 and can publish retained snapshots through MQTT. The package installs the
 syslens command; MQTT configuration remains per-user and opt-in.
EOF

mkdir -p "${OUTPUT_DIRECTORY}"
dpkg-deb --root-owner-group --build "${STAGING_DIRECTORY}" "${PACKAGE_PATH}"
echo "Built ${PACKAGE_PATH}"
