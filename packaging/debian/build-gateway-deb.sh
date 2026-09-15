#!/usr/bin/env bash
set -euo pipefail

# Build the independent gateway package from an already-built binary. Package
# installation does not create state, configure hosts, or start its service.

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
  *) echo "Unsupported Debian architecture: ${ARCHITECTURE}" >&2; exit 2 ;;
esac

if [[ ! -x "${BINARY}" ]]; then
  echo "Expected an executable syslens-gateway binary at ${BINARY}" >&2
  exit 2
fi

ROOT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DIRECTORY="$(mktemp -d)"
PACKAGE_PATH="${OUTPUT_DIRECTORY}/syslens-gateway_${VERSION}_${ARCHITECTURE}.deb"
trap 'rm -rf "${STAGING_DIRECTORY}"' EXIT

mkdir -p \
  "${STAGING_DIRECTORY}/DEBIAN" \
  "${STAGING_DIRECTORY}/usr/bin" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-gateway"

install -m 0755 "${BINARY}" "${STAGING_DIRECTORY}/usr/bin/syslens-gateway"
install -m 0644 "${ROOT_DIRECTORY}/packaging/debian/syslens-gateway.service" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user/syslens-gateway.service"
install -m 0644 "${ROOT_DIRECTORY}/LICENSE" "${STAGING_DIRECTORY}/usr/share/doc/syslens-gateway/copyright"
install -m 0644 "${ROOT_DIRECTORY}/README.md" "${STAGING_DIRECTORY}/usr/share/doc/syslens-gateway/README.md"

cat >"${STAGING_DIRECTORY}/DEBIAN/control" <<EOF
Package: syslens-gateway
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCHITECTURE}
Maintainer: Radoslav Chobanov
Depends: libc6 (>= 2.34)
Homepage: https://github.com/radoslavchobanov/syslens-core
Description: Optional SysLens evidence gateway and terminal client
 This optional user-owned service polls enrolled mTLS evidence hosts, stores
 bounded event history, and optionally performs AI reasoning. It never starts
 a model and remains disabled until explicitly configured and enabled.
EOF

mkdir -p "${OUTPUT_DIRECTORY}"
dpkg-deb --root-owner-group --build "${STAGING_DIRECTORY}" "${PACKAGE_PATH}"
echo "Built ${PACKAGE_PATH}"
