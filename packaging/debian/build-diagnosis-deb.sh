#!/usr/bin/env bash
set -euo pipefail

# Build the optional diagnosis companion package from an already-built binary.
# Installation deliberately does not enable its user service.

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
  echo "Expected an executable syslens-diagnosis binary at ${BINARY}" >&2
  exit 2
fi

ROOT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DIRECTORY="$(mktemp -d)"
PACKAGE_PATH="${OUTPUT_DIRECTORY}/syslens-diagnosis_${VERSION}_${ARCHITECTURE}.deb"
trap 'rm -rf "${STAGING_DIRECTORY}"' EXIT

mkdir -p \
  "${STAGING_DIRECTORY}/DEBIAN" \
  "${STAGING_DIRECTORY}/usr/bin" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-diagnosis"

install -m 0755 "${BINARY}" "${STAGING_DIRECTORY}/usr/bin/syslens-diagnosis"
install -m 0644 "${ROOT_DIRECTORY}/packaging/debian/syslens-diagnosis.service" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user/syslens-diagnosis.service"
install -m 0644 "${ROOT_DIRECTORY}/packaging/debian/syslens-diagnosis-api.service" \
  "${STAGING_DIRECTORY}/usr/lib/systemd/user/syslens-diagnosis-api.service"
install -m 0644 "${ROOT_DIRECTORY}/LICENSE" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-diagnosis/copyright"
install -m 0644 "${ROOT_DIRECTORY}/README.md" \
  "${STAGING_DIRECTORY}/usr/share/doc/syslens-diagnosis/README.md"

cat >"${STAGING_DIRECTORY}/DEBIAN/control" <<EOF
Package: syslens-diagnosis
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCHITECTURE}
Maintainer: Radoslav Chobanov
Depends: libc6 (>= 2.34)
Homepage: https://github.com/radoslavchobanov/syslens-core
Description: Optional local diagnosis companion for SysLens
 This optional package records local RAM and process evidence after explicit
 enablement. It has a disabled-by-default user service and no AI dependency.
EOF

mkdir -p "${OUTPUT_DIRECTORY}"
dpkg-deb --root-owner-group --build "${STAGING_DIRECTORY}" "${PACKAGE_PATH}"
echo "Built ${PACKAGE_PATH}"
