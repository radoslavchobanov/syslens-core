#!/usr/bin/env bash
set -euo pipefail

# Build a signed, static Debian repository from one or more already-built
# SysLens .deb packages.  It intentionally has no network access: CI supplies
# the packages and pushes the resulting static tree to the hosting branch.

usage() {
  cat <<'EOF'
Usage: build-repository.sh --repository <directory> --packages <directory> \
  --signing-key <fingerprint> [options]

Required:
  --repository <directory>  Repository root to create/update.
  --packages <directory>    Directory containing SysLens .deb artifacts.
  --signing-key <value>     Imported GPG signing key fingerprint or key ID.

Optional:
  --suite <name>            APT suite (default: stable).
  --component <name>        APT component (default: main).
  --origin <name>           Release Origin (default: SysLens).
  --label <name>            Release Label (default: SysLens).

Required commands: dpkg-scanpackages, apt-ftparchive, gpg.
EOF
}

REPOSITORY=""
PACKAGES=""
SIGNING_KEY=""
SUITE="stable"
COMPONENT="main"
ORIGIN="SysLens"
LABEL="SysLens"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repository) REPOSITORY="${2:?missing value for --repository}"; shift 2 ;;
    --packages) PACKAGES="${2:?missing value for --packages}"; shift 2 ;;
    --signing-key) SIGNING_KEY="${2:?missing value for --signing-key}"; shift 2 ;;
    --suite) SUITE="${2:?missing value for --suite}"; shift 2 ;;
    --component) COMPONENT="${2:?missing value for --component}"; shift 2 ;;
    --origin) ORIGIN="${2:?missing value for --origin}"; shift 2 ;;
    --label) LABEL="${2:?missing value for --label}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for required in dpkg-scanpackages apt-ftparchive gpg; do
  command -v "${required}" >/dev/null || {
    echo "Missing required command: ${required}" >&2
    exit 1
  }
done

[[ -n "${REPOSITORY}" && -n "${PACKAGES}" && -n "${SIGNING_KEY}" ]] || {
  usage >&2
  exit 2
}
[[ -d "${PACKAGES}" ]] || {
  echo "Package directory does not exist: ${PACKAGES}" >&2
  exit 1
}

mapfile -d '' DEB_PACKAGES < <(find "${PACKAGES}" -type f -name 'syslens-core_*.deb' -print0 | sort -z)
[[ ${#DEB_PACKAGES[@]} -gt 0 ]] || {
  echo "No syslens-core .deb artifacts found in ${PACKAGES}" >&2
  exit 1
}

POOL_DIRECTORY="${REPOSITORY}/pool/${COMPONENT}/s/syslens-core"
DISTS_DIRECTORY="${REPOSITORY}/dists/${SUITE}"
mkdir -p "${POOL_DIRECTORY}" "${DISTS_DIRECTORY}"

for package in "${DEB_PACKAGES[@]}"; do
  install -m 0644 "${package}" "${POOL_DIRECTORY}/$(basename "${package}")"
done

for architecture in amd64 arm64; do
  binary_directory="${DISTS_DIRECTORY}/${COMPONENT}/binary-${architecture}"
  mkdir -p "${binary_directory}"
  (
    cd "${REPOSITORY}"
    dpkg-scanpackages --arch "${architecture}" pool /dev/null >"${binary_directory}/Packages"
  )
  gzip --no-name --force --best --stdout "${binary_directory}/Packages" >"${binary_directory}/Packages.gz"
  xz --check=crc32 --force --stdout "${binary_directory}/Packages" >"${binary_directory}/Packages.xz"
done

release_file="${DISTS_DIRECTORY}/Release"
apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=${ORIGIN}" \
  -o "APT::FTPArchive::Release::Label=${LABEL}" \
  -o "APT::FTPArchive::Release::Suite=${SUITE}" \
  -o "APT::FTPArchive::Release::Codename=${SUITE}" \
  -o "APT::FTPArchive::Release::Components=${COMPONENT}" \
  -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
  release "${DISTS_DIRECTORY}" >"${release_file}"

gpg_arguments=(--batch --yes --local-user "${SIGNING_KEY}")
if [[ -n "${SYSLENS_APT_SIGNING_PASSPHRASE:-}" ]]; then
  gpg_arguments+=(--pinentry-mode loopback --passphrase "${SYSLENS_APT_SIGNING_PASSPHRASE}")
fi

gpg "${gpg_arguments[@]}" \
  --armor --detach-sign --output "${DISTS_DIRECTORY}/Release.gpg" "${release_file}"
gpg "${gpg_arguments[@]}" \
  --clearsign --output "${DISTS_DIRECTORY}/InRelease" "${release_file}"
gpg --batch --yes --export "${SIGNING_KEY}" >"${REPOSITORY}/syslens-archive-keyring.gpg"

echo "Updated signed repository: ${REPOSITORY}"
