#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
GARGOYLE_SRC="${ROOT_DIR}/../ctfvault"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

lb config \
  --mode debian \
  --distribution bookworm \
  --binary-images iso-hybrid \
  --linux-flavours amd64 \
  --bootappend-live "boot=live toram noeject" \
  --archive-areas "main contrib non-free-firmware" \
  --mirror-bootstrap "http://deb.debian.org/debian/" \
  --mirror-binary "http://deb.debian.org/debian/" \
  --mirror-chroot-security "http://security.debian.org/debian-security" \
  --mirror-binary-security "http://security.debian.org/debian-security"

# Overlay Gargoyle liveusb config (packages, hooks, includes).
mkdir -p config
if [ -d "${ROOT_DIR}/config" ]; then
  cp -a "${ROOT_DIR}/config/." config/
fi

# Build Gargoyle binary for the live image.
if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain not found. Install Go to build Gargoyle for the ISO."
  exit 1
fi

mkdir -p config/includes.chroot/usr/local/bin
(cd "${GARGOYLE_SRC}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${BUILD_DIR}/config/includes.chroot/usr/local/bin/gargoyle" ./cmd/gargoyle)

# Copy Gargoyle scripts and default config into the image.
mkdir -p config/includes.chroot/opt/gargoyle/scripts
cp -a "${GARGOYLE_SRC}/scripts/." config/includes.chroot/opt/gargoyle/scripts/

mkdir -p config/includes.chroot/etc/gargoyle
cp -f "${GARGOYLE_SRC}/gargoyle.yaml.example" config/includes.chroot/etc/gargoyle/gargoyle.yaml

lb build

echo "ISO created in ${BUILD_DIR}"
