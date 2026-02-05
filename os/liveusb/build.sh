#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

lb config \
  --distribution bookworm \
  --binary-images iso-hybrid \
  --linux-flavours amd64 \
  --bootappend-live "boot=live toram noeject" \
  --archive-areas "main contrib non-free-firmware" \
  --mirror-bootstrap "http://deb.debian.org/debian/" \
  --mirror-binary "http://deb.debian.org/debian/"

mkdir -p config/includes.chroot/etc/gargoyle
cp -f "${ROOT_DIR}/../ctfvault/gargoyle.yaml.example" config/includes.chroot/etc/gargoyle/gargoyle.yaml

lb build

echo "ISO created in ${BUILD_DIR}"
