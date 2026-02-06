#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CTF_DIR="$ROOT_DIR/os/ctfvault"

has_cmd() { command -v "$1" >/dev/null 2>&1; }

echo "[deps] Gargoyle Linux dependencies (best-effort)"

if ! has_cmd sudo; then
  echo "[deps] sudo not found. Run as root or install sudo."
  exit 1
fi

if has_cmd apt-get; then
  echo "[deps] Updating apt indexes..."
  sudo apt-get update -y
else
  echo "[deps] apt-get not found. Install packages manually for your distro."
fi

if ! has_cmd go; then
  if has_cmd apt-get; then
    echo "[deps] Installing Go (golang-go)..."
    sudo apt-get install -y golang-go
  else
    echo "[deps] Go not found. Install Go 1.24+ manually."
  fi
else
  echo "[deps] Go already installed: $(go version)"
fi

if has_cmd apt-get; then
  required=(
    whiptail sgdisk cryptsetup e2fsprogs exfatprogs
    iptables ufw network-manager curl git ca-certificates
    xz-utils tar
  )
  optional=(
    tor openvpn wireguard-tools
    postfix dovecot-core
    bubblewrap cage gamescope weston
    tshark avahi-utils
    wl-clipboard xclip
    python3-pip
  )

  echo "[deps] Installing required packages..."
  for pkg in "${required[@]}"; do
    sudo apt-get install -y "$pkg" || echo "[deps] WARN: failed to install $pkg"
  done

  echo "[deps] Installing optional packages (best-effort)..."
  for pkg in "${optional[@]}"; do
    sudo apt-get install -y "$pkg" || echo "[deps] WARN: failed to install $pkg"
  done
fi

if has_cmd go; then
  echo "[deps] Downloading Go modules..."
  (cd "$CTF_DIR" && go mod download)
fi

echo "[deps] Done."
