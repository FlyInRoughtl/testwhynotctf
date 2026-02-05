#!/usr/bin/env bash
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "Go not found. Attempting to install via apt..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y golang-go
  else
    echo "Go is required. Install from your package manager or https://go.dev/dl/"
    exit 1
  fi
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PROJ_DIR="$ROOT_DIR/os/ctfvault"
BIN_DIR="$PROJ_DIR/bin"

mkdir -p "$BIN_DIR"

cd "$PROJ_DIR"
go mod download
go build -o "$BIN_DIR/gargoyle" ./cmd/gargoyle
go build -o "$BIN_DIR/gargoylectl" ./cmd/gargoylectl

echo "Build complete: $BIN_DIR"
