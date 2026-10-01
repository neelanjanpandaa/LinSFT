#!/usr/bin/env bash
# Installs build dependencies (Ubuntu 24.04 / WSL2) and prepares runtime directories.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v cmake >/dev/null || ! command -v g++ >/dev/null || [ ! -f /usr/include/sqlite3.h ] || ! dpkg -s qt6-base-dev >/dev/null 2>&1; then
  echo "Installing dependencies (sudo required)..."
  sudo apt-get update
  sudo apt-get install -y build-essential cmake pkg-config libsqlite3-dev sqlite3 qt6-base-dev
else
  echo "Dependencies already installed."
fi
mkdir -p data storage logs config
chmod 750 storage data logs
echo "Setup complete. Next: ./scripts/build.sh"
