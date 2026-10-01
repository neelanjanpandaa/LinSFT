#!/usr/bin/env bash
# One-command demo: builds if needed, seeds demo accounts (once), starts the server in the
# background and launches the GUI (or the CLI if the GUI is unavailable). Ctrl+C / closing the
# client stops the server gracefully.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x ./network-file-server ] || ./scripts/build.sh
mkdir -p data storage logs config

if [ ! -f config/demo-credentials.txt ] || [ "${1:-}" = "--reset" ]; then
  echo "Creating demo accounts..."
  ./network-file-server --seed-demo
fi
echo
echo "Demo credentials (config/demo-credentials.txt):"
sed 's/^/  /' config/demo-credentials.txt | grep -v '^  #'
echo "You can also click 'Register' in the client to create your own STUDENT account."
echo

./network-file-server --quiet &
SRV=$!
trap 'kill -INT $SRV 2>/dev/null; wait $SRV 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/9090) 2>/dev/null && break; sleep 0.1; done

if [ -x ./network-file-gui ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  ./network-file-gui
else
  echo "(GUI unavailable or no display - starting the CLI client)"
  ./network-file-client
fi
