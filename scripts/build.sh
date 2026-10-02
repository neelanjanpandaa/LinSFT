#!/usr/bin/env bash
# Clean-or-incremental build. Usage: ./scripts/build.sh [--clean] [--no-gui] [--test]
set -euo pipefail
cd "$(dirname "$0")/.."
GUI=ON; TEST=0
for a in "$@"; do
  case "$a" in
    --clean) rm -rf build ;;
    --no-gui) GUI=OFF ;;
    --test) TEST=1 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done
mkdir -p build
cd build
cmake .. -DLINSFT_BUILD_GUI=$GUI
make -j"$(nproc)"
cd ..
echo
echo "Built: ./file_server (network-file-server)  ./file_client (network-file-client)  $( [ -e network-file-gui ] && echo ./network-file-gui || echo "(GUI skipped)")"
if [ "$TEST" = 1 ]; then
  (cd build && QT_QPA_PLATFORM=offscreen ctest --output-on-failure)
fi
