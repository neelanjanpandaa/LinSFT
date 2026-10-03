#!/bin/bash
# Real runtime verification of the securemon kernel module on a REAL Linux VM.
#   sudo scripts/vm_verify_driver.sh
# Raw command output goes to evidence/driver/. Nothing here edits the driver or application code.
# Statuses: PASS / FAIL / BLOCKED. A step is PASS only if its command really succeeded.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; EV="$ROOT/evidence/driver"; mkdir -p "$EV"
DRV="$ROOT/driver"; KO="$DRV/securemon.ko"; PORT=$((20000 + RANDOM % 20000))
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 2; }
R="$EV/summary.tsv"; : > "$R"
res() { printf '%-16s %-8s %s\n' "$1" "$2" "$3" | tee -a "$R"; }
run() { echo "\$ $*"; "$@" 2>&1; echo "[rc=$?]"; echo; }
cleanup() { [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null; rm -rf "${W:-/nonexistent}"; }
trap cleanup EXIT

# 1. environment
{ run uname -a; run uname -r; run cat /etc/os-release; run ls -ld "/lib/modules/$(uname -r)/build"
  run gcc --version; run make --version; run lsmod; } > "$EV/kernel-info.txt" 2>&1
[ -f "$DRV/securemon.c" ] && res source PASS "driver/securemon.c present" || { res source FAIL "missing"; exit 1; }
if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
  res headers BLOCKED "no /lib/modules/$(uname -r)/build (apt install linux-headers-$(uname -r), or kernel/headers mismatch)"; exit 1; fi
res headers PASS "$(uname -r)"

# 2. build
{ run make -C "$DRV" clean; run make -C "$DRV"; } > "$EV/build.txt" 2>&1
[ -f "$KO" ] || { res build FAIL "no securemon.ko; see build.txt"; exit 1; }
res build PASS "securemon.ko built"
{ run file "$KO"; run modinfo "$KO"; } > "$EV/modinfo.txt" 2>&1
VM="$(modinfo -F vermagic "$KO")"
case "$VM" in "$(uname -r) "*) res vermagic PASS "$VM";; *) res vermagic FAIL "$VM  !=  $(uname -r)";; esac

# 3. negative: device before load
lsmod | grep -q '^securemon ' && rmmod securemon
{ run ls -l /dev/securemon; run cat /dev/securemon; } > "$EV/negative-before-load.txt" 2>&1
[ ! -e /dev/securemon ] && res neg_before_load PASS "device absent before insmod" || res neg_before_load FAIL "device exists before load"

# 4. load
dmesg -C 2>/dev/null
{ run insmod "$KO"; run lsmod; run dmesg; } > "$EV/load.txt" 2>&1
lsmod | grep -q '^securemon ' || { res load FAIL "see load.txt (Secure Boot signature? vermagic? dmesg)"; exit 1; }
res load PASS "lsmod lists securemon"; sleep 1

# 5. device node
{ run ls -l /dev/securemon; run stat -c 'type=%F rdev(hex)=%t:%T mode=%a' /dev/securemon
  run grep securemon /proc/devices; run ls -l /sys/class/securemon/; } > "$EV/device.txt" 2>&1
[ -c /dev/securemon ] && res devnode PASS "$(ls -l /dev/securemon)" || { res devnode FAIL "missing"; exit 1; }

# 6. user-space read + compare with /proc
D="$(cat /dev/securemon 2>&1)"
{ echo "--- driver output"; echo "$D"; echo "--- /proc/meminfo"; grep -E 'MemTotal|MemFree' /proc/meminfo
  echo "--- nproc / uptime / release / page size"; nproc; cut -d' ' -f1 /proc/uptime; uname -r; getconf PAGESIZE; } > "$EV/runtime-test.txt" 2>&1
echo "$D" | grep -q '^securemon_version=' && res read PASS "key=value text returned" || res read FAIL "bad data"
g() { echo "$D" | sed -n "s/^$1=//p"; }
[ "$(g kernel_release)" = "$(uname -r)" ] && res cmp_release PASS "$(uname -r)" || res cmp_release FAIL "$(g kernel_release) vs $(uname -r)"
[ "$(g online_cpus)" = "$(nproc)" ] && res cmp_cpus PASS "$(nproc)" || res cmp_cpus FAIL "$(g online_cpus) vs $(nproc)"
[ "$(g page_size)" = "$(getconf PAGESIZE)" ] && res cmp_pagesize PASS "$(getconf PAGESIZE)" || res cmp_pagesize FAIL "$(g page_size) vs $(getconf PAGESIZE)"
MT=$(g mem_total_kb); PT=$(awk '/MemTotal/{print $2}' /proc/meminfo)
if [ -n "$MT" ] && [ "$MT" -le "$PT" ] && [ "$MT" -ge $((PT - PT/10)) ] 2>/dev/null; then res cmp_memtotal PASS "driver ${MT} kB vs /proc ${PT} kB (both derive from the kernel total-RAM page count)"
else res cmp_memtotal FAIL "driver '${MT}' vs /proc '${PT}'"; fi

# 7. negative: write (no .write op), 50x open/read/close
{ run bash -c 'echo x > /dev/securemon'; ok=0; for i in $(seq 1 50); do cat /dev/securemon >/dev/null && ok=$((ok+1)); done
  echo "50x open/read/close: $ok succeeded"; cat /dev/securemon | grep -E 'device_opens|device_reads'; } > "$EV/negative-runtime.txt" 2>&1
grep -q "50 succeeded" "$EV/negative-runtime.txt" && res repeat_open PASS "50/50 open/read/close" || res repeat_open FAIL "see negative-runtime.txt"
grep -qE "Permission denied|Invalid argument|Operation not permitted" "$EV/negative-runtime.txt" && res neg_write PASS "write rejected (no .write op / mode 0444)" || res neg_write FAIL "write not rejected? see file"

# 8. LinSFT integration: real server + real CLI client read the driver through SYSINFO
SRV="$ROOT/build/network-file-server"; CLI="$ROOT/build/network-file-client"
if [ -x "$SRV" ] && [ -x "$CLI" ]; then
  W="$(mktemp -d /tmp/linsft-drv-XXXXXX)"; mkdir -p "$W/data" "$W/logs" "$W/storage" "$W/config"
  printf 'port = %s\nstorage_dir = storage\ndb_path = data/l.db\nlog_path = logs/s.log\npbkdf2_iterations = 2000\ndriver_path = /dev/securemon\n' "$PORT" > "$W/server.conf"
  ( cd "$W" && "$SRV" --config server.conf --seed-demo > "$EV/integration-seed.txt" 2>&1 )
  FAC=$(awk '/^faculty1 /{print $3}' "$W/config/demo-credentials.txt")
  ( cd "$W" && "$SRV" --config server.conf > "$EV/integration-server.log" 2>&1 & echo $! > "$W/pid" ); SP=$(cat "$W/pid")
  for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done
  printf 'faculty1\n%s\nSYSINFO\nQUIT\n' "$FAC" | "$CLI" 127.0.0.1 "$PORT" --prompt-login > "$EV/integration.txt" 2>&1
  { echo "--- dmesg securemon"; dmesg | grep securemon | tail -20; } >> "$EV/integration.txt"
  grep -q "securemon driver *online" "$EV/integration.txt" && res integration PASS "SYSINFO shows securemon driver online + values from kernel" || res integration FAIL "see integration.txt"
  dmesg | grep -q "securemon: device opened" && res dmesg_activity PASS "driver logged opens" || res dmesg_activity FAIL "no activity in dmesg"
  kill -INT "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; SP=""
else
  res integration BLOCKED "build the project first: cmake -S . -B build && cmake --build build -j\$(nproc)"
fi

# 9. unload + repeatability + kernel error scan
{ run rmmod securemon; run lsmod; run ls -l /dev/securemon; run dmesg | tail -n 15
  for c in 1 2 3; do echo "== cycle $c"; insmod "$KO" && sleep 0.5 && cat /dev/securemon >/dev/null && rmmod securemon && echo "cycle $c ok" || echo "cycle $c FAILED"; done
  echo "== kernel log scan"; dmesg | grep -iE 'bug:|oops|call trace|warning|panic|leak' || echo "(no matches)"; } > "$EV/unload.txt" 2>&1
lsmod | grep -q '^securemon ' && res unload FAIL "still loaded" || res unload PASS "rmmod ok"
[ -e /dev/securemon ] && res devnode_removed FAIL "still present" || res devnode_removed PASS "/dev/securemon gone"
[ "$(grep -c 'ok$' "$EV/unload.txt")" -ge 3 ] && ! grep -q FAILED "$EV/unload.txt" && res repeat_cycles PASS "3 load/read/unload cycles" || res repeat_cycles FAIL "see unload.txt"
sed -n '/kernel log scan/,$p' "$EV/unload.txt" | grep -q "(no matches)" && res kernel_errors PASS "no bug/oops/warning in dmesg" || res kernel_errors FAIL "see unload.txt"
cp "$R" "$EV/final-result.txt"; echo; echo "Evidence written to $EV"
