#!/usr/bin/env bash
# End-to-end test of the real binaries: server process + CLI client + SIGINT graceful shutdown.
# Usage: e2e_cli.sh <network-file-server> <network-file-client>
set -u
SERVER="$(readlink -f "$1")"; CLIENT="$(readlink -f "$2")"
WORK="$(mktemp -d /tmp/linsft-e2e-XXXXXX)"
PORT=$((20000 + RANDOM % 20000))
PASS=0; FAILN=0
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill -KILL "$SRV_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
ok()   { PASS=$((PASS+1)); echo "  ok   - $1"; }
bad()  { FAILN=$((FAILN+1)); echo "  FAIL - $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/         | /'; }
expect() { if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1 (missing: $3)" "$2"; fi; }

mkdir -p "$WORK/config" "$WORK/data" "$WORK/logs" "$WORK/storage"
cat > "$WORK/server.conf" <<CONF
port = $PORT
storage_dir = storage
db_path = data/linsft.db
log_path = logs/server.log
pbkdf2_iterations = 2000
CONF
cd "$WORK" || exit 1

echo "== admin initialisation =="
out=$(LINSFT_ADMIN_PASSWORD='Init-Admin-Pass-1' "$SERVER" --config server.conf --init-admin bootadmin 2>&1)
expect "init-admin creates account" "$out" "Admin account 'bootadmin' created"
out=$(LINSFT_ADMIN_PASSWORD='Short' "$SERVER" --config server.conf --init-admin bootadmin2 2>&1)
expect "init-admin rejects weak password" "$out" "failed"
out=$("$SERVER" --config server.conf --seed-demo 2>&1)
expect "seed-demo creates accounts" "$out" "Demo accounts ready"
[ "$(stat -c %a config/demo-credentials.txt)" = "600" ] && ok "credentials file is mode 0600" || bad "credentials file mode"
ADM=$(awk '/^admin /{print $3}' config/demo-credentials.txt)
FAC=$(awk '/^faculty1 /{print $3}' config/demo-credentials.txt)

echo "== server start =="
"$SERVER" --config server.conf --quiet &
SRV_PID=$!
for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done
(exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && ok "server accepts TCP connections" || { bad "server did not start"; exit 1; }

cli() { "$CLIENT" --port "$PORT" 2>&1; }

echo "== normal user flow (STUDENT) =="
head -c 250000 /dev/urandom > "$WORK/blob.bin"
echo "hello from the e2e test" > "$WORK/note.txt"
EXPECT_SHA=$(sha256sum blob.bin | cut -d' ' -f1)
out=$(cli <<EOF
register newbie
Newbie-Pass-9
Newbie-Pass-9
login newbie
Newbie-Pass-9
whoami
ls
mkdir docs
upload $WORK/blob.bin /docs
upload $WORK/note.txt / --shared
ls /docs
info /docs/blob.bin
download /docs/blob.bin $WORK/blob.out
search note
rename note.txt renamed.txt
ls
history
sysinfo
users
upload $WORK/note.txt /../../
mkdir ../escape
rm renamed.txt
rm /docs/blob.bin
rmdir docs
ls
logout
quit
EOF
)
expect "registration works"          "$out" "registered"
expect "login works"                 "$out" "Logged in as newbie (STUDENT)"
expect "mkdir works"                 "$out" "directory created"
expect "upload verified by server"   "$out" "upload complete"
expect "info shows SHA-256"          "$out" "$EXPECT_SHA"
expect "download verified"           "$out" "SHA-256 verified"
expect "search finds file"           "$out" "/note.txt"
expect "rename works"                "$out" "renamed to /renamed.txt"
expect "history lists transfers"     "$out" "UPLOAD"
expect "student denied sysinfo"      "$out" "ERROR [FORBIDDEN]"
expect "delete works"                "$out" "deleted"
expect "rmdir works"                 "$out" "directory removed"
expect "logout works"                "$out" "logged out"
[ "$(sha256sum blob.out | cut -d' ' -f1)" = "$EXPECT_SHA" ] && ok "downloaded bytes identical (sha256sum)" || bad "downloaded bytes differ"
[ ! -e "$WORK/escape" ] && [ ! -e "$WORK/../escape" ] && ok "nothing created outside storage" || bad "escape directory exists"

echo "== wrong password =="
out=$(cli <<EOF
login newbie
wrong-password
ls
quit
EOF
)
expect "bad password rejected" "$out" "AUTH_FAILED"
expect "commands need login"   "$out" "AUTH_REQUIRED"

echo "== faculty and admin features =="
out=$(cli <<EOF
login faculty1
$FAC
sysinfo
history 5
users
quit
EOF
)
expect "faculty sysinfo works"             "$out" "Server uptime"
expect "sysinfo shows /dev/urandom driver" "$out" "urandom"
expect "faculty sees others' history"      "$out" "newbie"
expect "faculty denied user mgmt"          "$out" "FORBIDDEN"
out=$(cli <<EOF
login admin
$ADM
users
setrole newbie FACULTY
setrole newbie NOPE
setrole bootadmin STUDENT
setrole admin STUDENT
audit 15
deluser newbie
users
quit
EOF
)
expect "admin lists users"     "$out" "newbie"
expect "role update"           "$out" "role updated"
expect "invalid role rejected" "$out" "invalid role"
expect "last admin protected"  "$out" "cannot demote the last administrator"
expect "audit log visible"     "$out" "USER_SET_ROLE"
expect "user deletion"         "$out" "user deleted"

echo "== concurrent CLI clients =="
PIDS=""
for i in 1 2 3 4 5 6; do
  cli > "$WORK/par$i.out" <<EOF &
register par$i
Parallel-Pass-$i
Parallel-Pass-$i
login par$i
Parallel-Pass-$i
mkdir d$i
upload $WORK/blob.bin /d$i
rename /d$i/blob.bin blob$i.bin
download /d$i/blob$i.bin $WORK/par$i.dl
quit
EOF
  PIDS="$PIDS $!"
done
wait $PIDS
good=0
for i in 1 2 3 4 5 6; do grep -q "SHA-256 verified" "$WORK/par$i.out" && cmp -s blob.bin "par$i.dl" && good=$((good+1)); done
[ "$good" = 6 ] && ok "6 concurrent clients all transferred correctly" || bad "only $good/6 concurrent clients succeeded"

echo "== graceful shutdown on SIGINT =="
"$CLIENT" --port "$PORT" < <(sleep 30) > /dev/null 2>&1 &   # an idle connected client
IDLE=$!
sleep 0.5
kill -INT "$SRV_PID"
for i in $(seq 1 50); do kill -0 "$SRV_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$SRV_PID" 2>/dev/null; then bad "server still running after SIGINT"; else
  wait "$SRV_PID"; rc=$?
  [ "$rc" = 0 ] && ok "server exited with status 0" || bad "server exit status $rc"
fi
SRV_PID=""
expect "log records graceful shutdown" "$(cat logs/server.log)" "shutting down gracefully"
expect "log records server stopped"    "$(cat logs/server.log)" "server stopped"
(exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && bad "port still open" || ok "listening socket closed"
[ -z "$(ls storage/.tmp)" ] && ok "no staging files left" || bad "staging files left"
kill "$IDLE" 2>/dev/null
[ "$(stat -c %a data/linsft.db)" = "600" ] && ok "database file is mode 0600" || bad "database file mode"

echo
echo "e2e: $PASS passed, $FAILN failed"
[ "$FAILN" = 0 ]
