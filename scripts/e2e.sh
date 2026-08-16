#!/usr/bin/env bash
# qoqtun e2e lifecycle test (bash; also runs under Git Bash on Windows).
# Drives: ca init -> cert init -> create-token -> enroll -> write client.toml
# -> run -> local echo -> TCP forwarding -> tunnel stop/start -> graceful
# exit, and asserts the logs contain no sensitive strings.
#
# Usage: bash scripts/e2e.sh [workdir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
# Windows (Git Bash): native paths for the Go binaries
if command -v cygpath >/dev/null 2>&1; then
  WORK="$(cygpath -w "$WORK")"
fi
mkdir -p "$WORK"
cd "$WORK"

PASS=0; FAIL=0
ok()   { echo "  ok: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== [1] build =="
GOOS="$(cd "$ROOT" && go env GOOS)"
EXT=""
[ "$GOOS" = "windows" ] && EXT=".exe"
SERVER_BIN="$WORK/qoqtun-server$EXT"
CLIENT_BIN="$WORK/qoqtun-client$EXT"
( cd "$ROOT" && go build -o "$SERVER_BIN" ./cmd/server && go build -o "$CLIENT_BIN" ./cmd/client )
ok "build"

echo "== [2] server ca + token =="
cat > server.toml <<'EOF'
state_dir = "__WORK__/state"
[listen]
control_addr = "127.0.0.1:7400"
enroll_addr = "127.0.0.1:7401"
http_vhost_port = 28080
[policy]
allowed_targets = ["127.0.0.0/8:*"]
EOF
python3 - "$WORK" <<'PY'
import sys
p = 'server.toml'
data = open(p, encoding='utf-8').read()
open(p, 'w', encoding='utf-8').write(data.replace('__WORK__', sys.argv[1].replace(chr(92), '/')))
PY
"$SERVER_BIN" ca init --config server.toml --san 127.0.0.1
"$SERVER_BIN" client create-token --config server.toml 2>/dev/null | grep -oE 'qen_[A-Za-z0-9]+' > token.txt
ok "ca + token"

echo "== [3] enroll serve + client identity =="
"$SERVER_BIN" enroll serve --config server.toml >enroll.log 2>&1 &
ENROLL_PID=$!
sleep 2
"$CLIENT_BIN" cert init --name e2e --csr-out client.csr \
    --secrets-dir "$WORK/secrets" --keystore-backend file >/dev/null 2>&1
"$CLIENT_BIN" enroll --token "$(cat token.txt)" --server 127.0.0.1:7401 \
    --csr client.csr --cert-out client.crt --ca-out ca.crt \
    --state-out state.json --secrets-dir "$WORK/secrets" --keystore-backend file >/dev/null 2>&1
kill $ENROLL_PID 2>/dev/null || true
ok "enroll"

echo "== [4] local echo origin =="
python3 - <<'PY' >echo.log 2>&1 &
import socket, threading
def echo(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 24901)); s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
PY
ORIGIN_PID=$!
sleep 1

echo "== [5] run server + client =="
cat > client.toml <<'EOF'
server_addr = "127.0.0.1:7400"
[[tunnels]]
name = "echo"
type = "tcp"
remote_port = 24000
local_ip = "127.0.0.1"
local_port = 24901
enabled = true
EOF
"$SERVER_BIN" run --config server.toml >server.log 2>&1 &
SERVER_PID=$!
sleep 2
"$CLIENT_BIN" run --config client.toml --state state.json --ca ca.crt \
    --secrets-dir "$WORK/secrets" --keystore-backend file >client.log 2>&1 &
CLIENT_PID=$!
sleep 3

echo "== [6] TCP forwarding =="
if python3 -c "
import socket
c = socket.create_connection(('127.0.0.1', 24000), timeout=8)
c.sendall(b'hello e2e')
c.settimeout(8)
assert c.recv(64) == b'hello e2e'
c.close()
"; then ok "tcp echo through tunnel"; else fail "tcp echo"; fi

echo "== [7] tunnel start/stop via IPC =="
if "$CLIENT_BIN" tunnel list --state state.json | grep -q echo; then ok "tunnel list"; else fail "tunnel list"; fi
if "$CLIENT_BIN" tunnel start extra --remote-port 24001 --local 127.0.0.1:24901 --state state.json \
    && python3 -c "
import socket
c = socket.create_connection(('127.0.0.1', 24001), timeout=8)
c.sendall(b'x'); assert c.recv(64) == b'x'; c.close()
"; then ok "tunnel start via ipc"; else fail "tunnel start"; fi
if "$CLIENT_BIN" tunnel stop extra --state state.json; then ok "tunnel stop via ipc"; else fail "tunnel stop"; fi

echo "== [8] graceful shutdown =="
kill -TERM $CLIENT_PID 2>/dev/null || true
wait $CLIENT_PID 2>/dev/null && CLIENT_RC=0 || CLIENT_RC=$?
kill -TERM $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
kill $ORIGIN_PID 2>/dev/null || true

echo "== [9] log hygiene (no secrets) =="
BAD=""
if grep -riE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|qen_[A-Za-z0-9]{20,}' server.log client.log enroll.log 2>/dev/null; then
  BAD="sensitive strings in logs"
fi
if [ -n "$BAD" ]; then fail "$BAD"; else ok "no sensitive strings in logs"; fi

echo
echo "e2e: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
