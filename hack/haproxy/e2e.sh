#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of the engine's SPOE agent (inkwall-engine spoe, #282)
# with a real HAProxy in Docker (host network, so Linux only), configured
# with the samples of examples/haproxy, after checking them with
# `haproxy -c` and that docs/haproxy.md shows them as they are. The engine
# runs on the host, on a Unix socket in a directory HAProxy mounts, as a
# sidecar shares an emptyDir with HAProxy in a pod.
#
#   - Block mode: benign requests pass with an X-Request-Id (HTTP/1.1 and
#     HTTP/2), attacks in the query and in the body (Content-Length,
#     chunked, HTTP/2) get 403 but on the route left uninspected, a
#     client-sent X-Forwarded-For isn't taken for the client, a body over HAProxy's buffer 413, a
#     request the engine can't read 400, a denied
#     gRPC call HTTP 200 with grpc-status 7, a WebSocket handshake from a
#     forbidden origin 403.
#   - The engine down: 503 with the fail-closed rule (fail closed); without
#     it, requests pass (fail open).
#   - Detect mode: an attack passes, and is logged.
#
# HAPROXY_IMAGE picks HAProxy (3.1 or later); KEEP=1 leaves the container.
set -euo pipefail

cd "$(dirname "$0")/../.."

IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
# Below the kernel's ephemeral range (32768-60999 by default): a port in it
# can be any process's for a while, and HAProxy, unable to bind, exits
# (#340).
PORT=${HAPROXY_PORT:-18390}
APP_PORT=$((PORT + 1))
ADMIN_PORT=$((PORT + 2))
EXAMPLES=$PWD/examples/haproxy
NAME=inkwall-haproxy-e2e
SQLI='id=1%27%20OR%20%271%27%3D%271'
WORK=$(mktemp -d)
mkdir -p "$WORK/run" "$WORK/cfg"
pids=()
engine_pid=

failures=0
ok() { printf 'ok    %s\n' "$1"; }
fail() {
  printf 'FAIL  %s\n' "$1"
  failures=$((failures + 1))
}
check() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}
# eventually DESCRIPTION COMMAND...: retries for up to 30s.
eventually() {
  local what=$1
  shift
  for _ in $(seq 60); do
    if "$@" >/dev/null 2>&1; then
      ok "$what"
      return 0
    fi
    sleep 0.5
  done
  fail "$what"
}
U=http://127.0.0.1:$PORT
# listening PORT: something accepts connections on 127.0.0.1:PORT.
listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@" || true; }
is() {
  local want=$1
  shift
  [[ $(code "$@") == "$want" ]]
}

cleanup() {
  if [[ ${KEEP:-} == 1 ]]; then return; fi
  save_haproxy_log
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  if [[ $failures != 0 ]]; then
    echo "--- haproxy logs, each container's"
    tail -80 "$WORK/haproxy.log" || true
    echo "--- engine log"
    tail -50 "$WORK/engine.log" || true
  fi
  rm -rf "$WORK"
}
# save_haproxy_log keeps the log of the HAProxy container about to go: a
# failure shows every container's, not only the last one's.
save_haproxy_log() {
  if docker inspect "$NAME" >/dev/null 2>&1; then
    echo "--- container started $(docker inspect -f '{{.State.StartedAt}}' "$NAME")" >>"$WORK/haproxy.log"
    docker logs "$NAME" >>"$WORK/haproxy.log" 2>&1 || true
  fi
}
trap cleanup EXIT

# The test's ports must be free: a process already there would take
# HAProxy's, the app's or the engine's place (#340).
for p in "$PORT" "$APP_PORT" "$ADMIN_PORT"; do
  if listening "$p"; then
    echo "port $p is in use: free it, or set HAPROXY_PORT (HAProxy's; the app and the engine's admin take the next two)" >&2
    exit 1
  fi
done

# The samples: valid for HAProxy, and shown whole in docs/haproxy.md, each
# after a marker comment.
docker pull -q "$IMAGE" >/dev/null
check "haproxy.cfg is valid" docker run --rm --add-host app:127.0.0.1 -v "$EXAMPLES:/usr/local/etc/haproxy:ro" "$IMAGE" haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
guide_copy() {
  awk -v f="$1" '$0 == "<!-- examples/haproxy/" f ": hack/haproxy/e2e.sh checks that this copy is the file. -->" {m = 1; next}
    m == 1 && /^```haproxy$/ {m = 2; next} m == 2 && /^```$/ {exit} m == 2' docs/haproxy.md
}
for f in haproxy.cfg spoe.conf; do
  check "docs/haproxy.md shows $f as it is" diff <(guide_copy "$f") "$EXAMPLES/$f"
done

go build -o "$WORK/inkwall-engine" ./cmd/engine

# The app echoes the request line and X-Request-Id.
cat >"$WORK/app.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def handle_one(self):
        self.rfile.read(int(self.headers.get('Content-Length') or 0))
        out = ('%s %s id=%s\n' % (self.command, self.path, self.headers.get('X-Request-Id'))).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
    do_GET = do_POST = handle_one
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/app.py" "$APP_PORT" &
pids+=($!)

# start_engine ARGS...: the agent on the socket haproxy.cfg names.
start_engine() {
  "$WORK/inkwall-engine" spoe --listen "unix:$WORK/run/spoe.sock" --admin-listen "127.0.0.1:$ADMIN_PORT" "$@" >>"$WORK/engine.log" 2>&1 &
  engine_pid=$!
  pids+=("$engine_pid")
  for _ in $(seq 100); do
    curl -fs "127.0.0.1:$ADMIN_PORT/readyz" >/dev/null 2>&1 && return
    sleep 0.1
  done
  echo "the engine never got ready" >&2
  exit 1
}
stop_engine() {
  kill "$engine_pid"
  wait "$engine_pid" 2>/dev/null || true
}
# start_haproxy SED: HAProxy with haproxy.cfg on the test's ports, edited by
# SED, as the user that owns the socket.
start_haproxy() {
  sed -e "s|^    bind :8080|    bind 127.0.0.1:$PORT|" -e "s|server app app:80|server app 127.0.0.1:$APP_PORT|" \
    -e "$1" "$EXAMPLES/haproxy.cfg" >"$WORK/cfg/haproxy.cfg"
  cp "$EXAMPLES/spoe.conf" "$WORK/cfg/spoe.conf"
  save_haproxy_log
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --network host --user "$(id -u):$(id -g)" \
    -v "$WORK/cfg:/usr/local/etc/haproxy:ro" -v "$WORK/run:/var/run/inkwall" "$IMAGE" >/dev/null
  # HAProxy listens, or the test stops here, with its log: one that can't
  # bind exits, and every check after would fail for that reason (#340).
  local running
  for _ in $(seq 100); do
    running=$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)
    [[ $running == true ]] || break
    if listening "$PORT"; then
      # Someone listens: HAProxy, if it is still running a moment later
      # (one that can't bind exits at once).
      sleep 0.3
      [[ $(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true) == true ]] && return
      break
    fi
    sleep 0.1
  done
  echo "HAProxy isn't listening on 127.0.0.1:$PORT:" >&2
  docker logs "$NAME" >&2 || true
  exit 1
}

start_engine --mode block --websocket-origins https://app.example.com
start_haproxy 's|^$||'
eventually "HAProxy and the engine serve" is 200 "$U/"

check "a benign GET passes" is 200 "$U/products?id=42"
check "a benign POST passes" is 200 -X POST -d 'name=joe' "$U/form"
check "a benign GET over HTTP/2 passes" is 200 --http2-prior-knowledge "$U/products?id=42"
check "SQL injection in the query: 403" is 403 "$U/products?$SQLI"
check "the route left uninspected passes an attack" is 200 "$U/healthz?$SQLI"
check "a client-sent X-Forwarded-For isn't the client IP" bash -c "curl -s -o /dev/null -H 'X-Forwarded-For: 203.0.113.9' '$U/xff?$SQLI'; grep '\"path\":\"/xff\"' '$WORK/engine.log' | grep -q '\"client_ip\":\"127.0.0.1\"'"
check "XSS in a body: 403" is 403 -X POST -d 'q=<script>alert(1)</script>' "$U/form"
check "XSS in a chunked body: 403" is 403 -X POST -H 'Transfer-Encoding: chunked' -d 'q=<script>alert(1)</script>' "$U/form"
check "XSS in an HTTP/2 body: 403" is 403 --http2-prior-knowledge -X POST -d 'q=<script>alert(1)</script>' "$U/form"
check "a body over HAProxy's buffer: 413" is 413 -X POST --data-binary "name=$(head -c 20000 /dev/zero | tr '\0' a)" "$U/form"
check "a denial carries the request ID" bash -c "curl -s -D - -o /dev/null '$U/products?$SQLI' | grep -qiE '^x-request-id: [0-9a-f]{16}'"
# A request the engine can't read (a path with a malformed escape, which
# HAProxy passes on): its 400, not a 403, with the request ID of the
# engine's log line (#366).
check "a request the engine can't read: 400" is 400 "$U/products/%zz"
check "and its 400 carries the request ID" bash -c "curl -s -D - -o /dev/null '$U/products/%zz' | grep -qiE '^x-request-id: [0-9a-f]{16}'"
grpc() { curl -s -D - -o /dev/null --http2-prior-knowledge -X POST -H 'Content-Type: application/grpc' -H 'TE: trailers' --data-binary @/dev/null "$U/pkg.Svc/Call?$SQLI"; }
check "a denied gRPC call: HTTP 200" bash -c "$(declare -f grpc); U=$U SQLI='$SQLI' grpc | grep -q '^HTTP/2 200'"
check "a denied gRPC call: grpc-status 7" bash -c "$(declare -f grpc); U=$U SQLI='$SQLI' grpc | grep -qi '^grpc-status: 7'"
check "a denied gRPC call: content-type application/grpc" bash -c "$(declare -f grpc); U=$U SQLI='$SQLI' grpc | grep -qi '^content-type: application/grpc'"
ws=(-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==')
check "a WebSocket handshake from a forbidden origin: 403" is 403 "${ws[@]}" -H 'Origin: https://evil.example' "$U/chat"
check "a WebSocket handshake from an allowed origin passes" is 200 "${ws[@]}" -H 'Origin: https://app.example.com' "$U/chat"
check "the client's request ID reaches the app" bash -c "curl -s -H 'X-Request-Id: client-id-1' '$U/' | grep -q 'id=client-id-1'"
check "a request ID reaches the app" bash -c "curl -s '$U/' | grep -qE 'id=[0-9a-f]{16}'"
check "metrics count the denials" bash -c "curl -s 127.0.0.1:$ADMIN_PORT/metrics | grep -q 'inkwall_requests_total{action=\"deny\",adapter=\"spoe\",reason=\"rule\"}'"

# The engine down: the fail-closed rule denies, until the engine is back.
stop_engine
check "the engine down, fail closed: 503" is 503 "$U/products?id=42"
check "the engine down: the route left uninspected passes" is 200 "$U/healthz"
start_engine --mode block
eventually "the engine back: 200" is 200 "$U/products?id=42"

# Fail open: haproxy.cfg without the fail-closed rule.
start_haproxy '/deny_status 503 if !{ var(txn.inkwall.action) -m found }/d'
eventually "fail open: HAProxy serves" is 200 "$U/"
check "fail open: an attack still gets 403" is 403 "$U/products?$SQLI"
stop_engine
check "the engine down, fail open: 200" is 200 "$U/products?$SQLI"

# Detect mode: the attack passes, and is logged.
start_haproxy 's|^$||'
start_engine --mode detect
eventually "detect mode: an attack passes" is 200 "$U/products?$SQLI"
check "detect mode: the attack is logged" grep -q '"action":"log"' "$WORK/engine.log"

if [[ $failures != 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "PASS"
