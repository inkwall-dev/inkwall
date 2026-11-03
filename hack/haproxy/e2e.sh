#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End to end test of the SPOE agent (inkwall-engine spoe) with a real
# HAProxy in Docker (host network, so Linux only), configured with
# hack/haproxy/haproxy.cfg and spoe.conf: benign requests pass with an
# X-Request-Id, attacks in the URI and in the body (Content-Length, chunked,
# HTTP/2) are denied with 403, a stopped engine fails closed with 503, and
# in detect mode an attack passes.
set -euo pipefail

cd "$(dirname "$0")/../.."

IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
export HAPROXY_PORT=${HAPROXY_PORT:-47480} HAPROXY_H2C_PORT=${HAPROXY_H2C_PORT:-47481}
export APP_PORT=${APP_PORT:-47081} ENGINE_PORT=${ENGINE_PORT:-47004}
ADMIN_PORT=${ADMIN_PORT:-47482}
NAME=inkwall-haproxy-test-$$
WORK=$(mktemp -d)
pids=()

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  if [ "${fail:-0}" != 0 ]; then
    echo "--- engine log"; cat "$WORK/engine.log" || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

go build -o "$WORK/inkwall-engine" ./cmd/engine

# The app echoes the request line, X-Request-Id and the body length.
cat >"$WORK/app.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def handle_one(self):
        n = int(self.headers.get('Content-Length') or 0)
        self.rfile.read(n)
        out = ('%s %s id=%s\n' % (self.command, self.path, self.headers.get('X-Request-Id'))).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
    do_GET = do_POST = handle_one
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/app.py" "$APP_PORT" &
pids+=($!)

engine() {
  "$WORK/inkwall-engine" spoe --listen "127.0.0.1:$ENGINE_PORT" --admin-listen "127.0.0.1:$ADMIN_PORT" "$@" >>"$WORK/engine.log" 2>&1 &
  engine_pid=$!
  pids+=("$engine_pid")
  for _ in $(seq 50); do
    curl -fs "127.0.0.1:$ADMIN_PORT/readyz" >/dev/null 2>&1 && return
    sleep 0.1
  done
  echo "the engine never got ready" >&2
  exit 1
}
engine --mode block

docker run -d --name "$NAME" --network host \
  -e HAPROXY_PORT -e HAPROXY_H2C_PORT -e APP_PORT -e ENGINE_PORT \
  -v "$PWD/hack/haproxy:/usr/local/etc/haproxy:ro" "$IMAGE" >/dev/null

U=http://127.0.0.1:$HAPROXY_PORT
H2=http://127.0.0.1:$HAPROXY_H2C_PORT
# Wait for HAProxy and its health check of the agent.
for _ in $(seq 100); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/" || true)" = 200 ] && break
  sleep 0.2
done

fail=0
# expect <name> <status> [curl args...]
expect() {
  local name=$1 want=$2 got
  shift 2
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@" || true)
  if [ "$got" = "$want" ]; then
    echo "ok   $name: $got"
  else
    echo "FAIL $name: $got, want $want"
    fail=1
  fi
}

expect "benign GET" 200 "$U/products?id=42"
expect "benign POST" 200 -X POST -d 'name=joe' "$U/form"
expect "benign GET over HTTP/2" 200 --http2-prior-knowledge "$H2/products?id=42"
expect "SQL injection in the query" 403 "$U/products?id=1%27%20OR%20%271%27%3D%271"
expect "XSS in a body" 403 -X POST -d 'q=<script>alert(1)</script>' "$U/form"
expect "XSS in a chunked body" 403 -X POST -H 'Transfer-Encoding: chunked' -d 'q=<script>alert(1)</script>' "$U/form"
expect "XSS in an HTTP/2 body" 403 --http2-prior-knowledge -X POST -d 'q=<script>alert(1)</script>' "$H2/form"
# The engine's request ID reaches the app; the client's own is kept.
id=$(curl -s -H 'X-Request-Id: client-id-1' "$U/")
if [[ "$id" == *"id=client-id-1"* ]]; then echo "ok   client request ID kept"; else echo "FAIL client request ID: $id"; fail=1; fi
id=$(curl -s "$U/")
if [[ "$id" =~ id=[0-9a-f]{16} ]]; then echo "ok   request ID set"; else echo "FAIL request ID: $id"; fail=1; fi
if curl -s "127.0.0.1:$ADMIN_PORT/metrics" | grep -q 'inkwall_requests_total{action="deny",adapter="spoe",reason="rule"} 4'; then
  echo "ok   metrics"
else
  echo "FAIL metrics"; fail=1
fi

# A stopped engine: no verdict, and the fail-closed rule denies.
kill "$engine_pid"; wait "$engine_pid" 2>/dev/null || true
expect "engine stopped (fail closed)" 503 "$U/products?id=42"

# Detect mode: the attack passes, and is logged.
engine --mode detect
for _ in $(seq 50); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/" || true)" = 200 ] && break
  sleep 0.2
done
expect "detect mode" 200 "$U/products?id=1%27%20OR%20%271%27%3D%271"

if [ "$fail" != 0 ]; then
  echo "--- haproxy log"; docker logs "$NAME" 2>&1 | tail -30
  exit 1
fi
echo "PASS"
