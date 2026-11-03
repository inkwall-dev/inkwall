#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of WebSocket message inspection by the engine's reverse
# proxy (#276), in Docker: the engine (inkwall-engine proxy) in front of
# hack/wsecho, an echo server, and hack/wsecho as the client.
#
#   - block mode: a clean message echoes; an attack in the handshake's URL
#     gets 403 and no upgrade; an attack in a message closes the WebSocket
#     with 1008, and the engine logs its rule.
#   - detect mode: an attack in a message is echoed, and logged.
#   - off (the default): an attack in a message is echoed, unlogged.
#
# The proxy is the only adapter that sees a WebSocket's messages: through
# Envoy (ext_proc) and Traefik (ForwardAuth) only the handshake is
# inspected (docs/websocket.md). SKIP_BUILD=1 uses the engine image already
# built (IMAGE); KEEP=1 leaves the containers.
set -euo pipefail

cd "$(dirname "$0")/../.."

IMAGE=${IMAGE:-inkwall-engine:dev}
WS_IMAGE=inkwall-wsecho:e2e
PORT=${WEBSOCKET_E2E_PORT:-18290}
ADMIN_PORT=$((PORT + 1))
NAME=inkwall-websocket-e2e
SQLI_MESSAGE='{"q":"1'"'"' OR '"'"'1'"'"'='"'"'1'"'"' -- "}'

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

work=$(mktemp -d)
cleanup() {
  if [[ ${KEEP:-} != 1 ]]; then
    docker rm -f "$NAME-engine" "$NAME-app" >/dev/null 2>&1 || true
    docker network rm "$NAME" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
docker rm -f "$NAME-engine" "$NAME-app" >/dev/null 2>&1 || true
docker network rm "$NAME" >/dev/null 2>&1 || true

if [[ ${SKIP_BUILD:-} != 1 ]]; then
  docker build --target engine -t "$IMAGE" .
fi
# The echo server, built here: test only, never released.
mkdir -p "$work/img"
CGO_ENABLED=0 go build -trimpath -o "$work/img/wsecho" ./hack/wsecho
printf 'FROM gcr.io/distroless/static-debian12:nonroot\nCOPY wsecho /wsecho\nENTRYPOINT ["/wsecho"]\n' >"$work/img/Dockerfile"
docker build -q -t "$WS_IMAGE" "$work/img" >/dev/null
go build -o "$work/wsecho" ./hack/wsecho

docker network create "$NAME" >/dev/null
docker run -d --name "$NAME-app" --network "$NAME" --network-alias app "$WS_IMAGE" -listen :8080 >/dev/null

ready() { [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/readyz") == 200 ]]; }
# start_engine ARGS...: the engine's proxy in front of the echo server.
start_engine() {
  docker rm -f "$NAME-engine" >/dev/null 2>&1 || true
  docker run -d --name "$NAME-engine" --network "$NAME" --read-only --tmpfs /tmp \
    -p "127.0.0.1:$PORT:8480" -p "127.0.0.1:$ADMIN_PORT:9480" \
    "$IMAGE" proxy --upstream http://app:8080 "$@" >/dev/null
  eventually "the engine is ready" ready
}
# ws_is RESULT PATH [MESSAGE]: a WebSocket to PATH, sending MESSAGE, ends
# with RESULT: "upgraded" (echoed), "closed CODE", or an HTTP status.
ws_is() {
  local args=()
  [[ -n ${3:-} ]] && args=(-message "$3")
  [[ $("$work/wsecho" -host app.example.com -origin https://app.example.com "${args[@]}" "127.0.0.1:$PORT$2") == "$1" ]]
}
# logged PATH TEXT: the engine logged a security event for PATH with TEXT.
logged() {
  docker logs "$NAME-engine" 2>/dev/null | grep '"security event"' | grep -F "\"path\":\"$1\"" | grep -qF "$2"
}

echo "== block mode, --websocket-messages inspect"
start_engine --mode block --websocket-messages inspect
eventually "a clean message is echoed" ws_is upgraded /ws
check "a clean JSON message is echoed" ws_is upgraded /ws '{"type":"message","text":"Hello, how are you?"}'
check "an attack in the handshake's URL gets 403, no upgrade" ws_is 403 "/ws?room=1%27%20OR%20%271%27%3D%271"
check "an attack in a message closes the WebSocket with 1008" ws_is "closed 1008" /ws/block "$SQLI_MESSAGE"
eventually "and the engine logs its rule" logged /ws/block '"action":"deny"'

echo "== detect mode"
start_engine --mode detect --websocket-messages inspect
eventually "an attack in a message is echoed" ws_is upgraded /ws/detect "$SQLI_MESSAGE"
eventually "and logged" logged /ws/detect '"action":"log"'

echo "== messages off (the default)"
start_engine --mode block
eventually "an attack in a message is echoed" ws_is upgraded /ws/off "$SQLI_MESSAGE"
check "and not logged" bash -c "! docker logs $NAME-engine 2>/dev/null | grep -F '\"path\":\"/ws/off\"' | grep -q 'security event'"

if ((failures > 0)); then
  echo "$failures check(s) failed"
  docker logs --tail 50 "$NAME-engine" 2>&1 || true
  exit 1
fi
echo "all checks passed"
