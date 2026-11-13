#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of raw Envoy with the engine's ext_proc adapter (#283), in
# Docker: plain Envoy, the engine next to it (sharing its network namespace
# and a socket volume, as a sidecar in a pod) and an app. It runs Envoy with
# the samples of examples/raw-envoy, after checking them with Envoy's
# --mode validate:
#
#   - envoy.yaml, block mode over a Unix socket: an attack in the query or
#     the body gets 403, a benign request 200, a body over the engine's
#     limit 413, the route the filter is off for passes an attack, a
#     client-sent X-Forwarded-For doesn't become the client IP, a hung
#     engine's requests are rejected after message_timeout, and with the
#     engine down Envoy answers 503 (failure_mode_allow: false,
#     status_on_error), until it is back.
#   - envoy-detect.yaml, detect mode over loopback TCP (observability_mode):
#     an attack passes and is logged, and with the engine down requests pass
#     (failure_mode_allow: true).
#   - Response inspection (#274), both samples with Envoy sending the
#     responses as docs/raw-envoy.md shows: an app response that leaks a SQL
#     error is replaced with 403 in block mode (--inspect-responses), and
#     logged as a response event in detect mode; a clean one passes.
#   - Streamed responses event by event (#323, --response-streams inspect):
#     an app (a second Envoy, answering Server-Sent Events) streams a clean
#     stream, which passes whole, and one with an event leaking a SQL
#     error, whose stream is reset before the leak reaches the client in
#     block mode; the event is logged with its index.
#
# The Kubernetes sample (kustomization.yaml) is rendered with kubectl, when
# kubectl is installed. SKIP_BUILD=1 uses the engine image already built
# (IMAGE); KEEP=1 leaves the containers.
set -euo pipefail

cd "$(dirname "$0")/../.."
# The versions under test (#393).
# shellcheck source=hack/versions.env
. hack/versions.env

IMAGE=${IMAGE:-inkwall-engine:dev}
# The Envoy the samples are written and tested for; kubernetes.yaml names it
# too, and the test checks that they agree.
ENVOY_IMAGE=envoyproxy/envoy:$ENVOY_VERSION
APP_IMAGE=traefik/whoami:$WHOAMI_VERSION
PORT=${RAW_ENVOY_PORT:-18190}
ADMIN_PORT=$((PORT + 1))
EXAMPLES=$PWD/examples/raw-envoy
NAME=${RAW_ENVOY_NAME:-inkwall-raw-envoy-e2e}
HOST=app.example.com
SQLI='id=1%27%20OR%20%271%27%3D%271'

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

code() {
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$@" || true
}
get_is() { [[ $(code "http://127.0.0.1:$PORT$2") == "$1" ]]; }
post_is() { [[ $(code -X POST --data "$3" "http://127.0.0.1:$PORT$2") == "$1" ]]; }
ready() { [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/readyz") == 200 ]]; }
# event PATH: the engine's last security event for PATH.
event() { docker logs "$NAME-engine" 2>/dev/null | grep '"security event"' | grep -F "\"path\":\"$1\"" | tail -1; }
event_has() { event "$1" | grep -qF "$2"; }

cleanup() {
  if [[ ${KEEP:-} == 1 ]]; then return; fi
  docker rm -f "$NAME-engine" "$NAME-envoy" "$NAME-app" "$NAME-sse" >/dev/null 2>&1 || true
  docker volume rm "$NAME-socket" >/dev/null 2>&1 || true
  docker network rm "$NAME" >/dev/null 2>&1 || true
  [[ -z ${RESPONSES:-} ]] || rm -rf "$RESPONSES"
}
trap cleanup EXIT
cleanup

if [[ ${PULL_IMAGES:-} == 1 ]]; then
  docker pull -q "$IMAGE" >/dev/null
elif [[ ${SKIP_BUILD:-} != 1 ]]; then
  docker build --target engine -t "$IMAGE" .
fi
docker pull -q "$ENVOY_IMAGE" >/dev/null
docker pull -q "$APP_IMAGE" >/dev/null

# The samples.
for f in "$EXAMPLES"/envoy*.yaml; do
  check "Envoy accepts $(basename "$f")" \
    docker run --rm -v "$EXAMPLES:/cfg:ro" "$ENVOY_IMAGE" --mode validate -c "/cfg/$(basename "$f")"
done
check "kubernetes.yaml runs $ENVOY_IMAGE" grep -qF "image: $ENVOY_IMAGE" "$EXAMPLES/kubernetes.yaml"
# docs/raw-envoy.md shows envoy.yaml whole, after a marker comment.
guide_copy() {
  awk '/^<!-- examples\/raw-envoy\/envoy.yaml:/ {m = 1; next} m == 1 && /^```yaml$/ {m = 2; next} m == 2 && /^```$/ {exit} m == 2' docs/raw-envoy.md
}
check "docs/raw-envoy.md shows envoy.yaml as it is" diff <(guide_copy) "$EXAMPLES/envoy.yaml"
if command -v kubectl >/dev/null; then
  check "kustomization.yaml renders" kubectl kustomize "$EXAMPLES"
else
  echo "skip  kustomization.yaml renders (no kubectl)"
fi

docker network create "$NAME" >/dev/null
# The socket directory: an emptyDir in a pod; here a volume the engine's user
# (65532, as Envoy) may write to.
docker volume create "$NAME-socket" >/dev/null
docker run --rm --entrypoint chown -v "$NAME-socket:/s" "$ENVOY_IMAGE" 65532:65532 /s
docker run -d --name "$NAME-app" --network "$NAME" --network-alias app "$APP_IMAGE" --port 80 >/dev/null

# start_envoy CONFIG: Envoy with a sample, as the engine's user, owning the
# network namespace the engine joins (so the engine can stop alone).
start_envoy() {
  docker rm -f "$NAME-engine" "$NAME-envoy" >/dev/null 2>&1 || true
  docker run -d --name "$NAME-envoy" --network "$NAME" --user 65532:65532 \
    -p "127.0.0.1:$PORT:8080" -p "127.0.0.1:$ADMIN_PORT:9480" \
    -v "$NAME-socket:/var/run/inkwall" -v "$EXAMPLES:/cfg:ro" \
    "$ENVOY_IMAGE" -c "/cfg/$1" >/dev/null
}
# start_engine ARGS...: the engine's ext-proc adapter, next to Envoy.
start_engine() {
  docker rm -f "$NAME-engine" >/dev/null 2>&1 || true
  docker run -d --name "$NAME-engine" --network "container:$NAME-envoy" --read-only --tmpfs /tmp \
    -v "$NAME-socket:/var/run/inkwall" "$IMAGE" ext-proc --trusted-proxies=127.0.0.1/32,::1/128 "$@" >/dev/null
  eventually "the engine is ready" ready
}

echo "== block mode, Unix socket (envoy.yaml)"
start_envoy envoy.yaml
start_engine --listen=unix:/var/run/inkwall/extproc.sock --mode=block
eventually "a benign request: 200" get_is 200 /
check "an attack in the query: 403" get_is 403 "/?$SQLI"
check "an attack in the body: 403" post_is 403 /form "q=1%27%20OR%20%271%27%3D%271"
check "a benign body: 200" post_is 200 /form "q=hello"
# Over the engine's --max-body-bytes (64 KiB), under Envoy's buffer: in block
# mode the engine denies it uninspected (--oversize-body auto).
big="q=$(head -c 100000 /dev/zero | tr '\0' a)"
check "a body over the engine's limit: 413" post_is 413 /form "$big"
check "an attack on the route the filter is off for: 200" get_is 200 "/healthz?$SQLI"
spoofed=$(code -H 'X-Forwarded-For: 203.0.113.7' "http://127.0.0.1:$PORT/client-ip?$SQLI")
check "an attack with a client-sent X-Forwarded-For: 403" test "$spoofed" = 403
eventually "the attack's event is a deny" event_has /client-ip '"action":"deny"'
ip=$(event /client-ip | sed -n 's/.*"client_ip":"\([^"]*\)".*/\1/p')
check "its client IP is Envoy's peer ($ip), not the header's or loopback" \
  test -n "$ip" -a "$ip" != 203.0.113.7 -a "$ip" != 127.0.0.1

# A hung engine: Envoy gives up after message_timeout and rejects the
# request (failure_mode_allow: false), whatever its status.
docker pause "$NAME-engine" >/dev/null
hung=$(code --max-time 10 "http://127.0.0.1:$PORT/?$SQLI")
check "engine hung: an attack is rejected with a 5xx ($hung)" test "${hung:0:1}" = 5
docker unpause "$NAME-engine" >/dev/null
eventually "engine unpaused: a benign request gets 200" get_is 200 /

docker stop -t 5 "$NAME-engine" >/dev/null
check "engine down: a benign request gets 503 (failure_mode_allow: false)" get_is 503 /
check "engine down: an attack gets 503" get_is 503 "/?$SQLI"
docker start "$NAME-engine" >/dev/null
eventually "engine back: a benign request gets 200" get_is 200 /
check "engine back: an attack gets 403" get_is 403 "/?$SQLI"

echo "== detect mode, loopback (envoy-detect.yaml)"
start_envoy envoy-detect.yaml
start_engine --listen=127.0.0.1:9003 --mode=detect
eventually "a benign request: 200" get_is 200 /
check "an attack in the query: 200" get_is 200 "/detect?$SQLI"
eventually "the attack is logged (action log)" event_has /detect '"action":"log"'
check "an attack in the body: 200" post_is 200 /detect-body "q=1%27%20OR%20%271%27%3D%271"
eventually "the body attack is logged" event_has /detect-body '"action":"log"'
docker stop -t 5 "$NAME-engine" >/dev/null
check "engine down: a benign request gets 200 (failure_mode_allow: true)" get_is 200 /
check "engine down: an attack gets 200" get_is 200 "/?$SQLI"

# responses_config SAMPLE: SAMPLE with Envoy sending the responses, as
# "Response inspection" in docs/raw-envoy.md shows: the headers, and the
# body (BUFFERED_PARTIAL, or STREAMED, the only mode observability_mode
# allows), with mode_override allowed.
RESPONSES=$(mktemp -d)
chmod 755 "$RESPONSES"
responses_config() {
  local body=BUFFERED_PARTIAL
  grep -q 'observability_mode: true' "$EXAMPLES/$1" && body=STREAMED
  sed -e 's/response_header_mode: SKIP/response_header_mode: SEND/' \
    -e "s/response_body_mode: NONE/response_body_mode: $body/" \
    -e 's/^\( *\)request_attributes:/\1allow_mode_override: true\n&/' \
    "$EXAMPLES/$1" >"$RESPONSES/$1"
  chmod 644 "$RESPONSES/$1"
  grep -q "response_body_mode: $body" "$RESPONSES/$1" && grep -q allow_mode_override "$RESPONSES/$1"
}
# The app (whoami) echoes the request's headers in a text/plain body: this
# one makes it leak a MySQL error, which the request rules don't mind.
LEAK='X-Debug: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
leak_is() { [[ $(code -H "$LEAK" "http://127.0.0.1:$PORT$2") == "$1" ]]; }
body_lacks() { ! curl -s -H "Host: $HOST" -H "$LEAK" "http://127.0.0.1:$PORT$1" | grep -qF 'SQL syntax'; }

echo "== responses, block mode (envoy.yaml, --inspect-responses)"
for f in envoy.yaml envoy-detect.yaml; do
  check "$f sending responses: written" responses_config "$f"
  check "Envoy accepts $f sending responses" \
    docker run --rm -v "$RESPONSES:/cfg:ro" "$ENVOY_IMAGE" --mode validate -c "/cfg/$f"
done
EXAMPLES=$RESPONSES start_envoy envoy.yaml
start_engine --listen=unix:/var/run/inkwall/extproc.sock --mode=block --inspect-responses
eventually "a clean response: 200" get_is 200 /
check "a response leaking a SQL error: 403" leak_is 403 /leak
check "its body is replaced" body_lacks /leak
eventually "the leak's event is a response deny" event_has /leak '"phase":"response"'
check "the event is a deny" event_has /leak '"action":"deny"'
check "a leak on the route the filter is off for: 200" leak_is 200 /healthz
check "an attack in the query is still 403" get_is 403 "/?$SQLI"

echo "== responses, detect mode (envoy-detect.yaml, --inspect-responses)"
EXAMPLES=$RESPONSES start_envoy envoy-detect.yaml
start_engine --listen=127.0.0.1:9003 --mode=detect --inspect-responses
eventually "a clean response: 200" get_is 200 /
check "a response leaking a SQL error: 200" leak_is 200 /detect-leak
eventually "the leak is logged as a response event" event_has /detect-leak '"phase":"response"'
check "the event is a log" event_has /detect-leak '"action":"log"'
# Streamed responses (#323): the app is now a second Envoy answering
# Server-Sent Events itself (direct_response), the main one sending the
# responses as above; the engine inspects each event.
echo "== streamed responses, block mode (--response-streams inspect)"
docker rm -f "$NAME-app" >/dev/null
cat >"$RESPONSES/sse-app.yaml" <<'YAML'
static_resources:
  listeners:
    - address:
        socket_address: {address: 0.0.0.0, port_value: 80}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: sse
                route_config:
                  virtual_hosts:
                    - name: sse
                      domains: ["*"]
                      response_headers_to_add:
                        - header: {key: content-type, value: text/event-stream}
                          append_action: OVERWRITE_IF_EXISTS_OR_ADD
                      routes:
                        - match: {prefix: /sse-leak}
                          direct_response:
                            status: 200
                            body: {inline_string: "data: hello\n\ndata: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version\n\n"}
                        - match: {prefix: /}
                          direct_response:
                            status: 200
                            body: {inline_string: "data: hello\n\ndata: world\n\n"}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
YAML
chmod 644 "$RESPONSES/sse-app.yaml"
docker run -d --name "$NAME-sse" --network "$NAME" --network-alias app --user 0:0 \
  -v "$RESPONSES:/cfg:ro" "$ENVOY_IMAGE" -c /cfg/sse-app.yaml >/dev/null
EXAMPLES=$RESPONSES start_envoy envoy.yaml
start_engine --listen=unix:/var/run/inkwall/extproc.sock --mode=block --inspect-responses --response-streams=inspect
sse() { curl -sN --max-time 10 -H "Host: $HOST" "http://127.0.0.1:$PORT$1" || true; }
clean_stream() { [[ $(sse /sse) == $'data: hello\n\ndata: world' ]]; }
eventually "a clean stream passes whole" clean_stream
leak_cut() { ! sse /sse-leak | grep -qF 'SQL syntax'; }
check "a stream with a leaking event: the leak never reaches the client" leak_cut
eventually "the leaking event is logged as a response deny" event_has /sse-leak '"phase":"response"'
check "with its index in the stream" event_has /sse-leak '"stream_event":2'

if ((failures > 0)); then
  echo "$failures check(s) failed"
  docker logs --tail 50 "$NAME-envoy" 2>&1 || true
  docker logs --tail 50 "$NAME-engine" 2>&1 || true
  exit 1
fi
echo "all checks passed"
