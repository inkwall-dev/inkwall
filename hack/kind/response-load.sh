#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# A short load test of response inspection through Envoy Gateway on the kind
# cluster (#344): one Gateway, one HTTPRoute to an nginx serving a small
# (about 1 KB) and a larger (about 15 KB) HTML page, one WAFPolicy in Block
# mode. Each page is loaded for DURATION with CONCURRENCY clients
# (hack/loadgen, from this host to the Envoy Service's NodePort on the kind
# node), first with the policy inspecting requests only, then with
# responses.inspect on. It prints p50/p90/p99 latency and requests per
# second per run, the engine's peak RSS (sampled from its
# process_resident_memory_bytes) and its response check time. Every
# response must be a 200: response inspection must not deny a clean page.
# Needs the operator installed (make kind-operator); it installs Envoy
# Gateway as hack/kind/envoy-gateway-e2e.sh does, and removes what it
# created. Results are appended, as JSON lines, to OUT if set.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
NS=response-load
EG_NS=envoy-gateway-e2e # a proxy namespace (hack/kind/operator.sh)
EG_VERSION=v1.9.3
GATEWAY_API_VERSION=v1.7.0
HOST=load.example.com
CONCURRENCY=${CONCURRENCY:-8}
DURATION=${DURATION:-20s}
OUT=${OUT:-}
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")

if ! "${KUBECTL[@]}" -n inkwall-system get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-operator first" >&2
  exit 1
fi

work=$(mktemp -d)
pf=
gateway_api_installed=false
eg_crds_installed=false
cleanup() {
  [[ -z $pf ]] || kill "$pf" 2>/dev/null || true
  if [[ ${KEEP:-} != 1 ]]; then
    "${KUBECTL[@]}" delete namespace "$NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete gatewayclass inkwall-load --ignore-not-found >/dev/null 2>&1 || true
    "${HELM[@]}" -n "$EG_NS" uninstall eg --wait >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete namespace "$EG_NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
    if $eg_crds_installed; then "${KUBECTL[@]}" delete -f "$work/eg-crds.yaml" --ignore-not-found >/dev/null 2>&1 || true; fi
    if $gateway_api_installed; then "${KUBECTL[@]}" delete -f "$work/gateway-api.yaml" --ignore-not-found >/dev/null 2>&1 || true; fi
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# eventually DESCRIPTION COMMAND...: retries for up to 3 minutes.
eventually() {
  local what=$1
  shift
  for _ in $(seq 360); do
    if "$@" >/dev/null 2>&1; then
      echo "ok    $what"
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL  $what" >&2
  exit 1
}

echo "== Envoy Gateway $EG_VERSION"
if ! "${KUBECTL[@]}" get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  curl -fsSL "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >"$work/gateway-api.yaml"
  gateway_api_installed=true
  "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$work/gateway-api.yaml" >/dev/null
fi
helm template eg-crds oci://docker.io/envoyproxy/gateway-crds-helm --version "$EG_VERSION" \
  --set crds.gatewayAPI.enabled=false --set crds.envoyGateway.enabled=true >"$work/eg-crds.yaml" 2>/dev/null
if ! "${KUBECTL[@]}" get crd envoyproxies.gateway.envoyproxy.io >/dev/null 2>&1; then eg_crds_installed=true; fi
"${KUBECTL[@]}" apply --server-side --force-conflicts -f "$work/eg-crds.yaml" >/dev/null
"${HELM[@]}" upgrade --install eg oci://docker.io/envoyproxy/gateway-helm --version "$EG_VERSION" --skip-crds \
  --set crds.enabled=false --namespace "$EG_NS" --create-namespace --set config.envoyGateway.extensionApis.enableBackend=true \
  --wait --timeout 5m >/dev/null

# The app: nginx with a small and a larger HTML page (text/html, so the
# response rules read their bodies), uncompressed.
small=$(printf '<p>Order %04d: shipped.</p>\n' $(seq 1 30))
page=$(printf '<tr><td>Product %04d</td><td>A sturdy oak table, 120 x 80 cm.</td><td>249.00</td></tr>\n' $(seq 1 180))
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" -n "$NS" create configmap pages --from-literal=small.html="<html><body>$small</body></html>" \
  --from-literal=page.html="<html><body><table>$page</table></body></html>" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: load, namespace: $NS}
spec:
  targetRefs: [{group: gateway.networking.k8s.io, kind: HTTPRoute, name: app}]
  mode: Block
  timeout: 1s
${1:-}
YAML
}
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: $NS}
spec:
  selector: {matchLabels: {app: response-load}}
  template:
    metadata: {labels: {app: response-load}}
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          volumeMounts: [{name: pages, mountPath: /usr/share/nginx/html}]
      volumes: [{name: pages, configMap: {name: pages}}]
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: $NS}
spec:
  selector: {app: response-load}
  ports: [{name: http, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: inkwall-load}
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: load, namespace: $NS}
spec:
  gatewayClassName: inkwall-load
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app, namespace: $NS}
spec:
  parentRefs: [{name: load}]
  hostnames: [$HOST]
  rules: [{backendRefs: [{name: app, port: 80}]}]
YAML
"${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null
policy

gw_selector="gateway.envoyproxy.io/owning-gateway-name=load,gateway.envoyproxy.io/owning-gateway-namespace=$NS"
injected() {
  local p
  p=$("${KUBECTL[@]}" -n "$EG_NS" get pods -l "$gw_selector" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name}{"\n"}{end}' | grep '^|Running|') &&
    ! grep -qv '^|Running|inkwall-engine' <<<"$p"
}
eep() {
  "${KUBECTL[@]}" -n "$NS" get envoyextensionpolicy inkwall-waf-app -o jsonpath="$1"
}
accepted() { [[ $(eep '{.status.ancestors[*].conditions[?(@.type=="Accepted")].status}') == True ]]; }
response_mode() { [[ $(eep '{.spec.extProc[0].processingMode.response.body}') == "$1" ]] && accepted; }
ready() { [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy load -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]; }
eventually "the Gateway's Envoy pod has the engine" injected
eventually "Envoy Gateway accepts the EnvoyExtensionPolicy" accepted
eventually "the policy is Ready" ready

node_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLUSTER-control-plane")
svc=$("${KUBECTL[@]}" -n "$EG_NS" get svc -l "$gw_selector" -o jsonpath='{.items[0].metadata.name}')
node_port=$("${KUBECTL[@]}" -n "$EG_NS" get svc "$svc" -o jsonpath='{.spec.ports[?(@.port==80)].nodePort}')
base="http://$node_ip:$node_port"
ok200() { [[ $(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$base/$1") == 200 ]]; }
attack() { [[ $(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$base/small.html?id=1%27%20OR%20%271%27%3D%271") == 403 ]]; }
eventually "the pages are served through Envoy Gateway" ok200 page.html
eventually "an attack is blocked" attack

go build -o "$work/loadgen" ./hack/loadgen
# The engine's admin port, for its metrics.
metrics_port=$((20000 + RANDOM % 10000))
start_metrics() {
  local _
  for _ in 1 2 3; do
    [[ -z $pf ]] || kill "$pf" 2>/dev/null || true
    # The Running pod with the engine, not one being replaced.
    pod=$("${KUBECTL[@]}" -n "$EG_NS" get pods -l "$gw_selector" \
      -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name}{"\n"}{end}' |
      awk -F'|' '$2 == "" && $3 == "Running" && $4 ~ /inkwall-engine/ {print $1; exit}')
    if [[ -n $pod ]]; then
      "${KUBECTL[@]}" -n "$EG_NS" port-forward "pod/$pod" "$metrics_port:9480" >"$work/port-forward.log" 2>&1 &
      pf=$!
      for _ in $(seq 120); do curl -sf "http://127.0.0.1:$metrics_port/metrics" >/dev/null && return 0; sleep 0.25; done
    fi
    sleep 5
  done
  echo "FAIL  the engine's metrics (pod ${pod:-none}):" >&2
  cat "$work/port-forward.log" >&2
  exit 1
}
# metric NAME: the sum of a metric's samples, whatever their labels.
metric() {
  curl -sf "http://127.0.0.1:$metrics_port/metrics" |
    awk -v m="$1" '{ name = $1; sub(/\{.*/, "", name) } name == m { s += $2; n++ } END { if (n) printf "%.6g\n", s }'
}

# run MODE PAGE: one load run, with the engine's RSS sampled each second.
run() {
  local mode=$1 page=$2 peak=0 samples="$work/rss" result
  : >"$samples"
  (while :; do metric process_resident_memory_bytes >>"$samples" || true; sleep 1; done) &
  local sampler=$!
  result=$("$work/loadgen" -url "$base/$page" -host "$HOST" -c "$CONCURRENCY" -d "$DURATION")
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true
  peak=$(sort -g "$samples" | tail -1)
  local checks sum
  checks=$(metric inkwall_response_check_duration_seconds_count || true)
  sum=$(metric inkwall_response_check_duration_seconds_sum || true)
  printf '%-9s %-10s %s engineRssPeakMiB=%s responseChecks=%s\n' "$mode" "$page" "$result" \
    "$(awk -v b="${peak:-0}" 'BEGIN {printf "%.0f", b / 1048576}')" "${checks:-0}"
  if [[ -n $OUT ]]; then
    jq -c --arg mode "$mode" --arg page "$page" --argjson rss "${peak:-0}" --arg checks "${checks:-0}" --arg sum "${sum:-0}" \
      '. + {mode: $mode, page: $page, engineRssPeakBytes: $rss, responseChecks: ($checks | tonumber), responseCheckSeconds: ($sum | tonumber)}' \
      <<<"$result" >>"$OUT"
  fi
  if ! jq -e '.status | keys == ["200"]' <<<"$result" >/dev/null; then
    echo "FAIL  $mode $page: not every response was a 200" >&2
    exit 1
  fi
}

echo "== requests only"
start_metrics
for page in small.html page.html; do run requests "$page"; done

echo "== responses.inspect on"
policy '  responses: {inspect: true}'
eventually "Envoy holds the responses for the engine" response_mode BufferedPartial
eventually "the policy is Ready" ready
# Envoy takes the new configuration a moment after Envoy Gateway accepts it.
serving() {
  [[ $(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$base/missing-$RANDOM.html") == 404 ]] &&
    ok200 small.html
}
eventually "pages still served" serving
sleep 5
start_metrics
for page in small.html page.html; do run responses "$page"; done
checks=$(metric inkwall_response_check_duration_seconds_count || true)
if [[ ${checks:-0} == 0 ]]; then
  echo "FAIL  the engine checked no response" >&2
  exit 1
fi
echo "ok    the engine checked $checks responses"
