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
# with its headers, detect mode logs without blocking, and unprotecting or
# uninstalling leaves the user's objects as they were. Needs the operator
# installed (make kind-operator) with istio-e2e among the proxy
# namespaces; ends with helm uninstall. KEEP=1 leaves the test's objects.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
OPERATOR_NS=inkwall-system
# The Gateways, and so their pods (Istio runs them in the Gateway's
# namespace): a proxy namespace (hack/kind/operator.sh).
NS=istio-e2e
ISTIO_NS=istio-system
# Istio 1.31.3, from its Helm charts, on the Gateway API's standard CRDs
# (v1.7.0, as operator/go.mod).
ISTIO_VERSION=1.31.3
ISTIO_REPO=https://istio-release.storage.googleapis.com/charts
GATEWAY_API_VERSION=v1.7.0
HOST=istio.e2e.example.com
OPEN_HOST=open.istio.e2e.example.com
CUSTOM_PORT=${E2E_ISTIO_PORT:-18093}
PLAIN_PORT=$((CUSTOM_PORT + 1))
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")
SQLI='/?id=1%27%20OR%20%271%27%3D%271'

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
# eventually DESCRIPTION COMMAND...: retries for up to 3 minutes: Istio
# rolls a Gateway's pods when its ConfigMap changes.
eventually() {
  local what=$1
  shift
  for _ in $(seq 360); do
    if "$@" >/dev/null 2>&1; then
      ok "$what"
      return 0
    fi
    sleep 0.5
  done
  fail "$what"
}

if ! "${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-operator first" >&2
  exit 1
fi

pfs=()
work=$(mktemp -d)
gateway_api_installed=false
istio_installed=false
cleanup() {
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
          image: traefik/whoami:v1.10.3
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
"${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null

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
# policy [MODE]: the policy, in Block mode by default.
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
YAML
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

echo "== unprotected"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shared --timeout=60s >/dev/null
eventually "the operator's Istio objects are gone" no_wiring
eventually "the user's ConfigMap and Gateways are as they were" as_they_were
for gw in custom plain; do
  eventually "Gateway $gw's pods no longer have the engine" not_injected "$gw"
done
forward_all
eventually "the attack passes again" both_are 200 "$SQLI"

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
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shared --ignore-not-found --timeout=30s >/dev/null || true

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; operator and istiod logs:"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" logs deployment/inkwall-operator --tail=40 2>/dev/null || true
  "${KUBECTL[@]}" -n "$ISTIO_NS" logs deployment/istiod --tail=40 2>/dev/null || true
  exit 1
fi
echo "istio e2e: all checks passed"
