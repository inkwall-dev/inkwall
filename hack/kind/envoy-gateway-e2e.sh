#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of the Envoy Gateway integration on the kind cluster
# (#127): Envoy Gateway installed with nothing about Inkwall, one WAFPolicy
# protecting a Traefik Ingress and an HTTPRoute served by two Gateways (one
# naming the user's EnvoyProxy, one naming none). The engine joins the
# Envoy pods, attacks are blocked through both proxies, a body attack is
# held back with its headers, and unprotecting or uninstalling leaves the
# user's objects as they were. Needs the operator installed (make
# kind-operator); ends with helm uninstall. KEEP=1 leaves the test's objects.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
OPERATOR_NS=inkwall-system
NS=eg-e2e
EG_NS=envoy-gateway-e2e
# Envoy Gateway v1.9.3 (Gateway API v1.6), on the Gateway API's standard
# CRDs (v1.7.0, as operator/go.mod). Their safe-upgrades policy refuses
# the older ones Envoy Gateway's chart bundles, so Envoy Gateway is
# installed as its docs say for Gateway API CRDs managed separately: its
# own CRDs from gateway-crds-helm, then the chart with --skip-crds.
EG_VERSION=v1.9.3
GATEWAY_API_VERSION=v1.7.0
TRAEFIK_NS=traefik-e2e
TRAEFIK_CHART_VERSION=41.6.1 # Traefik v3.7.13, as hack/kind/up.sh
HOST=eg.e2e.example.com
TRAEFIK_PORT=${E2E_TRAEFIK_PORT:-18080}
CUSTOM_PORT=${E2E_EG_PORT:-18091}
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
# eventually DESCRIPTION COMMAND...: retries for up to 3 minutes: Envoy
# Gateway rolls its Envoy pods when their EnvoyProxy changes.
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
eg_crds=$work/eg-crds.yaml
gateway_api_installed=false
eg_crds_installed=false
cleanup() {
  for pf in "${pfs[@]}"; do kill "$pf" 2>/dev/null || true; done
  if [[ ${KEEP:-} == 1 ]]; then
    rm -rf "$work"
    return
  fi
  "${KUBECTL[@]}" delete namespace "$NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete gatewayclass inkwall-e2e --ignore-not-found >/dev/null 2>&1 || true
  "${HELM[@]}" -n "$EG_NS" uninstall eg --wait >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete namespace "$EG_NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  "${HELM[@]}" -n "$TRAEFIK_NS" uninstall traefik-e2e >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete namespace "$TRAEFIK_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # The CRDs this run installed, and only those.
  if $eg_crds_installed; then "${KUBECTL[@]}" delete -f "$eg_crds" --ignore-not-found >/dev/null 2>&1 || true; fi
  if $gateway_api_installed; then "${KUBECTL[@]}" delete -f "$work/gateway-api.yaml" --ignore-not-found >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

echo "== Envoy Gateway $EG_VERSION"
# The Gateway API's CRDs, unless installed already (as by another test).
if ! "${KUBECTL[@]}" get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  curl -fsSL "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >"$work/gateway-api.yaml"
  gateway_api_installed=true
  "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$work/gateway-api.yaml" >/dev/null
fi
helm template eg-crds oci://docker.io/envoyproxy/gateway-crds-helm --version "$EG_VERSION" \
  --set crds.gatewayAPI.enabled=false --set crds.envoyGateway.enabled=true >"$eg_crds" 2>/dev/null
if ! "${KUBECTL[@]}" get crd envoyproxies.gateway.envoyproxy.io >/dev/null 2>&1; then eg_crds_installed=true; fi
"${KUBECTL[@]}" apply --server-side --force-conflicts -f "$eg_crds" >/dev/null
# The Backend API is off by default; the engine's socket is a Backend.
"${HELM[@]}" upgrade --install eg oci://docker.io/envoyproxy/gateway-helm --version "$EG_VERSION" --skip-crds \
  --set crds.enabled=false --namespace "$EG_NS" --create-namespace --set config.envoyGateway.extensionApis.enableBackend=true \
  --wait --timeout 5m >/dev/null
ok "Envoy Gateway installed"

# Traefik, as in e2e.sh: the same policy protects an Ingress it serves.
"${HELM[@]}" upgrade --install traefik-e2e traefik --repo https://traefik.github.io/charts \
  --version "$TRAEFIK_CHART_VERSION" --namespace "$TRAEFIK_NS" --create-namespace --values hack/kind/traefik-e2e-values.yaml >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null

# The user's objects: an app, Envoy Gateway's class, an EnvoyProxy with a
# field of the user's, a Gateway naming it, one naming none, a route on both
# and an Ingress for Traefik.
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: $NS}
spec:
  selector: {matchLabels: {app: eg-e2e}}
  template:
    metadata: {labels: {app: eg-e2e}}
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
  selector: {app: eg-e2e}
  ports: [{name: http, port: 8080}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: inkwall-e2e}
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata: {name: custom, namespace: $NS}
spec:
  provider:
    type: Kubernetes
    kubernetes:
      envoyDeployment:
        pod:
          labels: {e2e: custom}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: custom, namespace: $NS}
spec:
  gatewayClassName: inkwall-e2e
  infrastructure:
    parametersRef: {group: gateway.envoyproxy.io, kind: EnvoyProxy, name: custom}
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: plain, namespace: $NS}
spec:
  gatewayClassName: inkwall-e2e
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
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: $NS}
spec:
  ingressClassName: traefik-e2e
  rules:
    - host: $HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: app, port: {number: 8080}}}
YAML
"${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null

# What the user wrote, to compare with after the operator is gone.
user_objects() {
  "${KUBECTL[@]}" -n "$NS" get envoyproxy custom -o jsonpath='{.metadata.annotations}{.spec}'
  echo
  "${KUBECTL[@]}" -n "$NS" get gateway custom plain -o jsonpath='{range .items[*]}{.metadata.annotations}{.spec}{"\n"}{end}'
}
as_they_were() { [[ $(user_objects) == "$original" ]]; }
original=$(user_objects)

# envoy_pods GATEWAY: its running Envoy pods and their init containers, one
# per line.
envoy_pods() {
  "${KUBECTL[@]}" -n "$EG_NS" get pods -l "gateway.envoyproxy.io/owning-gateway-name=$1,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name}{"\n"}{end}' | grep '^|Running|'
}
injected() { local p; p=$(envoy_pods "$1") && ! grep -qv '^|Running|inkwall-engine' <<<"$p"; }
not_injected() { local p; p=$(envoy_pods "$1") && ! grep -q inkwall-engine <<<"$p"; }
# forward GATEWAY PORT: a port-forward to the Gateway's Envoy Service.
forward() {
  local svc
  svc=$("${KUBECTL[@]}" -n "$EG_NS" get svc -l "gateway.envoyproxy.io/owning-gateway-name=$1,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
    -o jsonpath='{.items[0].metadata.name}')
  "${KUBECTL[@]}" -n "$EG_NS" port-forward "svc/$svc" "$2:80" >/dev/null 2>&1 &
  pfs+=($!)
}
# A port-forward follows a pod: forward again after a rollout.
forward_all() {
  for pf in "${pfs[@]}"; do kill "$pf" 2>/dev/null || true; done
  pfs=()
  forward custom "$CUSTOM_PORT"
  forward plain "$PLAIN_PORT"
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" port-forward svc/traefik-e2e "$TRAEFIK_PORT:80" >/dev/null 2>&1 &
  pfs+=($!)
  sleep 1
}
# code PORT PATH [CURL_ARGS...]
code() {
  local port=$1 path=$2
  shift 2
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$@" "http://127.0.0.1:$port$path" || true
}
# all_are STATUS PATH [CURL_ARGS...]: through both Gateways and Traefik.
all_are() {
  local want=$1
  shift
  for port in "$CUSTOM_PORT" "$PLAIN_PORT" "$TRAEFIK_PORT"; do
    [[ $(code "$port" "$@") == "$want" ]] || return 1
  done
}
envoy_are() {
  local want=$1
  shift
  for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
    [[ $(code "$port" "$@") == "$want" ]] || return 1
  done
}
condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy shared -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
ready() { [[ $(condition Ready status) == True ]]; }
programmed_both() { [[ $(condition Programmed message) == *"wired to the engine in Traefik"*"wired to the engine in Envoy Gateway"* ]]; }
policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: shared, namespace: $NS}
spec:
  targetRefs:
    - {kind: Ingress, name: web}
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: app}
  mode: Block
  # CRS takes about 200 ms on the 48 KB form field below on a fast machine,
  # more on a CI runner: past the default 250 ms, the engine fails closed
  # (503). Envoy waits 500 ms longer than this.
  timeout: 1s
YAML
}
eep_accepted() {
  [[ $("${KUBECTL[@]}" -n "$NS" get envoyextensionpolicy inkwall-waf-app \
    -o jsonpath='{.status.ancestors[*].conditions[?(@.type=="Accepted")].status}') == "True True" ]]
}
has_sidecar() {
  [[ $("${KUBECTL[@]}" -n "$NS" get envoyproxy custom -o jsonpath='{.spec.provider.kubernetes.envoyDeployment.initContainers[0].name}') == inkwall-engine ]]
}
names_ours() { [[ $("${KUBECTL[@]}" -n "$NS" get gateway plain -o jsonpath='{.spec.infrastructure.parametersRef.name}') == inkwall-waf-plain ]]; }
labelled() { "${KUBECTL[@]}" -n "$EG_NS" get pods -l e2e=custom -o name | grep . >/dev/null; }
# whoami --verbose logs each request it gets, with its headers.
never_reached_app() { ! "${KUBECTL[@]}" -n "$NS" logs deployment/app --since=10m | grep -i "$1" >/dev/null; }
# The operator's buffer limit, in force on both Gateways.
limits_accepted() {
  for gw in custom plain; do
    [[ $("${KUBECTL[@]}" -n "$NS" get clienttrafficpolicy "inkwall-waf-$gw" \
      -o jsonpath='{.status.ancestors[*].conditions[?(@.type=="Accepted")].status}') == True ]] || return 1
  done
}
no_wiring() {
  ! "${KUBECTL[@]}" -n "$NS" get envoyextensionpolicy inkwall-waf-app >/dev/null 2>&1 &&
    ! "${KUBECTL[@]}" -n "$NS" get backend inkwall-engine >/dev/null 2>&1 &&
    ! "${KUBECTL[@]}" -n "$NS" get clienttrafficpolicy inkwall-waf-custom inkwall-waf-plain -o name 2>/dev/null | grep . &&
    ! "${KUBECTL[@]}" -n "$NS" get envoyproxy inkwall-waf-plain >/dev/null 2>&1
}

for gw in custom plain; do
  eventually "Envoy Gateway runs Gateway $gw" envoy_pods "$gw"
done
forward_all
eventually "the Gateways and Traefik serve the app" all_are 200 /
check "no policy yet: the attack passes" all_are 200 "$SQLI"

echo "== one policy, two proxies"
policy
eventually "the user's EnvoyProxy gets the engine" has_sidecar
eventually "Gateway plain names the operator's EnvoyProxy" names_ours
for gw in custom plain; do
  eventually "Envoy Gateway replaced Gateway $gw's pods with ones that have the engine" \
    injected "$gw"
done
eventually "Envoy Gateway accepts the EnvoyExtensionPolicy on both Gateways" eep_accepted
eventually "and the buffer limit on both Gateways" limits_accepted
eventually "Programmed through Traefik and Envoy Gateway" programmed_both
eventually "the policy is Ready" ready
forward_all
eventually "the attack is blocked through both Gateways and Traefik" all_are 403 "$SQLI"
check "benign traffic passes" all_are 200 /products/42
check "the user's pod label is kept" labelled

# The body: a benign one larger than Envoy's default buffer (32 KiB), so
# the operator's ClientTrafficPolicy matters, and an attack in a body.
{
  printf x=
  head -c 48000 /dev/zero | tr '\0' a
} >"$work/big"
big=$(for port in "$CUSTOM_PORT" "$PLAIN_PORT"; do
  code "$port" / -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$work/big"
  echo -n " "
done)
if [[ $big == "200 200 " ]]; then
  ok "a 48 KB benign body passes"
else
  fail "a 48 KB benign body passes (got $big)"
  # Envoy's answer, and the engines' verdicts: a 503 with reason timeout
  # is the engine's deadline; Envoy's own ext_proc errors are 500 or 504.
  curl -s -i -H "Host: $HOST" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$work/big" \
    "http://127.0.0.1:$CUSTOM_PORT/" | head -12
  "${KUBECTL[@]}" -n "$EG_NS" logs -l app.kubernetes.io/name=envoy -c inkwall-engine --tail=5 --prefix || true
fi
check "an attack in the body is blocked" envoy_are 403 / --data-urlencode "q=1' OR '1'='1"
# BufferedPartial: Envoy holds the headers until the engine has seen the
# body, so the app never sees the blocked request.
mark=held-$RANDOM$RANDOM
check "a body attack with a marked header is blocked" envoy_are 403 / -H "X-E2e-Mark: $mark" --data-urlencode "q=1' OR '1'='1"
check "and never reached the app" never_reached_app "$mark"

echo "== unprotected"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shared --timeout=60s >/dev/null
eventually "the operator's Envoy Gateway objects are gone" no_wiring
eventually "the user's EnvoyProxy and Gateways are as they were" as_they_were
for gw in custom plain; do
  eventually "Gateway $gw's pods no longer have the engine" \
    not_injected "$gw"
done
forward_all
eventually "the attack passes again" all_are 200 "$SQLI"

echo "== uninstall"
policy
for gw in custom plain; do
  eventually "Gateway $gw's pods have the engine again" \
    injected "$gw"
done
eventually "Programmed again" programmed_both
forward_all
eventually "blocking again" all_are 403 "$SQLI"
if "${HELM[@]}" uninstall inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm uninstall (with the unwire hook)"
else
  fail "helm uninstall"
fi
check "the operator's Envoy Gateway objects are gone" no_wiring
check "the user's EnvoyProxy and Gateways are as they were" as_they_were
for gw in custom plain; do
  eventually "Gateway $gw's pods no longer have the engine" \
    not_injected "$gw"
done
forward_all
eventually "the routes still answer after the uninstall (uninspected)" envoy_are 200 "$SQLI"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shared --ignore-not-found --timeout=30s >/dev/null || true

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; operator and Envoy logs:"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" logs deployment/inkwall-operator --tail=40 2>/dev/null || true
  "${KUBECTL[@]}" -n "$EG_NS" logs deployment/envoy-gateway --tail=40 2>/dev/null || true
  exit 1
fi
echo "envoy-gateway e2e: all checks passed"
