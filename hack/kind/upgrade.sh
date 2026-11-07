#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Upgrade test on kind (#129, #390): the last released chart, from GHCR,
# protects an Ingress and an IngressRoute through Traefik, and an HTTPRoute
# through Envoy Gateway (from 0.3.0, which wires it); `helm upgrade` to the chart
# and images of this checkout keeps them protected, wired once, and their
# policy Accepted and Programmed, with the CRDs at the new version;
# `helm rollback` to the last release, as docs/upgrading.md says, keeps them
# protected too; then, upgraded again, `helm uninstall` leaves the routes as
# they were before Inkwall wired them.
#
# A probe in the cluster sends attacks and benign requests through Traefik
# and Envoy Gateway all along. An attack that reaches the app fails the test at once. A
# request that gets no verdict (Traefik or its engine restarting, the route
# briefly gone) is a gap, unless it never reached Traefik while a request
# sent straight to Traefik's pod got its verdict (#348: the cluster's
# networking, after Traefik's pod was replaced; see the probe): the upgrade itself must leave none, since engines
# swap bundles atomically and keep enforcing while the operator restarts
# (also when it is rolled back);
# a Traefik restart may leave one of at most MAX_RESTART_GAP seconds. Envoy
# Gateway rolls its Envoy pods whenever the engine image changes (the
# upgrade and the rollback): its route may have a gap of at most
# MAX_ENVOY_GAP seconds then.
#
# Runs on a kind cluster without Inkwall installed, since it installs a
# release of its own: UPGRADE_CLUSTER, created if needed (at
# KIND_NODE_IMAGE, if set) and then deleted afterwards (KEEP=1 keeps it and the test's objects). Needs network access
# to ghcr.io and Traefik's chart repository.
set -euo pipefail

cd "$(dirname "$0")/../.."
# The versions under test (#393).
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${UPGRADE_CLUSTER:-inkwall-upgrade}
# The release it upgrades from: the latest, worked out from the tags (on a
# release-X.Y branch, the latest up to X.Y). UPGRADE_BRANCH is the branch
# under test (CI's checkout is detached); FROM_VERSION overrides it all.
if [[ -z ${FROM_VERSION:-} ]]; then
  FROM_VERSION=$(go run ./hack/releases -branch "${UPGRADE_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}")
fi
FROM_CHART=oci://ghcr.io/inkwall-dev/charts/inkwall
CHART=${CHART:-deploy/helm/inkwall}
OPERATOR_IMAGE=${OPERATOR_IMAGE:-inkwall-operator:dev}
ENGINE_IMAGE=${IMAGE:-inkwall-engine:dev}
# Seconds a request may go without a verdict, through the upgrade (and the
# rollback) and through the Traefik restart that follows it (see above).
MAX_UPGRADE_GAP=${MAX_UPGRADE_GAP:-0}
MAX_RESTART_GAP=${MAX_RESTART_GAP:-5}
MAX_ENVOY_GAP=${MAX_ENVOY_GAP:-5}
# Envoy Gateway, as in envoy-gateway-e2e.sh. UPGRADE_ENVOY_GATEWAY=0 leaves
# it out; so does a FROM_VERSION before 0.3.0, which doesn't wire it.
# Both from hack/versions.env (sourced above).
EG_VERSION=$ENVOY_GATEWAY_VERSION
EG_NS=envoy-gateway-upgrade
EG_HOST=gateway.upgrade.example.com
eg=true
if [[ ${UPGRADE_ENVOY_GATEWAY:-1} == 0 ]] || [[ $(printf '%s\n' 0.3.0 "$FROM_VERSION" | sort -V | head -1) != 0.3.0 ]]; then
  eg=false
fi
OPERATOR_NS=inkwall-system
NS=inkwall-upgrade
TRAEFIK_NS=traefik-e2e
HOST=ingress.upgrade.example.com
ROUTE_HOST=route.upgrade.example.com
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")
SQLI='/?id=1%27%20OR%20%271%27%3D%271'

# eventually retries for up to 2 minutes.
EVENTUALLY_TRIES=240
. hack/kind/lib.sh

created=false
if ! kind get clusters | grep -x "$CLUSTER" >/dev/null; then
  kind create cluster --name "$CLUSTER" ${KIND_NODE_IMAGE:+--image "$KIND_NODE_IMAGE"} --wait 120s
  created=true
fi
cleanup() {
  if [[ ${KEEP:-} == 1 ]]; then return; fi
  if $created; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  else
    # With the unwire hook, so nothing waits on the operator's finalizer.
    "${HELM[@]}" -n "$OPERATOR_NS" uninstall inkwall --wait --timeout 3m >/dev/null 2>&1 ||
      "${HELM[@]}" -n "$OPERATOR_NS" uninstall inkwall --no-hooks >/dev/null 2>&1 || true
    "${HELM[@]}" -n "$TRAEFIK_NS" uninstall traefik-e2e >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete namespace "$NS" "$TRAEFIK_NS" --wait=false >/dev/null 2>&1 || true
    if $eg; then
      "${KUBECTL[@]}" delete gatewayclass inkwall-upgrade --ignore-not-found >/dev/null 2>&1 || true
      "${HELM[@]}" -n "$EG_NS" uninstall eg --wait >/dev/null 2>&1 || true
      "${KUBECTL[@]}" delete namespace "$EG_NS" --wait=false >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT
if "${HELM[@]}" -n "$OPERATOR_NS" status inkwall >/dev/null 2>&1; then
  echo "cluster $CLUSTER already has an inkwall release; delete it first: kind delete cluster --name $CLUSTER" >&2
  exit 1
fi

# The images of this checkout, loaded now so the upgrade doesn't wait on
# them.
# PULL_IMAGES=1: the published images of a release candidate (make
# IMAGES=ghcr:<version>).
if [[ ${PULL_IMAGES:-} == 1 ]]; then
  docker pull -q "$OPERATOR_IMAGE" >/dev/null
  docker pull -q "$ENGINE_IMAGE" >/dev/null
else
  docker build --target operator -t "$OPERATOR_IMAGE" .
  docker build --target engine -t "$ENGINE_IMAGE" .
fi
kind load docker-image "$OPERATOR_IMAGE" "$ENGINE_IMAGE" --name "$CLUSTER"

# Envoy Gateway before Inkwall, so the release's rbac.integrations (auto)
# grants it.
PROXY_NAMESPACES=$TRAEFIK_NS
if $eg; then
  echo "== Envoy Gateway $EG_VERSION"
  PROXY_NAMESPACES=$TRAEFIK_NS,$EG_NS
  if ! "${KUBECTL[@]}" get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
    curl -fsSL "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" |
      "${KUBECTL[@]}" apply --server-side --force-conflicts -f - >/dev/null
  fi
  helm template eg-crds oci://docker.io/envoyproxy/gateway-crds-helm --version "$EG_VERSION" \
    --set crds.gatewayAPI.enabled=false --set crds.envoyGateway.enabled=true 2>/dev/null |
    "${KUBECTL[@]}" apply --server-side --force-conflicts -f - >/dev/null
  # The Backend API is off by default; the engine's socket is a Backend.
  "${HELM[@]}" upgrade --install eg oci://docker.io/envoyproxy/gateway-helm --version "$EG_VERSION" --skip-crds \
    --set crds.enabled=false --namespace "$EG_NS" --create-namespace --set config.envoyGateway.extensionApis.enableBackend=true \
    --wait --timeout 5m >/dev/null
  ok "Envoy Gateway installed"
fi

echo "== install $FROM_VERSION"
# From 0.2.2 and 0.1.5, only pods in injection.proxyNamespaces get the
# engine: list the proxies' namespaces when the old chart has the value.
from_values=()
if helm show values "$FROM_CHART" --version "$FROM_VERSION" 2>/dev/null | grep -q '^  proxyNamespaces:'; then
  from_values=(--set "injection.proxyNamespaces={$PROXY_NAMESPACES}")
fi
"${HELM[@]}" install inkwall "$FROM_CHART" --version "$FROM_VERSION" "${from_values[@]}" \
  --namespace "$OPERATOR_NS" --create-namespace --wait --timeout 5m >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
ok "chart $FROM_VERSION installed"

# Traefik, then the app behind it: an Ingress and an IngressRoute, each
# with a Middleware of the user's, which must outlive Inkwall's wiring.
# Without its Gateway API provider: this cluster has no Gateway API CRDs.
"${HELM[@]}" upgrade --install traefik-e2e traefik --repo https://traefik.github.io/charts \
  --version "$TRAEFIK_CHART_VERSION" --namespace "$TRAEFIK_NS" --create-namespace \
  --values hack/kind/traefik-e2e-values.yaml --set providers.kubernetesGateway.enabled=false \
  --set accessLog.enabled=true --set accessLog.filters.minDuration=1s >/dev/null # slow requests, for a gap (#320)
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: $NS}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: traefik/whoami:$WHOAMI_VERSION
          args: ["--port", "8080"]
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: $NS}
spec:
  selector: {app: web}
  ports: [{name: http, port: 8080}]
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: user-header, namespace: $NS}
spec:
  headers:
    customRequestHeaders: {X-User: kept}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: $NS
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: $NS-user-header@kubernetescrd
spec:
  ingressClassName: traefik-e2e
  rules:
    - host: $HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: web, port: {number: 8080}}}
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: {name: web, namespace: $NS}
spec:
  ingressClassName: traefik-e2e
  entryPoints: [web]
  routes:
    - kind: Rule
      match: Host(\`$ROUTE_HOST\`)
      middlewares: [{name: user-header}]
      services: [{name: web, port: 8080}]
YAML
if $eg; then
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: inkwall-upgrade}
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: web, namespace: $NS}
spec:
  gatewayClassName: inkwall-upgrade
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: web, namespace: $NS}
spec:
  parentRefs: [{name: web}]
  hostnames: [$EG_HOST]
  rules: [{backendRefs: [{name: web, port: 8080}]}]
YAML
fi
# The probe: while /tmp/run exists, it sends an attack and a benign request
# to the Ingress and an attack to the IngressRoute, through Traefik's
# Service (no port-forward, which a Traefik restart would break), and an
# attack and a benign request to the HTTPRoute through Envoy's Service
# (/tmp/eg; none without Envoy Gateway), and logs
# "uptime ingress-attack ingress-benign route-attack direct eg-attack eg-benign | dns/connect/total ..."
# (HTTP codes, 000 without an answer; each request's curl times, in
# seconds, 0 for a step it didn't finish). It runs as the pod's process: one started by
# kubectl exec may die with the exec session.
#
# It sends to the Service's ClusterIP, which probe_start writes to
# /tmp/svc, not to its DNS name (#320): a lookup in the pod (musl, five
# search domains) that loses a UDP query retries it only after 2.5 s. The
# probe measures Traefik and the engine, not the cluster's DNS.
#
# Each round also sends the attack straight to Traefik's pod (/tmp/pod,
# its IP:port, also from probe_start), for #348: a request to the
# ClusterIP whose TCP connect never finished (connect 0, total 2 s) while
# the direct one got its verdict in the same round never reached Traefik.
# The cause, reproduced on kind: a SYN sent to a Traefik pod while it was
# being replaced leaves a conntrack entry (SYN_SENT, 120 s, renewed by
# every SYN on it) DNATed to that pod, which kube-proxy doesn't remove for
# TCP; a later connection that reuses the source port is sent to the dead
# pod. probe_stop counts those as the cluster's misses, not gaps.
"${KUBECTL[@]}" -n "$NS" create configmap probe --from-file=probe.sh=/dev/stdin --dry-run=client -o yaml <<'SH' |
trap 'exit 0' TERM
# c HOST PATH [ADDR]: "CODE DNS/CONNECT/TOTAL" (curl's times, in seconds),
# through the Service, or to ADDR.
c() { curl -s -o /dev/null -m 2 -w '%{http_code} %{time_namelookup}/%{time_connect}/%{time_total}' -H "Host: $1" "http://${3:-$svc}$2"; }
while true; do
  if [ -e /tmp/run ]; then
    read -r svc </tmp/svc
    read -r pod </tmp/pod
    eg=$(cat /tmp/eg 2>/dev/null)
    read -r up _ </proc/uptime
    if [ -n "$eg" ]; then
      set -- $(c "$HOST" "$SQLI") $(c "$HOST" /products/42) $(c "$ROUTE_HOST" "$SQLI") $(c "$HOST" "$SQLI" "$pod") \
        $(c "$EG_HOST" "$SQLI" "$eg") $(c "$EG_HOST" /products/42 "$eg")
    else
      set -- $(c "$HOST" "$SQLI") $(c "$HOST" /products/42) $(c "$ROUTE_HOST" "$SQLI") $(c "$HOST" "$SQLI" "$pod") \
        "403 0/0/0" "200 0/0/0"
    fi
    echo "$up $1 $3 $5 $7 $9 ${11} | $2 $4 $6 $8 ${10} ${12}" >>/tmp/probe.log
  fi
  sleep 0.2
done
SH
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: probe, namespace: $NS}
spec:
  terminationGracePeriodSeconds: 1
  containers:
    - name: curl
      image: curlimages/curl:8.11.1
      command: ["sh", "/probe/probe.sh"]
      env:
        - {name: HOST, value: "$HOST"}
        - {name: ROUTE_HOST, value: "$ROUTE_HOST"}
        - {name: EG_HOST, value: "$EG_HOST"}
        - {name: SQLI, value: "$SQLI"}
      volumeMounts: [{name: probe, mountPath: /probe}]
  volumes: [{name: probe, configMap: {name: probe}}]
YAML
"${KUBECTL[@]}" -n "$NS" rollout status deployment/web --timeout=120s >/dev/null
"${KUBECTL[@]}" -n "$NS" wait --for=condition=Ready pod/probe --timeout=120s >/dev/null

# traefik_ip: Traefik's Service's ClusterIP, looked up through the API
# server rather than the cluster's DNS (#320), each time: a Service
# created again gets another.
traefik_ip() { "${KUBECTL[@]}" -n "$TRAEFIK_NS" get service traefik-e2e -o jsonpath='{.spec.clusterIP}'; }
# traefik_pod: the IP:port of Traefik's ready pod behind that Service, its
# web entry point. After a restart it is the new pod's; requests to it
# fail while that pod is replaced, so it never excuses a gap there.
traefik_pod() {
  local slices=("${KUBECTL[@]}" -n "$TRAEFIK_NS" get endpointslices -l kubernetes.io/service-name=traefik-e2e)
  local ip port
  ip=$("${slices[@]}" -o jsonpath='{range .items[*].endpoints[?(@.conditions.ready==true)]}{.addresses[0]}{"\n"}{end}' | head -1)
  port=$("${slices[@]}" -o jsonpath='{range .items[*].ports[?(@.name=="web")]}{.port}{"\n"}{end}' | head -1)
  if [[ -n $ip && -n $port ]]; then echo "$ip:$port"; fi
}
# eg_ip: Envoy's Service's ClusterIP, for the Gateway (empty without
# Envoy Gateway).
eg_ip() {
  if ! $eg; then return; fi
  "${KUBECTL[@]}" -n "$EG_NS" get svc -l "gateway.envoyproxy.io/owning-gateway-name=web,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
    -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null || true
}
# One request, from the probe pod to Traefik's Service (or, for the
# HTTPRoute's host, Envoy's).
code() {
  local ip
  ip=$(traefik_ip)
  if [[ $1 == "$EG_HOST" ]]; then ip=$(eg_ip); fi
  "${KUBECTL[@]}" -n "$NS" exec probe -- curl -s -o /dev/null -m 5 -w '%{http_code}' -H "Host: $1" "http://$ip$2" || true
}
status_is() { [[ $(code "$2" "$3") == "$1" ]]; }
user_header() {
  "${KUBECTL[@]}" -n "$NS" exec probe -- curl -s -m 5 -H "Host: $1" "http://$(traefik_ip)/" | grep '^X-User: kept' >/dev/null
}

# What the user wrote: the routes are back to it after the uninstall.
route_state() {
  "${KUBECTL[@]}" -n "$NS" get ingress web -o jsonpath='{.metadata.annotations}{.spec}'
  echo
  "${KUBECTL[@]}" -n "$NS" get ingressroutes.traefik.io web -o jsonpath='{.metadata.annotations}{.spec}'
}
eventually "Traefik serves the Ingress" status_is 200 "$HOST" /
eventually "Traefik serves the IngressRoute" status_is 200 "$ROUTE_HOST" /
if $eg; then eventually "Envoy Gateway serves the HTTPRoute" status_is 200 "$EG_HOST" /; fi
check "no policy yet: the attack passes" status_is 200 "$HOST" "$SQLI"
users_routes=$(route_state)

echo "== protect the routes with $FROM_VERSION"
traefik_engine_image() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" get pods -l app.kubernetes.io/name=traefik \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}' |
    sed -n 's/^|//p'
}
engine_image_is() { [[ $(traefik_engine_image | sort -u) == "$1" ]]; }
# Envoy's pods' engine image, as engine_image_is: Envoy Gateway's pods get
# the engine through the operator's EnvoyProxy, once a policy targets a
# route of their Gateway.
envoy_engine_image() {
  "${KUBECTL[@]}" -n "$EG_NS" get pods -l "gateway.envoyproxy.io/owning-gateway-name=web,gateway.envoyproxy.io/owning-gateway-namespace=$NS" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}' |
    sed -n 's/^|//p'
}
envoy_engine_is() { ! $eg || [[ $(envoy_engine_image | sort -u) == "$1" ]]; }
eventually "Traefik's pod has the $FROM_VERSION engine" engine_image_is "ghcr.io/inkwall-dev/inkwall-engine:$FROM_VERSION"
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: web, namespace: $NS}
spec:
  targetRefs:
    - {kind: Ingress, name: web}
    - {group: traefik.io, kind: IngressRoute, name: web}
$(if $eg; then echo "    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: web}"; fi)
  mode: Block
YAML
condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath="{.status.conditions[?(@.type==\"$1\")].status}" 2>/dev/null
}
accepted_programmed() { [[ $(condition Accepted)/$(condition Programmed)/$(condition Ready) == True/True/True ]]; }
# The wiring: the Ingress's middlewares, the IngressRoute's, the wired
# annotations, and the Middlewares in the namespace.
wiring() {
  "${KUBECTL[@]}" -n "$NS" get ingress web \
    -o jsonpath='{.metadata.annotations.traefik\.ingress\.kubernetes\.io/router\.middlewares}|{.metadata.annotations.waf\.inkwall\.dev/wired}'
  echo
  "${KUBECTL[@]}" -n "$NS" get ingressroutes.traefik.io web \
    -o jsonpath='{range .spec.routes[*]}{.middlewares[*].name}{";"}{end}|{.metadata.annotations.waf\.inkwall\.dev/wired}'
  echo
  "${KUBECTL[@]}" -n "$NS" get middlewares.traefik.io -o jsonpath='{.items[*].metadata.name}'
  echo
}
wired_once() {
  [[ $(wiring) == "$NS-inkwall-waf@kubernetescrd,$NS-user-header@kubernetescrd|$NS-inkwall-waf@kubernetescrd
inkwall-waf user-header;|inkwall-waf
inkwall-waf user-header" ]]
}
eventually "the policy is Accepted, Programmed and Ready" accepted_programmed
eventually "the Ingress and the IngressRoute are wired once, first, keeping the user's Middleware" wired_once
eventually "the attack is blocked on the Ingress" status_is 403 "$HOST" "$SQLI"
eventually "the attack is blocked on the IngressRoute" status_is 403 "$ROUTE_HOST" "$SQLI"
if $eg; then
  eventually "Envoy's pods have the $FROM_VERSION engine" envoy_engine_is "ghcr.io/inkwall-dev/inkwall-engine:$FROM_VERSION"
  eventually "the attack is blocked on the HTTPRoute" status_is 403 "$EG_HOST" "$SQLI"
  check "benign traffic passes on the HTTPRoute" status_is 200 "$EG_HOST" /products/42
fi
check "benign traffic passes" status_is 200 "$HOST" /products/42
check "the user's Middleware applies" user_header "$HOST"
wiring_before=$(wiring)

# probe_start / probe_stop NAME MAX_GAP [MAX_ENVOY_GAP]: start and stop
# the probe; probe_stop checks what it saw, with MAX_ENVOY_GAP (MAX_GAP by
# default) for the HTTPRoute.
probe_start() {
  local ip pod
  ip=$(traefik_ip)
  [[ -n $ip ]] || { fail "probe: no ClusterIP for Service $TRAEFIK_NS/traefik-e2e"; return; }
  pod=$(traefik_pod)
  [[ -n $pod ]] || { fail "probe: no ready endpoint of Service $TRAEFIK_NS/traefik-e2e"; return; }
  "${KUBECTL[@]}" -n "$NS" exec probe -- sh -c "echo $ip >/tmp/svc; echo $pod >/tmp/pod; echo $(eg_ip) >/tmp/eg; rm -f /tmp/probe.log; touch /tmp/run"
}
probe_stop() {
  local name=$1 max=$2 max_eg=${3:-$2} log summary
  "${KUBECTL[@]}" -n "$NS" exec probe -- rm -f /tmp/run
  # A round in flight ends within its three 2s timeouts.
  sleep 7
  log=$("${KUBECTL[@]}" -n "$NS" exec probe -- cat /tmp/probe.log 2>/dev/null || true)
  # For each request kind: requests, wrong answers, attacks that got
  # through (2xx), and the longest gap (s), from the first wrong answer to
  # the next right one (or the end). A request to the ClusterIP that never
  # connected while the one sent straight to Traefik's pod got its verdict
  # (403) is the cluster's miss (#348, see the probe): counted apart, not a
  # wrong answer; more than 3 of a kind fail the check all the same.
  summary=$(awk -v max="$max" -v max_eg="$max_eg" '
    # missed(times, direct): no TCP connection to the Service within the
    # 2 s timeout, while Traefik answered directly.
    function missed(times, direct,   a) {
      split(times, a, "/")
      return direct == 403 && a[2] + 0 == 0 && a[3] + 0 >= 1.9
    }
    function verdict(i, code, want, t, times, direct) {
      if (code == "000" && missed(times, direct)) { miss[i]++; return }
      n[i]++
      if (code == want) {
        if (start[i] != "") { g = t - start[i]; if (g > gap[i]) gap[i] = g; start[i] = "" }
        return
      }
      bad[i]++
      if (i != 2 && code ~ /^2/) through[i]++
      if (start[i] == "") start[i] = t
    }
    # uptime, six codes (ingress-attack ingress-benign route-attack direct
    # eg-attack eg-benign), "|", their times. Envoy has no direct request:
    # its misses are gaps.
    NF >= 14 {
      verdict(1, $2, 403, $1, $9, $5); verdict(2, $3, 200, $1, $10, $5); verdict(3, $4, 403, $1, $11, $5)
      verdict(4, $6, 403, $1, $13, 0); verdict(5, $7, 200, $1, $14, 0); last = $1
    }
    END {
      split("ingress-attack ingress-benign route-attack httproute-attack httproute-benign", names, " ")
      for (i = 1; i <= 5; i++) {
        limit = i >= 4 ? max_eg : max
        if (start[i] != "") { g = last - start[i] + 0.2; if (g > gap[i]) gap[i] = g }
        printf "%s: %d requests, %d without the right verdict, %d attacks through, longest gap %.1fs, %d never connected to the Service (Traefik answered directly)\n",
          names[i], n[i], bad[i], through[i], gap[i], miss[i]
        if (through[i] > 0) fail = 1
        if (miss[i] > 3) fail = 1
        if (bad[i] > 0 && gap[i] > limit + 0.0001) fail = 1
        if (n[i] < 10) { print "too few requests: is the probe running?"; fail = 1 }
      }
      exit fail
    }' <<<"$log") && rc=0 || rc=$?
  sed 's/^/      /' <<<"$summary"
  # The wrong rounds, even within the gap allowed, with each request's
  # dns/connect/total times.
  grep -Ev '^[0-9.]* 403 200 403 [0-9]+ 403 200 ' <<<"$log" | head -20 | sed 's/^/        /' || true
  if [[ $rc == 0 ]]; then
    ok "$name: no attack got through, no gap over ${max}s (Envoy Gateway: ${max_eg}s)"
  else
    fail "$name: an attack got through, a gap over ${max}s (Envoy Gateway: ${max_eg}s), or no probe traffic"
    # The engine's and Traefik's logs of the last 2 minutes; Traefik's
    # access log has the requests that took 1 s or more.
    echo "      engine (in Traefik's pod) and Traefik, last 2 minutes:"
    "${KUBECTL[@]}" -n "$TRAEFIK_NS" logs deployment/traefik-e2e --all-containers --prefix --since=2m 2>&1 |
      tail -80 | sed 's/^/      /' || true
    if $eg; then
      echo "      engine and Envoy (in Envoy's pods), last 2 minutes:"
      "${KUBECTL[@]}" -n "$EG_NS" logs -l "gateway.envoyproxy.io/owning-gateway-name=web" --all-containers --prefix --since=2m 2>&1 |
        tail -80 | sed 's/^/      /' || true
    fi
  fi
}

# upgrade: helm upgrade to the chart and images of this checkout, with
# rbac.integrations auto (true by default), which the checks below test, and
# Traefik's namespace listed in injection.proxyNamespaces, as the upgrade
# guide says (not a default proxy namespace).
upgrade() {
  "${HELM[@]}" upgrade inkwall "$CHART" --namespace "$OPERATOR_NS" \
    --set "injection.proxyNamespaces={$PROXY_NAMESPACES}" \
    --set operator.image.repository="${OPERATOR_IMAGE%:*}" \
    --set operator.image.tag="${OPERATOR_IMAGE##*:}" \
    --set operator.image.pullPolicy=Never \
    --set engine.image.repository="${ENGINE_IMAGE%:*}" \
    --set engine.image.tag="${ENGINE_IMAGE##*:}" \
    --set engine.image.pullPolicy=Never \
    --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=auto --set rbac.integrations.istio=auto --set rbac.integrations.istioIngress=auto \
    --wait --timeout 5m >/dev/null
}

echo "== helm upgrade to $CHART"
probe_start
sleep 5
# Traefik runs in a namespace of its own, not one of the default proxy
# namespaces: without it listed, the upgrade stops (its pods run the
# engine) instead of leaving its routes uninspected. --reset-values drops
# the value whether or not the old release set it.
if out=$("${HELM[@]}" upgrade inkwall "$CHART" --namespace "$OPERATOR_NS" --reset-values 2>&1) ||
  ! grep "pods with the Inkwall engine run in namespace(s) .*$TRAEFIK_NS" <<<"$out" >/dev/null; then
  fail "helm upgrade without $TRAEFIK_NS in injection.proxyNamespaces: want it refused, got: $out"
else
  ok "helm upgrade refused while Traefik's namespace isn't a proxy namespace"
fi
if upgrade; then
  ok "helm upgrade"
else
  fail "helm upgrade"
fi
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
# operator_image_is IMAGE: every operator replica runs it.
operator_image_is() {
  [[ $("${KUBECTL[@]}" -n "$OPERATOR_NS" get pods -l app.kubernetes.io/component=operator \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.spec.containers[0].image}{"\n"}{end}' | sed -n 's/^|//p' | sort -u) == "$1" ]]
}
eventually "every operator replica runs the new image" operator_image_is "$OPERATOR_IMAGE"
# The new operator puts the new engine in Envoy's pods: Envoy Gateway
# rolls them.
if $eg; then eventually "Envoy's pods have the new engine" envoy_engine_is "$ENGINE_IMAGE"; fi
# The new leader reconciles everything at start; give it time to touch
# what it would, with the probe still running.
sleep 30
probe_stop "through the upgrade" "$MAX_UPGRADE_GAP" "$MAX_ENVOY_GAP"

# Each CRD is the chart's: the same spec as files/crds (a server-side diff,
# empty), labelled with the new chart.
chart_label="inkwall-$(sed -n 's/^version: *//p' "$CHART/Chart.yaml" | tr + _)"
crds_new() {
  local f name
  for f in "$CHART"/files/crds/*.yaml; do
    "${KUBECTL[@]}" diff --server-side --force-conflicts -f "$f" >/dev/null || return 1
    name=$(sed -n 's/^  name: //p' "$f" | head -1)
    [[ $("${KUBECTL[@]}" get crd "$name" -o jsonpath='{.metadata.labels.helm\.sh/chart}') == "$chart_label" ]] || return 1
  done
}
check "the CRDs are the new chart's ($chart_label)" crds_new
# rbac.integrations auto: the cluster serves Traefik's API group, and
# Envoy Gateway's when it is installed, not Istio's (either API).
integration_roles() {
  "${KUBECTL[@]}" get clusterrole inkwall-operator-traefik &&
    if $eg; then "${KUBECTL[@]}" get clusterrole inkwall-operator-envoy-gateway; else ! "${KUBECTL[@]}" get clusterrole inkwall-operator-envoy-gateway; fi &&
    ! "${KUBECTL[@]}" get clusterrole inkwall-operator-istio &&
    ! "${KUBECTL[@]}" get clusterrole inkwall-operator-istio-ingress
}
check "only the installed proxies' integration roles are granted (auto)" integration_roles
same_wiring() { [[ $(wiring) == "$wiring_before" ]]; }
check "the wiring is unchanged, not duplicated" same_wiring
# The new operator may add settings to its Middleware (it rewrites it to its
# own spec), so check the ones protection depends on, not the whole spec.
operator_middleware() {
  [[ $("${KUBECTL[@]}" -n "$NS" get middlewares.traefik.io inkwall-waf \
    -o jsonpath='{.spec.forwardAuth.address} {.spec.forwardAuth.trustForwardHeader} {.spec.forwardAuth.forwardBody}') == \
    "http://127.0.0.1:9001/v1/forward-auth false true" ]]
}
eventually "Inkwall's Middleware calls the engine, with trustForwardHeader off and bodies forwarded" operator_middleware
eventually "the policy is still Accepted, Programmed and Ready" accepted_programmed
check "the attack is blocked on the Ingress" status_is 403 "$HOST" "$SQLI"
check "the attack is blocked on the IngressRoute" status_is 403 "$ROUTE_HOST" "$SQLI"
if $eg; then check "the attack is blocked on the HTTPRoute" status_is 403 "$EG_HOST" "$SQLI"; fi
check "benign traffic passes" status_is 200 "$HOST" /products/42

# Traefik restarted: its new pod gets the new engine from the new operator.
echo "== Traefik restarted onto the new engine"
probe_start
sleep 5
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
eventually "Traefik's pod has the new engine" engine_image_is "$ENGINE_IMAGE"
sleep 15
probe_stop "through the Traefik restart" "$MAX_RESTART_GAP"
check "the wiring is unchanged, not duplicated" same_wiring
eventually "Inkwall's Middleware calls the engine, with trustForwardHeader off and bodies forwarded" operator_middleware
eventually "the policy is Accepted, Programmed and Ready" accepted_programmed
eventually "the user's Middleware still applies" user_header "$HOST"

# docs/upgrading.md, rolling back to 0.2.x: nothing to unprotect here (no
# HTTPRoute), so roll back, then restart Traefik onto the older engine.
echo "== helm rollback to $FROM_VERSION"
probe_start
sleep 5
if "${HELM[@]}" rollback inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm rollback"
else
  fail "helm rollback"
fi
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
eventually "every operator replica runs the $FROM_VERSION image" operator_image_is "ghcr.io/inkwall-dev/inkwall-operator:$FROM_VERSION"
if $eg; then eventually "Envoy's pods have the $FROM_VERSION engine again" envoy_engine_is "ghcr.io/inkwall-dev/inkwall-engine:$FROM_VERSION"; fi
sleep 30
probe_stop "through the rollback" "$MAX_UPGRADE_GAP" "$MAX_ENVOY_GAP"
release_chart_is() { "${HELM[@]}" -n "$OPERATOR_NS" list --filter '^inkwall$' -o json | grep -F "\"chart\":\"inkwall-$1\"" >/dev/null; }
check "the release is back on chart $FROM_VERSION" release_chart_is "$FROM_VERSION"
# 0.3.0 added a ClusterRole per integration: rolling back to an older
# release removes it, to 0.3.0 or later keeps it.
if helm show values "$FROM_CHART" --version "$FROM_VERSION" 2>/dev/null | grep -q '^  integrations:'; then
  integration_roles() { "${KUBECTL[@]}" get clusterrole inkwall-operator-traefik; }
  check "the integration roles are back to $FROM_VERSION's" integration_roles
else
  no_integration_roles() { ! "${KUBECTL[@]}" get clusterrole inkwall-operator-traefik; }
  check "the integration roles are gone" no_integration_roles
fi
check "the wiring is unchanged, not duplicated" same_wiring
eventually "the policy is Accepted, Programmed and Ready" accepted_programmed
check "the attack is blocked on the Ingress" status_is 403 "$HOST" "$SQLI"
check "the attack is blocked on the IngressRoute" status_is 403 "$ROUTE_HOST" "$SQLI"
if $eg; then check "the attack is blocked on the HTTPRoute" status_is 403 "$EG_HOST" "$SQLI"; fi
check "benign traffic passes" status_is 200 "$HOST" /products/42
probe_start
sleep 5
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
eventually "Traefik's pod has the $FROM_VERSION engine again" engine_image_is "ghcr.io/inkwall-dev/inkwall-engine:$FROM_VERSION"
sleep 15
probe_stop "through the Traefik restart after the rollback" "$MAX_RESTART_GAP"
check "the wiring is unchanged, not duplicated" same_wiring
eventually "the policy is Accepted, Programmed and Ready" accepted_programmed
eventually "the user's Middleware still applies" user_header "$HOST"

# Upgraded again, so the uninstall below runs this chart's hook.
echo "== helm upgrade to $CHART again"
if upgrade; then
  ok "helm upgrade"
else
  fail "helm upgrade"
fi
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
eventually "every operator replica runs the new image" operator_image_is "$OPERATOR_IMAGE"
eventually "the policy is Accepted, Programmed and Ready" accepted_programmed
check "the wiring is unchanged, not duplicated" same_wiring
check "the attack is blocked on the Ingress" status_is 403 "$HOST" "$SQLI"
if $eg; then
  eventually "Envoy's pods have the new engine" envoy_engine_is "$ENGINE_IMAGE"
  eventually "the attack is blocked on the HTTPRoute" status_is 403 "$EG_HOST" "$SQLI"
fi

echo "== helm uninstall"
if "${HELM[@]}" uninstall inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm uninstall (with the unwire hook)"
else
  fail "helm uninstall"
fi
same_routes() { [[ $(route_state) == "$users_routes" ]]; }
check "the Ingress and the IngressRoute are as the user wrote them" same_routes
same_routes || diff <(echo "$users_routes") <(route_state) | sed 's/^/      /' || true
no_middleware() { ! "${KUBECTL[@]}" -n "$NS" get middlewares.traefik.io inkwall-waf >/dev/null 2>&1; }
check "Inkwall's Middleware is deleted" no_middleware
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
eventually "a new Traefik pod has no engine" engine_image_is ""
eventually "the Ingress is served (uninspected)" status_is 200 "$HOST" "$SQLI"
eventually "so is the IngressRoute" status_is 200 "$ROUTE_HOST" "$SQLI"
if $eg; then
  eventually "Envoy's pods no longer have the engine" envoy_engine_is ""
  eventually "the HTTPRoute is served (uninspected)" status_is 200 "$EG_HOST" "$SQLI"
fi
eventually "the user's Middleware still applies" user_header "$HOST"

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; operator logs:"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" logs deployment/inkwall-operator --tail=40 2>/dev/null || true
  exit 1
fi
echo "upgrade: all checks passed"
