#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of operator milestone O2 on the kind cluster (#26): a
# WAFPolicy applied in the cluster is enforced by an engine, which takes it
# from the operator. Needs the operator installed (make kind-operator, which
# make kind-e2e runs first). KEEP=1 leaves the test's objects in place.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${IMAGE:-inkwall-engine:dev}
OPERATOR_NS=inkwall-system
CHART=${CHART:-deploy/helm/inkwall}
NS=inkwall-e2e
HOST=e2e.example.com
PORT=${E2E_PORT:-18480}
TRAEFIK_PORT=${E2E_TRAEFIK_PORT:-18080}
TRAEFIK_NS=traefik-e2e
TRAEFIK_HOST=traefik.e2e.example.com
TRAEFIK_CHART_VERSION=41.6.1 # Traefik v3.7.13, as hack/kind/up.sh
KUBECTL=(kubectl --context "kind-$CLUSTER")
SQLI='/?id=1%27%20OR%20%271%27%3D%271'

failures=0
ok() { printf 'ok    %s\n' "$1"; }
fail() {
  printf 'FAIL  %s\n' "$1"
  failures=$((failures + 1))
}

# check DESCRIPTION COMMAND...: one try.
check() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then
    ok "$what"
  else
    fail "$what"
  fi
}

# eventually DESCRIPTION COMMAND...: retries for up to 60s; a failure is
# counted, and the test goes on.
eventually() {
  local what=$1
  shift
  for _ in $(seq 120); do
    if "$@" >/dev/null 2>&1; then
      ok "$what"
      return 0
    fi
    sleep 0.5
  done
  fail "$what"
}

code() {
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "http://127.0.0.1:$PORT$1" || true
}
status_is() { [[ $(code "$2") == "$1" ]]; }

condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy app -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
enforced_by_all() { [[ $(condition Enforced reason) == Enforced && $(condition Enforced message) == 1/1\ engines* ]]; }

engine_pod() { "${KUBECTL[@]}" -n "$NS" get pods -l app=e2e -o jsonpath='{.items[0].metadata.name}'; }
restarts() { "${KUBECTL[@]}" -n "$NS" get pods -l app=e2e -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="inkwall-engine")].restartCount}'; }

policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: app
  namespace: $NS
spec:
  targetRefs: [{kind: Ingress, name: app}]
  mode: $1
YAML
}

if ! "${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-operator first" >&2
  exit 1
fi

# The engine image with bundle mode.
docker build --target engine -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER"

# The trust ConfigMap: the operator's CA and the bundle public key, both
# public, copied into the app's namespace.
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
trust=$(mktemp -d)
# cp_cleanup undoes the control plane section, also when it fails midway:
# a GitOps InkwallConfig left behind would change the next run.
cp_cleanup() {
  if [[ -n ${cp_ca:-} ]]; then rm -f "$cp_ca"; fi
  "${KUBECTL[@]}" delete inkwallconfig default --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" -n "$OPERATOR_NS" delete secret inkwall-control-plane-identity --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete namespace inkwall-cp-stub --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
cleanup() {
  if [[ -n ${pf:-} ]]; then kill "$pf" 2>/dev/null || true; fi
  if [[ ${KEEP:-} != 1 ]]; then cp_cleanup; fi
  if [[ -n ${tpf:-} ]]; then kill "$tpf" 2>/dev/null || true; fi
  rm -rf "$trust"
  if [[ ${KEEP:-} != 1 ]]; then
    "${KUBECTL[@]}" delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
    "${KUBECTL[@]}" -n "$OPERATOR_NS" delete role,rolebinding inkwall-e2e-bundle-reader >/dev/null 2>&1 || true
    helm --kube-context "kind-$CLUSTER" -n "$TRAEFIK_NS" uninstall traefik-e2e >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete namespace "$TRAEFIK_NS" --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
"${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-operator-webhook-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$trust/ca.crt"
"${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle-signing-key -o jsonpath='{.data.ed25519\.pub}' | base64 -d >"$trust/ed25519.pub"
"${KUBECTL[@]}" -n "$NS" create configmap inkwall-trust --from-file="$trust/ca.crt" --from-file="$trust/ed25519.pub" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null

"${KUBECTL[@]}" -n "$NS" delete wafpolicy app --ignore-not-found >/dev/null
"${KUBECTL[@]}" apply -f hack/kind/e2e.yaml >/dev/null
"${KUBECTL[@]}" -n "$NS" rollout restart deployment/app >/dev/null
"${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null
eventually "one engine pod" bash -c "[[ \$(${KUBECTL[*]} -n $NS get pods -l app=e2e --no-headers | wc -l) == 1 ]]"

"${KUBECTL[@]}" -n "$NS" port-forward svc/app "$PORT:8480" >/dev/null 2>&1 &
pf=$!
eventually "engine reachable" status_is 200 /

echo "== no policy"
others=$("${KUBECTL[@]}" get wafpolicy -A --no-headers 2>/dev/null | wc -l)
if [[ $others == 0 ]]; then
  eventually "an attack passes: no policy covers the route" status_is 200 "$SQLI"
else
  # Another policy may cover every host (an Ingress without a host).
  echo "skip  $others other WAFPolicy objects in the cluster may cover this host"
fi

echo "== a policy in block mode"
policy Block
pod=$(engine_pod)
eventually "the engine blocks the attack" status_is 403 "$SQLI"
check "a benign request passes" status_is 200 /products/42
eventually "the policy is Enforced by the engine (1/1)" enforced_by_all

echo "== a policy change, without restarting the engine"
policy Detect
eventually "detect mode lets the attack through" status_is 200 "$SQLI"
same_pod() { [[ $(engine_pod) == "$pod" && $(restarts) == 0 ]]; }
check "same engine pod, no restart" same_pod
policy Block
eventually "block mode again" status_is 403 "$SQLI"

echo "== operator down"
# A policy blocks: proxy pods must not start without the engine (#51).
pod_webhook_policy() {
  "${KUBECTL[@]}" get mutatingwebhookconfiguration inkwall-operator-mutating -o jsonpath='{.webhooks[?(@.name=="pods.waf.inkwall.dev")].failurePolicy}'
}
fails() { [[ $(pod_webhook_policy) == "$1" ]]; }
eventually "the Pod webhook fails closed (a policy blocks)" fails Fail
# proxy_pod [EXTRA_LABELS [KUBECTL_ARGS...]]: creates a Traefik pod (dry run).
proxy_pod() {
  local extra=${1:-}
  shift || true
  "${KUBECTL[@]}" apply --dry-run=server "$@" -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: traefik-check
  namespace: $NS
  labels: {app.kubernetes.io/name: traefik${extra:+, $extra}}
spec:
  containers: [{name: traefik, image: traefik:v3.7.13}]
YAML
}
"${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=0 >/dev/null
eventually "operator stopped" bash -c "[[ -z \$(${KUBECTL[*]} -n $OPERATOR_NS get pods -l app.kubernetes.io/component=operator -o name) ]]"
check "the engine still blocks without the operator" status_is 403 "$SQLI"
check "benign traffic unaffected" status_is 200 /products/42
# Refused by the webhook itself, not for another reason.
refused() {
  local out
  out=$(proxy_pod 2>&1) && return 1
  grep -q "failed calling webhook" <<<"$out"
}
eventually "a new proxy pod is refused without the operator" refused
# The way out: a pod labeled to opt out skips the webhook and starts.
opted_out() { proxy_pod 'waf.inkwall.dev/inject: "false"' >/dev/null 2>&1; }
check "a proxy pod labeled to opt out starts without the operator" opted_out
# A new pod, with no cached bundle, while the operator is down: it reads the
# bundle Secret (#40).
"${KUBECTL[@]}" -n "$NS" rollout restart deployment/app >/dev/null
"${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null
eventually "the old engine pod is gone" bash -c "[[ \$(${KUBECTL[*]} -n $NS get pods -l app=e2e --no-headers | wc -l) == 1 ]]"
kill "$pf" 2>/dev/null || true
"${KUBECTL[@]}" -n "$NS" port-forward svc/app "$PORT:8480" >/dev/null 2>&1 &
pf=$!
eventually "a new engine pod blocks without the operator (bundle Secret)" status_is 403 "$SQLI"
secret_logged() { "${KUBECTL[@]}" -n "$NS" logs deployment/app -c inkwall-engine | grep -q "bundle applied from the Secret"; }
check "it took the bundle from the Secret" secret_logged
"${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=2 >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
eventually "Enforced again once the operator is back" enforced_by_all

echo "== the policy deleted"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy app >/dev/null
eventually "enforcement stops" status_is 200 "$SQLI"
blocking=$("${KUBECTL[@]}" get wafpolicy -A -o jsonpath='{.items[?(@.spec.mode=="Block")].metadata.name}' 2>/dev/null)
if [[ -z $blocking ]]; then
  eventually "the Pod webhook fails open again (no policy blocks)" fails Ignore
else
  echo "skip  other policies block: $blocking"
fi

# Through Traefik (#27): a Traefik installed with nothing about Inkwall gets
# the engine injected, and a policy on an Ingress it serves is wired,
# enforced in Traefik's pod and Ready.
tcode() {
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $TRAEFIK_HOST" "http://127.0.0.1:$TRAEFIK_PORT$1" || true
}
tstatus_is() { [[ $(tcode "$2") == "$1" ]]; }
tcondition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
ready() { [[ $(tcondition Ready status) == True ]]; }
wired() {
  [[ $("${KUBECTL[@]}" -n "$NS" get ingress web -o jsonpath='{.metadata.annotations.traefik\.ingress\.kubernetes\.io/router\.middlewares}') == *inkwall-waf@kubernetescrd* ]]
}
unwired() { ! wired; }
# Running pods (not terminating) and their init containers, one per line.
traefik_pods() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" get pods -l app.kubernetes.io/name=traefik \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.spec.initContainers[*].name}{"\n"}{end}' | grep '^|'
}
# Every running Traefik pod has the engine, first.
traefik_injected() {
  local pods
  pods=$(traefik_pods) && ! grep -qv '^|inkwall-engine' <<<"$pods"
}

echo "== through Traefik"
helm --kube-context "kind-$CLUSTER" upgrade --install traefik-e2e traefik --repo https://traefik.github.io/charts \
  --version "$TRAEFIK_CHART_VERSION" --namespace "$TRAEFIK_NS" --create-namespace --values hack/kind/traefik-e2e-values.yaml >/dev/null
# Restarted: pods from an earlier run may predate this operator (or an
# uninstall).
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
eventually "Traefik's pod has the injected engine" traefik_injected
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: $NS
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: web
          image: traefik/whoami:v1.10.3
          args: ["--port", "8080"]
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: $NS
spec:
  selector: {app: web}
  ports: [{name: http, port: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: $NS
spec:
  ingressClassName: traefik-e2e
  rules:
    - host: $TRAEFIK_HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: web, port: {number: 8080}}}
YAML
"${KUBECTL[@]}" -n "$NS" rollout status deployment/web --timeout=120s >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" port-forward svc/traefik-e2e "$TRAEFIK_PORT:80" >/dev/null 2>&1 &
tpf=$!
eventually "Traefik serves the app" tstatus_is 200 /
check "no policy yet: the attack passes through Traefik" tstatus_is 200 "$SQLI"

"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
  namespace: $NS
spec:
  targetRefs: [{kind: Ingress, name: web}]
  mode: Block
YAML
eventually "the operator wired the Ingress" wired
eventually "the engine in Traefik's pod blocks the attack" tstatus_is 403 "$SQLI"
check "benign traffic passes through Traefik" tstatus_is 200 /products/42
eventually "the policy is Ready" ready
# Security events (#91): the engine sends what it blocked to the operator.
events_received() {
  local pod n total=0
  for pod in $("${KUBECTL[@]}" -n "$OPERATOR_NS" get pods -l app.kubernetes.io/component=operator -o name); do
    n=$("${KUBECTL[@]}" get --raw "/api/v1/namespaces/$OPERATOR_NS/pods/${pod#pod/}:8080/proxy/metrics" |
      sed -n 's/^inkwall_operator_events_received_total \([0-9.e+]*\)$/\1/p')
    total=$(awk -v a="$total" -v b="${n:-0}" 'BEGIN { print a + b }')
  done
  awk -v t="$total" 'BEGIN { exit !(t >= 1) }'
}
eventually "the operator received the engine's security events" events_received

"${KUBECTL[@]}" -n "$NS" delete wafpolicy web >/dev/null
eventually "unwired when the policy is deleted" unwired
eventually "the attack passes again" tstatus_is 200 "$SQLI"

# Traefik deployed with other labels (#50): InkwallConfig names them, the
# operator restarts with them, and their pods get the engine.
injected() {
  [[ $(proxy_pod "$1" -o jsonpath='{.spec.initContainers[0].name}' 2>/dev/null) == inkwall-engine ]]
}
not_injected() { proxy_pod "$1" >/dev/null 2>&1 && ! injected "$1"; }
selector_is() {
  [[ $("${KUBECTL[@]}" get mutatingwebhookconfiguration inkwall-operator-mutating \
    -o jsonpath='{.webhooks[?(@.name=="pods.waf.inkwall.dev")].objectSelector.matchLabels}') == "$1" ]]
}
# eventually_long DESCRIPTION COMMAND...: like eventually, for up to 2
# minutes (the replicas restart up to 30s apart).
eventually_long() {
  local what=$1
  shift
  for _ in $(seq 240); do
    if "$@" >/dev/null 2>&1; then
      ok "$what"
      return 0
    fi
    sleep 0.5
  done
  fail "$what"
}
echo "== custom proxy labels"
if "${KUBECTL[@]}" get inkwallconfig default >/dev/null 2>&1; then
  echo "skip  an InkwallConfig exists; not changing its integrations"
else
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  integrations:
  - controller: traefik
    selector: {matchLabels: {app.kubernetes.io/component: edge-proxy}}
YAML
  eventually_long "the Pod webhook follows the InkwallConfig's selector" selector_is '{"app.kubernetes.io/component":"edge-proxy"}'
  eventually_long "a pod with the custom labels gets the engine" injected "app.kubernetes.io/component: edge-proxy"
  check "the default labels alone no longer match" not_injected ""
  "${KUBECTL[@]}" delete inkwallconfig default >/dev/null
  eventually_long "back to the default selector" selector_is '{"app.kubernetes.io/name":"traefik"}'
  "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
fi

# The optional control plane (#88): a stub in the cluster (never a real one),
# the operator trusting its CA through the chart (#89), enrollment with a
# one-time token, the primary stream, and the token refused a second time.
echo "== control plane (stub)"
CP_NS=inkwall-cp-stub
CP_HOST=stub.$CP_NS.svc
CP_TOKEN=e2e-token-$RANDOM
docker build -q -f hack/kind/stub.Dockerfile -t inkwall-cp-stub:dev . >/dev/null
kind load docker-image inkwall-cp-stub:dev --name "$CLUSTER" >/dev/null
"${KUBECTL[@]}" create namespace "$CP_NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: stub, namespace: $CP_NS}
spec:
  selector: {matchLabels: {app: cp-stub}}
  template:
    metadata: {labels: {app: cp-stub}}
    spec:
      containers:
        - name: stub
          image: inkwall-cp-stub:dev
          imagePullPolicy: Never
          args: ["--host=$CP_HOST", "--token=$CP_TOKEN"]
          ports: [{containerPort: 8443}, {containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: stub, namespace: $CP_NS}
spec:
  selector: {app: cp-stub}
  ports: [{name: grpc, port: 8443}, {name: admin, port: 8080}]
YAML
"${KUBECTL[@]}" -n "$CP_NS" rollout status deployment/stub --timeout=120s >/dev/null
# Through the API server's service proxy: no local port to collide with.
stub_get() { "${KUBECTL[@]}" get --raw "/api/v1/namespaces/$CP_NS/services/stub:admin/proxy/$1"; }
stub_stats() { stub_get stats; }
eventually "the stub control plane serves" stub_stats
cp_ca=$(mktemp)
stub_get ca.crt >"$cp_ca"

helm --kube-context "kind-$CLUSTER" upgrade inkwall "$CHART" --namespace "$OPERATOR_NS" --reuse-values \
  --set-file controlPlane.caBundle="$cp_ca" --set controlPlane.enrollmentToken="$CP_TOKEN" >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata: {name: default}
spec:
  mode: GitOps
  controlPlane:
    endpoint: grpcs://$CP_HOST:8443
    enrollmentSecretRef: {name: inkwall-enrollment, namespace: $OPERATOR_NS}
YAML
cp_reason() {
  "${KUBECTL[@]}" get inkwallconfig default -o jsonpath='{.status.conditions[?(@.type=="ControlPlaneConnected")].reason}'
}
cp_is() { [[ $(cp_reason) == "$1" ]]; }
eventually_long "the cluster enrolls and connects (ControlPlaneConnected)" cp_is Connected
identity() { "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-control-plane-identity >/dev/null 2>&1; }
check "its certificate is stored" identity
primary_hello() { stub_stats | grep -q '"STREAM_ROLE_PRIMARY CLUSTER_MODE_GITOPS'; }
check "the stub got a primary Hello in GitOps mode" primary_hello
beats() { [[ $(stub_stats | sed -n 's/.*"heartbeats":\([0-9]*\).*/\1/p') -ge 1 ]]; }
eventually "heartbeats arrive" beats
# State sync (#90): the leader reports the cluster, and every change
# within seconds; it never writes the objects.
state_has() { stub_stats | grep -qF "\"$1\""; }
eventually "the stub got the cluster state (InkwallConfig)" state_has "InkwallConfig /default"
last_state() { stub_stats | sed -n "s/.*\"lastState\":{[^}]*\"$1\":\([0-9]*\).*/\1/p"; }
engines_seen() { [[ $(last_state engines) -ge 1 && $(last_state podsWithEngine) -ge 1 && $(last_state bundleVersion) -ge 1 ]]; }
# The operator just restarted: its engines reconnect and are reported again
# within seconds, and the change is sent.
eventually "the state has the engines, Traefik pods with the engine and the bundle" engines_seen ||
  echo "      stub stats: $(stub_stats)"
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: cp-sync
  namespace: $NS
spec:
  # No such Ingress: the policy changes nothing, it only has to be reported.
  targetRefs: [{kind: Ingress, name: cp-sync}]
  mode: Detect
YAML
eventually "a new WAFPolicy reaches the control plane" state_has "WAFPolicy $NS/cp-sync"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy cp-sync --wait >/dev/null
state_lacks() { ! state_has "$1"; }
eventually "and so does its deletion" state_lacks "WAFPolicy $NS/cp-sync"
# A restarted operator without its certificate (lost, say) can only enroll
# again: the token is used, so the stub refuses it. A running stream keeps
# its certificate in memory, hence the restart.
"${KUBECTL[@]}" -n "$OPERATOR_NS" delete secret inkwall-control-plane-identity --ignore-not-found >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout restart deployment/inkwall-operator >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
eventually_long "a used token is refused (EnrollmentTokenRejected)" cp_is EnrollmentTokenRejected

cp_cleanup
eventually "back to Standalone: the InkwallConfig is gone" bash -c "[[ -z \$(${KUBECTL[*]} get inkwallconfig default -o name 2>/dev/null) ]]"

# Uninstall (#68): the operator unwires the routes before it goes, so a
# Traefik pod started afterwards, without the engine, still serves them.
echo "== uninstall"
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
  namespace: $NS
spec:
  targetRefs: [{kind: Ingress, name: web}]
  mode: Block
YAML
eventually "wired again before the uninstall" wired
eventually "blocking before the uninstall" tstatus_is 403 "$SQLI"
if helm --kube-context "kind-$CLUSTER" uninstall inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm uninstall (with the unwire hook)"
else
  fail "helm uninstall"
fi
check "the Ingress is unwired" unwired
no_middleware() { ! "${KUBECTL[@]}" -n "$NS" get middlewares.traefik.io inkwall-waf >/dev/null 2>&1; }
check "the Middleware is deleted" no_middleware
kept() { "${KUBECTL[@]}" -n "$NS" get wafpolicy web >/dev/null 2>&1; }
check "the WAFPolicy is kept" kept
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
no_engine() { traefik_pods >/dev/null && ! traefik_pods | grep -q inkwall-engine; }
eventually "a new Traefik pod has no engine" no_engine
kill "$tpf" 2>/dev/null || true
"${KUBECTL[@]}" -n "$TRAEFIK_NS" port-forward svc/traefik-e2e "$TRAEFIK_PORT:80" >/dev/null 2>&1 &
tpf=$!
eventually "the route still answers after the uninstall (uninspected)" tstatus_is 200 "$SQLI"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy web --ignore-not-found >/dev/null

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; engine logs:"
  "${KUBECTL[@]}" -n "$NS" logs deployment/app -c inkwall-engine --tail=40 || true
  exit 1
fi
echo "e2e: all checks passed"
