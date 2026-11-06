#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of the HAProxy Kubernetes Ingress Controller integration
# on the kind cluster (#282): the controller installed from its Helm chart
# with nothing about Inkwall, one WAFPolicy protecting an Ingress, and
# another Ingress to the same Service left unprotected. The Pod webhook
# gives the controller's pods the engine and the SPOE agent's
# configuration, the protected Ingress gets its own backend with the
# filter, the policy is Programmed only once the operator's probe has
# proven the filter on every pod, attacks are blocked on the protected
# Ingress and pass on the other, Programmed notes HAProxy's buffer below
# body.maxBytes (a 48 KB body is oversized) until tune.bufsize is raised, a client can't pass for the probe, a
# controller pod without the engine leaves the policy not Programmed (its
# traffic is uninspected), a stopped engine fails closed in block mode and
# open in detect mode, and unprotecting or uninstalling puts the user's
# Ingress back as it was. Needs the operator installed (make kind-operator)
# with haproxy-e2e among the proxy namespaces; ends with helm uninstall.
# KEEP=1 leaves the test's objects.
set -euo pipefail

cd "$(dirname "$0")/../.."
# The versions under test (#393).
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${KIND_CLUSTER:-inkwall}
OPERATOR_NS=inkwall-system
# The controller's namespace, a proxy namespace (hack/kind/operator.sh),
# and the apps'.
NS=haproxy-e2e
# Controller v3.2.19 (HAProxy 3.2), from its chart.
HAPROXY_IMAGE_TAG=3.2.19
HAPROXY_REPO=https://haproxytech.github.io/helm-charts
CLASS=haproxy-e2e
HOST=haproxy.e2e.example.com
OPEN_HOST=open.haproxy.e2e.example.com
PORT=${E2E_HAPROXY_PORT:-18095}
POD_PORT=$((PORT + 1))
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
# eventually DESCRIPTION COMMAND...: retries for up to 3 minutes.
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
work_big=$(mktemp)
haproxy_installed=false
cleanup() {
  for pf in "${pfs[@]}"; do kill "$pf" 2>/dev/null || true; done
  rm -f "$work_big"
  if [[ ${KEEP:-} == 1 ]]; then return; fi
  if $haproxy_installed; then
    "${HELM[@]}" -n "$NS" uninstall haproxy --wait >/dev/null 2>&1 || true
  fi
  "${KUBECTL[@]}" delete namespace "$NS" --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete ingressclass "$CLASS" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== HAProxy Kubernetes Ingress Controller $HAPROXY_IMAGE_TAG"
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
# The app, the protected Ingress (with a snippet of the user's own) and an
# unprotected one to the same Service.
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: $NS}
spec:
  selector: {matchLabels: {app: haproxy-e2e}}
  template:
    metadata: {labels: {app: haproxy-e2e}}
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
  selector: {app: haproxy-e2e}
  ports: [{name: http, port: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  namespace: $NS
  annotations:
    haproxy.org/backend-config-snippet: |
      http-request set-header X-User-Snippet yes
spec:
  ingressClassName: $CLASS
  rules:
    - host: $HOST
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: app, port: {number: 8080}}}}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: open, namespace: $NS}
spec:
  ingressClassName: $CLASS
  rules:
    - host: $OPEN_HOST
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: app, port: {number: 8080}}}}]}
YAML
"${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null
haproxy_installed=true
"${HELM[@]}" upgrade --install haproxy kubernetes-ingress --repo "$HAPROXY_REPO" --version "$HAPROXY_CHART_VERSION" \
  --namespace "$NS" --set controller.image.tag="$HAPROXY_IMAGE_TAG" --set controller.replicaCount=2 \
  --set controller.ingressClass="$CLASS" --set controller.ingressClassResource.name="$CLASS" \
  --set controller.service.type=ClusterIP --wait --timeout 5m >/dev/null
ok "the controller is installed"

user_ingress() { "${KUBECTL[@]}" -n "$NS" get ingress app -o jsonpath='{.metadata.annotations}'; }
original=$(user_ingress)
as_it_was() { [[ $(user_ingress) == "$original" ]]; }

SELECTOR=app.kubernetes.io/name=kubernetes-ingress
controller_pods() {
  "${KUBECTL[@]}" -n "$NS" get pods -l "$SELECTOR" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name}{"\n"}{end}' | grep '^|Running|'
}
injected() { local p; p=$(controller_pods) && [[ $(wc -l <<<"$p") -ge 2 ]] && ! grep -qv '^|Running|inkwall-engine' <<<"$p"; }
forward() {
  for pf in "${pfs[@]}"; do kill "$pf" 2>/dev/null || true; done
  pfs=()
  "${KUBECTL[@]}" -n "$NS" port-forward svc/haproxy-kubernetes-ingress "$PORT:80" >/dev/null 2>&1 &
  pfs+=($!)
  sleep 1
}
code() {
  local host=$1 path=$2
  shift 2
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $host" "$@" "http://127.0.0.1:$PORT$path" || true
}
is() {
  local want=$1
  shift
  [[ $(code "$@") == "$want" ]]
}
# all_are STATUS HOST PATH [CURL_ARGS...]: four times, so both pods answer.
all_are() {
  for _ in 1 2 3 4; do is "$@" || return 1; done
}
condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy shop -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
programmed() { [[ $(condition Programmed status) == True && $(condition Programmed message) == *"wired to the engine in HAProxy"* ]]; }
not_programmed() { [[ $(condition Programmed status) == False && $(condition Programmed reason) == "$1" ]]; }
ready() { [[ $(condition Ready status) == True ]]; }
policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: shop, namespace: $NS}
spec:
  targetRefs: [{kind: Ingress, name: app}]
  mode: ${1:-Block}
  timeout: 1s
YAML
}
wired() {
  local a
  a=$("${KUBECTL[@]}" -n "$NS" get ingress app -o jsonpath='{.metadata.annotations}')
  [[ $a == *'filter spoe engine inkwall'* && $a == *'X-User-Snippet'* && $a == *'"haproxy.org/standalone-backend":"true"'* ]]
}
never_reached_app() { ! "${KUBECTL[@]}" -n "$NS" logs deployment/app --since=10m | grep -i "$1" >/dev/null; }
logged() {
  "${KUBECTL[@]}" -n "$NS" logs -l "$SELECTOR" -c inkwall-engine --tail=-1 |
    grep '"security event"' | grep '"action":"log"' | grep "\"path\":\"$1\"" >/dev/null
}
signal_engines() {
  local pod node cid pid
  for pod in $("${KUBECTL[@]}" -n "$NS" get pods -l "$SELECTOR" --field-selector=status.phase=Running -o name); do
    node=$("${KUBECTL[@]}" -n "$NS" get "$pod" -o jsonpath='{.spec.nodeName}')
    cid=$("${KUBECTL[@]}" -n "$NS" get "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="inkwall-engine")].containerID}')
    [[ -n $cid ]] || continue
    pid=$(docker exec "$node" crictl inspect --output go-template --template '{{.info.pid}}' "${cid#*://}")
    docker exec "$node" kill "-$1" "$pid"
  done
}

echo "== block mode"
policy
# The controller's pods predate the policy but not the operator: the Pod
# webhook injected them. Restart anyway, as the docs say for pods from
# before Inkwall.
"${KUBECTL[@]}" -n "$NS" rollout restart deployment/haproxy-kubernetes-ingress >/dev/null
"${KUBECTL[@]}" -n "$NS" rollout status deployment/haproxy-kubernetes-ingress --timeout=180s >/dev/null
eventually "the controller's pods have the engine" injected
check "the agent's ConfigMap is in the controller's namespace" "${KUBECTL[@]}" -n "$NS" get configmap inkwall-haproxy
eventually "the Ingress has its own backend with the filter, the user's snippet kept" wired
eventually "Programmed once the probe proved the filter on both pods" programmed
eventually "the policy is Ready" ready
forward
eventually "the attack is blocked" all_are 403 "$HOST" "$SQLI"
check "benign traffic passes" all_are 200 "$HOST" /products/42
check "the unprotected Ingress to the same Service lets the attack through" all_are 200 "$OPEN_HOST" "$SQLI"
check "an attack in a body is blocked" all_are 403 "$HOST" / --data-urlencode "q=1' OR '1'='1"
mark=/held-$RANDOM$RANDOM
check "a body attack on a marked path is blocked" all_are 403 "$HOST" "$mark" --data-urlencode "q=1' OR '1'='1"
check "and never reached the app" never_reached_app "$mark"
check "the user's snippet still applies" bash -c "curl -s -H 'Host: $HOST' http://127.0.0.1:$PORT/ | grep -qi 'X-User-Snippet: yes'"
# A client can't pass for the probe: without the key's MAC it is inspected.
fake='/.well-known/inkwall-probe/AAAAAAAAAAAAAAAAAAAAAAAA'
check "a forged probe gets no 299" bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: $HOST' -H 'X-Inkwall-Probe: AAAAAAAAAAAAAAAAAAAAAAAA.00' http://127.0.0.1:$PORT$fake) != 299 ]]"

echo "== HAProxy's buffer (#345)"
# The policy inspects bodies up to 64 KiB (body.maxBytes unset); HAProxy's
# default buffer lets the engine see about 15 KiB: Programmed says so, and
# stays True. A 48 KB benign body is cut, so handled as oversized (413).
buffer_noted() { [[ $(condition Programmed message) == *"tune.bufsize 16384"* ]]; }
check "Programmed names HAProxy's buffer below body.maxBytes" buffer_noted
check "and stays True" programmed
{
  printf x=
  head -c 48000 /dev/zero | tr '\0' a
} >"$work_big"
check "a 48 KB benign body is oversized for the default buffer: 413" all_are 413 "$HOST" / -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$work_big"
# tune.bufsize raised in the controller's ConfigMap: the note goes, and the
# body is inspected whole.
"${HELM[@]}" upgrade haproxy kubernetes-ingress --repo "$HAPROXY_REPO" --version "$HAPROXY_CHART_VERSION" \
  --namespace "$NS" --reuse-values --set-string 'controller.config.global-config-snippet=tune.bufsize 81920' --wait --timeout 5m >/dev/null
not_noted() { programmed && ! buffer_noted; }
eventually "Programmed no longer names the buffer once tune.bufsize is raised" not_noted
forward
eventually "the 48 KB benign body passes" all_are 200 "$HOST" / -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$work_big"
check "an attack in a body is still blocked" all_are 403 "$HOST" / --data-urlencode "q=1' OR '1'='1"

echo "== a controller pod without the engine"
# A pod of the controller that opted out: its HAProxy can't load the filter
# (the controller drops the snippet), so the route isn't protected there,
# and the policy says so.
"${KUBECTL[@]}" -n "$NS" get pod -l "$SELECTOR" -o json | jq '.items[0] | {apiVersion: "v1", kind: "Pod",
  metadata: {name: "haproxy-bare", namespace: .metadata.namespace, labels: (.metadata.labels + {"waf.inkwall.dev/inject": "false"} | del(."pod-template-hash"))},
  spec: (.spec | del(.nodeName) | .initContainers = [] |
    .containers[0].volumeMounts = [.containers[0].volumeMounts[] | select(.name | startswith("inkwall") | not)] |
    .volumes = [.volumes[] | select(.name | startswith("inkwall") | not)])}' | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" -n "$NS" wait pod/haproxy-bare --for=condition=Ready --timeout=120s >/dev/null
eventually "not Programmed while a pod runs without the engine" not_programmed SidecarMissing
"${KUBECTL[@]}" -n "$NS" port-forward pod/haproxy-bare "$POD_PORT:8080" >/dev/null 2>&1 &
pfs+=($!)
sleep 1
check "through that pod, the attack passes (uninspected, as the status says)" \
  bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: $HOST' 'http://127.0.0.1:$POD_PORT$SQLI') == 200 ]]"
"${KUBECTL[@]}" -n "$NS" delete pod haproxy-bare --wait=true --timeout=60s >/dev/null
eventually "Programmed again once it is gone" programmed

echo "== engine down"
signal_engines STOP
eventually "engine down: a benign request is refused (fails closed)" all_are 503 "$HOST" /
check "engine down: the unprotected Ingress still answers" all_are 200 "$OPEN_HOST" /
signal_engines CONT
eventually "engine back: benign traffic passes" all_are 200 "$HOST" /
eventually "engine back: the attack is blocked" all_are 403 "$HOST" "$SQLI"

echo "== detect mode"
policy Detect
no_closed_rule() { ! "${KUBECTL[@]}" -n "$NS" get ingress app -o jsonpath='{.metadata.annotations}' | grep -F 'deny_status 503 if !{' >/dev/null; }
eventually "the snippet fails open" no_closed_rule
forward
eventually "the attack passes" all_are 200 "$HOST" "$SQLI"
probe=/detect-$RANDOM$RANDOM
check "an attack on a fresh path passes" all_are 200 "$HOST" "$probe?id=1%27%20OR%20%271%27%3D%271"
eventually "and the engines log it" logged "$probe"
signal_engines STOP
eventually "engine down in detect mode: requests pass (fails open)" all_are 200 "$HOST" /
signal_engines CONT

echo "== unprotected"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shop --timeout=60s >/dev/null
eventually "the user's Ingress is as it was" as_it_was
eventually "the attack passes again" all_are 200 "$HOST" "$SQLI"

echo "== uninstall"
policy
eventually "Programmed again" programmed
eventually "blocking again" all_are 403 "$HOST" "$SQLI"
if "${HELM[@]}" uninstall inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm uninstall (with the unwire hook)"
else
  fail "helm uninstall"
fi
check "the user's Ingress is as it was" as_it_was
check "the agent's ConfigMap stays while the controller's pods mount it" "${KUBECTL[@]}" -n "$NS" get configmap inkwall-haproxy
eventually "the route still answers after the uninstall (uninspected)" all_are 200 "$HOST" "$SQLI"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shop --ignore-not-found --timeout=30s >/dev/null || true

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; operator and controller logs:"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" logs deployment/inkwall-operator --tail=60 2>/dev/null || true
  "${KUBECTL[@]}" -n "$NS" logs deployment/haproxy-kubernetes-ingress -c kubernetes-ingress-controller --tail=40 2>/dev/null || true
  exit 1
fi
echo "haproxy e2e: all checks passed"
