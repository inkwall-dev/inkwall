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
ROUTE_HOST=route.e2e.example.com
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

# The trust ConfigMap: the operator's CA and the bundle public keys, all
# public, copied into the app's namespace (app_trust), as someone who sets
# up an engine by hand does; the operator keeps it for the proxies it
# injects.
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
trust=$(mktemp -d)
# cp_cleanup undoes the control plane section, also when it fails midway:
# a GitOps InkwallConfig left behind would change the next run.
cp_cleanup() {
  if [[ -n ${cp_ca:-} ]]; then rm -f "$cp_ca"; fi
  if [[ -n ${snap:-} ]]; then rm -f "$snap"; fi
  "${KUBECTL[@]}" delete inkwallconfig default --ignore-not-found >/dev/null 2>&1 || true
  # The control plane's policies, if a Managed run stopped midway: out of
  # Managed mode (once the webhook sees it) anyone may delete them.
  for _ in $(seq 20); do
    "${KUBECTL[@]}" delete wafpolicies,wafrulesets,clusterwafrulesets -A -l inkwall.dev/source=saas >/dev/null 2>&1 && break
    sleep 0.5
  done
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
app_trust() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-operator-webhook-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$trust/ca.crt"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle-signing-key -o jsonpath='{.data.ed25519\.pub}' | base64 -d >"$trust/ed25519.pub"
  "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle-signing-key -o jsonpath='{.data.trusted-keys\.pub}' | base64 -d >"$trust/trusted-keys.pub"
  # A Secret written before key rotation has one key, as the operator assumes.
  if [[ ! -s $trust/trusted-keys.pub ]]; then cp "$trust/ed25519.pub" "$trust/trusted-keys.pub"; fi
  "${KUBECTL[@]}" -n "$NS" create configmap inkwall-trust --from-file="$trust/ca.crt" --from-file="$trust/ed25519.pub" \
    --from-file="$trust/trusted-keys.pub" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
}
app_trust

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
no_engine() { traefik_pods >/dev/null && ! traefik_pods | grep -q inkwall-engine; }
# restart_traefik replaces Traefik's pods, and the port-forward to them.
restart_traefik() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart deployment/traefik-e2e >/dev/null
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status deployment/traefik-e2e --timeout=180s >/dev/null
  if [[ -n ${tpf:-} ]]; then kill "$tpf" 2>/dev/null || true; fi
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" port-forward svc/traefik-e2e "$TRAEFIK_PORT:80" >/dev/null 2>&1 &
  tpf=$!
}
web_policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
  namespace: $NS
spec:
  targetRefs: [$1]
  mode: Block
YAML
}
# held POLICY: the operator's finalizer holds it.
held() {
  [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy "$1" -o jsonpath='{.metadata.finalizers}' 2>/dev/null) == *waf.inkwall.dev/unwire* ]]
}
policy_gone() { ! "${KUBECTL[@]}" -n "$NS" get wafpolicy "$1" >/dev/null 2>&1; }
no_middleware() { ! "${KUBECTL[@]}" -n "$NS" get middlewares.traefik.io inkwall-waf >/dev/null 2>&1; }
stop_operator() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=0 >/dev/null
  eventually "operator stopped" bash -c "[[ -z \$(${KUBECTL[*]} -n $OPERATOR_NS get pods -l app.kubernetes.io/component=operator -o name) ]]"
}
start_operator() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=2 >/dev/null
  "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
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

web_policy "{kind: Ingress, name: web}"
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

# The client IP behind a load balancer (#120): Traefik's web entry point
# takes the PROXY protocol from the pod network only (traefik-e2e-values.yaml).
# A pod there stands in for the load balancer; the port-forward, from
# 127.0.0.1, is an untrusted source. Each request carries its own request ID,
# to find its security event in the engine's log.
echo "== client IP through the PROXY protocol"
LB_IP=203.0.113.50 # documentation range (RFC 5737)
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: lb
  namespace: $NS
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.11.1 # --haproxy-clientip needs curl 8.2+
      command: ["sleep", "3600"]
YAML
"${KUBECTL[@]}" -n "$NS" wait --for=condition=Ready pod/lb --timeout=120s >/dev/null
pp_id=e2e-pp-$RANDOM
# lb_attack ID [CURL_ARGS...]: the attack through Traefik's Service, sent
# from the load balancer's pod.
lb_attack() {
  local id=$1
  shift
  "${KUBECTL[@]}" -n "$NS" exec lb -- curl -s -o /dev/null -w '%{http_code}' -H "Host: $TRAEFIK_HOST" \
    -H "X-Request-Id: $id" "$@" "http://traefik-e2e.$TRAEFIK_NS.svc$SQLI" || true
}
# event_ip ID: the client IP of the security event for request ID.
event_ip() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" logs deployment/traefik-e2e -c inkwall-engine |
    grep -F '"msg":"security event"' | grep -F "\"request_id\":\"$1\"" |
    sed -n 's/.*"client_ip":"\([^"]*\)".*/\1/p' | tail -1
}
event_ip_is() { [[ $(event_ip "$1") == "$2" ]]; }
# pp_check DESCRIPTION ID WANT: the event for ID has client IP WANT.
pp_check() {
  eventually "$1" event_ip_is "$2" "$3"
  event_ip_is "$2" "$3" || echo "      client IP: '$(event_ip "$2")', want $3"
}
is_403() { [[ $1 == 403 ]]; }
check "a PROXY header from the load balancer: the attack is blocked" \
  is_403 "$(lb_attack "$pp_id-a" --haproxy-protocol --haproxy-clientip "$LB_IP")"
pp_check "its security event has the PROXY header's client IP" "$pp_id-a" "$LB_IP"
check "with a client-sent X-Forwarded-For too: blocked" \
  is_403 "$(lb_attack "$pp_id-b" --haproxy-protocol --haproxy-clientip "$LB_IP" -H 'X-Forwarded-For: 6.6.6.6')"
pp_check "the client's X-Forwarded-For doesn't change the client IP" "$pp_id-b" "$LB_IP"
check "no PROXY header from the load balancer: blocked" is_403 "$(lb_attack "$pp_id-c")"
lb_ip=$("${KUBECTL[@]}" -n "$NS" get pod lb -o jsonpath='{.status.podIP}')
pp_check "its event has the load balancer's own IP" "$pp_id-c" "$lb_ip"
# From the port-forward, outside trustedIPs: Traefik reads the header but
# ignores its address.
untrusted=$(curl -s -o /dev/null -w '%{http_code}' --haproxy-protocol --haproxy-clientip "$LB_IP" \
  -H "Host: $TRAEFIK_HOST" -H "X-Request-Id: $pp_id-d" "http://127.0.0.1:$TRAEFIK_PORT$SQLI" || true)
check "a PROXY header from an untrusted source: blocked" is_403 "$untrusted"
pp_check "its address is ignored: the event has the real peer (127.0.0.1)" "$pp_id-d" 127.0.0.1
"${KUBECTL[@]}" -n "$NS" delete pod lb --wait=false >/dev/null

# Signing key rotation (#41), requested on the InkwallConfig with two
# engines connected: Traefik's, whose trust ConfigMap the operator keeps,
# and the app's, whose ConfigMap this test keeps (app_trust). The operator
# signs with the new key only once both trust it, and retires the old key
# once both run a bundle it signed: no engine rejects a bundle or restarts.
echo "== signing key rotation"
# eventually_within SECONDS DESCRIPTION COMMAND...: the kubelet takes a
# minute or so to update a mounted ConfigMap.
eventually_within() {
  local secs=$1 what=$2
  shift 2
  for _ in $(seq $((secs * 2))); do
    if "$@" >/dev/null 2>&1; then
      ok "$what"
      return 0
    fi
    sleep 0.5
  done
  fail "$what"
}
key_secret() { "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle-signing-key -o jsonpath="$1"; }
phase_is() { [[ $(key_secret '{.metadata.annotations.waf\.inkwall\.dev/rotation-phase}') == "$1" ]]; }
trusted_keys() { key_secret '{.data.trusted-keys\.pub}' | base64 -d; }
trusted_count_is() { [[ $(trusted_keys | wc -c) == $(($1 * 32)) ]]; }
signed_with() {
  [[ $("${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle -o jsonpath='{.metadata.annotations.waf\.inkwall\.dev/key-id}') == "$1" ]]
}
# An engine in NAMESPACE reports trusting KEY_ID (the replicas' reports).
reports_key() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" get configmaps -l waf.inkwall.dev/engines=true -o jsonpath='{.items[*].data.engines\.json}' |
    grep -o '{[^{}]*}' | grep "\"podNamespace\":\"$1\"" | grep -q "\"$2\""
}
engine_logs() {
  "${KUBECTL[@]}" -n "$NS" logs deployment/app -c inkwall-engine
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" logs deployment/traefik-e2e -c inkwall-engine
}
no_rejection() { ! engine_logs | grep -q '"bundle rejected"'; }
traefik_engine() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" get pods -l app.kubernetes.io/name=traefik \
    -o jsonpath='{range .items[*]}{.metadata.name}/{.status.initContainerStatuses[?(@.name=="inkwall-engine")].restartCount}{"\n"}{end}'
}
same_engines() { [[ $(engine_pod)/$(restarts) == "$app_engine/0" && $(traefik_engine) == "$traefik_before" ]]; }
app_engine=$(engine_pod)
traefik_before=$(traefik_engine)
old_key=$(key_secret '{.data.key-id}' | base64 -d)
created_config=false
if ! "${KUBECTL[@]}" get inkwallconfig default >/dev/null 2>&1; then
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata: {name: default}
YAML
  created_config=true
fi
"${KUBECTL[@]}" annotate inkwallconfig default --overwrite "waf.inkwall.dev/rotate-signing-key=e2e-$(date +%s)" >/dev/null
published() { phase_is Publishing && trusted_count_is 2; }
eventually "the new key is published" published
new_key=$(trusted_keys | tail -c 32 | sha256sum | cut -c1-16)
eventually_within 180 "Traefik's engine reloads its keys and reports the new one" reports_key "$TRAEFIK_NS" "$new_key"
check "the old key still signs: the app's engine doesn't trust the new one" signed_with "$old_key"
not_reported() { reports_key "$NS" "$old_key" && ! reports_key "$NS" "$new_key"; }
check "the app's engine reports only the old key" not_reported
app_trust
eventually_within 180 "the new key signs once every engine trusts it" signed_with "$new_key"
retired() { phase_is "" && trusted_count_is 1 && [[ $(trusted_keys | sha256sum | cut -c1-16) == "$new_key" ]]; }
eventually_within 180 "the old key is retired" retired
app_trust
check "no engine rejected a bundle" no_rejection
check "neither engine restarted" same_engines
eventually "the engine in Traefik's pod still blocks the attack" tstatus_is 403 "$SQLI"
eventually "the policy is still Ready" ready
if $created_config; then "${KUBECTL[@]}" delete inkwallconfig default >/dev/null; fi

# Deleted while the operator is down (#81): the finalizer keeps the policy,
# and the route wired, until the operator is back and unwires it.
check "the policy is held by the unwire finalizer" held web
stop_operator
"${KUBECTL[@]}" -n "$NS" delete wafpolicy web --wait=false >/dev/null
terminating() { [[ -n $("${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null) ]]; }
check "deleted while the operator is down: the policy waits" terminating
check "and the Ingress stays wired" wired
start_operator
eventually "unwired once the operator is back" unwired
eventually "then the policy is gone" policy_gone web
eventually "the attack passes again" tstatus_is 200 "$SQLI"

# A Traefik IngressRoute (#79): its routes get the operator's Middleware
# first, the user's own kept, and lose it when the policy goes.
rget() { curl -s -H "Host: $ROUTE_HOST" "http://127.0.0.1:$TRAEFIK_PORT$1" || true; }
rcode() {
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $ROUTE_HOST" "http://127.0.0.1:$TRAEFIK_PORT$1" || true
}
rstatus_is() { [[ $(rcode "$2") == "$1" ]]; }
route_middlewares() {
  "${KUBECTL[@]}" -n "$NS" get ingressroutes.traefik.io web -o jsonpath='{.spec.routes[*].middlewares[*].name}|{.metadata.annotations.waf\.inkwall\.dev/wired}'
}
route_wired() { [[ $(route_middlewares) == "inkwall-waf e2e-header|inkwall-waf" ]]; }
route_unwired() { [[ $(route_middlewares) == "e2e-header|" ]]; }
# whoami echoes the request headers: the user's Middleware still applies.
user_middleware() { rget /products/42 | grep -q '^X-E2e: route'; }
rready() {
  [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy web-route -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == True ]]
}

echo "== an IngressRoute through Traefik"
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: e2e-header
  namespace: $NS
spec:
  headers:
    customRequestHeaders: {X-E2E: route}
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: web
  namespace: $NS
spec:
  ingressClassName: traefik-e2e
  entryPoints: [web]
  routes:
    - kind: Rule
      match: Host(\`$ROUTE_HOST\`) && PathPrefix(\`/\`)
      middlewares: [{name: e2e-header}]
      services: [{name: web, port: 8080}]
YAML
eventually "Traefik serves the IngressRoute" rstatus_is 200 /
check "no policy yet: the attack passes through the IngressRoute" rstatus_is 200 "$SQLI"
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web-route
  namespace: $NS
spec:
  targetRefs: [{group: traefik.io, kind: IngressRoute, name: web}]
  mode: Block
YAML
eventually "the operator wired the IngressRoute, first, keeping the user's Middleware" route_wired
eventually "the engine blocks the attack on the IngressRoute" rstatus_is 403 "$SQLI"
check "benign traffic passes the IngressRoute" rstatus_is 200 /products/42
check "the user's Middleware still applies" user_middleware
eventually "the IngressRoute's policy is Ready" rready
"${KUBECTL[@]}" -n "$NS" delete wafpolicy web-route >/dev/null
eventually "the IngressRoute is unwired when the policy is deleted, the user's Middleware kept" route_unwired
eventually "the attack passes the IngressRoute again" rstatus_is 200 "$SQLI"

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
  web_policy "{kind: Ingress, name: web}"
  eventually "a policy blocks through Traefik" tstatus_is 403 "$SQLI"
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
  # Traefik's pods aren't selected any more: new ones would get no engine
  # (#81), so the route is unwired, and served uninspected.
  eventually_long "Traefik's pods not selected: the Ingress is unwired" unwired
  eventually "the route is served, uninspected" tstatus_is 200 "$SQLI"
  "${KUBECTL[@]}" delete inkwallconfig default >/dev/null
  eventually_long "back to the default selector" selector_is '{"app.kubernetes.io/name":"traefik"}'
  "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
  eventually_long "the InkwallConfig deleted, Traefik's pods selected again: wired" wired
  eventually "blocking again" tstatus_is 403 "$SQLI"
  "${KUBECTL[@]}" -n "$NS" delete wafpolicy web --wait >/dev/null
  eventually "unwired when the policy is deleted" unwired
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
          args: ["--host=$CP_HOST", "--token=$CP_TOKEN", "--accept-events"]
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
# Events (#92): an attack blocked in Traefik reaches the control plane, on
# the events streams of the operator's replicas.
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
eventually "a policy blocks through Traefik" tstatus_is 403 "$SQLI"
events_stream() { stub_stats | grep -q '"STREAM_ROLE_EVENTS CLUSTER_MODE_GITOPS'; }
eventually "the replicas opened events streams" events_stream
stub_events() { [[ $(stub_stats | sed -n 's/.*"events":\([0-9]*\).*/\1/p') -ge 1 ]]; }
eventually "the blocked attack reaches the control plane as a security event" stub_events
"${KUBECTL[@]}" -n "$NS" delete wafpolicy web --wait >/dev/null

# Managed mode (#93, #94): the stub's policies are written as CRDs labelled
# inkwall.dev/source: saas, enforced, acknowledged and reported Enforced;
# no one else may change them, a refused snapshot changes nothing, and a
# snapshot without a policy deletes it.
echo "== control plane (stub): Managed mode"
"${KUBECTL[@]}" patch inkwallconfig default --type=merge -p '{"spec":{"mode":"Managed"}}' >/dev/null
managed_hello() { stub_stats | grep -q '"STREAM_ROLE_PRIMARY CLUSTER_MODE_MANAGED'; }
eventually "the operator reconnects in Managed mode" managed_hello
snap=$(mktemp)
# send_snapshot VERSION: sends the YAML list on stdin as that snapshot.
send_snapshot() {
  cat >"$snap"
  "${KUBECTL[@]}" create --raw "/api/v1/namespaces/$CP_NS/services/stub:admin/proxy/snapshot?version=$1" -f "$snap" >/dev/null
}
acked() { stub_stats | grep -Eq "\"acks\":\[([0-9]+,)*$1[],]"; }
nacked() { stub_stats | grep -q "\"$1: "; }
managed_policy() {
  cat <<YAML
- apiVersion: waf.inkwall.dev/v1alpha1
  kind: WAFPolicy
  metadata: {name: managed, namespace: $NS}
  spec:
    targetRefs: [{kind: Ingress, name: web}]
    mode: Block
YAML
}
managed_policy | send_snapshot 1
eventually "the stub's snapshot is acknowledged (PolicyAck)" acked 1
saas_label() { [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy managed -o jsonpath='{.metadata.labels.inkwall\.dev/source}') == saas ]]; }
check "its policy is written, labelled inkwall.dev/source: saas" saas_label
eventually "Traefik blocks the attack under the stub's policy" tstatus_is 403 "$SQLI"
enforced_in_state() {
  stub_stats | sed -n 's/.*"enforced":\[\([^]]*\)\].*/\1/p' | grep -qF "\"WAFPolicy $NS/managed\""
}
eventually "the stub gets it back Enforced in the ClusterState" enforced_in_state
# guarded COMMAND...: the webhook refuses it, naming the control plane.
guarded() {
  local out
  out=$("$@" 2>&1) && return 1
  grep -q "come from the control plane" <<<"$out"
}
check "kubectl edit of the policy is refused" guarded env KUBE_EDITOR="sed -i 's/mode: Block/mode: Detect/'" "${KUBECTL[@]}" -n "$NS" edit wafpolicy managed
check "kubectl patch of the policy is refused" guarded "${KUBECTL[@]}" -n "$NS" patch wafpolicy managed --type=merge -p '{"spec":{"mode":"Detect"}}'
check "removing its label is refused" guarded "${KUBECTL[@]}" -n "$NS" label wafpolicy managed inkwall.dev/source-
check "deleting it is refused" guarded "${KUBECTL[@]}" -n "$NS" delete wafpolicy managed --wait=false
forged() {
  "${KUBECTL[@]}" apply -f - <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: forged, namespace: $NS, labels: {inkwall.dev/source: saas}}
spec: {targetRefs: [{kind: Ingress, name: web}]}
YAML
}
check "creating one labelled saas is refused" guarded forged
still_block() { [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy managed -o jsonpath='{.spec.mode}') == Block ]]; }
check "the policy is unchanged" still_block
# All or nothing: one object the webhook refuses (an unclean path) refuses
# the snapshot, and the policy in force stays.
{
  managed_policy
  cat <<YAML
- apiVersion: waf.inkwall.dev/v1alpha1
  kind: WAFPolicy
  metadata: {name: broken, namespace: $NS}
  spec:
    targetRefs: [{kind: Ingress, name: web}]
    skip: {paths: ["/a/../b"]}
YAML
} | send_snapshot 2
eventually "a snapshot with a bad object is refused (PolicyNack)" nacked 2
no_broken() { ! "${KUBECTL[@]}" -n "$NS" get wafpolicy broken >/dev/null 2>&1; }
check "nothing of it is written" no_broken
check "the policy in force stays" tstatus_is 403 "$SQLI"
echo '[]' | send_snapshot 3
eventually "an empty snapshot is acknowledged" acked 3
no_managed() { ! "${KUBECTL[@]}" -n "$NS" get wafpolicy managed >/dev/null 2>&1; }
eventually "and deletes the stub's policy" no_managed
eventually "the attack passes again" tstatus_is 200 "$SQLI"

# A restarted operator without its certificate (lost, say) can only enroll
# again: the token is used, so the stub refuses it. A running stream keeps
# its certificate in memory, hence the restart.
"${KUBECTL[@]}" -n "$OPERATOR_NS" delete secret inkwall-control-plane-identity --ignore-not-found >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout restart deployment/inkwall-operator >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
eventually_long "a used token is refused (EnrollmentTokenRejected)" cp_is EnrollmentTokenRejected

cp_cleanup
eventually "back to Standalone: the InkwallConfig is gone" bash -c "[[ -z \$(${KUBECTL[*]} get inkwallconfig default -o name 2>/dev/null) ]]"

# Injection off (#81): new Traefik pods get no engine, so the operator
# unwires the routes and releases the policies; on again, it wires them.
pprogrammed() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath='{.status.conditions[?(@.type=="Programmed")].reason}' 2>/dev/null
}
programmed_is() { [[ $(pprogrammed) == "$1" ]]; }
no_pod_webhook() { ! "${KUBECTL[@]}" get mutatingwebhookconfiguration inkwall-operator-mutating >/dev/null 2>&1; }
not_held() { ! held web; }
inject() {
  helm --kube-context "kind-$CLUSTER" upgrade inkwall "$CHART" --namespace "$OPERATOR_NS" --reuse-values \
    --set injection.enabled="$1" >/dev/null
  "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
}
echo "== injection off"
both="{kind: Ingress, name: web}, {group: traefik.io, kind: IngressRoute, name: web}"
web_policy "$both"
eventually "wired" wired
eventually "the IngressRoute wired" route_wired
eventually "blocking" tstatus_is 403 "$SQLI"
inject false
check "the Pod webhook is removed" no_pod_webhook
eventually "the Ingress is unwired" unwired
eventually "the IngressRoute is unwired, the user's Middleware kept" route_unwired
eventually "the Middleware is deleted" no_middleware
eventually "the policy is released from the finalizer" not_held
eventually "Programmed=False (InjectionDisabled)" programmed_is InjectionDisabled
eventually "the route is served, uninspected" tstatus_is 200 "$SQLI"
check "so is the IngressRoute" rstatus_is 200 "$SQLI"
restart_traefik
eventually "a new Traefik pod has no engine" no_engine
eventually "and serves the route, uninspected" tstatus_is 200 "$SQLI"
check "and the IngressRoute" rstatus_is 200 "$SQLI"
inject true
# The Pod webhook, created again, injects once it has its CA and fails
# closed (a policy blocks): a pod created before would start without the
# engine (fail open).
pod_webhook_ready() {
  [[ -n $("${KUBECTL[@]}" get mutatingwebhookconfiguration inkwall-operator-mutating -o jsonpath='{.webhooks[0].clientConfig.caBundle}') ]] &&
    fails Fail
}
eventually "the Pod webhook is back, failing closed" pod_webhook_ready
restart_traefik
eventually "injection on again: Traefik's pod has the engine" traefik_injected
eventually "wired again" wired
eventually "the IngressRoute wired again" route_wired
eventually "held again" held web
eventually "blocking again" tstatus_is 403 "$SQLI"

# Uninstall (#68): the operator unwires the routes before it goes, so a
# Traefik pod started afterwards, without the engine, still serves them.
echo "== uninstall"
web_policy "$both"
eventually "wired again before the uninstall" wired
eventually "the IngressRoute wired again before the uninstall" route_wired
eventually "blocking before the uninstall" tstatus_is 403 "$SQLI"
eventually "blocking on the IngressRoute before the uninstall" rstatus_is 403 "$SQLI"
if helm --kube-context "kind-$CLUSTER" uninstall inkwall --namespace "$OPERATOR_NS" --wait --timeout 5m >/dev/null; then
  ok "helm uninstall (with the unwire hook)"
else
  fail "helm uninstall"
fi
check "the Ingress is unwired" unwired
check "the IngressRoute is unwired, the user's Middleware kept" route_unwired
check "the Middleware is deleted" no_middleware
kept() { "${KUBECTL[@]}" -n "$NS" get wafpolicy web >/dev/null 2>&1; }
check "the WAFPolicy is kept" kept
check "released from the finalizer: deleting it won't wait for an operator" not_held
restart_traefik
eventually "a new Traefik pod has no engine" no_engine
eventually "the route still answers after the uninstall (uninspected)" tstatus_is 200 "$SQLI"
check "so does the IngressRoute" rstatus_is 200 "$SQLI"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy web --ignore-not-found --timeout=30s >/dev/null || true
check "and it is deleted without the operator" policy_gone web

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; engine logs:"
  "${KUBECTL[@]}" -n "$NS" logs deployment/app -c inkwall-engine --tail=40 || true
  exit 1
fi
echo "e2e: all checks passed"
