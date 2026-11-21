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
# body.maxBytes (a 48 KB body is oversized) until tune.bufsize is raised, a
# request over one SPOE frame gets 413 in Block mode, a client can't pass for the probe, a
# controller pod without the engine leaves the policy not Programmed (its
# traffic is uninspected), a stopped engine fails closed in block mode and
# open in detect mode, a policy with responses.inspect gets the response
# rules and is Programmed once the probe's response leg came back answered
# by the engine from every pod (#595), a response leaking a SQL error is replaced with 403
# in Block mode and logged in Detect mode (#470), and unprotecting or
# uninstalling puts the user's Ingress back as it was. Needs the operator installed (make kind-operator)
# with haproxy-e2e among the proxy namespaces; ends with helm uninstall.
# HAPROXY_IMAGE_TAG is the controller's release: 3.4 and later (the
# chart's default since 1.55.0) are wired through the controller's Backend
# custom resource, 3.1 to 3.2 through backend config snippets, which 3.4
# dropped (#753); the Ingress then carries a snippet of the user's own,
# which stays, and the controller is upgraded to 3.4 and back mid-test. KEEP=1 leaves the test's objects.
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
# The controller's release, from its chart: 3.4.1 (HAProxy 3.4), the
# chart's, or 3.2.20 (HAProxy 3.2, make kind-e2e-haproxy-snippets), which
# is upgraded to UPGRADE_TAG and back down mid-test.
HAPROXY_IMAGE_TAG=${HAPROXY_IMAGE_TAG:-3.4.1}
UPGRADE_TAG=3.4.1
# v34: wired through the Backend custom resource (3.4 and later).
v34=false
is_v34() {
  local major minor
  IFS=. read -r major minor _ <<<"$1"
  ((major > 3 || (major == 3 && minor >= 4)))
}
if is_v34 "$HAPROXY_IMAGE_TAG"; then v34=true; fi
started_v34=$v34
BACKEND=backends.ingress.v3.haproxy.org/inkwall-waf-app
GLOBAL=inkwall-e2e-global
HAPROXY_REPO=https://haproxytech.github.io/helm-charts
CLASS=haproxy-e2e
HOST=haproxy.e2e.example.com
OPEN_HOST=open.haproxy.e2e.example.com
PORT=${E2E_HAPROXY_PORT:-18095}
POD_PORT=$((PORT + 1))
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")
SQLI='/?id=1%27%20OR%20%271%27%3D%271'

# eventually retries for up to 3 minutes.
EVENTUALLY_TRIES=360
. hack/kind/lib.sh

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
$(if $v34; then
  # 3.4 has no snippets: a backend annotation of the user's, which the
  # operator's Backend makes the controller ignore, and the status says.
  echo "    haproxy.org/timeout-server: 30s"
else
  printf '    haproxy.org/backend-config-snippet: |\n      http-request set-header X-User-Snippet yes\n'
fi)
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
${2:-}
YAML
}
RESPONSES='  responses: {inspect: true}'
# whoami echoes the request's headers in its text/plain body: this one makes
# it leak a MySQL error, which the request rules don't mind.
LEAK='X-Debug: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
# wiring: what the operator wrote for the protected Ingress: its
# annotations, with the snippet (3.2), or its Backend's spec (3.4), as JSON.
wiring() {
  if $v34; then
    "${KUBECTL[@]}" -n "$NS" get "$BACKEND" -o jsonpath='{.spec}' 2>/dev/null
  else
    "${KUBECTL[@]}" -n "$NS" get ingress app -o jsonpath='{.metadata.annotations}'
  fi
}
# The rules the checks look for, as each writes them.
patterns() {
  if $v34; then
    RESPONSES_SCOPE='"spoe_engine":"inkwall-responses"' REQUEST_SCOPE='"spoe_engine":"inkwall"'
    SEND_RESPONSE='"type":"send-spoe-group"' RESPONSE_RULES='http_response_rule_list'
    FRAME_RULE='"cond_test":"{ var(txn.inkwall.error) -m int 3 259 }","deny_status":413'
    CLOSED_RULE='"cond_test":"!{ var(txn.inkwall.action) -m found }","deny_status":503'
  else
    RESPONSES_SCOPE='filter spoe engine inkwall-responses' REQUEST_SCOPE='filter spoe engine inkwall config'
    SEND_RESPONSE='http-response send-spoe-group' RESPONSE_RULES='http-response'
    FRAME_RULE='deny_status 413 if { var(txn.inkwall.error) -m int 3 259 }'
    CLOSED_RULE='deny_status 503 if !{'
  fi
}
patterns
responses_wired() {
  local a
  a=$(wiring)
  [[ $a == *"$RESPONSES_SCOPE"* && $a == *"$SEND_RESPONSE"* && $a == *'txn.inkwall.response_probe'* ]]
}
responses_unwired() {
  local a
  a=$(wiring)
  [[ $a == *"$REQUEST_SCOPE"* && $a != *"$RESPONSE_RULES"* ]]
}
leak_replaced() {
  for _ in 1 2 3 4; do
    ! curl -s -H "Host: $HOST" -H "$LEAK" "http://127.0.0.1:$PORT/leak" | matches -F 'SQL syntax' || return 1
  done
}
# logged_response PATH ACTION: an engine in the controller's pods logged a
# response event for PATH.
logged_response() {
  "${KUBECTL[@]}" -n "$NS" logs -l "$SELECTOR" -c inkwall-engine --tail=-1 |
    grep '"security event"' | grep '"phase":"response"' | grep "\"action\":\"$2\"" | grep "\"path\":\"$1\"" >/dev/null
}
wired() {
  local a
  a=$("${KUBECTL[@]}" -n "$NS" get ingress app -o jsonpath='{.metadata.annotations}')
  [[ $a == *'"haproxy.org/standalone-backend":"true"'* ]] || return 1
  if $v34; then
    [[ $a == *"\"haproxy.org/cr-backend\":\"$NS/inkwall-waf-app\""* && $(wiring) == *'"type":"spoe"'* ]]
  else
    [[ $a == *'filter spoe engine inkwall'* && $a == *'X-User-Snippet'* ]]
  fi
}
# backend_gone: the operator's Backend custom resource for the Ingress is
# deleted.
backend_gone() { ! "${KUBECTL[@]}" -n "$NS" get "$BACKEND" >/dev/null 2>&1; }
# set_bufsize SIZE: tune.bufsize, in the controller ConfigMap's
# global-config-snippet (3.2), or the Global custom resource its cr-global
# names (3.4, which has no snippets).
set_bufsize() {
  if $v34; then
    "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: ingress.v3.haproxy.org/v3
kind: Global
metadata: {name: $GLOBAL, namespace: $NS}
spec: {tune_buffer_options: {bufsize: $1}}
YAML
    "${HELM[@]}" upgrade haproxy kubernetes-ingress --repo "$HAPROXY_REPO" --version "$HAPROXY_CHART_VERSION" \
      --namespace "$NS" --reuse-values --set-string "controller.config.cr-global=$NS/$GLOBAL" --wait --timeout 5m >/dev/null
  else
    "${HELM[@]}" upgrade haproxy kubernetes-ingress --repo "$HAPROXY_REPO" --version "$HAPROXY_CHART_VERSION" \
      --namespace "$NS" --reuse-values --set-string "controller.config.global-config-snippet=tune.bufsize $1" --wait --timeout 5m >/dev/null
  fi
}
# probe_reached_app_since TIME: the app logged a request on the probe's
# reserved path since TIME. Where the engine answers the request leg itself
# (Block mode; HAProxy in both modes), only the response leg reaches the app
# (#595). whoami logs the path, not the query, so the leg's mark isn't in it.
probe_reached_app_since() { "${KUBECTL[@]}" -n "$NS" logs deployment/app --since-time="$1" | grep -F ".well-known/inkwall-probe/" >/dev/null; }
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
if $v34; then
  eventually "the Ingress has its own backend, with the operator's Backend and its filter" wired
else
  eventually "the Ingress has its own backend with the filter, the user's snippet kept" wired
fi
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
if $v34; then
  ignored_noted() { [[ $(condition Programmed message) == *"haproxy.org/timeout-server don't apply"* ]]; }
  check "Programmed notes the user's backend annotation that doesn't apply with the Backend" ignored_noted
else
  check "the snippet the user set still applies" bash -c "curl -s -H 'Host: $HOST' http://127.0.0.1:$PORT/ | grep -qi 'X-User-Snippet: yes'"
fi
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
# tune.bufsize raised: the note goes, and the body is inspected whole.
set_bufsize 81920
not_noted() { programmed && ! buffer_noted; }
eventually "Programmed no longer names the buffer once tune.bufsize is raised" not_noted
forward
eventually "the 48 KB benign body passes" all_are 200 "$HOST" / -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$work_big"
check "an attack in a body is still blocked" all_are 403 "$HOST" / --data-urlencode "q=1' OR '1'='1"

echo "== a request over one SPOE frame (#336)"
# In Block mode the snippet handles a request HAProxy can't fit in one SPOE
# frame as oversized: a 12 MiB buffer holds an 11.6 MB body, more than the
# engine's frame (in bundle mode, body.maxBytes' 10 MiB maximum plus 1 MiB),
# so HAProxy sends none of it.
frame_rule() { wiring | grep -F "$FRAME_RULE" >/dev/null; }
check "Block mode: the snippet has the rule" frame_rule
set_bufsize 12582912
forward
head -c 11600000 /dev/zero | tr '\0' a >"$work_big"
eventually "an 11.6 MB body over one SPOE frame is oversized: 413" all_are 413 "$HOST" / -H 'Content-Type: application/octet-stream' --data-binary "@$work_big"
check "a benign request still passes" all_are 200 "$HOST" /products/42
check "an attack in a body is still blocked" all_are 403 "$HOST" / --data-urlencode "q=1' OR '1'='1"
set_bufsize 81920
forward

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
check "through that pod, the attack passes: uninspected, as the status says" \
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
no_closed_rule() { ! wiring | grep -F "$CLOSED_RULE" >/dev/null; }
eventually "the snippet fails open" no_closed_rule
no_frame_rule() { ! frame_rule; }
check "Detect mode: no rule on SPOE's error" no_frame_rule
forward
eventually "the attack passes" all_are 200 "$HOST" "$SQLI"
probe=/detect-$RANDOM$RANDOM
check "an attack on a fresh path passes" all_are 200 "$HOST" "$probe?id=1%27%20OR%20%271%27%3D%271"
eventually "and the engines log it" logged "$probe"
signal_engines STOP
eventually "engine down in detect mode: requests pass (fails open)" all_are 200 "$HOST" /
signal_engines CONT

echo "== responses"
responses_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
policy Block "$RESPONSES"
eventually "the Ingress gets the response rules" responses_wired
eventually "Programmed: HAProxy sends the responses" programmed
# The probe's response leg (#595) goes through to the app, and the engine
# answers its response: Programmed rests on that, on both pods.
eventually "the probe's response leg went through to the app" probe_reached_app_since "$responses_since"
eventually "Programmed with the responses proven on every pod" programmed
# From Detect mode: the engines enforce Block once they run the new bundle
# (Ready), which Programmed, the filter proven, doesn't wait for.
eventually "the policy is Ready: the engines run it in Block mode" ready
check "a clean response passes" all_are 200 "$HOST" /products/42
eventually "a response leaking a SQL error is replaced: 403" all_are 403 "$HOST" /leak -H "$LEAK"
check "its body is gone" leak_replaced
eventually "the engines log it as a response deny" logged_response /leak deny
check "the unprotected Ingress lets the leak through" all_are 200 "$OPEN_HOST" /leak -H "$LEAK"
check "an attack in the request is still blocked" all_are 403 "$HOST" "$SQLI"
leak_path=/detect-leak-$RANDOM$RANDOM
policy Detect "$RESPONSES"
eventually "the snippet fails open" no_closed_rule
check "in detect mode, a leaking response passes" all_are 200 "$HOST" "$leak_path" -H "$LEAK"
eventually "and the engines log it as a response event" logged_response "$leak_path" log
eventually "detect mode: Programmed, the response leg answered too (HAProxy waits for it)" programmed
policy Detect
eventually "responses off: the response rules go" responses_unwired

if ! $started_v34; then
  # A live upgrade (#753): the controller from 3.2 to 3.4 moves the route
  # from the snippet to the operator's Backend, and once the rollout is
  # done the probe proves it and attacks are blocked; and back down to
  # 3.2, back to the snippet. Traffic during the rollout isn't checked.
  echo "== the controller upgraded to $UPGRADE_TAG, and back to $HAPROXY_IMAGE_TAG"
  policy
  controller_release() {
    "${HELM[@]}" upgrade haproxy kubernetes-ingress --repo "$HAPROXY_REPO" --version "$HAPROXY_CHART_VERSION" \
      --namespace "$NS" --reuse-values --set controller.image.tag="$1" --wait --timeout 5m >/dev/null
    "${KUBECTL[@]}" -n "$NS" rollout status deployment/haproxy-kubernetes-ingress --timeout=180s >/dev/null
    v34=false
    if is_v34 "$1"; then v34=true; fi
    patterns
  }
  no_snippet() { ! "${KUBECTL[@]}" -n "$NS" get ingress app -o jsonpath='{.metadata.annotations}' | grep -F 'inkwall:begin' >/dev/null; }
  controller_release "$UPGRADE_TAG"
  eventually "$UPGRADE_TAG: the controller's pods have the engine" injected
  eventually "$UPGRADE_TAG: the Ingress names the operator's Backend" wired
  check "$UPGRADE_TAG: the operator's snippet is gone" no_snippet
  eventually "$UPGRADE_TAG: Programmed once the probe proved the filter on both pods" programmed
  forward
  eventually "$UPGRADE_TAG: the attack is blocked" all_are 403 "$HOST" "$SQLI"
  check "$UPGRADE_TAG: benign traffic passes" all_are 200 "$HOST" /products/42
  controller_release "$HAPROXY_IMAGE_TAG"
  eventually "back to $HAPROXY_IMAGE_TAG: the controller's pods have the engine" injected
  eventually "back to $HAPROXY_IMAGE_TAG: the snippet is back, the user's kept" wired
  eventually "back to $HAPROXY_IMAGE_TAG: the operator's Backend is gone" backend_gone
  eventually "back to $HAPROXY_IMAGE_TAG: Programmed" programmed
  forward
  eventually "back to $HAPROXY_IMAGE_TAG: the attack is blocked" all_are 403 "$HOST" "$SQLI"
fi

echo "== unprotected"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy shop --timeout=60s >/dev/null
eventually "the user's Ingress is as it was" as_it_was
if $v34; then eventually "the operator's Backend is gone" backend_gone; fi
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
if $v34; then check "the operator's Backend is gone" backend_gone; fi
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
