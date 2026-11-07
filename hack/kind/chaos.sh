#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The operator's failure modes on kind (#379; 0004 §6, §9): each scenario
# breaks something, checks the documented behaviour while it is broken,
# then the recovery. Throughout, a client in the cluster sends an attack
# through a Traefik whose Ingress a policy in Block mode protects, every
# 0.2 s: the scenarios check its answers, and the suite ends by checking
# that none was the app's (an uninspected request). Needs the operator
# installed (make kind-chaos installs it first).
#
#   1. a leader change in each phase of a signing key rotation;
#   2. the operator down, then Traefik scaled up: refused while a policy
#      blocks (the Pod webhook fails closed), started uninspected and
#      reported while every policy is in Detect mode (it fails open);
#   3. the bundle Secret, then the signing key Secret, deleted while the
#      operator is down;
#   4. the API server stopped just after a policy change;
#   5. the webhook certificate expired, and renewed.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${KIND_CLUSTER:-inkwall}
OPERATOR_NS=inkwall-system
NS=inkwall-chaos
TRAEFIK_NS=traefik-e2e
TRAEFIK=traefik-chaos
HOST=chaos.example.com
KUBECTL=(kubectl --context "kind-$CLUSTER")
SQLI='/?id=1%27%20OR%20%271%27%3D%271'
LEASE=inkwall-operator.waf.inkwall.dev

. hack/kind/lib.sh

# eventually_within SECONDS DESCRIPTION COMMAND...
eventually_within() {
  local secs=$1
  shift
  EVENTUALLY_TRIES=$((secs * 2)) eventually "$@"
}

condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
ready() { [[ $(condition Ready status) == True ]]; }
policy() {
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: web, namespace: $NS}
spec:
  targetRefs: [{kind: Ingress, name: web}]
  mode: $1
YAML
}
traefik_ready() {
  [[ $("${KUBECTL[@]}" -n "$TRAEFIK_NS" get deployment "$TRAEFIK" -o jsonpath='{.status.readyReplicas}') == "$1" ]]
}
# Running Traefik pods without the engine (pods selects them, once Traefik
# is installed).
pods=
uninjected() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" get pods -l "$pods" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.spec.initContainers[*].name}{"\n"}{end}' |
    grep '^|' | grep -vc inkwall-engine || true
}
injected() { [[ $(uninjected) == 0 ]]; }
one_uninjected() { [[ $(uninjected) == 1 ]]; }
pod_webhook_policy() {
  "${KUBECTL[@]}" get mutatingwebhookconfiguration inkwall-operator-mutating -o jsonpath='{.webhooks[?(@.name=="pods.waf.inkwall.dev")].failurePolicy}'
}
fails() { [[ $(pod_webhook_policy) == "$1" ]]; }
operator_pods() { "${KUBECTL[@]}" -n "$OPERATOR_NS" get pods -l app.kubernetes.io/component=operator -o name; }
stop_operator() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=0 >/dev/null
  eventually "the operator stopped" bash -c "[[ -z \$(${KUBECTL[*]} -n $OPERATOR_NS get pods -l app.kubernetes.io/component=operator -o name) ]]"
}
start_operator() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=2 >/dev/null
  "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
}
leader() {
  local holder
  holder=$("${KUBECTL[@]}" -n "$OPERATOR_NS" get lease "$LEASE" -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)
  echo "${holder%%_*}"
}
leader_is_not() { local l; l=$(leader) && [[ -n $l && $l != "$1" ]] && "${KUBECTL[@]}" -n "$OPERATOR_NS" get pod "$l" >/dev/null 2>&1; }
# kill_leader: deletes the leader's pod at once; another replica takes over.
kill_leader() {
  local was
  was=$(leader)
  "${KUBECTL[@]}" -n "$OPERATOR_NS" delete pod "$was" --grace-period=0 --force >/dev/null 2>&1
  eventually_within 120 "another replica leads (was $was)" leader_is_not "$was"
}

# The client: the attack through Traefik's Service every 0.2 s, one answer
# per line, with the time.
since=0
answers() { "${KUBECTL[@]}" -n "$NS" logs client | awk -v s="$since" '$1 >= s { print $2 }'; }
mark() { since=$(date +%s); }
# never_uninspected: no answer since the last mark was the app's (200);
# the engine's are 403, Traefik's own 500 while it can't reach it.
never_uninspected() { ! answers | grep -qx 200; }
# answered: the engine blocked the attack since the last mark.
answered() { [[ $(answers | grep -cx 403 || true) -gt 0 ]]; }

key_secret() { "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle-signing-key -o jsonpath="$1" 2>/dev/null; }
phase_is() { [[ $(key_secret '{.metadata.annotations.waf\.inkwall\.dev/rotation-phase}') == "$1" ]]; }
trusted_count_is() { [[ $(key_secret '{.data.trusted-keys\.pub}' | base64 -d | wc -c) == $(($1 * 32)) ]]; }
no_rejection() {
  ! "${KUBECTL[@]}" -n "$TRAEFIK_NS" logs "deployment/$TRAEFIK" -c inkwall-engine | grep '"bundle rejected"' >/dev/null
}

echo "== setup"
helm --kube-context "kind-$CLUSTER" upgrade --install "$TRAEFIK" traefik --repo https://traefik.github.io/charts \
  --version "$TRAEFIK_CHART_VERSION" --namespace "$TRAEFIK_NS" --create-namespace \
  --values hack/kind/traefik-chaos-values.yaml >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart "deployment/$TRAEFIK" >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status "deployment/$TRAEFIK" --timeout=180s >/dev/null
pods=$("${KUBECTL[@]}" -n "$TRAEFIK_NS" get deployment "$TRAEFIK" -o json |
  jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')
eventually "Traefik's pod has the engine" injected
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: $NS}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: "traefik/whoami:$WHOAMI_VERSION", args: ["--port", "8080"]}]
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: $NS}
spec:
  selector: {app: web}
  ports: [{name: http, port: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: $NS}
spec:
  ingressClassName: $TRAEFIK
  rules:
    - host: $HOST
      http:
        paths: [{path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 8080}}}}]
---
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: $NS}
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.11.1
      command:
        - sh
        - -c
        - >-
          while true; do
          c=\$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H 'Host: $HOST' 'http://$TRAEFIK.$TRAEFIK_NS.svc$SQLI');
          echo "\$(date +%s) \$c"; sleep 0.2; done
YAML
"${KUBECTL[@]}" -n "$NS" rollout status deployment/web --timeout=120s >/dev/null
"${KUBECTL[@]}" -n "$NS" wait --for=condition=Ready pod/client --timeout=120s >/dev/null
policy Block
eventually "the policy is Ready" ready
mark
eventually "the attack is blocked through Traefik" answered
created_config=false
if ! "${KUBECTL[@]}" get inkwallconfig default >/dev/null 2>&1; then
  "${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata: {name: default}
YAML
  created_config=true
fi

echo "== 1. a leader change in each phase of a key rotation"
mark
"${KUBECTL[@]}" annotate inkwallconfig default --overwrite "waf.inkwall.dev/rotate-signing-key=chaos-$(date +%s)" >/dev/null
eventually "the rotation publishes the new key" phase_is Publishing
kill_leader
eventually_within 300 "the new leader switches to the new key" phase_is Retiring
kill_leader
eventually_within 300 "the new leader retires the old key" phase_is ""
check "one key is trusted" trusted_count_is 1
start_operator
eventually "the policy is Ready" ready
check "Traefik's engine rejected no bundle" no_rejection
check "no request passed uninspected" never_uninspected
check "the attack was blocked throughout" answered

echo "== 2. the operator down, Traefik scaled up"
eventually "a policy blocks: the Pod webhook fails closed" fails Fail
mark
stop_operator
"${KUBECTL[@]}" -n "$TRAEFIK_NS" scale "deployment/$TRAEFIK" --replicas=2 >/dev/null
# refused: the ReplicaSet of this Traefik failed to create a pod, the
# webhook unreachable, since the last mark.
refused() {
  "${KUBECTL[@]}" -n "$TRAEFIK_NS" get events --field-selector reason=FailedCreate -o json |
    jq -e --arg rs "$TRAEFIK-" --argjson since "$since" '[.items[] | select((.involvedObject.name | startswith($rs))
      and (.message | contains("failed calling webhook"))
      and (((.lastTimestamp // .eventTime) | sub("\\.[0-9]+"; "") | fromdateiso8601) >= $since))] | length > 0' >/dev/null
}
eventually_within 60 "Block mode: the new pod is refused" refused
check "and no pod runs without the engine" injected
check "the running pod still blocks" answered
check "no request passed uninspected" never_uninspected
start_operator
eventually_within 180 "the operator back, the new pod starts with the engine" traefik_ready 2
check "every pod has the engine" injected
"${KUBECTL[@]}" -n "$TRAEFIK_NS" scale "deployment/$TRAEFIK" --replicas=1 >/dev/null
eventually_within 120 "scaled back" traefik_ready 1
policy Detect
eventually "every policy detects: the Pod webhook fails open" fails Ignore
stop_operator
"${KUBECTL[@]}" -n "$TRAEFIK_NS" scale "deployment/$TRAEFIK" --replicas=2 >/dev/null
eventually_within 120 "Detect mode: the new pod starts" traefik_ready 2
check "without the engine (uninspected, as documented for Detect mode)" one_uninjected
start_operator
missing() { [[ $(condition Programmed reason) == SidecarMissing ]]; }
eventually "the operator back, the policy reports SidecarMissing" missing
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart "deployment/$TRAEFIK" >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status "deployment/$TRAEFIK" --timeout=180s >/dev/null
eventually "restarted, every pod has the engine" injected
"${KUBECTL[@]}" -n "$TRAEFIK_NS" scale "deployment/$TRAEFIK" --replicas=1 >/dev/null
eventually_within 120 "scaled back" traefik_ready 1
policy Block
eventually "Block again: Ready" ready
mark
eventually "the attack is blocked again" answered

echo "== 3. the bundle Secret and the signing key Secret deleted while the operator is down"
bundle_secret() { "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle >/dev/null 2>&1; }
stop_operator
"${KUBECTL[@]}" -n "$OPERATOR_NS" delete secret inkwall-bundle >/dev/null
mark
sleep 5
check "the bundle Secret gone: the engine still blocks" answered
start_operator
eventually "the operator recreates the bundle Secret" bundle_secret
eventually "the policy is Ready" ready
old_key=$(key_secret '{.data.key-id}' | base64 -d)
stop_operator
"${KUBECTL[@]}" -n "$OPERATOR_NS" delete secret inkwall-bundle-signing-key >/dev/null
mark
start_operator
new_key() { local k; k=$(key_secret '{.data.key-id}' | base64 -d) && [[ -n $k && $k != "$old_key" ]]; }
eventually "every replica down, the operator creates a new signing key" new_key
policy_edit() {
  "${KUBECTL[@]}" -n "$NS" patch wafpolicy web --type=merge -p "{\"spec\":{\"body\":{\"maxBytes\":$1}}}" >/dev/null
}
policy_edit 65536
# The engine trusts the old key until the kubelet updates its trust
# ConfigMap: it rejects bundles the new key signed, and keeps its own.
eventually_within 180 "the engine trusts the new key and runs the new bundle: Ready" ready
check "the attack was blocked throughout" answered
check "no request passed uninspected" never_uninspected

echo "== 4. the API server stopped just after a policy change"
node=$CLUSTER-control-plane
api_up() { "${KUBECTL[@]}" get --raw /readyz >/dev/null 2>&1; }
mark
policy_edit 131072
docker exec "$node" mv /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/kube-apiserver.yaml.chaos
api_down() { ! api_up; }
eventually "the API server is down" api_down
mark
sleep 20
down_until=$(date +%s)
docker exec "$node" mv /etc/kubernetes/kube-apiserver.yaml.chaos /etc/kubernetes/manifests/kube-apiserver.yaml
eventually_within 180 "the API server is back" api_up
while_down() {
  "${KUBECTL[@]}" -n "$NS" logs client | awk -v s="$since" -v u="$down_until" '$1 >= s && $1 <= u { print $2 }' | grep -qx 403
}
check "the engine blocked the attack while the API server was down" while_down
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=300s >/dev/null
max_bytes_is() { [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath='{.status.observedGeneration}') == $("${KUBECTL[@]}" -n "$NS" get wafpolicy web -o jsonpath='{.metadata.generation}') ]] && ready; }
eventually_within 180 "the change is published and enforced: Ready for its generation" max_bytes_is
check "no request passed uninspected" never_uninspected

echo "== 5. the webhook certificate expired, then renewed"
cert_dir=$(mktemp -d)
trap 'rm -rf "$cert_dir"' EXIT
go run ./hack/expiredcert -dns "inkwall-operator-webhook.$OPERATOR_NS.svc" "$cert_dir"
"${KUBECTL[@]}" -n "$OPERATOR_NS" create secret generic inkwall-operator-webhook-tls --dry-run=client -o yaml \
  --from-file=ca.crt="$cert_dir/ca.crt" --from-file=ca.key="$cert_dir/ca.key" \
  --from-file=tls.crt="$cert_dir/tls.crt" --from-file=tls.key="$cert_dir/tls.key" |
  "${KUBECTL[@]}" apply -f - >/dev/null
not_after() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-operator-webhook-tls -o jsonpath='{.data.tls\.crt}' | base64 -d |
    openssl x509 -noout -enddate | cut -d= -f2
}
renewed() { local t; t=$(not_after) && (($(date -d "$t" +%s) > $(date +%s) + 86400)); }
eventually_within 120 "the operator renews the expired certificate" renewed
ca_injected() {
  [[ $("${KUBECTL[@]}" get mutatingwebhookconfiguration inkwall-operator-mutating -o jsonpath='{.webhooks[0].clientConfig.caBundle}') == \
    $("${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-operator-webhook-tls -o jsonpath='{.data.ca\.crt}') ]]
}
eventually "and injects its CA into the webhooks" ca_injected
webhook_answers() { "${KUBECTL[@]}" -n "$NS" patch wafpolicy web --type=merge -p '{"spec":{"body":{"maxBytes":65536}}}' --dry-run=server >/dev/null; }
eventually "the validating webhook answers" webhook_answers
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout restart "deployment/$TRAEFIK" >/dev/null
"${KUBECTL[@]}" -n "$TRAEFIK_NS" rollout status "deployment/$TRAEFIK" --timeout=180s >/dev/null
eventually "the Pod webhook injects a new Traefik pod" injected
eventually "and its engine connects: the policy is Ready" ready

if [[ ${KEEP:-} != 1 ]]; then
  "${KUBECTL[@]}" delete namespace "$NS" --wait=false >/dev/null
  helm --kube-context "kind-$CLUSTER" uninstall "$TRAEFIK" --namespace "$TRAEFIK_NS" >/dev/null
  if $created_config; then "${KUBECTL[@]}" delete inkwallconfig default >/dev/null; fi
fi

if ((failures > 0)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
