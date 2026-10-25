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
NS=inkwall-e2e
HOST=e2e.example.com
PORT=${E2E_PORT:-18480}
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
cleanup() {
  if [[ -n ${pf:-} ]]; then kill "$pf" 2>/dev/null || true; fi
  rm -rf "$trust"
  if [[ ${KEEP:-} != 1 ]]; then
    "${KUBECTL[@]}" delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
    "${KUBECTL[@]}" -n "$OPERATOR_NS" delete role,rolebinding inkwall-e2e-bundle-reader >/dev/null 2>&1 || true
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
"${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=0 >/dev/null
eventually "operator stopped" bash -c "[[ -z \$(${KUBECTL[*]} -n $OPERATOR_NS get pods -l app.kubernetes.io/component=operator -o name) ]]"
check "the engine still blocks without the operator" status_is 403 "$SQLI"
check "benign traffic unaffected" status_is 200 /products/42
"${KUBECTL[@]}" -n "$OPERATOR_NS" scale deployment/inkwall-operator --replicas=2 >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=180s >/dev/null
eventually "Enforced again once the operator is back" enforced_by_all

echo "== the policy deleted"
"${KUBECTL[@]}" -n "$NS" delete wafpolicy app >/dev/null
eventually "enforcement stops" status_is 200 "$SQLI"

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed; engine logs:"
  "${KUBECTL[@]}" -n "$NS" logs deployment/app -c inkwall-engine --tail=40 || true
  exit 1
fi
echo "e2e: all checks passed"
