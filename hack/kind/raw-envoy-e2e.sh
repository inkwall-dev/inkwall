#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of raw Envoy in Kubernetes on the kind cluster (#283):
# examples/raw-envoy applied as docs/raw-envoy.md says (the trust ConfigMap,
# then kubectl apply -k), with the engine image of this checkout. The engine
# next to Envoy takes the sample's WAFPolicy from the operator (bundle mode):
# an attack on the policy's host is blocked, a benign request and a host no
# policy covers pass, the policy reports Enforced, and Programmed=False
# (ControllerUnsupported: the operator wires nothing for raw Envoy); in
# Detect mode the attack passes. Needs the operator installed (make
# kind-operator, which loads the engine image). KEEP=1 leaves the objects.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${IMAGE:-inkwall-engine:dev}
OPERATOR_NS=inkwall-system
NS=raw-envoy
HOST=app.example.com
PORT=${E2E_RAW_ENVOY_PORT:-18093}
KUBECTL=(kubectl --context "kind-$CLUSTER")
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
# eventually DESCRIPTION COMMAND...: retries for up to 2 minutes.
eventually() {
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

if ! "${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-operator first" >&2
  exit 1
fi

work=$(mktemp -d)
pf=
cleanup() {
  if [[ -n $pf ]]; then kill "$pf" 2>/dev/null || true; fi
  if [[ ${KEEP:-} != 1 ]]; then
    "${KUBECTL[@]}" delete -k "$work" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# The sample, with this checkout's engine image and one Envoy replica.
cat >"$work/kustomization.yaml" <<YAML
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [$(realpath --relative-to="$work" examples/raw-envoy)]
images: [{name: ghcr.io/inkwall-dev/inkwall-engine, newName: ${IMAGE%:*}, newTag: ${IMAGE##*:}}]
replicas: [{name: envoy, count: 1}]
YAML

# The trust ConfigMap, as the guide creates it.
"${KUBECTL[@]}" create namespace "$NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
key() { "${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-bundle-signing-key -o jsonpath="{.data.$1}" | base64 -d; }
"${KUBECTL[@]}" -n "$OPERATOR_NS" get secret inkwall-operator-webhook-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$work/ca.crt"
key 'trusted-keys\.pub' >"$work/trusted-keys.pub"
if [[ ! -s $work/trusted-keys.pub ]]; then key 'ed25519\.pub' >"$work/trusted-keys.pub"; fi
"${KUBECTL[@]}" -n "$NS" create configmap inkwall-trust --from-file="$work/ca.crt" --from-file="$work/trusted-keys.pub" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null

"${KUBECTL[@]}" apply -k "$work" >/dev/null
if "${KUBECTL[@]}" -n "$NS" rollout status deployment/envoy --timeout=180s >/dev/null &&
  "${KUBECTL[@]}" -n "$NS" rollout status deployment/app --timeout=120s >/dev/null; then
  ok "Envoy and the app run, the engine next to Envoy"
else
  fail "Envoy and the app run, the engine next to Envoy"
  "${KUBECTL[@]}" -n "$NS" get pods -o wide || true
  "${KUBECTL[@]}" -n "$NS" logs deployment/envoy -c inkwall-engine --tail=30 || true
fi

"${KUBECTL[@]}" -n "$NS" port-forward svc/envoy "$PORT:80" >/dev/null 2>&1 &
pf=$!
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1:$PORT$2" || true; }
is() { [[ $(code "$2" "$3") == "$1" ]]; }
condition() {
  "${KUBECTL[@]}" -n "$NS" get wafpolicy app -o jsonpath="{.status.conditions[?(@.type==\"$1\")].$2}" 2>/dev/null
}
condition_is() { [[ $(condition "$1" status) == "$2" && $(condition "$1" reason) == "$3" ]]; }

eventually "an attack on the policy's host: 403" is 403 "$HOST" "$SQLI"
check "a benign request: 200" is 200 "$HOST" /
check "an attack on a host no policy covers: 200 (no policy)" is 200 other.example.com "$SQLI"
check "an attack on the route Envoy's filter is off for: 200" is 200 "$HOST" "/healthz?id=1%27%20OR%20%271%27%3D%271"
eventually "the policy is Enforced" condition_is Enforced True Enforced
check "the policy is not Programmed (ControllerUnsupported)" condition_is Programmed False ControllerUnsupported

"${KUBECTL[@]}" -n "$NS" patch wafpolicy app --type merge -p '{"spec":{"mode":"Detect"}}' >/dev/null
eventually "Detect mode: the attack passes" is 200 "$HOST" "$SQLI"

if ((failures > 0)); then
  echo "$failures check(s) failed; engine and operator logs:"
  "${KUBECTL[@]}" -n "$NS" logs deployment/envoy -c inkwall-engine --tail=40 2>/dev/null || true
  "${KUBECTL[@]}" -n "$OPERATOR_NS" logs deployment/inkwall-operator --tail=40 2>/dev/null || true
  exit 1
fi
echo "raw-envoy e2e: all checks passed"
