#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Builds the operator image, loads it into the kind cluster (make kind-up
# creates it), installs the Helm chart, and checks the operator: the
# webhook accepts a valid rule set and rejects an invalid one, and the
# sample policy is built into a bundle served to engines.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${OPERATOR_IMAGE:-inkwall-operator:dev}
CHART=${CHART:-deploy/helm/inkwall}
NAMESPACE=inkwall-system
KUBECTL=(kubectl --context "kind-$CLUSTER")

if ! kind get clusters | grep -qx "$CLUSTER"; then
  echo "no kind cluster $CLUSTER: run make kind-up first" >&2
  exit 1
fi

docker build --target operator -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER"

existed=false
"${KUBECTL[@]}" -n "$NAMESPACE" get deployment/inkwall-operator >/dev/null 2>&1 && existed=true
helm --kube-context "kind-$CLUSTER" upgrade --install inkwall "$CHART" \
  --namespace "$NAMESPACE" --create-namespace \
  --set operator.image.repository="${IMAGE%:*}" \
  --set operator.image.tag="${IMAGE##*:}" \
  --set operator.image.pullPolicy=Never
# Pick up a rebuilt image with the same tag.
if $existed; then
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout restart deployment/inkwall-operator
fi
"${KUBECTL[@]}" -n "$NAMESPACE" rollout status deployment/inkwall-operator --timeout=180s

failures=0
ok() { printf 'ok    %s\n' "$1"; }
fail() {
  printf 'FAIL  %s\n' "$1"
  failures=$((failures + 1))
}

if "${KUBECTL[@]}" apply --dry-run=server -f operator/config/samples/clusterwafruleset.yaml >/dev/null; then
  ok "valid rule set accepted"
else
  fail "valid rule set rejected"
fi

bad=$(cat <<'YAML'
apiVersion: waf.inkwall.dev/v1alpha1
kind: ClusterWAFRuleSet
metadata:
  name: kind-check-bad
spec:
  source:
    seclang: |
      SecRule ARGS "@rx a" "id:100001,phase:1,deny"
      SecRule ARGS "@nosuchop a" "id:100002,phase:1,deny"
YAML
)
if out=$("${KUBECTL[@]}" apply --dry-run=server -f - <<<"$bad" 2>&1); then
  fail "invalid rule set accepted"
elif grep -q "line 2: .*operator nosuchop not found" <<<"$out"; then
  ok "invalid rule set rejected with its line"
else
  fail "invalid rule set rejected for another reason: $out"
fi

# Bundles: the distribution Service has ready endpoints, the bundle is
# built, and a policy is accepted. It reports NoEngines until engines are
# injected (#27).
if [[ -n $("${KUBECTL[@]}" -n "$NAMESPACE" get endpoints inkwall-operator -o jsonpath='{.subsets[*].addresses[*].ip}') ]]; then
  ok "distribution Service has endpoints"
else
  fail "distribution Service has no ready endpoints"
fi
if "${KUBECTL[@]}" -n "$NAMESPACE" get secret inkwall-bundle >/dev/null 2>&1; then
  ok "bundle published"
else
  fail "no bundle Secret"
fi
"${KUBECTL[@]}" apply --server-side -f operator/config/samples/clusterwafruleset.yaml -f operator/config/samples/wafruleset.yaml \
  -f operator/config/samples/wafpolicy.yaml >/dev/null
accepted=""
for _ in $(seq 30); do
  accepted=$("${KUBECTL[@]}" -n inkwall-demo get wafpolicy demo -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}/{.status.conditions[?(@.type=="Enforced")].reason}')
  [[ $accepted == True/NoEngines ]] && break
  sleep 1
done
if [[ $accepted == True/NoEngines ]]; then
  ok "sample policy accepted, waiting for engines"
else
  fail "sample policy: Accepted/Enforced reason is $accepted, want True/NoEngines"
fi

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "operator: all checks passed"
