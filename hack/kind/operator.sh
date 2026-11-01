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
ENGINE_IMAGE=${IMAGE_ENGINE:-inkwall-engine:dev}
CHART=${CHART:-deploy/helm/inkwall}
NAMESPACE=inkwall-system
KUBECTL=(kubectl --context "kind-$CLUSTER")
# The injection checks below: a proxy namespace, and one that isn't.
CHECK_NS=inkwall-inject-check
OTHER_NS=inkwall-inject-other
# The proxy namespaces: kind-up's Traefik, the e2e tests', and the
# injection check's.
PROXY_NAMESPACES=${PROXY_NAMESPACES:-traefik,traefik-e2e,$CHECK_NS}

if ! kind get clusters | grep -x "$CLUSTER" >/dev/null; then
  echo "no kind cluster $CLUSTER: run make kind-up first" >&2
  exit 1
fi

docker build --target operator -t "$IMAGE" .
# The engine image, injected into proxy pods.
docker build --target engine -t "$ENGINE_IMAGE" .
kind load docker-image "$IMAGE" "$ENGINE_IMAGE" --name "$CLUSTER"

existed=false
"${KUBECTL[@]}" -n "$NAMESPACE" get deployment/inkwall-operator >/dev/null 2>&1 && existed=true
helm --kube-context "kind-$CLUSTER" upgrade --install inkwall "$CHART" \
  --namespace "$NAMESPACE" --create-namespace \
  --set operator.image.repository="${IMAGE%:*}" \
  --set operator.image.tag="${IMAGE##*:}" \
  --set operator.image.pullPolicy=Never \
  --set engine.image.repository="${ENGINE_IMAGE%:*}" \
  --set engine.image.tag="${ENGINE_IMAGE##*:}" \
  --set engine.image.pullPolicy=Never \
  --set "injection.proxyNamespaces={$PROXY_NAMESPACES}"
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

# A ready operator pod can take a moment to be reachable through its
# Service (kube-proxy programs the new endpoints): wait until the webhook
# answers before checking what it says.
for _ in $(seq 30); do
  out=$("${KUBECTL[@]}" apply --dry-run=server -f operator/config/samples/clusterwafruleset.yaml 2>&1) && break
  grep -q "failed calling webhook" <<<"$out" || break
  sleep 1
done

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
# The samples live in the demo namespace and target its Ingress (make
# kind-up); on a cluster without the demo, create both for the check.
created_demo=false
if ! "${KUBECTL[@]}" get namespace inkwall-demo >/dev/null 2>&1; then
  created_demo=true
  "${KUBECTL[@]}" apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: inkwall-demo
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo
  namespace: inkwall-demo
spec:
  defaultBackend:
    service: {name: demo, port: {number: 8480}}
YAML
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
# The sample policy targets the demo Ingress, which has no host: left in
# place it would cover every host in the cluster.
"${KUBECTL[@]}" delete -f operator/config/samples/wafpolicy.yaml -f operator/config/samples/wafruleset.yaml \
  -f operator/config/samples/clusterwafruleset.yaml --ignore-not-found >/dev/null
if $created_demo; then
  "${KUBECTL[@]}" delete namespace inkwall-demo --wait=false >/dev/null
fi

# Injection on a real kubelet: a pod labeled like Traefik's gets the engine
# as a native sidecar, which starts with its token and trust ConfigMap and
# connects to the operator.
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $CHECK_NS
---
apiVersion: v1
kind: Pod
metadata:
  name: proxy
  namespace: $CHECK_NS
  labels:
    app.kubernetes.io/name: traefik
spec:
  containers:
    - name: proxy
      image: traefik/whoami:v1.10.3
YAML
if "${KUBECTL[@]}" -n "$CHECK_NS" wait pod/proxy --for=condition=Ready --timeout=120s >/dev/null 2>&1 &&
  [[ $("${KUBECTL[@]}" -n "$CHECK_NS" get pod proxy -o jsonpath='{.spec.initContainers[0].name}') == inkwall-engine ]]; then
  ok "a Traefik pod starts with the injected engine"
else
  fail "the injected engine didn't start"
  "${KUBECTL[@]}" -n "$CHECK_NS" describe pod proxy | tail -20 || true
fi
connected=false
for _ in $(seq 30); do
  if "${KUBECTL[@]}" -n "$NAMESPACE" get configmap -l waf.inkwall.dev/engines=true -o jsonpath='{.items[*].data.engines\.json}' |
    grep "\"podName\":\"proxy\"" >/dev/null; then
    connected=true
    break
  fi
  sleep 1
done
if $connected; then
  ok "the injected engine is connected to the operator"
else
  fail "the injected engine isn't connected to the operator"
  "${KUBECTL[@]}" -n "$CHECK_NS" logs proxy -c inkwall-engine --tail=20 || true
fi

# The same pod outside the proxy namespaces is no proxy pod: no engine, and
# its ServiceAccount isn't granted the bundle.
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $OTHER_NS
---
apiVersion: v1
kind: Pod
metadata:
  name: proxy
  namespace: $OTHER_NS
  labels:
    app.kubernetes.io/name: traefik
spec:
  containers:
    - name: proxy
      image: traefik/whoami:v1.10.3
YAML
# The check pod's grant shows the operator has reconciled since.
granted=""
for _ in $(seq 30); do
  granted=$("${KUBECTL[@]}" -n "$NAMESPACE" get rolebinding inkwall-bundle-reader -o jsonpath='{range .subjects[*]}{.namespace}{" "}{end}')
  [[ " $granted " == *" $CHECK_NS "* ]] && break
  sleep 1
done
if [[ -z $("${KUBECTL[@]}" -n "$OTHER_NS" get pod proxy -o jsonpath='{.spec.initContainers[*].name}') &&
  " $granted " == *" $CHECK_NS "* && " $granted " != *" $OTHER_NS "* ]] &&
  ! "${KUBECTL[@]}" auth can-i get secret/inkwall-bundle -n "$NAMESPACE" --as "system:serviceaccount:$OTHER_NS:default" >/dev/null 2>&1; then
  ok "a pod labeled like Traefik's outside the proxy namespaces gets no engine and no access to the bundle"
else
  fail "a pod outside the proxy namespaces: engine [$("${KUBECTL[@]}" -n "$OTHER_NS" get pod proxy -o jsonpath='{.spec.initContainers[*].name}')], granted namespaces [$granted]"
fi
"${KUBECTL[@]}" delete namespace "$CHECK_NS" "$OTHER_NS" --wait=false >/dev/null

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "operator: all checks passed"
