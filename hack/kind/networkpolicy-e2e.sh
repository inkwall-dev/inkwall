#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The chart's NetworkPolicies on kind (#387), whose network plugin
# (kindnet) enforces them: with networkPolicy.enabled and egress on, and a
# default-deny policy for every pod of the operator's namespace, the
# operator restarts and reaches the API server, the API server reaches the
# webhook, a proxy pod gets the engine and the engine connects to the
# distribution server, and Prometheus' namespace scrapes the metrics. Other
# namespaces reach neither the distribution server nor the metrics. Then
# puts the release's values back. make kind-operator installs the chart
# first.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${KIND_CLUSTER:-inkwall}
NAMESPACE=inkwall-system
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")
CHART=${CHART:-deploy/helm/inkwall}
PROXY_NS=inkwall-np-proxy
MONITORING_NS=inkwall-np-monitoring
OTHER_NS=inkwall-np-other
CURL_IMAGE=curlimages/curl:8.11.1

failures=0
ok() { printf 'ok    %s\n' "$1"; }
fail() {
  printf 'FAIL  %s\n' "$1"
  failures=$((failures + 1))
}

work=$(mktemp -d)
"${HELM[@]}" get values inkwall --namespace "$NAMESPACE" -o yaml >"$work/values.yaml"
proxy_namespaces=$("${KUBECTL[@]}" -n "$NAMESPACE" get deployment inkwall-operator -o jsonpath='{.spec.template.spec.containers[0].args}' |
  tr '"' '\n' | sed -n 's/^--proxy-namespaces=//p')
proxy_namespaces=${proxy_namespaces:-traefik}
# The engine's pod goes first: the chart refuses an upgrade that leaves
# pods with the engine outside the proxy namespaces.
restore() {
  "${KUBECTL[@]}" delete namespace "$PROXY_NS" "$MONITORING_NS" "$OTHER_NS" --ignore-not-found --timeout=120s >/dev/null || true
  "${KUBECTL[@]}" -n "$NAMESPACE" delete networkpolicy default-deny --ignore-not-found >/dev/null || true
  if ! "${HELM[@]}" upgrade inkwall "$CHART" --namespace "$NAMESPACE" -f "$work/values.yaml" >/dev/null; then
    fail "putting the release's values back"
  fi
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout status deployment/inkwall-operator --timeout=180s >/dev/null || true
  rm -rf "$work"
}
trap restore EXIT

for ns in "$PROXY_NS" "$MONITORING_NS" "$OTHER_NS"; do
  "${KUBECTL[@]}" create namespace "$ns" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
done

echo "== networkPolicy.enabled, egress on, default deny in $NAMESPACE"
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: $NAMESPACE
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
YAML
"${HELM[@]}" upgrade inkwall "$CHART" --namespace "$NAMESPACE" --reuse-values \
  --set "injection.proxyNamespaces={$proxy_namespaces,$PROXY_NS}" \
  --set networkPolicy.enabled=true --set networkPolicy.egress.enabled=true \
  --set "networkPolicy.metricsFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=$MONITORING_NS" >/dev/null
# A restart under the policies: the operator must reach the API server
# (leader election, its caches) to become ready.
"${KUBECTL[@]}" -n "$NAMESPACE" rollout restart deployment/inkwall-operator >/dev/null
if "${KUBECTL[@]}" -n "$NAMESPACE" rollout status deployment/inkwall-operator --timeout=180s >/dev/null; then
  ok "the operator restarts and is ready under default deny"
else
  fail "the operator isn't ready under default deny"
  "${KUBECTL[@]}" -n "$NAMESPACE" logs deployment/inkwall-operator --tail=30 || true
fi

# The API server calls the validating webhook.
webhook=false
for _ in $(seq 30); do
  if "${KUBECTL[@]}" apply --dry-run=server -f operator/config/samples/clusterwafruleset.yaml >/dev/null 2>&1; then
    webhook=true
    break
  fi
  sleep 2
done
if $webhook; then
  ok "the API server reaches the webhook"
else
  fail "the API server doesn't reach the webhook: $("${KUBECTL[@]}" apply --dry-run=server -f operator/config/samples/clusterwafruleset.yaml 2>&1 | tail -1)"
fi

# Injection and distribution: a pod labeled like Traefik's in a proxy
# namespace gets the engine, which connects to the operator. The Pod
# webhook fails open and its namespaceSelector is the leader's to keep:
# until the restarted operator's leader holds the lease (and has added the
# namespace), a pod may start without the engine, so retry for a while.
for _ in $(seq 30); do
  injected=$("${KUBECTL[@]}" create -o jsonpath='{.spec.initContainers[*].name}' -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: proxy
  namespace: $PROXY_NS
  labels:
    app.kubernetes.io/name: traefik
spec:
  containers:
    - name: proxy
      image: traefik/whoami:$WHOAMI_VERSION
YAML
  )
  [[ $injected == *inkwall-engine* ]] && break
  "${KUBECTL[@]}" -n "$PROXY_NS" delete pod proxy --wait >/dev/null
  sleep 3
done
if "${KUBECTL[@]}" -n "$PROXY_NS" wait pod/proxy --for=condition=Ready --timeout=120s >/dev/null 2>&1 &&
  [[ $("${KUBECTL[@]}" -n "$PROXY_NS" get pod proxy -o jsonpath='{.spec.initContainers[0].name}') == inkwall-engine ]]; then
  ok "a proxy pod gets the engine"
else
  fail "the proxy pod has no running engine"
  "${KUBECTL[@]}" -n "$PROXY_NS" describe pod proxy | tail -20 || true
fi
connected=false
for _ in $(seq 60); do
  if "${KUBECTL[@]}" -n "$NAMESPACE" get configmap -l waf.inkwall.dev/engines=true -o jsonpath='{.items[*].data.engines\.json}' |
    grep "\"podNamespace\":\"$PROXY_NS\"" >/dev/null; then
    connected=true
    break
  fi
  sleep 2
done
if $connected; then
  ok "the engine connects to the distribution server"
else
  fail "the engine isn't connected to the operator"
  "${KUBECTL[@]}" -n "$PROXY_NS" logs proxy -c inkwall-engine --tail=20 || true
fi

# reach NAMESPACE PORT [PATH]: curl's exit status from a pod in NAMESPACE
# to the operator's pod: 28 (timed out) when a policy drops it.
operator_ip=$("${KUBECTL[@]}" -n "$NAMESPACE" get pods -l app.kubernetes.io/component=operator -o jsonpath='{.items[0].status.podIP}')
reach() {
  local status=0
  "${KUBECTL[@]}" -n "$1" run "curl-$RANDOM" --rm -i --quiet --restart=Never --image "$CURL_IMAGE" --command -- \
    curl -sk -o /dev/null --connect-timeout 5 "http://$operator_ip:$2${3:-/}" >/dev/null 2>&1 || status=$?
  # kubectl run passes the container's exit status on.
  echo "$status"
}
if [[ $(reach "$MONITORING_NS" 8080 /metrics) == 0 ]]; then
  ok "Prometheus' namespace scrapes the metrics"
else
  fail "Prometheus' namespace can't scrape the metrics"
fi
if [[ $(reach "$OTHER_NS" 8080 /metrics) == 28 ]]; then
  ok "another namespace can't reach the metrics"
else
  fail "another namespace reaches the metrics"
fi
if [[ $(reach "$OTHER_NS" 9445) == 28 ]]; then
  ok "a namespace that isn't a proxy namespace can't reach the distribution server"
else
  fail "a namespace that isn't a proxy namespace reaches the distribution server"
fi

trap - EXIT
restore
if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "networkpolicy: all checks passed"
