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
# the same with the metrics over HTTPS (metrics.secure), authenticated and
# authorized, and puts the release's values back. make kind-operator
# installs the chart first.
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
# Grants the metrics reader ClusterRole to Prometheus' service account in
# MONITORING_NS, for the metrics.secure section.
READER_BINDING=inkwall-np-metrics-reader

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
  "${KUBECTL[@]}" delete clusterrolebinding "$READER_BINDING" --ignore-not-found >/dev/null || true
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

# live_operator_ip: the address of a ready operator pod that isn't being
# deleted. After the restart above, the old replicas can still be listed
# (terminating) for a while: a request to one times out like one a policy
# drops (#513).
live_operator_ip() {
  local ips
  # Not | head -1: head exiting early would fail kubectl with SIGPIPE, and
  # the script with it (pipefail).
  # shellcheck disable=SC2016 # a Go template, not a shell expression
  ips=$("${KUBECTL[@]}" -n "$NAMESPACE" get pods -l app.kubernetes.io/component=operator -o go-template='{{range .items}}{{$ip := .status.podIP}}{{if not .metadata.deletionTimestamp}}{{range .status.conditions}}{{if and (eq .type "Ready") (eq .status "True")}}{{$ip}}{{"\n"}}{{end}}{{end}}{{end}}{{end}}') || true
  echo "${ips%%$'\n'*}"
}
# reach NAMESPACE IP PORT [PATH]: curl's exit status from a pod in NAMESPACE
# to IP: 28 (timed out) when a policy drops it.
reach() {
  local status=0
  "${KUBECTL[@]}" -n "$1" run "curl-$RANDOM" --rm -i --quiet --restart=Never --image "$CURL_IMAGE" --command -- \
    curl -sk -o /dev/null --connect-timeout 5 "http://$2:$3${4:-/}" >/dev/null 2>&1 || status=$?
  # kubectl run passes the container's exit status on.
  echo "$status"
}
# The allowed scrape, retried for a while: kindnet programs the policies
# and the new pods' addresses asynchronously. The address that answers is
# the one the denials below are checked against, so a timeout there is the
# policy, not a pod that went away.
operator_ip="" status=""
for _ in $(seq 12); do
  operator_ip=$(live_operator_ip)
  if [[ -n $operator_ip ]]; then
    status=$(reach "$MONITORING_NS" "$operator_ip" 8080 /metrics)
    [[ $status == 0 ]] && break
  fi
  sleep 5
done
if [[ $status == 0 ]]; then
  ok "Prometheus' namespace scrapes the metrics"
else
  fail "Prometheus' namespace can't scrape the metrics (operator pod ${operator_ip:-none ready}, curl exit status ${status:-none})"
fi
# The denials, once each: a request that gets through fails the check.
if [[ $(reach "$OTHER_NS" "$operator_ip" 8080 /metrics) == 28 ]]; then
  ok "another namespace can't reach the metrics"
else
  fail "another namespace reaches the metrics"
fi
if [[ $(reach "$OTHER_NS" "$operator_ip" 9445) == 28 ]]; then
  ok "a namespace that isn't a proxy namespace can't reach the distribution server"
else
  fail "a namespace that isn't a proxy namespace reaches the distribution server"
fi

# Secure metrics (#430): with metrics.secure on, under the same policies,
# the metrics are served over HTTPS behind the API server's TokenReview and
# SubjectAccessReview. From Prometheus' namespace: no token or an invalid
# one is 401, a service account without the metrics reader ClusterRole 403,
# and one bound to it reads the metrics. Another namespace still can't
# reach the port.
echo "== metrics.secure: HTTPS, authenticated and authorized"
for sa in prometheus other; do
  "${KUBECTL[@]}" -n "$MONITORING_NS" create serviceaccount "$sa" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
done
"${KUBECTL[@]}" create clusterrolebinding "$READER_BINDING" --clusterrole=inkwall-operator-metrics-reader \
  --serviceaccount="$MONITORING_NS:prometheus" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
if "${HELM[@]}" upgrade inkwall "$CHART" --namespace "$NAMESPACE" --reuse-values --set metrics.secure.enabled=true >/dev/null &&
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout status deployment/inkwall-operator --timeout=180s >/dev/null; then
  ok "helm upgrade with metrics.secure.enabled"
else
  fail "helm upgrade with metrics.secure.enabled"
fi
# scrape NAMESPACE IP [TOKEN]: the body of an HTTPS scrape of /metrics from
# a pod in NAMESPACE, then its status on a line of its own (000: no answer).
scrape() {
  local args=(-sk -w '\n%{http_code}' --connect-timeout 5 --max-time 15)
  if [[ -n ${3:-} ]]; then
    args+=(-H "Authorization: Bearer $3")
  fi
  "${KUBECTL[@]}" -n "$1" run "curl-$RANDOM" --rm -i --quiet --restart=Never --image "$CURL_IMAGE" --command -- \
    curl "${args[@]}" "https://$2:8080/metrics" 2>/dev/null || true
}
status_of() { tail -n 1 <<<"$1"; }
reader_token=$("${KUBECTL[@]}" -n "$MONITORING_NS" create token prometheus --duration=10m)
other_token=$("${KUBECTL[@]}" -n "$MONITORING_NS" create token other --duration=10m)
# The authorized scrape, retried: the new pods' addresses and the policies
# are programmed asynchronously, as above.
operator_ip="" got=""
for _ in $(seq 12); do
  operator_ip=$(live_operator_ip)
  if [[ -n $operator_ip ]]; then
    got=$(scrape "$MONITORING_NS" "$operator_ip" "$reader_token")
    [[ $(status_of "$got") == 200 ]] && grep -q '^# TYPE inkwall_operator_' <<<"$got" && break
  fi
  sleep 5
done
if [[ $(status_of "$got") == 200 ]] && grep -q '^# TYPE inkwall_operator_' <<<"$got"; then
  ok "a service account with the metrics reader role scrapes the metrics over HTTPS"
else
  fail "the authorized scrape: status $(status_of "$got") from operator pod ${operator_ip:-none ready}"
fi
got=$(status_of "$(scrape "$MONITORING_NS" "$operator_ip")")
if [[ $got == 401 ]]; then
  ok "a scrape without a token gets 401"
else
  fail "a scrape without a token: $got, want 401"
fi
# A token the API server rejects is unauthenticated too (#562), not a
# server error.
got=$(status_of "$(scrape "$MONITORING_NS" "$operator_ip" not-a-token)")
if [[ $got == 401 ]]; then
  ok "a scrape with an invalid token gets 401"
else
  fail "a scrape with an invalid token: $got, want 401"
fi
got=$(status_of "$(scrape "$MONITORING_NS" "$operator_ip" "$other_token")")
if [[ $got == 403 ]]; then
  ok "a service account without the role gets 403"
else
  fail "a service account without the role: $got, want 403"
fi
if [[ $(reach "$OTHER_NS" "$operator_ip" 8080 /metrics) == 28 ]]; then
  ok "another namespace still can't reach the metrics"
else
  fail "another namespace reaches the secure metrics"
fi

trap - EXIT
restore
if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "networkpolicy: all checks passed"
