#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Renders the Helm chart with rbac.integrations and checks each
# integration's ClusterRole and binding: granted by default (true), also
# without the values (helm upgrade --reuse-values from 0.2), and with auto
# (which grants every role when Helm can't ask the cluster, as here); left
# out when turned off; the operator's pod lists the integrations granted, so
# it restarts when they change; and the Pod webhook selects no pod without
# Traefik's. hack/kind/upgrade.sh checks auto against a cluster. Then checks
# that long release names don't give two objects the same name, and that the
# proxy namespaces reach the operator's flag and the Pod webhook.
set -euo pipefail

cd "$(dirname "$0")/.."

CHART=${CHART:-deploy/helm/inkwall}
fail=0

# check <want: the granted integrations, comma-separated> [helm flags...]
check() {
  local want=$1 out roles expected annotation
  shift
  out=$(helm template inkwall "$CHART" --namespace inkwall-system "$@")
  roles=$(awk '/^kind: ClusterRole(Binding)?$/ {k=$2; getline; getline; if ($2 ~ /^inkwall-operator-/) print k, $2}' <<<"$out" | sort | tr '\n' ' ')
  expected=$(for name in ${want//,/ }; do
    echo "ClusterRole inkwall-operator-$name"
    echo "ClusterRoleBinding inkwall-operator-$name"
  done | sort | tr '\n' ' ')
  annotation=$(sed -n 's/^ *waf.inkwall.dev\/integrations: "\(.*\)"$/\1/p' <<<"$out")
  if [[ "$roles" != "$expected" || "$annotation" != "$want" ]]; then
    echo "helm template $*: roles [$roles], annotation \"$annotation\"; want [$expected], \"$want\"" >&2
    fail=1
  fi
}

check envoy-gateway,haproxy,istio,istio-ingress,traefik
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac=null
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac.integrations=null
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=auto --set rbac.integrations.istio=auto --set rbac.integrations.haproxy=auto --set rbac.integrations.istioIngress=auto
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=true
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set-string rbac.integrations.traefik=true
check haproxy,istio,istio-ingress,traefik --set rbac.integrations.envoyGateway=false
check envoy-gateway,haproxy,istio-ingress,traefik --set rbac.integrations.istio=false
check envoy-gateway,haproxy,istio,traefik --set rbac.integrations.istioIngress=false
check envoy-gateway,haproxy,istio,istio-ingress --set rbac.integrations.traefik=false
check envoy-gateway,istio,istio-ingress,traefik --set rbac.integrations.haproxy=false
check "" --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false --set rbac.integrations.istio=false --set rbac.integrations.haproxy=false --set rbac.integrations.istioIngress=false

if out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=yes 2>&1) ||
  ! grep -q 'rbac.integrations.traefik must be auto, true or false' <<<"$out"; then
  echo "rbac.integrations.traefik=yes: want an error, got: $out" >&2
  fail=1
fi

# The Pod webhooks' objectSelectors: Traefik's, HAProxy's and Istio's
# ingress gateway pods, or none without the integration's role.
# selector WEBHOOK [helm flags...]: a Pod webhook's objectSelector, on one
# line. awk reads all of helm's output (no exit): stopping early would fail
# helm with SIGPIPE under pipefail.
selector() {
  local name=$1
  shift
  helm template inkwall "$CHART" --namespace inkwall-system "$@" |
    awk -v name="name: $name" 'done {next} $0 ~ "^ *" name "$" {on=1; next} on && /reinvocationPolicy/ {done=1; next} on && /objectSelector/ {p=1} p' | tr -s ' \n' ' '
}
# selects WEBHOOK LABEL VALUE: its default selector, and none without the role.
selects() {
  local webhook=$1 label=$2 key=$3 sel
  sel=$(selector "$webhook")
  if ! grep -q "$label" <<<"$sel"; then
    echo "$webhook objectSelector: $sel; want pods labelled $label" >&2
    fail=1
  fi
  sel=$(selector "$webhook" --set "rbac.integrations.$key=false")
  if grep -q "$label" <<<"$sel" || ! grep -q 'operator: Exists' <<<"$sel" || ! grep -q 'operator: DoesNotExist' <<<"$sel"; then
    echo "$webhook objectSelector without its role: $sel; want none" >&2
    fail=1
  fi
}
selects pods.waf.inkwall.dev 'app.kubernetes.io/name: traefik' traefik
selects haproxy.pods.waf.inkwall.dev 'app.kubernetes.io/name: kubernetes-ingress' haproxy
selects istio-ingress.pods.waf.inkwall.dev 'istio: ingressgateway' istioIngress

# The base ClusterRole is always there, without the integrations' writes.
out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false --set rbac.integrations.istio=false --set rbac.integrations.haproxy=false --set rbac.integrations.istioIngress=false)
base=$(awk '/^kind: ClusterRole$/ {getline; getline; if ($2 == "inkwall-operator") on=1; next} /^---/ {on=0} on' <<<"$out")
if [[ -z "$base" ]] || grep -E 'middlewares|envoyproxies|envoyfilters' <<<"$base" >/dev/null; then
  echo "the base ClusterRole is missing, or has an integration's rules:" >&2
  echo "$base" >&2
  fail=1
fi

# Names are cut to 63 characters: a long release name (Helm allows 53) must
# keep the suffixes that tell the operator's objects apart.
for release in abcdefghijabcdefghijabcdefghijabcdefghijabcdef abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabc; do
  names=$(helm template "$release" "$CHART" --namespace inkwall-system |
    awk '/^kind:/ {k=$2} /^metadata:/ {m=1; next} m && /^  name:/ {print k, $2; m=0}')
  if dups=$(sort <<<"$names" | uniq -d) && [[ -n "$dups" ]]; then
    echo "release $release (${#release} characters): objects share a name:" >&2
    echo "$dups" >&2
    fail=1
  fi
  if [[ $(grep -c -e '^ClusterRole ' -e '^Service ' <<<"$names") != 8 ]]; then
    echo "release $release: want 6 ClusterRoles and 2 Services, got:" >&2
    echo "$names" >&2
    fail=1
  fi
done

# The proxy namespaces: the operator's flag and the Pod webhook's
# namespaceSelector, by default, from the value, and also without it (helm
# upgrade --reuse-values from 0.2); none with "*"; an error when empty.
# proxy [helm flags...]: the --proxy-namespaces flag, and the Pod webhook's
# namespaceSelector on one line.
proxy() {
  local out
  out=$(helm template inkwall "$CHART" --namespace inkwall-system "$@")
  printf '%s|' "$(sed -n 's/^ *- --proxy-namespaces=//p' <<<"$out")"
  awk '/name: pods.waf.inkwall.dev/ {on=1; next} on && /objectSelector/ {exit} on && /namespaceSelector/ {p=1} p' <<<"$out" |
    tr -s ' \n' ' ' | sed 's/^ *//; s/ *$//'
}
want="traefik,kube-system,envoy-gateway-system,istio-ingress,istio-system,haproxy-controller|namespaceSelector: matchExpressions: - key: kubernetes.io/metadata.name operator: In values: - envoy-gateway-system - haproxy-controller - istio-ingress - istio-system - kube-system - traefik"
for flags in "" "--set injection.proxyNamespaces=null"; do
  # shellcheck disable=SC2086
  if [[ $(proxy $flags) != "$want" ]]; then
    echo "proxy namespaces ($flags): $(proxy $flags); want $want" >&2
    fail=1
  fi
done
got=$(proxy --set "injection.proxyNamespaces={ingress}")
if [[ $got != "ingress|namespaceSelector: matchExpressions: - key: kubernetes.io/metadata.name operator: In values: - ingress" ]]; then
  echo "proxy namespaces {ingress}: $got" >&2
  fail=1
fi
got=$(proxy --set "injection.proxyNamespaces={*}")
if [[ $got != "*|" ]]; then
  echo "proxy namespaces {*}: $got; want every namespace, no namespaceSelector" >&2
  fail=1
fi
if out=$(helm template inkwall "$CHART" --namespace inkwall-system --set "injection.proxyNamespaces={}" 2>&1) ||
  ! grep -q 'injection.proxyNamespaces must list' <<<"$out"; then
  echo "injection.proxyNamespaces={}: want an error, got: $out" >&2
  fail=1
fi
exit $fail
