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
# that long release names don't give two objects the same name.
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

check envoy-gateway,traefik
check envoy-gateway,traefik --set rbac=null
check envoy-gateway,traefik --set rbac.integrations=null
check envoy-gateway,traefik --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=auto
check envoy-gateway,traefik --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=true
check envoy-gateway,traefik --set-string rbac.integrations.traefik=true
check traefik --set rbac.integrations.envoyGateway=false
check envoy-gateway --set rbac.integrations.traefik=false
check "" --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false

if out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=yes 2>&1) ||
  ! grep -q 'rbac.integrations.traefik must be auto, true or false' <<<"$out"; then
  echo "rbac.integrations.traefik=yes: want an error, got: $out" >&2
  fail=1
fi

# The Pod webhook's objectSelector: Traefik's pods, or none without
# Traefik's role.
# selector [helm flags...]: the Pod webhook's objectSelector, on one line.
selector() {
  helm template inkwall "$CHART" --namespace inkwall-system "$@" |
    awk '/name: pods.waf.inkwall.dev/ {on=1; next} on && /reinvocationPolicy/ {exit} on' | tr -s ' \n' ' '
}
sel=$(selector)
if ! grep -q 'app.kubernetes.io/name: traefik' <<<"$sel"; then
  echo "Pod webhook objectSelector: $sel; want Traefik's pods" >&2
  fail=1
fi
sel=$(selector --set rbac.integrations.traefik=false)
if grep -q 'traefik' <<<"$sel" || ! grep -q 'operator: Exists' <<<"$sel" || ! grep -q 'operator: DoesNotExist' <<<"$sel"; then
  echo "Pod webhook objectSelector without Traefik's role: $sel; want none" >&2
  fail=1
fi

# The base ClusterRole is always there, without the integrations' writes.
out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false)
base=$(awk '/^kind: ClusterRole$/ {getline; getline; if ($2 == "inkwall-operator") on=1; next} /^---/ {on=0} on' <<<"$out")
if [[ -z "$base" ]] || grep -E 'middlewares|envoyproxies' <<<"$base" >/dev/null; then
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
  if [[ $(grep -c -e '^ClusterRole ' -e '^Service ' <<<"$names") != 5 ]]; then
    echo "release $release: want 3 ClusterRoles and 2 Services, got:" >&2
    echo "$names" >&2
    fail=1
  fi
done
exit $fail
