#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Renders the Helm chart with rbac.integrations and checks each
# integration's ClusterRole and binding: granted by default, also without
# the values (helm upgrade --reuse-values from 0.2), left out when turned
# off; and the operator's pod lists the integrations granted, so it
# restarts when they change.
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
check traefik --set rbac.integrations.envoyGateway=false
check envoy-gateway --set rbac.integrations.traefik=false
check "" --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false

# The base ClusterRole is always there, without the integrations' writes.
out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false)
base=$(awk '/^kind: ClusterRole$/ {getline; getline; if ($2 == "inkwall-operator") on=1; next} /^---/ {on=0} on' <<<"$out")
if [[ -z "$base" ]] || grep -E 'middlewares|envoyproxies' <<<"$base" >/dev/null; then
  echo "the base ClusterRole is missing, or has an integration's rules:" >&2
  echo "$base" >&2
  fail=1
fi
exit $fail
