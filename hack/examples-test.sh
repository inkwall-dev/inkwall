#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Checks each example's WAFPolicy (examples/<proxy>/) with inkwallctl test
# --policy, as the operator would resolve and the engine compile it, set to
# Block mode: the requests of examples/tests/benign.http must be allowed,
# those of attacks.http denied (#388).
set -euo pipefail

cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go build -o "$work/inkwallctl" ./cmd/inkwallctl

fail=0
for dir in examples/traefik examples/envoy-gateway examples/istio; do
  sed 's/^  mode: Detect$/  mode: Block/' "$dir/wafpolicy.yaml" >"$work/wafpolicy.yaml"
  for check in "allow benign" "deny attacks"; do
    read -r expect file <<<"$check"
    if "$work/inkwallctl" test --policy "$work/wafpolicy.yaml" --ingress "$dir/route.yaml" \
      --expect "$expect" --request "examples/tests/$file.http" >"$work/out" 2>&1; then
      echo "ok    $dir: $file.http $expect"
    else
      echo "FAIL  $dir: $file.http, want $expect:"
      sed 's/^/      /' "$work/out"
      fail=1
    fi
  done
done
exit $fail
