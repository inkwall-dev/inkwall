#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Creates the kind cluster (if needed), builds the engine image, loads it into
# the cluster and deploys the demo app behind the engine.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${IMAGE:-inkwall-engine:dev}

if ! kind get clusters | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --config hack/kind/cluster.yaml
fi

docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER"

KUBECTL=(kubectl --context "kind-$CLUSTER")
existed=false
"${KUBECTL[@]}" -n inkwall-demo get deployment/demo >/dev/null 2>&1 && existed=true
"${KUBECTL[@]}" apply -f hack/kind/demo.yaml
# Pick up a rebuilt image with the same tag.
if $existed; then
  "${KUBECTL[@]}" -n inkwall-demo rollout restart deployment/demo
fi
"${KUBECTL[@]}" -n inkwall-demo rollout status deployment/demo --timeout=120s

# The Service keeps routing to the terminating pod for a moment after the
# rollout; wait until only ready pods are left behind the NodePort.
ready=false
for _ in $(seq 30); do
  if [[ $("${KUBECTL[@]}" -n inkwall-demo get pods -l app=demo --no-headers | wc -l) == 1 ]] &&
    curl -sf -o /dev/null http://127.0.0.1:30481/readyz; then
    ready=true
    break
  fi
  sleep 1
done
if ! $ready; then
  echo "demo not reachable on 127.0.0.1:30481 after the rollout" >&2
  exit 1
fi

echo
echo "proxy: http://127.0.0.1:30480  admin: http://127.0.0.1:30481/metrics"
