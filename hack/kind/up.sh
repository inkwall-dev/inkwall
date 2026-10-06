#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Creates the kind cluster (if needed), builds the engine image, loads it into
# the cluster and deploys the demo app twice: behind the engine's reverse
# proxy, and through Traefik with the engine as a forward-auth sidecar.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${IMAGE:-inkwall-engine:dev}
TRAEFIK_CHART_VERSION=41.6.1 # Traefik v3.7.13

if ! kind get clusters | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --config hack/kind/cluster.yaml
fi
# Port mappings are fixed when a kind cluster is created.
if ! docker port "$CLUSTER-control-plane" | grep -q '^30080/tcp'; then
  echo "cluster $CLUSTER predates the Traefik port mappings; recreate it: make kind-down kind-up" >&2
  exit 1
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

traefik_existed=false
"${KUBECTL[@]}" -n traefik get deployment/traefik >/dev/null 2>&1 && traefik_existed=true
helm --kube-context "kind-$CLUSTER" upgrade --install traefik traefik \
  --repo https://traefik.github.io/charts --version "$TRAEFIK_CHART_VERSION" \
  --namespace traefik --create-namespace --values hack/kind/traefik-values.yaml
if $traefik_existed; then
  "${KUBECTL[@]}" -n traefik rollout restart deployment/traefik
fi
"${KUBECTL[@]}" -n traefik rollout status deployment/traefik --timeout=180s
"${KUBECTL[@]}" apply -f hack/kind/traefik-demo.yaml

# The Service keeps routing to the terminating pod for a moment after the
# rollout; wait until only ready pods are left behind the NodePort.
ready=false
for _ in $(seq 30); do
  if [[ $("${KUBECTL[@]}" -n inkwall-demo get pods -l app=demo --no-headers | wc -l) == 1 ]] &&
    [[ $("${KUBECTL[@]}" -n traefik get pods -l app.kubernetes.io/name=traefik --no-headers | wc -l) == 1 ]] &&
    curl -sf -o /dev/null http://127.0.0.1:30481/readyz &&
    curl -sf -o /dev/null http://127.0.0.1:30482/readyz &&
    curl -s -o /dev/null http://127.0.0.1:30080/ ; then
    ready=true
    break
  fi
  sleep 1
done
if ! $ready; then
  echo "demo not reachable on 127.0.0.1:30481 / 30482 / 30080 after the rollout" >&2
  exit 1
fi

echo
echo "reverse proxy: http://127.0.0.1:30480  admin: http://127.0.0.1:30481/metrics"
echo "traefik:       http://127.0.0.1:30080  admin: http://127.0.0.1:30482/metrics"
