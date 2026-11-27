#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Runs tests under stress, to find timing flakes before a pull request does
# (#395): with the race detector, in a shuffled order, COUNT times, on
# GOMAXPROCS=2, while HOGS busy loops take CPU from them.
#
#   hack/ci/stress.sh PACKAGE...
#
# Environment: COUNT (10), SEED (the shuffle seed; default: the time), HOGS
# (2), INKWALL_FIT_SEED_BASE (the first scenario of the bundle fit property
# test; default: random), KUBEBUILDER_ASSETS for the operator's envtest
# packages. The seeds are printed first: rerun a failure with SEED=<it>,
# INKWALL_FIT_SEED_BASE=<it> and the failing package.
set -euo pipefail

cd "$(dirname "$0")/../.."

COUNT=${COUNT:-10}
SEED=${SEED:-$(date +%s)}
# Each run checks other scenarios than make test's (seed 1 on).
INKWALL_FIT_SEED_BASE=${INKWALL_FIT_SEED_BASE:-$((RANDOM * 32768 + RANDOM))}
export INKWALL_FIT_SEED_BASE
HOGS=${HOGS:-2}
echo "stress: -shuffle=$SEED -count=$COUNT GOMAXPROCS=2, $HOGS CPU hogs, INKWALL_FIT_SEED_BASE=$INKWALL_FIT_SEED_BASE: $*"

hogs=()
stop_hogs() {
  local p
  for p in "${hogs[@]}"; do
    kill "$p" 2>/dev/null || true
  done
}
trap stop_hogs EXIT
for _ in $(seq "$HOGS"); do
  (while :; do :; done) &
  hogs+=($!)
done

GOMAXPROCS=2 go test -race -shuffle="$SEED" -count="$COUNT" -timeout 100m "$@"
