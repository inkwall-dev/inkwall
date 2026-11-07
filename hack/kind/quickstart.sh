#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Runs docs/quickstart.md as a new user would (#388): each sh block after a
# "<!-- quickstart: NAME -->" comment, in order, on a kind cluster of its
# own, with the released chart and images. The demo comes from this
# checkout's examples/traefik instead of GitHub's main, so a change to the
# example is tested before it lands. Checks that the attack passes in
# Detect mode and gets 403 in Block mode. KEEP=1 leaves the cluster.
set -euo pipefail

cd "$(dirname "$0")/../.."
root=$PWD
doc=docs/quickstart.md

# block NAME prints the sh block after <!-- quickstart: NAME -->.
block() {
  awk -v m="<!-- quickstart: $1 -->" 'index($0, m) == 1 { f = 1; next } f && /^```sh$/ { p = 1; next } p && /^```$/ { exit } p' "$doc"
}

run() {
  local b
  b=$(block "$1")
  if [[ -z $b ]]; then
    echo "no block \"quickstart: $1\" in $doc" >&2
    exit 1
  fi
  # The example from this checkout, not GitHub's main.
  b=${b//"'https://github.com/inkwall-dev/inkwall//examples/traefik?ref=main'"/"$root/examples/traefik"}
  echo "== quickstart: $1"
  eval "$b"
}

cleanup() {
  if [[ ${KEEP:-} != 1 ]]; then
    kill %1 2>/dev/null || true
    kind delete cluster --name inkwall-quickstart >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run cluster
run inkwall
run traefik
run protect
detect=$(run detect | tail -1)
block_status=$(run block | tail -1)
echo "Detect mode: $detect; Block mode: $block_status"
if [[ $detect != 200 || $block_status != 403 ]]; then
  echo "FAIL  want 200 in Detect mode and 403 in Block mode" >&2
  kubectl -n inkwall-system logs deployment/inkwall-operator --tail=50 >&2 || true
  kubectl get wafpolicy -A -o wide >&2 || true
  exit 1
fi
# Its cleanup block, last.
if [[ ${KEEP:-} != 1 ]]; then
  trap - EXIT
  run cleanup
fi
echo "quickstart: ok"
