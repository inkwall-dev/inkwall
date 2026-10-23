#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Compares the Go benchmarks of the working tree against a base revision
# (0001 §8, micro benchmarks) and fails on a significant regression.
#
#   hack/bench/compare.sh [BASE_REF]      (default origin/main)
#
# Both sides are compiled once, then run interleaved (base, head, base, ...)
# COUNT times, so drift on the machine (thermal throttling, a noisy CI
# neighbour) hits both sides alike instead of looking like a regression.
# benchstat compares the runs; hack/benchgate fails when a difference is both
# significant and above THRESHOLD percent.
#
# Environment: COUNT (8), BENCH (regexp, .), BENCHTIME (go's default),
# THRESHOLD (5), OUT (directory for base.txt, head.txt, benchstat.txt).
set -euo pipefail

cd "$(dirname "$0")/../.."
root=$PWD

BASE_REF=${1:-origin/main}
COUNT=${COUNT:-8}
BENCH=${BENCH:-.}
BENCHTIME=${BENCHTIME:-}
THRESHOLD=${THRESHOLD:-5}
BENCHSTAT=(go run golang.org/x/perf/cmd/benchstat@v0.0.0-20260908200009-22c9c6c9d4da)

work=$(mktemp -d)
OUT=${OUT:-$work/out}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
cleanup() {
  git -C "$root" worktree remove --force "$work/base" >/dev/null 2>&1 || true
  rm -rf "$work/bin" "$work/base"
}
trap cleanup EXIT

base=$(git merge-base HEAD "$BASE_REF")
echo "== base $(git log -1 --format='%h %s' "$base")"
echo "== head working tree ($(git log -1 --format=%h HEAD))"
git worktree add --quiet --detach "$work/base" "$base"

# build compiles the test binary of every package with benchmarks under
# tree into $work/bin/<side>/, one per package, and lists "binary dir" pairs.
build() {
  local side=$1 tree=$2
  mkdir -p "$work/bin/$side"
  (cd "$tree" && go list -f '{{.ImportPath}} {{.Dir}}' ./...) | while read -r pkg dir; do
    grep -qs '^func Benchmark' "$dir"/*_test.go || continue
    local bin=$work/bin/$side/${pkg//\//_}.test
    (cd "$tree" && go test -c -o "$bin" "$pkg")
    echo "$bin $dir"
  done
}
build base "$work/base" >"$work/base.list"
build head "$root" >"$work/head.list"

args=(-test.run='^$' -test.bench="$BENCH" -test.benchmem -test.count=1)
[[ -n $BENCHTIME ]] && args+=(-test.benchtime="$BENCHTIME")

: >"$OUT/base.txt"
: >"$OUT/head.txt"
for i in $(seq "$COUNT"); do
  echo "== run $i/$COUNT"
  for side in base head; do
    while read -r bin dir; do
      # Tests may read testdata relative to their package directory.
      (cd "$dir" && "$bin" "${args[@]}") >>"$OUT/$side.txt"
    done <"$work/$side.list"
  done
done

# benchstat labels columns with the file names given; keep them short.
(cd "$OUT" && "${BENCHSTAT[@]}" base.txt head.txt) | tee "$OUT/benchstat.txt"
(cd "$OUT" && "${BENCHSTAT[@]}" -format csv base.txt head.txt 2>/dev/null) |
  go run ./hack/benchgate -threshold "$THRESHOLD"
