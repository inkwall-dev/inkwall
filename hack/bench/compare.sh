#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Compares the Go benchmarks of the working tree against a base revision
# (0001 §8, micro benchmarks) and fails on a significant regression.
#
#   hack/bench/compare.sh [BASE_REF]      (default origin/main)
#
# Both sides are compiled once, with -trimpath so that the same source gives
# the same binary on both. A package whose test binary and testdata/ are
# identical on both sides runs the same code, so it cannot have regressed:
# it is skipped instead of letting runner noise fail the gate on it. (Files
# a benchmark reads at run time from outside its testdata/ are not seen; keep
# benchmark inputs embedded or in testdata/.)
#
# The other packages run interleaved (base, head, base, ...) COUNT times, so
# drift on the machine (thermal throttling, a noisy CI neighbour) hits both
# sides alike instead of looking like a regression. benchstat compares the
# runs; hack/benchgate flags a difference that is both significant and above
# THRESHOLD percent. Flagged benchmarks are run again, interleaved COUNT
# times, and the gate fails only on a regression that shows on both runs.
#
# Environment: COUNT (8), BENCH (regexp, .), BENCHTIME (go's default),
# THRESHOLD (5), OUT (directory for the results: base.txt, head.txt,
# benchstat.txt, recheck/, summary.md).
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
rm -rf "$OUT/recheck"
rm -f "$OUT"/{base,head}.txt "$OUT"/benchstat.{txt,csv} "$OUT"/{flagged,gate,skipped,compared}.txt "$OUT/summary.md"

summary=$OUT/summary.md
base=$(git merge-base HEAD "$BASE_REF")
echo "== base $(git log -1 --format='%h %s' "$base")"
echo "== head working tree ($(git log -1 --format=%h HEAD))"
{
  echo "### Benchmarks"
  echo
  echo "Base $(git log -1 --format=%h "$base"), head $(git log -1 --format=%h HEAD) (working tree)."
} >"$summary"
git worktree add --quiet --detach "$work/base" "$base"

mkdir -p "$work/bin"
go build -o "$work/bin/benchgate" ./hack/benchgate

# build compiles the test binary of every package with benchmarks under
# tree into $work/bin/<side>/ and lists "importpath binary dir" lines.
build() {
  local side=$1 tree=$2
  mkdir -p "$work/bin/$side"
  (cd "$tree" && go list -f '{{.ImportPath}} {{.Dir}}' ./...) | while read -r pkg dir; do
    grep -qs '^func Benchmark' "$dir"/*_test.go || continue
    local bin=$work/bin/$side/${pkg//\//_}.test
    (cd "$tree" && go test -c -trimpath -o "$bin" "$pkg")
    echo "$pkg $bin $dir"
  done
}
build base "$work/base" >"$work/base.list"
build head "$root" >"$work/head.list"

# lookup prints "binary dir" of a package on one side, nothing if it has none.
lookup() {
  local side=$1 want=$2 pkg bin dir
  while read -r pkg bin dir; do
    if [[ $pkg == "$want" ]]; then
      echo "$bin $dir"
      return
    fi
  done <"$work/$side.list"
}

# same_testdata succeeds when two testdata/ directories have the same files,
# or neither exists: tests may read them at run time, outside the binary.
same_testdata() {
  [[ ! -e $1 && ! -e $2 ]] && return 0
  diff -rq "$1" "$2" >/dev/null 2>&1
}

# The plan lists "importpath regexp" for every package to run.
: >"$work/plan"
: >"$OUT/skipped.txt"
: >"$OUT/compared.txt"
while read -r pkg bin dir; do
  read -r bbin bdir <<<"$(lookup base "$pkg")" || true
  if [[ -n ${bbin:-} ]] && cmp -s "$bbin" "$bin" && same_testdata "$bdir/testdata" "$dir/testdata"; then
    echo "$pkg" >>"$OUT/skipped.txt"
  else
    echo "$pkg" >>"$OUT/compared.txt"
    echo "$pkg $BENCH" >>"$work/plan"
  fi
done <"$work/head.list"

{
  echo
  echo "Skipped, test binary unchanged:"
  sed 's/^/- /' "$OUT/skipped.txt"
  [[ -s $OUT/skipped.txt ]] || echo "- none"
  echo
  echo "Compared:"
  sed 's/^/- /' "$OUT/compared.txt"
  [[ -s $OUT/compared.txt ]] || echo "- none"
} >>"$summary"
sed 's/^/== skipped, test binary unchanged: /' "$OUT/skipped.txt"

if [[ ! -s $work/plan ]]; then
  echo "== no package with benchmarks changed; nothing to compare"
  printf '\nNo package with benchmarks changed; nothing to compare.\n' >>"$summary"
  exit 0
fi

args=(-test.run='^$' -test.benchmem -test.count=1)
[[ -n $BENCHTIME ]] && args+=(-test.benchtime="$BENCHTIME")

# bench runs the plan interleaved COUNT times into dir/{base,head}.txt.
bench() {
  local plan=$1 dir=$2 i side pkg re bin pdir
  mkdir -p "$dir"
  : >"$dir/base.txt"
  : >"$dir/head.txt"
  for i in $(seq "$COUNT"); do
    echo "== run $i/$COUNT"
    for side in base head; do
      while read -r pkg re; do
        bin= pdir=
        read -r bin pdir <<<"$(lookup "$side" "$pkg")" || true
        # A package new in head (or gone from it) has one side only;
        # benchstat shows it without a comparison.
        [[ -n $bin ]] || continue
        # Tests may read testdata relative to their package directory.
        (cd "$pdir" && "$bin" "${args[@]}" -test.bench="$re" </dev/null) >>"$dir/$side.txt"
      done <"$plan"
    done
  done
}

# gate compares dir/{base,head}.txt and runs benchgate with the given flags,
# keeping its output in dir/gate.txt; returns benchgate's exit status.
gate() {
  local dir=$1 rc=0
  shift
  # benchstat labels columns with the file names given; keep them short.
  (cd "$dir" && "${BENCHSTAT[@]}" base.txt head.txt) | tee "$dir/benchstat.txt"
  (cd "$dir" && "${BENCHSTAT[@]}" -format csv base.txt head.txt 2>/dev/null) >"$dir/benchstat.csv"
  "$work/bin/benchgate" -threshold "$THRESHOLD" "$@" <"$dir/benchstat.csv" >"$dir/gate.txt" || rc=$?
  cat "$dir/gate.txt"
  {
    echo
    echo '```'
    cat "$dir/benchstat.txt"
    echo
    cat "$dir/gate.txt"
    echo '```'
  } >>"$summary"
  return "$rc"
}

bench "$work/plan" "$OUT"
rc=0
gate "$OUT" -flagged "$OUT/flagged.txt" || rc=$?
if [[ $rc -ne 1 ]]; then
  exit "$rc"
fi

# Re-check: run the flagged benchmarks again and fail only if the same
# regression shows again. benchstat names a benchmark without its Benchmark
# prefix and with a -GOMAXPROCS suffix on the last element; the top-level
# name is a Go identifier, so it has no "-" of its own.
while IFS=$'\t' read -r pkg name _; do
  top=${name%%/*}
  echo "$pkg ${top%-*}"
done <"$OUT/flagged.txt" | sort -u |
  awk '{ if ($1 in re) re[$1] = re[$1] "|" $2; else re[$1] = $2 }
    END { for (p in re) print p, "^Benchmark(" re[p] ")$" }' >"$work/recheck.plan"
echo "== re-checking the flagged benchmarks:"
sed 's/^/   /' "$work/recheck.plan"
{
  echo
  echo "Re-checked, the gate fails only on a regression that shows on both runs:"
  sed 's/^/- /' "$work/recheck.plan"
} >>"$summary"
bench "$work/recheck.plan" "$OUT/recheck"
rc=0
gate "$OUT/recheck" -confirm "$OUT/flagged.txt" || rc=$?
exit "$rc"
