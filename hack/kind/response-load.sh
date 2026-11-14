#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The latency Inkwall adds, per proxy, response inspection off and on (#344,
# #600), on the kind cluster: each proxy of PROXIES (default all of
# hack/kind/stacks.sh's: Traefik, Envoy Gateway, Istio, HAProxy, raw Envoy,
# the standalone proxy) is set up in turn, with one nginx app serving a
# small (about 1 KB) and a larger (about 15 KB) HTML page, then removed.
# Each page is loaded for DURATION with CONCURRENCY clients (hack/loadgen,
# closed loop, after a 3 s warm-up, from this host to the proxy's NodePort
# on the kind node):
#
#   baseline   through the proxy on a route no policy protects (raw Envoy:
#              a virtual host with the filter off; standalone: the app's
#              own Service, no proxy at all)
#   requests   the protected route: a WAFPolicy in Block mode (the CRS at
#              its defaults), requests inspected
#   responses  the same with responses.inspect on (Traefik can't send
#              responses: not run)
#
# It prints p50/p90/p99 latency and requests per second per run, the
# engine's peak RSS (its process_resident_memory_bytes, read through the
# API server every second) and its response checks, and at the end a
# markdown table of the added latency (each run's p50 and p99 minus the
# baseline's, same proxy and page) with the machine it ran on. Every
# response must be a 200: inspection must not deny a clean page. Results
# are appended, as JSON lines, to OUT if set, and the table written to
# OUT_MD if set. Needs the operator installed (make kind-operator); it
# removes what it created (KEEP=1 leaves it).
set -euo pipefail

cd "$(dirname "$0")/../.."
# The versions under test (#393).
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${IMAGE:-inkwall-engine:dev}
CONCURRENCY=${CONCURRENCY:-8}
DURATION=${DURATION:-20s}
OUT=${OUT:-}
OUT_MD=${OUT_MD:-}
KUBECTL=(kubectl --context "kind-$CLUSTER")
HELM=(helm --kube-context "kind-$CLUSTER")

. hack/kind/lib.sh
. hack/kind/stacks.sh
read -r -a PROXIES <<<"${PROXIES:-${STACK_PROXIES[*]}}"

if ! "${KUBECTL[@]}" -n inkwall-system get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-operator first" >&2
  exit 1
fi

work=$(mktemp -d)
sampler=
cleanup() {
  [[ -z $sampler ]] || kill "$sampler" 2>/dev/null || true
  stacks_cleanup
  rm -rf "$work"
}
trap cleanup EXIT
results=$work/results.jsonl
: >"$results"

go build -o "$work/loadgen" ./hack/loadgen

# engine_pod PROXY: the running pod with the proxy's engine.
engine_pod() { stack_running_pods "$1" | head -1; }
# metric PROXY NAME: the sum of a metric's samples on the proxy's engine,
# whatever their labels, through the API server.
metric() {
  local ns pod
  ns=$(stack_ns "$1")
  pod=$(engine_pod "$1")
  "${KUBECTL[@]}" get --raw "/api/v1/namespaces/$ns/pods/$pod:9480/proxy/metrics" 2>/dev/null |
    awk -v m="$2" '{ name = $1; sub(/\{.*/, "", name) } name == m { s += $2; n++ } END { if (n) printf "%.6g\n", s }'
}

# run PROXY MODE PAGE: one load run, with the engine's RSS sampled each
# second.
run() {
  local p=$1 mode=$2 page=$3 url host samples=$work/rss result peak checks sum
  url=$(stack_url "$p")
  host=$(stack_host "$p")
  if [[ $mode == baseline ]]; then
    url=$(stack_url "$p" open)
    host=$(stack_open_host "$p")
  fi
  : >"$samples"
  (while :; do metric "$p" process_resident_memory_bytes >>"$samples" || true; sleep 1; done) &
  sampler=$!
  result=$("$work/loadgen" -url "$url/$page" -host "$host" -c "$CONCURRENCY" -d "$DURATION")
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true
  sampler=
  peak=$(sort -g "$samples" | tail -1)
  checks=$(metric "$p" inkwall_response_check_duration_seconds_count || true)
  sum=$(metric "$p" inkwall_response_check_duration_seconds_sum || true)
  printf '%-13s %-9s %-10s %s engineRssPeakMiB=%s responseChecks=%s\n' "$p" "$mode" "$page" "$result" \
    "$(awk -v b="${peak:-0}" 'BEGIN {printf "%.0f", b / 1048576}')" "${checks:-0}"
  jq -c --arg proxy "$p" --arg mode "$mode" --arg page "$page" --argjson rss "${peak:-0}" --arg checks "${checks:-0}" --arg sum "${sum:-0}" \
    '. + {proxy: $proxy, mode: $mode, page: $page, engineRssPeakBytes: $rss, responseChecks: ($checks | tonumber), responseCheckSeconds: ($sum | tonumber)}' \
    <<<"$result" >>"$results"
  if ! jq -e '.status | keys == ["200"]' <<<"$result" >/dev/null; then
    echo "FAIL  $p $mode $page: not every response was a 200" >&2
    exit 1
  fi
}

# responses_on PROXY: the policy inspects responses (raw Envoy: Envoy
# sends them too; standalone: --inspect-responses), and the proxy serves.
responses_on() {
  local p=$1
  case $p in
  standalone)
    STACK_STANDALONE_ARGS="--mode=block --inspect-responses" stacks_standalone
    ;;
  raw-envoy)
    stack_policy "$p" '  responses: {inspect: true}'
    stacks_raw_envoy responses
    ;;
  *) stack_policy "$p" '  responses: {inspect: true}' ;;
  esac
  stack_wait "$p"
  # A proxy takes a new configuration a moment after it is accepted.
  sleep 5
}

for p in "${PROXIES[@]}"; do
  STACK_STANDALONE_ARGS=--mode=block
  stacks_up "$p"
  EVENTUALLY_TRIES=360 eventually "$p: the baseline route serves the app" stack_serves "$p" open
  if ((failures > 0)); then
    echo "$failures check(s) failed setting up $p"
    exit 1
  fi
  echo "== $p: baseline, requests only"
  for page in small.html page.html; do
    run "$p" baseline "$page"
    run "$p" requests "$page"
  done
  if stack_responses "$p"; then
    echo "== $p: responses inspected"
    responses_on "$p"
    if ((failures > 0)); then
      echo "$failures check(s) failed turning response inspection on for $p"
      exit 1
    fi
    for page in small.html page.html; do run "$p" responses "$page"; done
    checks=$(metric "$p" inkwall_response_check_duration_seconds_count || true)
    if [[ ${checks:-0} == 0 ]]; then
      echo "FAIL  $p: the engine checked no response" >&2
      exit 1
    fi
    echo "ok    $p: the engine checked $checks responses"
  fi
  # One proxy at a time on the node: the next one's numbers are its own.
  stack_down "$p"
done

[[ -z $OUT ]] || cat "$results" >>"$OUT"
{
  echo "Latency Inkwall adds, per proxy: $CONCURRENCY concurrent clients, $DURATION per run (closed loop, after a 3 s warm-up),"
  echo "GET of an nginx HTML page, small.html (about 1 KB) or page.html (about 15 KB), uncompressed. One kind node"
  echo "(Kubernetes $("${KUBECTL[@]}" version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion')), one replica of each proxy, the client on the host:"
  echo "$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1), $(nproc) CPUs, $(free -g | awk '/^Mem:/ {print $2}') GiB."
  echo "Added: p50 and p99 minus the baseline's (the proxy without a policy; standalone: the app directly)."
  echo
  echo "| Proxy | Page | Baseline p50 / p99 | Requests inspected p50 / p99 | Added | Responses inspected too p50 / p99 | Added | Engine RSS peak |"
  echo "|---|---|---|---|---|---|---|---|"
  jq -rs '
    def f: . * 100 | round / 100;
    def added($b): "+\((.p50ms - $b.p50ms) | f) / +\((.p99ms - $b.p99ms) | f) ms";
    def order($p): ["traefik", "envoy-gateway", "istio", "haproxy", "raw-envoy", "standalone"] | index($p);
    group_by(.proxy + " " + .page) | sort_by([order(.[0].proxy), .[0].page != "small.html"]) | .[] |
    (map(select(.mode == "baseline"))[0]) as $b | (map(select(.mode == "requests"))[0]) as $q | (map(select(.mode == "responses"))[0]) as $r |
    "| \($b.proxy) | \($b.page) | \($b.p50ms) / \($b.p99ms) ms | \($q.p50ms) / \($q.p99ms) ms | \($q | added($b)) | " +
    (if $r then "\($r.p50ms) / \($r.p99ms) ms | \($r | added($b))" else "n/a (no responses) | " end) +
    " | \([$q.engineRssPeakBytes, ($r.engineRssPeakBytes // 0)] | max / 1048576 | round) MiB |"' "$results"
} >"$work/latency.md"
echo
cat "$work/latency.md"
[[ -z $OUT_MD ]] || cp "$work/latency.md" "$OUT_MD"
