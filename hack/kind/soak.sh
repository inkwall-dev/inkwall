#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The soak test of the announcement's battle test (#600, #520): every proxy
# Inkwall protects on one kind cluster (hack/kind/stacks.sh), each serving
# steady mixed traffic for DURATION: clean requests and attacks
# (hack/kind/soak/clean.http and attacks.http, from hack/loadgen's mix
# mode, SOAK_RATE requests per second per proxy, one in five an attack).
# Every SOAK_SAMPLE it samples:
#
#   - the restarts of every container of the operator, the proxies and the
#     apps: none outside chaos;
#   - the engines' and the operator's memory (RSS of their cgroups, from
#     crictl stats on the node, so it is read while the API server is down);
#   - each policy's status: whenever it claims its protection (Ready, or
#     Enforced for raw Envoy, for its current generation), a canary request
#     only that generation's rules deny must be denied through its proxy.
#
# The policies' canary changes every SOAK_CANARY_EVERY (a new WAFRuleSet
# that denies ?soak_canary=c<N>, swapped into each policy): a policy edit,
# which must reach every engine (claimed and the new canary denied) within
# SOAK_RECOVERY.
#
# With SOAK_CHAOS=1, every SOAK_CHAOS_EVERY one of these, in turn: the
# operator's leader killed; an engine killed (each proxy's in turn); a
# proxy's pod deleted (each in turn); the API server stopped for 20 s; the
# bundle distribution cut (a NetworkPolicy keeps the engines from the
# operator, which restarts so their streams end, and a policy edit is made
# while they can't get it) for SOAK_CUT_FOR. Each must recover within
# SOAK_RECOVERY: every policy claims its protection again, the app answers
# through every proxy, and attacks and the canary are denied. The status
# checks run throughout: status never claims protection that isn't there.
#
# At the end it writes OUT/summary.json and OUT/summary.md, and the raw
# samples (OUT/*.jsonl), and fails on any violation:
#
#   - an attack the app answered (got through), at any time;
#   - a clean request denied (403, a false denial), outside chaos (a chaos
#     window lasts from its start to SOAK_GRACE after its recovery);
#   - other failed answers (5xx, no answer) to more than SOAK_MAX_ERROR_RATE
#     of the requests outside chaos;
#   - a restart outside chaos;
#   - a status that claimed protection the canary showed wasn't there;
#   - a policy edit or a chaos scenario not recovered from in SOAK_RECOVERY;
#   - memory growth of an engine or the operator beyond the bound: the
#     median RSS of a container's last fifth of samples over that of its
#     samples after the first fifth (its warm-up) may grow by
#     SOAK_MEM_GROWTH percent of the latter, or SOAK_MEM_MIN_MIB, whichever
#     is larger. Steady traffic at a fixed rate keeps the engine's memory
#     flat (the compiled rule sets and buffers it reuses); the floor is above
#     the garbage collector's swings, and a leak of one KiB per request at
#     the default rate passes it within two hours. A container that chaos
#     replaced is a new series; one with fewer than 10 samples is reported,
#     not judged.
#
# Needs the operator installed (make kind-soak installs it first, with the
# bt-* proxy namespaces). PROXIES narrows the stacks; KEEP=1 leaves them.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=hack/versions.env
. hack/versions.env

CLUSTER=${KIND_CLUSTER:-inkwall}
IMAGE=${IMAGE:-inkwall-engine:dev}
DURATION=${DURATION:-1h}
SOAK_CHAOS=${SOAK_CHAOS:-}
SOAK_RATE=${SOAK_RATE:-5}
SOAK_SAMPLE=${SOAK_SAMPLE:-60s}
SOAK_CANARY_EVERY=${SOAK_CANARY_EVERY:-10m}
SOAK_CHAOS_EVERY=${SOAK_CHAOS_EVERY:-15m}
SOAK_CUT_FOR=${SOAK_CUT_FOR:-90s}
SOAK_RECOVERY=${SOAK_RECOVERY:-5m}
SOAK_GRACE=${SOAK_GRACE:-60s}
SOAK_MEM_GROWTH=${SOAK_MEM_GROWTH:-20}
SOAK_MEM_MIN_MIB=${SOAK_MEM_MIN_MIB:-32}
SOAK_MAX_ERROR_RATE=${SOAK_MAX_ERROR_RATE:-0.001}
OUT=${OUT:-bin/soak/$(date -u +%Y%m%dT%H%M%SZ)}
OPERATOR_NS=inkwall-system
NODE=$CLUSTER-control-plane
KUBECTL=(kubectl --context "kind-$CLUSTER" --request-timeout=20s)
HELM=(helm --kube-context "kind-$CLUSTER")
LEASE=inkwall-operator.waf.inkwall.dev

. hack/kind/lib.sh
. hack/kind/stacks.sh
read -r -a PROXIES <<<"${PROXIES:-${STACK_PROXIES[*]}}"

# secs DURATION: 90s, 15m, 24h, or seconds.
secs() {
  case $1 in
  *h) echo $((${1%h} * 3600)) ;;
  *m) echo $((${1%m} * 60)) ;;
  *s) echo "${1%s}" ;;
  *) echo "$1" ;;
  esac
}
duration=$(secs "$DURATION")
sample_every=$(secs "$SOAK_SAMPLE")
canary_every=$(secs "$SOAK_CANARY_EVERY")
chaos_every=$(secs "$SOAK_CHAOS_EVERY")
cut_for=$(secs "$SOAK_CUT_FOR")
recovery=$(secs "$SOAK_RECOVERY")
grace=$(secs "$SOAK_GRACE")

if ! "${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment/inkwall-operator >/dev/null 2>&1; then
  echo "the operator is not installed: run make kind-soak, which installs it" >&2
  exit 1
fi
mkdir -p "$OUT"
OUT=$(realpath "$OUT")
work=$(mktemp -d)
loadgens=()
apiserver_moved=false
cut_applied=false
cleanup() {
  local pid
  for pid in ${loadgens[@]+"${loadgens[@]}"}; do kill "$pid" 2>/dev/null || true; done
  if $apiserver_moved; then
    docker exec "$NODE" mv /etc/kubernetes/kube-apiserver.yaml.soak /etc/kubernetes/manifests/kube-apiserver.yaml || true
  fi
  if $cut_applied; then "${KUBECTL[@]}" -n "$OPERATOR_NS" delete networkpolicy bt-soak-cut --ignore-not-found >/dev/null 2>&1 || true; fi
  stacks_cleanup
  rm -rf "$work"
}
trap cleanup EXIT

: >"$OUT/violations.jsonl"
: >"$OUT/chaos.jsonl"
: >"$OUT/samples.jsonl"
: >"$OUT/memory.jsonl"
: >"$OUT/canary.jsonl"
# violation KIND MESSAGE: recorded, and printed.
violation() {
  jq -nc --argjson t "$(date +%s)" --arg kind "$1" --arg msg "$2" '{time: $t, kind: $kind, message: $msg}' >>"$OUT/violations.jsonl"
  echo "FAIL  $1: $2"
}

echo "== the request mixes, checked offline against the soak's policy"
go build -o "$work/inkwallctl" ./cmd/inkwallctl
go build -o "$work/loadgen" ./hack/loadgen
# canary_rule_set N NAMESPACE: the WAFRuleSet that denies ?soak_canary=cN.
canary_rule_set() {
  cat <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFRuleSet
metadata: {name: bt-canary-$1, namespace: $2}
spec:
  source:
    seclang: |
      SecRule ARGS:soak_canary "@streq c$1" "id:9600001,phase:1,deny,status:403,log,msg:'soak canary c$1'"
YAML
}
canary_spec() {
  cat <<YAML
  ruleSets:
    - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
    - ref: {kind: WAFRuleSet, name: bt-canary-$1}
YAML
}
{
  printf 'apiVersion: waf.inkwall.dev/v1alpha1\nkind: WAFPolicy\nmetadata: {name: app, namespace: bt}\n'
  printf 'spec:\n  targetRefs: [{kind: Ingress, name: app}]\n  mode: Block\n'
  canary_spec 1
  echo ---
  canary_rule_set 1 bt
} >"$work/policy.yaml"
iwc() { "$work/inkwallctl" test --policy "$work/policy.yaml" --rule-set operator/config/samples/clusterwafruleset.yaml "$@" >"$work/iwc.out" 2>&1 || {
  cat "$work/iwc.out" >&2
  return 1
}; }
iwc --expect allow --request hack/kind/soak/clean.http
iwc --expect deny --request hack/kind/soak/attacks.http
iwc --expect deny 'http://shop.example.com/?soak_canary=c1'
iwc --expect allow 'http://shop.example.com/?soak_canary=c2'
ok "clean requests allowed, attacks and the canary denied"

operator_proxies=()
for p in "${PROXIES[@]}"; do
  if stack_has_operator "$p"; then operator_proxies+=("$p"); fi
done
canary=1
# Each stack gets the first canary before its policy names it.
stack_pre_policy() {
  if stack_has_operator "$1"; then canary_rule_set "$canary" "$(stack_ns "$1")" | "${KUBECTL[@]}" apply -f - >/dev/null; fi
}
STACK_POLICY_SPEC=$(canary_spec "$canary")
stacks_up "${PROXIES[@]}"
if ((failures > 0)); then
  echo "$failures check(s) failed setting up the stacks"
  exit 1
fi

# canary_denied PROXY N: the proxy doesn't let the app answer canary N.
canary_denied() { [[ $(stack_code "$1" "/?soak_canary=c$2") != *" app" ]]; }
# check_claims: for every policy that claims its protection, the canary of
# the canary it names is denied through its proxy. Logged in
# OUT/canary.jsonl.
check_claims() {
  local p ns s n claimed code
  for p in ${operator_proxies[@]+"${operator_proxies[@]}"}; do
    ns=$(stack_ns "$p")
    s=$("${KUBECTL[@]}" -n "$ns" get wafpolicy app -o json 2>/dev/null) || continue
    n=$(jq -r '[.spec.ruleSets[]?.ref.name | select(startswith("bt-canary-"))][0] // "" | ltrimstr("bt-canary-")' <<<"$s")
    claimed=$(jq --arg c "$(stack_claims "$p")" '.metadata.generation as $g |
      any(.status.conditions[]?; .type == $c and .status == "True" and .observedGeneration == $g)' <<<"$s")
    [[ $claimed == true && -n $n ]] || continue
    code=$(stack_code "$p" "/?soak_canary=c$n")
    jq -nc --argjson t "$(date +%s)" --arg p "$p" --arg n "$n" --arg code "$code" '{time: $t, proxy: $p, canary: $n, answer: $code}' >>"$OUT/canary.jsonl"
    if [[ $code == *" app" ]]; then
      violation status "$p: the policy claims $(stack_claims "$p") for its generation, but canary c$n got through ($code)"
    fi
  done
}

# Restarts: the containers' restart counts at the last sample, and the
# namespaces watched.
declare -A restarts=()
watched=("$OPERATOR_NS")
for p in "${PROXIES[@]}"; do watched+=("$(stack_ns "$p")"); done
if [[ " ${PROXIES[*]} " == *" istio "* ]]; then watched+=(istio-system); fi
# sample_restarts [expected]: compares restart counts with the last sample;
# a new restart is a violation unless chaos is on (or "expected" is given).
chaos_on=false
chaos_until=0
sample_restarts() {
  local ns line key n prev
  for ns in "${watched[@]}"; do
    "${KUBECTL[@]}" -n "$ns" get pods -o json 2>/dev/null |
      jq -r '.items[] | .metadata.namespace as $ns | .metadata.name as $pod |
        ((.status.initContainerStatuses // []) + (.status.containerStatuses // []))[] | "\($ns)/\($pod)/\(.name) \(.restartCount)"' ||
      return 0
  done >"$work/restarts"
  while read -r key n; do
    prev=${restarts[$key]:-0}
    if ((n > prev)); then
      jq -nc --argjson t "$(date +%s)" --arg c "$key" --argjson d $((n - prev)) --argjson chaos "$({ $chaos_on || (($(date +%s) < chaos_until)) || [[ ${1:-} == expected ]]; } && echo true || echo false)" \
        '{time: $t, restart: $c, count: $d, duringChaos: $chaos}' >>"$OUT/samples.jsonl"
      if ! $chaos_on && (($(date +%s) >= chaos_until)) && [[ ${1:-} != expected ]]; then
        violation restart "$key restarted $((n - prev)) time(s)"
      fi
    fi
    restarts[$key]=$n
  done <"$work/restarts"
}
# sample_memory: the RSS of the engines and the operator.
sample_memory() {
  local t
  t=$(date +%s)
  docker exec "$NODE" crictl stats -o json 2>/dev/null | jq -c --argjson t "$t" --arg nss " ${watched[*]} " '
    .stats[] | .attributes as $a | ($a.labels["io.kubernetes.pod.namespace"]) as $ns |
    select(($nss | contains(" " + $ns + " ")) and ($a.metadata.name == "inkwall-engine" or $a.metadata.name == "operator")) |
    {time: $t, container: "\($ns)/\($a.labels["io.kubernetes.pod.name"])/\($a.metadata.name)", id: $a.id[:12],
     rssBytes: (.memory.rssBytes.value // "0" | tonumber)}' >>"$OUT/memory.jsonl" || true
}
next_sample=0
start=$(date +%s)
# tick: a sample when one is due; called by every wait.
tick() {
  local now
  now=$(date +%s)
  ((now >= next_sample)) || return 0
  next_sample=$((now + sample_every))
  sample_restarts
  sample_memory
  check_claims
  progress
}
progress() {
  local p line
  line="[$(date -u +%H:%M:%S) +$((($(date +%s) - start) / 60))m]"
  for p in "${PROXIES[@]}"; do
    line+=" $p:$(jq -s '[.[] | .clean.app] | add // 0' "$OUT/traffic-$p.jsonl" 2>/dev/null || echo 0)ok"
    line+="/$(jq -s '[.[] | .attack.app] | add // 0' "$OUT/traffic-$p.jsonl" 2>/dev/null || echo 0)through"
  done
  echo "$line"
}

# all_recovered: what recovery means: the operator's replicas ready, every
# policy claims its protection for its current canary, which is denied, and
# the app answers through every proxy, which denies an attack.
all_recovered() {
  local p
  local replicas
  replicas=$("${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment inkwall-operator -o jsonpath='{.status.readyReplicas}/{.spec.replicas}' 2>/dev/null) || return 1
  [[ -n ${replicas%%/*} && ${replicas%%/*} == "${replicas#*/}" ]] || return 1
  for p in "${PROXIES[@]}"; do
    if stack_has_operator "$p"; then
      stack_claimed "$p" && canary_denied "$p" "$canary" || return 1
    fi
    stack_serves "$p" && stack_blocks "$p" || return 1
  done
}
# recover WHAT: waits up to SOAK_RECOVERY for all_recovered, sampling;
# prints and returns the seconds it took, or fails.
recover() {
  local from deadline
  from=$(date +%s)
  deadline=$((from + recovery))
  while (($(date +%s) < deadline)); do
    if all_recovered 2>/dev/null; then
      recovered_in=$(($(date +%s) - from))
      return 0
    fi
    check_claims
    tick
    sleep 2
  done
  recovered_in=-1
  violation recovery "$1: not recovered in $SOAK_RECOVERY"
  return 1
}

# rotate_canary: the next canary in every policy, the one before the last
# deleted.
rotate_canary() {
  local p ns
  canary=$((canary + 1))
  for p in ${operator_proxies[@]+"${operator_proxies[@]}"}; do
    ns=$(stack_ns "$p")
    for _ in $(seq 30); do
      canary_rule_set "$canary" "$ns" | "${KUBECTL[@]}" apply -f - >/dev/null 2>&1 && break
      sleep 2
    done
    stack_policy "$p" "$(canary_spec "$canary")" || true
    "${KUBECTL[@]}" -n "$ns" delete wafruleset "bt-canary-$((canary - 2))" --ignore-not-found >/dev/null 2>&1 || true
  done
}

# Chaos: the scenarios, each run in turn.
scenarios=(operator engine proxy apiserver distribution)
scenario_i=0
# The proxies whose engine, and whose pod, go next.
engine_i=0
proxy_i=0
chaos_begin() {
  chaos_on=true
  chaos_start=$(date +%s)
  echo "== chaos: $1"
}
chaos_end() {
  local name=$1 detail=$2 ok=$3
  # The restarts the scenario caused are its own.
  sample_restarts expected
  chaos_on=false
  chaos_until=$(($(date +%s) + grace))
  jq -nc --arg s "$name" --arg d "$detail" --argjson start "$chaos_start" --argjson end "$(date +%s)" \
    --argjson rec "$recovered_in" --argjson ok "$ok" --argjson grace "$grace" \
    '{scenario: $s, detail: $d, start: $start, end: $end, graceUntil: ($end + $grace), recoverySeconds: $rec, recovered: $ok}' >>"$OUT/chaos.jsonl"
  if [[ $ok == true ]]; then ok "$name ($detail): recovered in ${recovered_in}s"; fi
}
# engine_pid PROXY: the node and PID of the engine of one of its pods.
engine_pid() {
  local pod cid
  pod=$(stack_running_pods "$1" | head -1)
  cid=$("${KUBECTL[@]}" -n "$(stack_ns "$1")" get pod "$pod" -o json |
    jq -r '[(.status.initContainerStatuses // [])[], (.status.containerStatuses // [])[]] | map(select(.name == "inkwall-engine"))[0].containerID')
  docker exec "$NODE" crictl inspect --output go-template --template '{{.info.pid}}' "${cid#*://}"
}
leader() {
  local holder
  holder=$("${KUBECTL[@]}" -n "$OPERATOR_NS" get lease "$LEASE" -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)
  echo "${holder%%_*}"
}
api_up() { "${KUBECTL[@]}" get --raw /readyz >/dev/null 2>&1; }
run_chaos() {
  local s=${scenarios[$((scenario_i % ${#scenarios[@]}))]} victim detail ok=true
  scenario_i=$((scenario_i + 1))
  recovered_in=-1
  case $s in
  operator)
    detail="leader $(leader) killed"
    chaos_begin "$s: $detail"
    "${KUBECTL[@]}" -n "$OPERATOR_NS" delete pod "$(leader)" --grace-period=0 --force >/dev/null 2>&1 || true
    ;;
  engine)
    victim=${PROXIES[$((engine_i % ${#PROXIES[@]}))]}
    engine_i=$((engine_i + 1))
    detail="$victim's engine killed (SIGKILL)"
    chaos_begin "$s: $detail"
    docker exec "$NODE" kill -KILL "$(engine_pid "$victim")" || true
    ;;
  proxy)
    victim=${PROXIES[$((proxy_i % ${#PROXIES[@]}))]}
    proxy_i=$((proxy_i + 1))
    detail="$victim's pod deleted"
    chaos_begin "$s: $detail"
    "${KUBECTL[@]}" -n "$(stack_ns "$victim")" delete pod "$(stack_running_pods "$victim" | head -1)" --wait=false >/dev/null
    ;;
  apiserver)
    detail="stopped for 20 s"
    chaos_begin "$s: $detail"
    docker exec "$NODE" mv /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/kube-apiserver.yaml.soak
    apiserver_moved=true
    for _ in $(seq 120); do api_up || break; sleep 0.5; done
    for _ in $(seq 10); do tick; sleep 2; done
    docker exec "$NODE" mv /etc/kubernetes/kube-apiserver.yaml.soak /etc/kubernetes/manifests/kube-apiserver.yaml
    apiserver_moved=false
    for _ in $(seq 360); do api_up && break; sleep 0.5; done
    ;;
  distribution)
    detail="engines cut from the operator for $SOAK_CUT_FOR, a policy edit made meanwhile"
    chaos_begin "$s: $detail"
    cut_applied=true
    "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: bt-soak-cut, namespace: $OPERATOR_NS}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/component: operator}}
  policyTypes: [Ingress]
  # Everything but the distribution server: the metrics, the probes, the
  # webhook.
  ingress: [{ports: [{port: 8080}, {port: 8081}, {port: 9443}]}]
YAML
    # The engines' streams end with the replicas; new ones are refused.
    "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout restart deployment/inkwall-operator >/dev/null
    "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=300s >/dev/null || true
    rotate_canary
    local until=$(($(date +%s) + cut_for)) behind=0 p
    while (($(date +%s) < until)); do
      check_claims
      tick
      sleep 5
    done
    for p in ${operator_proxies[@]+"${operator_proxies[@]}"}; do stack_claimed "$p" || behind=$((behind + 1)); done
    detail+="; $behind of ${#operator_proxies[@]} policies not claimed at the end of the cut"
    "${KUBECTL[@]}" -n "$OPERATOR_NS" delete networkpolicy bt-soak-cut --ignore-not-found >/dev/null
    cut_applied=false
    ;;
  esac
  recover "chaos $s ($detail)" || ok=false
  chaos_end "$s" "$detail" "$ok"
}

echo "== traffic: $SOAK_RATE requests per second per proxy for $DURATION"
for p in "${PROXIES[@]}"; do
  "$work/loadgen" -url "$(stack_url "$p")" -host "$(stack_host "$p")" -clean hack/kind/soak/clean.http \
    -attacks hack/kind/soak/attacks.http -app-header "$STACK_APP_HEADER" -rate "$SOAK_RATE" -c 16 -d 0 \
    -report 10s >"$OUT/traffic-$p.jsonl" 2>"$OUT/loadgen-$p.log" &
  loadgens+=($!)
done
start=$(date +%s)
end=$((start + duration))
next_canary=$((start + canary_every))
next_chaos=$((start + chaos_every))
sample_restarts expected
while (($(date +%s) < end)); do
  tick
  now=$(date +%s)
  if [[ $SOAK_CHAOS == 1 ]] && ((now >= next_chaos && now + recovery < end)); then
    run_chaos
    next_chaos=$(($(date +%s) + chaos_every))
  elif ((now >= next_canary && now + recovery < end)) && ((${#operator_proxies[@]} > 0)); then
    echo "== canary c$((canary + 1))"
    rotate_canary
    recover "canary c$canary" && ok "canary c$canary: enforced and claimed in ${recovered_in}s" || true
    next_canary=$(($(date +%s) + canary_every))
  fi
  sleep 1
done
for pid in "${loadgens[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
for pid in "${loadgens[@]}"; do wait "$pid" 2>/dev/null || true; done
loadgens=()
next_sample=0
tick

echo "== summary"
# Traffic: each window inside a chaos window (start to graceUntil) is
# chaos's; the rest is judged.
for p in "${PROXIES[@]}"; do
  jq -s --arg p "$p" --slurpfile chaos "$OUT/chaos.jsonl" '
    def inchaos($w): any($chaos[]; $w.time - $w.seconds < .graceUntil and $w.time > .start);
    def sum(f): map(f) | add // 0;
    def others(f): [.[] | f.other // {} | to_entries[] | .value] | add // 0;
    (map(select(inchaos(.) | not))) as $calm |
    {proxy: $p,
     clean: {sent: sum(.clean.sent), app: sum(.clean.app), denied: sum(.clean.denied), other: others(.clean)},
     attack: {sent: sum(.attack.sent), app: sum(.attack.app), denied: sum(.attack.denied), other: others(.attack)},
     attacksThrough: sum(.attack.app),
     attacksThroughExamples: ([.[].attack.examples[]?] | unique | .[:10]),
     falseDenials: ($calm | sum(.clean.denied)),
     falseDenialExamples: ([$calm[].clean.examples[]?] | unique | .[:10]),
     errorsOutsideChaos: (($calm | others(.clean)) + ($calm | others(.attack))),
     sentOutsideChaos: ($calm | sum(.clean.sent) + sum(.attack.sent)),
     deniedDuringChaos: (map(select(inchaos(.))) | sum(.clean.denied)),
     skipped: sum(.skipped),
     p50ms: (map(.p50ms) | sort | .[length / 2 | floor] // 0),
     p99ms: (map(.p99ms) | max // 0)}' "$OUT/traffic-$p.jsonl"
done | jq -s . >"$work/traffic.json"
jq -c '.[]' "$work/traffic.json" | while read -r t; do
  p=$(jq -r .proxy <<<"$t")
  (($(jq .attacksThrough <<<"$t") == 0)) || violation attack-through "$p: $(jq .attacksThrough <<<"$t") attack(s) got through: $(jq -c .attacksThroughExamples <<<"$t")"
  (($(jq .falseDenials <<<"$t") == 0)) || violation false-denial "$p: $(jq .falseDenials <<<"$t") clean request(s) denied outside chaos: $(jq -c .falseDenialExamples <<<"$t")"
  (($(jq '.clean.app' <<<"$t") > 0)) || violation traffic "$p: the app answered no clean request"
  jq -e --argjson max "$SOAK_MAX_ERROR_RATE" '.sentOutsideChaos == 0 or .errorsOutsideChaos / .sentOutsideChaos <= $max' <<<"$t" >/dev/null ||
    violation errors "$p: $(jq .errorsOutsideChaos <<<"$t") of $(jq .sentOutsideChaos <<<"$t") requests outside chaos failed (over $SOAK_MAX_ERROR_RATE)"
done

# Memory: per container (a new container is a new series).
jq -s --argjson pct "$SOAK_MEM_GROWTH" --argjson min "$SOAK_MEM_MIN_MIB" '
  def median: sort | .[length / 2 | floor];
  def mib: . / 1048576 | . * 10 | round / 10;
  group_by(.container + "@" + .id) | map(sort_by(.time) | . as $s | ($s | length) as $n | ($n / 5 | floor) as $f |
    {container: $s[0].container, id: $s[0].id, samples: $n, from: $s[0].time, to: $s[-1].time} +
    if $n < 10 then {judged: false}
    else ($s[$f:2 * $f] | map(.rssBytes) | median) as $base | ($s[$n - $f:] | map(.rssBytes) | median) as $last |
      ([$min * 1048576, $base * $pct / 100] | max) as $bound |
      {judged: true, baselineMiB: ($base | mib), finalMiB: ($last | mib), peakMiB: ($s | map(.rssBytes) | max | mib),
       growthMiB: (($last - $base) | mib), boundMiB: ($bound | mib), ok: (($last - $base) <= $bound)}
    end)' "$OUT/memory.jsonl" >"$work/memory.json"
jq -c '.[] | select(.judged and (.ok | not))' "$work/memory.json" | while read -r m; do
  violation memory "$(jq -r '"\(.container): \(.baselineMiB) MiB to \(.finalMiB) MiB (+\(.growthMiB), bound \(.boundMiB))"' <<<"$m")"
done

jq -n --arg duration "$DURATION" --arg chaos "${SOAK_CHAOS:-0}" --argjson rate "$SOAK_RATE" --arg started "$(date -u -d "@$start" +%FT%TZ)" \
  --slurpfile traffic "$work/traffic.json" --slurpfile memory "$work/memory.json" \
  --slurpfile chaosRuns <(jq -s . "$OUT/chaos.jsonl") --slurpfile violations <(jq -s . "$OUT/violations.jsonl") \
  --slurpfile restarts <(jq -s . "$OUT/samples.jsonl") --slurpfile canary <(jq -s . "$OUT/canary.jsonl") \
  --argjson canaries "$canary" --arg proxies "${PROXIES[*]}" '
  {started: $started, duration: $duration, chaos: ($chaos == "1"), ratePerProxy: $rate, proxies: ($proxies | split(" ")),
   traffic: $traffic[0], memory: $memory[0], chaosRuns: $chaosRuns[0], restarts: $restarts[0],
   canary: {rotations: ($canaries - 1), statusChecks: ($canary[0] | length)},
   violations: $violations[0], pass: ($violations[0] | length == 0)}' >"$OUT/summary.json"

{
  echo "# Soak: $DURATION$([[ $SOAK_CHAOS == 1 ]] && echo ", with chaos"), $(jq -r '.started' "$OUT/summary.json")"
  echo
  echo "**$(jq -r 'if .pass then "Passed" else "Failed: \(.violations | length) violation(s)" end' "$OUT/summary.json")**."
  echo "$SOAK_RATE requests per second per proxy, one in five an attack; $(jq -r '.canary.rotations' "$OUT/summary.json") policy edits (canaries), $(jq -r '.canary.statusChecks' "$OUT/summary.json") status checks."
  echo
  echo "| Proxy | Clean (app answered) | Attacks (denied) | Attacks through | False denials | Failed outside chaos | p50 / p99 |"
  echo "|---|---|---|---|---|---|---|"
  jq -r '.traffic[] | "| \(.proxy) | \(.clean.sent) (\(.clean.app)) | \(.attack.sent) (\(.attack.denied)) | \(.attacksThrough) | \(.falseDenials) | \(.errorsOutsideChaos) of \(.sentOutsideChaos) | \(.p50ms) / \(.p99ms) ms |"' "$OUT/summary.json"
  echo
  echo "| Container | Samples | RSS after warm-up | At the end | Peak | Growth (bound) |"
  echo "|---|---|---|---|---|---|"
  jq -r '.memory[] | if .judged then "| \(.container) | \(.samples) | \(.baselineMiB) MiB | \(.finalMiB) MiB | \(.peakMiB) MiB | \(.growthMiB) MiB (\(.boundMiB))\(if .ok then "" else " **over**" end) |"
    else "| \(.container) | \(.samples) | | | | too few samples |" end' "$OUT/summary.json"
  if [[ $(jq '.chaosRuns | length' "$OUT/summary.json") -gt 0 ]]; then
    echo
    echo "| Chaos | Recovered in |"
    echo "|---|---|"
    jq -r '.chaosRuns[] | "| \(.scenario): \(.detail) | \(if .recovered then "\(.recoverySeconds) s" else "**not recovered**" end) |"' "$OUT/summary.json"
  fi
  if [[ $(jq '.violations | length' "$OUT/summary.json") -gt 0 ]]; then
    echo
    echo "Violations:"
    echo
    jq -r '.violations[] | "- \(.kind): \(.message)"' "$OUT/summary.json"
  fi
} >"$OUT/summary.md"
cat "$OUT/summary.md"
echo
echo "results in $OUT"
if [[ $(jq .pass "$OUT/summary.json") != true ]]; then exit 1; fi
