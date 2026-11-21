# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2154 # start, duration, recovery: the sourcing script's

# Export to a SIEM under the soak (design 0010 §9), sourced by
# hack/kind/soak.sh with SOAK_EXPORT=1 (the default): every engine's events
# go to an HTTP sink (operator/test/eventsink) that fails half the requests
# at first, then is down (503) for SOAK_EXPORT_DOWN_FOR from a third of the
# run, then answers. The replicas' export buffer is small
# (SOAK_EXPORT_BUFFER_MIB in memory, SOAK_EXPORT_DISK_MIB on disk), so the
# outage fills it: at the soak's rate (5 requests a second per proxy, one in
# five an attack) the events come at a few KiB a second, which would take
# hours to fill the default 32 MiB; set SOAK_EXPORT_BUFFER_MIB=32 and
# SOAK_EXPORT_DISK_MIB=512 with a higher SOAK_RATE and a longer
# SOAK_EXPORT_DOWN_FOR to fill the defaults. Judged at the end:
#
#   - no operator container was OOMKilled (the peak RSS is reported), its
#     buffer full;
#   - the full buffer's drops are counted
#     (inkwall_operator_events_export_dropped_total{reason="buffer_full"});
#   - the engines drop nothing (inkwall_operator_engine_events_dropped_total,
#     what they report, its growth outside chaos): a down sink never slows
#     them;
#   - requests' p99 doesn't move while the sink is down: the median p99 of
#     the traffic windows of the outage within +20% or +5 ms of the rest;
#   - once the sink is back, the backlog drains within SOAK_RECOVERY (fewer
#     events pending than one request holds) and the sink got events.
#
# The release's export values are put back at the end.
#
# Uses soak.sh's KUBECTL, HELM, OPERATOR_NS, OUT, work, start, duration,
# recovery, secs, ok and violation.

SOAK_EXPORT_DOWN_FOR=${SOAK_EXPORT_DOWN_FOR:-10m}
SOAK_EXPORT_BUFFER_MIB=${SOAK_EXPORT_BUFFER_MIB:-1}
SOAK_EXPORT_DISK_MIB=${SOAK_EXPORT_DISK_MIB:-2}
EXPORT_NS=inkwall-soak-sink
export_phase=flaky

sink_admin() { "${KUBECTL[@]}" get --raw "/api/v1/namespaces/$EXPORT_NS/services/eventsink:admin/proxy/$1"; }
sink_mode() { "${KUBECTL[@]}" create --raw "/api/v1/namespaces/$EXPORT_NS/services/eventsink:admin/proxy/mode?$1" -f /dev/null >/dev/null; }

# op_metric NAME [SELECTOR]: the sum of an operator metric over its ready
# replicas (their /metrics, through the API server's pod proxy); empty
# when none answers.
op_metric() {
  local pods p sum="" v
  pods=$("${KUBECTL[@]}" -n "$OPERATOR_NS" get pods -l app.kubernetes.io/component=operator -o jsonpath='{.items[*].metadata.name}' 2>/dev/null) || return 0
  for p in $pods; do
    v=$("${KUBECTL[@]}" get --raw "/api/v1/namespaces/$OPERATOR_NS/pods/$p:8080/proxy/metrics" 2>/dev/null |
      awk -v n="$1" -v sel="${2:-}" '$1 ~ "^"n"({|$)" && index($1, sel) { s += $2; found = 1 } END { if (found) printf "%.0f", s }') || continue
    [[ -n $v ]] && sum=$((${sum:-0} + v))
  done
  echo "$sum"
}

export_setup() {
  export_down_for=$(secs "$SOAK_EXPORT_DOWN_FOR")
  echo "== export: an HTTP sink that fails half the requests, then is down for $SOAK_EXPORT_DOWN_FOR"
  docker build -q -f hack/kind/eventsink.Dockerfile -t inkwall-eventsink:dev . >/dev/null
  kind load docker-image inkwall-eventsink:dev --name "$CLUSTER" >/dev/null
  "${KUBECTL[@]}" create namespace "$EXPORT_NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
  "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: eventsink, namespace: $EXPORT_NS}
spec:
  selector: {matchLabels: {app: eventsink}}
  template:
    metadata: {labels: {app: eventsink}}
    spec:
      containers:
        - name: sink
          image: inkwall-eventsink:dev
          imagePullPolicy: Never
          args: ["--dns-name=eventsink.$EXPORT_NS.svc", "--keep=50"]
          ports: [{containerPort: 8080}, {containerPort: 8081}]
---
apiVersion: v1
kind: Service
metadata: {name: eventsink, namespace: $EXPORT_NS}
spec:
  selector: {app: eventsink}
  ports: [{name: http, port: 8080}, {name: admin, port: 8081}]
YAML
  "${KUBECTL[@]}" -n "$EXPORT_NS" rollout status deployment/eventsink --timeout=120s >/dev/null
  export_prev=$("${HELM[@]}" get values inkwall --namespace "$OPERATOR_NS" -a -o json | jq -c '.events.export // {}')
  # A small buffer, so the outage fills it; the operator restarts with it,
  # before the traffic starts.
  "${HELM[@]}" upgrade inkwall "$CHART" --namespace "$OPERATOR_NS" --reuse-values \
    --set "events.export.bufferMiB=$SOAK_EXPORT_BUFFER_MIB" --set "events.export.diskMiB=$SOAK_EXPORT_DISK_MIB" >/dev/null
  "${KUBECTL[@]}" -n "$OPERATOR_NS" rollout status deployment/inkwall-operator --timeout=300s >/dev/null
  "${KUBECTL[@]}" get inkwallconfig default >/dev/null 2>&1 ||
    printf 'apiVersion: waf.inkwall.dev/v1alpha1\nkind: InkwallConfig\nmetadata: {name: default}\nspec: {}\n' | "${KUBECTL[@]}" apply -f - >/dev/null
  "${KUBECTL[@]}" patch inkwallconfig default --type=merge -p "{\"spec\":{\"events\":{\"export\":{\"sinks\":[
    {\"name\":\"soak\",\"json\":{\"url\":\"http://eventsink.$EXPORT_NS.svc:8080/soak\"},\"insecure\":true,\"batch\":{\"maxDelay\":\"1s\"}}]}}}}" >/dev/null
  sink_mode "fail=0.5"
  export_limit=$("${KUBECTL[@]}" -n "$OPERATOR_NS" get deployment inkwall-operator -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}')
  : >"$OUT/export.jsonl"
}

# export_tick: the sink's phase by the clock, and a sample of the export's
# metrics. Called by soak.sh's tick.
export_tick() {
  local now t0 down_at up_at
  now=$(date +%s)
  down_at=$((start + duration / 3))
  up_at=$((down_at + export_down_for))
  if [[ $export_phase == flaky ]] && ((now >= down_at)); then
    sink_mode "status=503" && export_phase=down && export_down_at=$now && echo "== export: the sink is down for $SOAK_EXPORT_DOWN_FOR"
  elif [[ $export_phase == down ]] && ((now >= up_at)); then
    sink_mode "status=200" && export_phase=up && export_up_at=$now && echo "== export: the sink is back"
  fi
  t0=$(jq -nc --argjson t "$now" --arg phase "$export_phase" \
    --arg pending "$(op_metric inkwall_operator_events_export_pending)" \
    --arg full "$(op_metric inkwall_operator_events_export_dropped_total 'reason="buffer_full"')" \
    --arg engines "$(op_metric inkwall_operator_engine_events_dropped_total)" \
    --arg exported "$(op_metric inkwall_operator_events_exported_total)" \
    '{time: $t, phase: $phase, pending: $pending, bufferFull: $full, engineDropped: $engines, exported: $exported}')
  echo "$t0" >>"$OUT/export.jsonl"
  # Drained: less pending than one request (maxEvents, 500) holds, as new
  # events keep coming.
  if [[ $export_phase == up && -z ${export_drained:-} ]] && [[ -n $(jq -r .pending <<<"$t0") ]] && (($(jq -r .pending <<<"$t0") < 500)); then
    export_drained=$((now - export_up_at))
  fi
}

# export_summary: the judgement, at the end.
export_summary() {
  local last peak sink
  last=$(tail -n 1 "$OUT/export.jsonl" 2>/dev/null)
  if [[ -z $last || $(jq -r .exported <<<"$last") == "" ]]; then
    violation export "no export metric sampled: the sampling broke"
    return
  fi
  if [[ $export_phase != up ]]; then
    violation export "the sink never came back within the run (phase $export_phase): run longer than 3 x SOAK_EXPORT_DOWN_FOR"
    return
  fi
  if (($(jq -r .bufferFull <<<"$last") > 0)); then
    ok "export: the full buffer's drops are counted ($(jq -r .bufferFull <<<"$last") events)"
  else
    violation export "the sink was down $SOAK_EXPORT_DOWN_FOR, but no event was dropped for a full buffer: none counted"
  fi
  # The engines' drops: what grew between samples, outside chaos windows
  # (a killed operator or a cut distribution makes engines drop).
  local engine_drops
  engine_drops=$(jq -s --slurpfile chaos "$OUT/chaos.jsonl" '
    def inchaos($a; $b): any($chaos[]; $a < .graceUntil and $b > .start);
    [range(1; length) as $i | .[$i - 1] as $p | .[$i] as $s |
      select(($p.engineDropped | length) > 0 and ($s.engineDropped | length) > 0 and (inchaos($p.time; $s.time) | not)) |
      (($s.engineDropped | tonumber) - ($p.engineDropped | tonumber)) | select(. > 0)] | add // 0' "$OUT/export.jsonl")
  if [[ $engine_drops == 0 ]]; then
    ok "export: the engines dropped no event outside chaos"
  else
    violation export "the engines dropped $engine_drops events outside chaos with the sink failing or down"
  fi
  # Requests' p99 while the sink is down, against the rest (chaos apart).
  local p99
  p99=$(jq -s --argjson a "${export_down_at:-0}" --argjson b "${export_up_at:-0}" --slurpfile chaos "$OUT/chaos.jsonl" '
    def inchaos($w): any($chaos[]; $w.time - $w.seconds < .graceUntil and $w.time > .start);
    def median: sort | if length == 0 then null else .[length / 2 | floor] end;
    map(select((.p99ms // 0) > 0 and (inchaos(.) | not))) |
    {down: (map(select(.time > $a and .time - .seconds < $b)) | map(.p99ms) | median),
     rest: (map(select(.time <= $a or .time - .seconds >= $b)) | map(.p99ms) | median)}' "$OUT"/traffic-*.jsonl)
  if jq -e '.down != null and .rest != null and .down <= ([.rest * 1.2, .rest + 5] | max)' <<<"$p99" >/dev/null; then
    ok "export: requests' p99 while the sink was down $(jq -r .down <<<"$p99") ms, otherwise $(jq -r .rest <<<"$p99") ms"
  else
    violation export "requests' p99 moved while the sink was down: $(jq -c . <<<"$p99") (ms; bound +20% or +5 ms)"
  fi
  if [[ -n ${export_drained:-} ]] && ((export_drained <= recovery)); then
    ok "export: the backlog drained ${export_drained}s after the sink came back"
  else
    violation export "the backlog didn't drain within $SOAK_RECOVERY of the sink coming back (pending $(jq -r .pending <<<"$last"))"
  fi
  sink=$(sink_admin stats 2>/dev/null | jq -r '.acceptedEvents // 0')
  if ((${sink:-0} > 0)); then
    ok "export: the sink accepted $sink events"
  else
    violation export "the sink accepted no event"
  fi
  # The operator: never OOMKilled, its buffer full; the peak reported.
  local oom
  peak=$(jq -s '[.[] | select(.container | endswith("/operator")) | .rssBytes] | max // 0' "$OUT/memory.jsonl")
  oom=$("${KUBECTL[@]}" -n "$OPERATOR_NS" get pods -l app.kubernetes.io/name=inkwall,app.kubernetes.io/component=operator -o json |
    jq '[.items[].status.containerStatuses[]? | select(.lastState.terminated.reason == "OOMKilled")] | length')
  if [[ ${oom:-} == 0 ]]; then
    ok "export: no operator container OOMKilled (peak RSS $((peak >> 20)) MiB, limit ${export_limit:-unknown})"
  else
    violation export "an operator container was OOMKilled (${oom:-unknown}); peak RSS $((peak >> 20)) MiB, limit ${export_limit:-unknown}"
  fi
}

# export_restore: the release's export values back, and no sinks.
export_restore() {
  "${KUBECTL[@]}" patch inkwallconfig default --type=json -p '[{"op":"remove","path":"/spec/events/export"}]' >/dev/null 2>&1 || true
  [[ -n ${export_prev:-} ]] || return 0
  "${HELM[@]}" upgrade inkwall "$CHART" --namespace "$OPERATOR_NS" --reuse-values \
    --set "events.export.bufferMiB=$(jq -r '.bufferMiB // 32' <<<"$export_prev")" \
    --set "events.export.diskMiB=$(jq -r '.diskMiB // 512' <<<"$export_prev")" >/dev/null 2>&1 || true
}
