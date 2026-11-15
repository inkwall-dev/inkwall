# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2154 # work, grace, watched: the sourcing script's

# The soak's restart classification (hack/kind/soak.sh), sourced by it and by
# its test (hack/kind/soak_test.go). Needs KUBECTL, OUT, work, grace and
# watched (the namespaces).

# soak_now: the time, in seconds; the test sets it.
soak_now() { date +%s; }

# violation KIND MESSAGE: recorded, and printed.
violation() {
  jq -nc --argjson t "$(soak_now)" --arg kind "$1" --arg msg "$2" '{time: $t, kind: $kind, message: $msg}' >>"$OUT/violations.jsonl"
  echo "FAIL  $1: $2"
}

# Restarts: the containers' restart counts at the last sample, and the
# containers a chaos scenario restarted (its name), whose restarts stay that
# scenario's until they have run for SOAK_GRACE (#627).
declare -A restarts=() tainted=()
chaos_on=false
chaos_name=
chaos_start=0
chaos_until=0
# The closed chaos windows: "START UNTIL SCENARIO", UNTIL the end of the
# grace period.
chaos_windows=()
# chaos_begin SCENARIO DETAIL: a chaos window opens.
chaos_begin() {
  chaos_on=true
  chaos_name=$1
  chaos_start=$(soak_now)
  echo "== chaos: $1: $2"
}
# chaos_stop: the scenario has recovered (or not); its window lasts SOAK_GRACE
# more.
chaos_stop() {
  # The restarts the scenario caused are its own.
  sample_restarts expected
  chaos_on=false
  chaos_until=$(($(soak_now) + grace))
  chaos_windows+=("$chaos_start $chaos_until $chaos_name")
}
# restart_scenario KEY LAST_START LAST_END [expected]: the chaos scenario a
# new restart of container KEY is due to, empty if none. LAST_START and
# LAST_END bound the run the restart ended (0 if unknown). A restart is a
# scenario's while its window is open (to SOAK_GRACE after its recovery);
# after it, when the run it ended stopped inside the window (the kubelet
# reports restarts late, and a container in back-off from the chaos restarts
# minutes later), or when the container already restarted for the scenario
# and hasn't run for SOAK_GRACE since.
restart_scenario() {
  local key=$1 from=$2 to=$3 now w start until name
  now=$(soak_now)
  if $chaos_on || [[ ${4:-} == expected ]]; then
    echo "$chaos_name"
    return
  fi
  if ((now < chaos_until)); then
    echo "${chaos_windows[-1]#* * }"
    return
  fi
  if ((to > 0)); then
    for w in ${chaos_windows[@]+"${chaos_windows[@]}"}; do
      read -r start until name <<<"$w"
      if ((to >= start && to < until)); then
        echo "$name"
        return
      fi
    done
    if [[ -n ${tainted[$key]:-} ]] && ((from > 0 && to - from < grace)); then
      echo "${tainted[$key]}"
      return
    fi
  fi
  echo
}
# sample_restarts [expected|baseline]: compares restart counts with the last
# sample; a new restart is a violation unless it is a chaos scenario's
# (restart_scenario; "expected": the current one's). "baseline" only records
# the counts.
sample_restarts() {
  local ns key n from to prev scenario
  for ns in "${watched[@]}"; do
    "${KUBECTL[@]}" -n "$ns" get pods -o json 2>/dev/null |
      jq -r 'def secs: if . then fromdateiso8601 else 0 end;
        .items[] | .metadata.namespace as $ns | .metadata.name as $pod |
        ((.status.initContainerStatuses // []) + (.status.containerStatuses // []))[] |
        "\($ns)/\($pod)/\(.name) \(.restartCount) \(.lastState.terminated.startedAt | secs) \(.lastState.terminated.finishedAt | secs)"' ||
      return 0
  done >"$work/restarts"
  while read -r key n from to; do
    prev=${restarts[$key]:-0}
    restarts[$key]=$n
    ((n > prev)) && [[ ${1:-} != baseline ]] || continue
    scenario=$(restart_scenario "$key" "$from" "$to" "${1:-}")
    jq -nc --argjson t "$(soak_now)" --arg c "$key" --argjson d $((n - prev)) --arg s "$scenario" \
      '{time: $t, restart: $c, count: $d, duringChaos: ($s != "")} + if $s != "" then {scenario: $s} else {} end' >>"$OUT/samples.jsonl"
    if [[ -n $scenario ]]; then
      tainted[$key]=$scenario
    else
      violation restart "$key restarted $((n - prev)) time(s)"
    fi
  done <"$work/restarts"
}
