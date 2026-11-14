#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The false-positive run (#600): a HAR of a real application's traffic,
# every request a user's, checked with inkwallctl test --har against a
# policy at each OWASP CRS paranoia level, as the operator would resolve
# it and the engine compile it. Every request the policy denies is a false
# positive. Prints, per level, the requests, the denials and their rate, and
# the rules that denied (the CRS rule each denial's score came from), as a
# markdown table; with OUT, also writes OUT/fp-run.md and OUT/fp-run.json
# (each level's counts, rules and denied requests).
#
#   HAR      the traffic, a HAR file, gzip-compressed if its name ends
#            with .gz (default hack/fptraffic/juice-shop.har.gz, recorded
#            from OWASP Juice Shop by hack/fptraffic: make fp-har)
#   LEVELS   the paranoia levels (default "1 2 3 4")
#   POLICY   a WAFPolicy file of your own (with its rule sets, as
#            inkwallctl test --policy reads them): one run with it as it
#            is, instead of the default policy at each level (the built-in
#            CRS, Block mode, nothing excluded)
#   OUT      a directory for the results
set -euo pipefail

cd "$(dirname "$0")/.."

HAR=${HAR:-hack/fptraffic/juice-shop.har.gz}
LEVELS=${LEVELS:-1 2 3 4}
POLICY=${POLICY:-}
OUT=${OUT:-}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go build -o "$work/inkwallctl" ./cmd/inkwallctl

# policy LEVEL: the default policy at a paranoia level.
policy() {
  cat <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: fp-run, namespace: default}
spec:
  targetRefs: [{kind: Ingress, name: app}]
  mode: Block
  ruleSets:
    - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
      paranoiaLevel: $1
YAML
}
# POLICY: one run, with that policy as it is.
if [[ -n $POLICY ]]; then LEVELS=policy; fi
# The built-in CRS, for policies that name it.
rule_sets=(--rule-set operator/config/samples/clusterwafruleset.yaml)

har=$work/traffic.har
if [[ $HAR == *.gz ]]; then gzip -dc "$HAR" >"$har"; else cp "$HAR" "$har"; fi
requests=$(jq '.log.entries | length' "$har")
# The HAR's requests, one per line, in its order (inkwallctl's output is
# in the same order): method and URL without the origin.
jq -r '.log.entries[].request | "\(.method) \(.url | sub("^[a-z]+://[^/]*"; ""))"' "$har" >"$work/requests"

: >"$work/levels.jsonl"
for level in $LEVELS; do
  if [[ $level == policy ]]; then cp "$POLICY" "$work/policy-$level.yaml"; else policy "$level" >"$work/policy-$level.yaml"; fi
  "$work/inkwallctl" test --policy "$work/policy-$level.yaml" "${rule_sets[@]}" --har "$har" --json \
    >"$work/verdicts-$level.jsonl" 2>"$work/notes-$level"
  if [[ $(wc -l <"$work/verdicts-$level.jsonl") != "$requests" ]]; then
    echo "level $level: $(wc -l <"$work/verdicts-$level.jsonl") verdicts for $requests requests" >&2
    cat "$work/notes-$level" >&2
    exit 1
  fi
  # Each denial with its request, and the rules that scored (not the
  # anomaly evaluation, 949110, nor the CRS's own setup rules).
  jq -nc --rawfile reqs "$work/requests" --arg level "$level" --argjson total "$requests" '
    ($reqs | split("\n")) as $r |
    [inputs] | to_entries | map(select(.value.action == "ACTION_DENY") | {
      request: $r[.key],
      rules: ([.value.rule_ids[]? | select(. != 949110 and . != 959100 and . != 980170)] | unique),
      interrupting: .value.interrupting_rule_id
    }) as $denied |
    {level: $level, requests: $total, denied: ($denied | length),
     rate: (if $total > 0 then ($denied | length) / $total else 0 end),
     rules: ([$denied[].rules[]] | group_by(.) | map({rule: .[0], requests: length}) | sort_by(-.requests, .rule)),
     deniedRequests: $denied}' "$work/verdicts-$level.jsonl" >>"$work/levels.jsonl"
done

jq -s --arg har "$HAR" --arg policy "${POLICY:-default}" '{har: $har, policy: $policy, levels: .}' "$work/levels.jsonl" >"$work/fp-run.json"
{
  echo "False positives of $HAR ($requests requests), policy: ${POLICY:-the CRS, Block mode, nothing excluded}"
  echo
  echo "| Paranoia level | Requests | Denied | False-positive rate | Rules (requests) |"
  echo "|---|---|---|---|---|"
  jq -r '.levels[] | "| \(.level) | \(.requests) | \(.denied) | \(.rate * 10000 | round / 100)% | \(
    if (.rules | length) == 0 then "" else ([.rules[:8][] | "\(.rule) (\(.requests))"] | join(", ")) end) |"' "$work/fp-run.json"
} >"$work/fp-run.md"
cat "$work/fp-run.md"
if [[ -n $OUT ]]; then
  mkdir -p "$OUT"
  cp "$work/fp-run.md" "$work/fp-run.json" "$OUT/"
  echo
  echo "wrote $OUT/fp-run.md and $OUT/fp-run.json"
fi
