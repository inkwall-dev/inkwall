# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# inkwallctl explain on the kind cluster (#438), sourced by hack/kind/e2e.sh
# while its policy "app" blocks: a denied request's ID is explained end to
# end (the engine's log read through the API server, the CRS description,
# the suggested exclusion verified with the cluster's policy, and the
# exclusion, applied, lets the request through), and a policy that isn't
# Ready is explained with the troubleshooting guide's cause and fix.
# Uses e2e.sh's CLUSTER, NS, HOST, PORT, SQLI, KUBECTL, policy and the
# lib.sh checks.

echo "== inkwallctl explain"
explain_dir=$(mktemp -d)
go build -o "$explain_dir/inkwallctl" ./cmd/inkwallctl
# iwc request|policy ARGS...: inkwallctl explain on this cluster (its flags
# follow the subcommand).
iwc() { "$explain_dir/inkwallctl" explain "$1" --context "kind-$CLUSTER" "${@:2}"; }

# A denied request, and the ID its client got.
denied_id() {
  curl -s -o /dev/null -D - -H "Host: $HOST" "http://127.0.0.1:$PORT$SQLI" |
    tr -d '\r' | awk 'tolower($1) == "x-request-id:" { print $2 }'
}
rid=$(denied_id)
check "a denial carries its request ID" test -n "$rid"

explained() {
  iwc request -o json "$rid" >"$explain_dir/request.json" &&
    jq -e --arg ns "$NS" '
      .found and (.events | length) == 1 and (.events[0] |
        .policy == ($ns + "/app") and .action == "deny" and .reason == "rule" and .threshold == 5 and
        (.rules | any(.source == "crs" and (.description | test("SQL Injection")))) and
        (.request.matches | any(.variable == "ARGS:id")) and
        (.suggestions | length) == 1 and .suggestions[0].verified and .suggestions[0].verifiedWith == "the cluster" and
        .suggestions[0].exclusion.when == {"path": "/", "argument": "id"} and .allowedWithSuggestions)
      and (.untrusted | index("events[].request"))' "$explain_dir/request.json"
}
# The engine logs the event as it answers; the log may lag a little.
eventually "explain request finds the denial in the engine's log, and suggests a verified exclusion" explained
text_names_rule() { iwc request "$rid" | grep -q 'SQL Injection Attack Detected'; }
check "explain request's text names the rule" text_names_rule
explain_unknown() {
  iwc request no-such-request-id >/dev/null
  [[ $? == 1 ]]
}
check "explain request exits 1 for an ID no event has" explain_unknown

# The suggestion, applied, lets that request through; the policy back as
# it was blocks it again.
apply_suggestion() {
  "${KUBECTL[@]}" -n "$NS" patch wafpolicy app --type merge \
    -p "{\"spec\":{\"exclusions\":$(jq -c '[.events[0].suggestions[].exclusion]' "$explain_dir/request.json")}}" >/dev/null
}
if apply_suggestion; then
  eventually "the suggested exclusion lets the request through" status_is 200 "$SQLI"
  check "and nothing more: an attack in another argument is still denied" status_is 403 '/?q=1%27%20OR%20%271%27%3D%271'
else
  fail "the suggested exclusion applies"
fi
"${KUBECTL[@]}" -n "$NS" patch wafpolicy app --type json -p '[{"op":"remove","path":"/spec/exclusions"}]' >/dev/null 2>&1 || true
eventually "block mode again without the exclusion" status_is 403 "$SQLI"

# A policy that isn't Ready: its target doesn't exist (Accepted: InvalidRef).
"${KUBECTL[@]}" apply --server-side -f - >/dev/null <<YAML
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: explain-no-target
  namespace: $NS
spec:
  targetRefs: [{kind: Ingress, name: explain-missing}]
YAML
policy_explained() {
  iwc policy -o json "$NS/explain-no-target" >"$explain_dir/policy.json"
  [[ $? == 1 ]] && jq -e '
    (.ready | not) and
    (.conditions[] | select(.type == "Accepted") | .status == "False" and .reason == "InvalidRef" and .current and
      (.message | test("explain-missing")) and (.fix | startswith("Create it, or fix the name. The message names it."))) and
    (.conditions[] | select(.type == "Ready") | .reason == "InvalidRef" and (.cause | test("doesn.t exist"))) and
    (.targets == [{"kind": "Ingress", "name": "explain-missing"}])' "$explain_dir/policy.json"
}
eventually "explain policy gives the guide's cause and fix for a policy whose target doesn't exist" policy_explained
"${KUBECTL[@]}" -n "$NS" delete wafpolicy explain-no-target >/dev/null
rm -rf "$explain_dir"
