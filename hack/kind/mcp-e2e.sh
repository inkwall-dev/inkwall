# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# inkwallctl mcp on the kind cluster (#439), sourced by hack/kind/e2e.sh
# while its policy "app" blocks: an MCP client (hack/mcpclient) starts
# `inkwallctl mcp` over stdio, as an assistant does, lists its read-only
# tools, reads a doc, and calls each tool against the cluster; the policy
# is unchanged after. Uses e2e.sh's CLUSTER, NS, HOST, PORT, SQLI, KUBECTL
# and the lib.sh checks.

echo "== inkwallctl mcp"
mcp_dir=$(mktemp -d)
go build -o "$mcp_dir/inkwallctl" ./cmd/inkwallctl
go build -o "$mcp_dir/mcpclient" ./hack/mcpclient
# mcp_call TOOL JSON: the tool's result, as JSON.
mcp_call() { "$mcp_dir/mcpclient" -tool "$1" -args "$2" -- "$mcp_dir/inkwallctl" mcp --context "kind-$CLUSTER"; }
mcp_tools() {
  [[ $("$mcp_dir/mcpclient" -list -- "$mcp_dir/inkwallctl" mcp --context "kind-$CLUSTER" | sort | tr '\n' ' ') == \
    "explain_policy true explain_request true get_policy true list_policies true status true suggest_exclusions true test_policy true " ]]
}
check "mcp lists its seven tools, each read-only" mcp_tools
mcp_doc() {
  "$mcp_dir/mcpclient" -read inkwall://docs/troubleshooting.md -- "$mcp_dir/inkwallctl" mcp --context "kind-$CLUSTER" |
    grep -q '^## Explaining a policy or a denial'
}
check "mcp serves this version's troubleshooting guide" mcp_doc

policy_generation=$("${KUBECTL[@]}" -n "$NS" get wafpolicy app -o jsonpath='{.metadata.generation}')
mcp_status() { mcp_call status '{}' | jq -e '.policies.total >= 1'; }
check "mcp status reads the cluster" mcp_status
mcp_rid=$(curl -s -o /dev/null -D - -H "Host: $HOST" "http://127.0.0.1:$PORT$SQLI" | tr -d '\r' | awk 'tolower($1) == "x-request-id:" { print $2 }')
mcp_explained() {
  mcp_call explain_request "{\"requestId\":\"$mcp_rid\"}" | jq -e --arg ns "$NS" '
    .found and .events[0].policy == ($ns + "/app") and .events[0].suggestions[0].verified and
    (.untrusted | index("events[].request"))'
}
eventually "mcp explain_request explains the denial" mcp_explained
mcp_tested() {
  mcp_call test_policy "{\"namespace\":\"$NS\",\"name\":\"app\",\"url\":\"http://$HOST$SQLI\"}" | jq -e '.results[0].action == "deny"' &&
    mcp_call test_policy "{\"namespace\":\"$NS\",\"name\":\"app\",\"url\":\"http://$HOST$SQLI\",\"policySpec\":{\"targetRefs\":[{\"kind\":\"Ingress\",\"name\":\"app\"}],\"exclusions\":[{\"ruleIDs\":[942100],\"when\":{\"path\":\"/\",\"argument\":\"id\"}}]}}" |
    jq -e '.results[0].action == "allow"'
}
check "mcp test_policy denies the attack, and allows it with the exclusion added" mcp_tested
mcp_suggested() {
  mcp_call suggest_exclusions "{\"policy\":\"$NS/app\",\"since\":\"1h\"}" |
    jq -e '.policies[0].verified and (.policies[0].exclusions | any(.when.argument == "id" and (.ruleIDs | index(942100))))'
}
check "mcp suggest_exclusions suggests the verified exclusion" mcp_suggested
mcp_policies() {
  mcp_call list_policies "{\"namespace\":\"$NS\"}" | jq -e '.policies | any(.name == "app")' &&
    mcp_call get_policy "{\"namespace\":\"$NS\",\"name\":\"app\"}" | jq -e '.spec.mode == "Block"' &&
    mcp_call explain_policy "{\"namespace\":\"$NS\",\"name\":\"app\"}" | jq -e '.name == "app" and (.conditions | length) == 4'
}
check "mcp list_policies, get_policy and explain_policy read the policy" mcp_policies
policy_unchanged() { [[ $("${KUBECTL[@]}" -n "$NS" get wafpolicy app -o jsonpath='{.metadata.generation}') == "$policy_generation" ]]; }
check "the policy is unchanged: mcp only reads" policy_unchanged
rm -rf "$mcp_dir"
