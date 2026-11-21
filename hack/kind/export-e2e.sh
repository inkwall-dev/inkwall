# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Exporting security events to SIEMs (design 0010, #723), sourced by
# hack/kind/e2e.sh while the stub control plane takes events and the
# policy "web" blocks through Traefik. An OpenTelemetry Collector (pinned,
# OTLP receivers, a file exporter) and a small HTTP sink
# (operator/test/eventsink) receive the events of an attack through
# Traefik: with the cluster's ID and name, the policy, the rule IDs and the
# request ID; a password argument's snippet absent; a sink's omit and
# filters holding; a rotated header Secret used without a restart; the
# EventsExported condition going ExportFailing and back; and the same
# events at the stub control plane. Uses e2e.sh's CLUSTER, NS,
# OPERATOR_NS, TRAEFIK_HOST, TRAEFIK_PORT, KUBECTL, stub_stats and the
# lib.sh checks; the operator runs with --export-status-window=30s
# (E2E_OPERATOR_ARGS).

echo "== export to SIEMs: a Collector and an HTTP sink"
EX_NS=inkwall-export-e2e
SINK_HOST=eventsink.$EX_NS.svc
docker build -q -f hack/kind/eventsink.Dockerfile -t inkwall-eventsink:dev . >/dev/null
kind load docker-image inkwall-eventsink:dev --name "$CLUSTER" >/dev/null
"${KUBECTL[@]}" create namespace "$EX_NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ConfigMap
metadata: {name: otel-collector, namespace: $EX_NS}
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc: {endpoint: 0.0.0.0:4317}
          http: {endpoint: 0.0.0.0:4318}
    exporters:
      file: {path: /data/logs.jsonl}
    service:
      pipelines:
        logs: {receivers: [otlp], exporters: [file]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: otel-collector, namespace: $EX_NS}
spec:
  selector: {matchLabels: {app: otel-collector}}
  template:
    metadata: {labels: {app: otel-collector}}
    spec:
      securityContext: {fsGroup: 10001}
      containers:
        - name: collector
          image: otel/opentelemetry-collector-contrib:${OTEL_COLLECTOR_VERSION#v}
          args: ["--config=/conf/config.yaml"]
          ports: [{containerPort: 4317}, {containerPort: 4318}]
          volumeMounts: [{name: conf, mountPath: /conf}, {name: data, mountPath: /data}]
        # The Collector's image has no shell: this one reads its file.
        - name: reader
          image: registry.k8s.io/e2e-test-images/agnhost:$AGNHOST_VERSION
          args: ["pause"]
          volumeMounts: [{name: data, mountPath: /data}]
      volumes:
        - {name: conf, configMap: {name: otel-collector}}
        - {name: data, emptyDir: {}}
---
apiVersion: v1
kind: Service
metadata: {name: otel-collector, namespace: $EX_NS}
spec:
  selector: {app: otel-collector}
  ports: [{name: grpc, port: 4317}, {name: http, port: 4318}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: eventsink, namespace: $EX_NS}
spec:
  selector: {matchLabels: {app: eventsink}}
  template:
    metadata: {labels: {app: eventsink}}
    spec:
      containers:
        - name: sink
          image: inkwall-eventsink:dev
          imagePullPolicy: Never
          args: ["--dns-name=$SINK_HOST", "--header=Authorization", "--header=X-Tenant"]
          ports: [{containerPort: 8443}, {containerPort: 8081}]
---
apiVersion: v1
kind: Service
metadata: {name: eventsink, namespace: $EX_NS}
spec:
  selector: {app: eventsink}
  ports: [{name: https, port: 8443}, {name: admin, port: 8081}]
YAML
"${KUBECTL[@]}" -n "$EX_NS" rollout status deployment/otel-collector --timeout=180s >/dev/null
"${KUBECTL[@]}" -n "$EX_NS" rollout status deployment/eventsink --timeout=120s >/dev/null
sink_get() { "${KUBECTL[@]}" get --raw "/api/v1/namespaces/$EX_NS/services/eventsink:admin/proxy/$1"; }
sink_post() { "${KUBECTL[@]}" create --raw "/api/v1/namespaces/$EX_NS/services/eventsink:admin/proxy/$1" -f /dev/null >/dev/null; }
eventually "the event sink serves" sink_get stats
sink_ca=$(mktemp)
sink_get ca.crt >"$sink_ca"
"${KUBECTL[@]}" -n "$OPERATOR_NS" create secret generic e2e-sink-ca --from-file=ca.crt="$sink_ca" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" -n "$OPERATOR_NS" create secret generic e2e-sink-headers \
  --from-literal=Authorization="Bearer one" --from-literal=X-Tenant=e2e \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null

# Whatever happens, the test's sinks go: later sections run without them.
export_e2e_cleanup() {
  "${KUBECTL[@]}" patch inkwallconfig default --type=json -p '[{"op":"remove","path":"/spec/events/export"}]' >/dev/null 2>&1 || true
}
trap 'export_e2e_cleanup; cleanup' EXIT

# Four sinks: the Collector over gRPC and over HTTP, plaintext in the
# cluster; the HTTP sink over TLS with its CA and headers from Secrets;
# and the HTTP sink again, for denials of the test's namespace only,
# without snippets or client IPs.
"${KUBECTL[@]}" patch inkwallconfig default --type=merge -p "$(cat <<JSON
{"spec":{"events":{"export":{"clusterName":"kind-e2e","sinks":[
  {"name":"collector","otlp":{"endpoint":"grpc://otel-collector.$EX_NS.svc:4317"},"insecure":true,"batch":{"maxDelay":"1s"}},
  {"name":"collector-http","otlp":{"endpoint":"http://otel-collector.$EX_NS.svc:4318/v1/logs"},"insecure":true,"batch":{"maxDelay":"1s"}},
  {"name":"sink","json":{"url":"https://$SINK_HOST:8443/all"},"headersSecretRef":{"name":"e2e-sink-headers"},
   "tls":{"caSecretRef":{"name":"e2e-sink-ca"}},"batch":{"maxDelay":"1s"}},
  {"name":"denials","json":{"url":"https://$SINK_HOST:8443/denials","framing":"Array"},"tls":{"caSecretRef":{"name":"e2e-sink-ca"}},
   "batch":{"maxDelay":"1s"},"filter":{"actions":["Deny"],"policyNamespaces":["$NS"]},"omit":["Snippets","ClientIP"]}
]}}}}
JSON
)" >/dev/null
export_reason() {
  "${KUBECTL[@]}" get inkwallconfig default -o jsonpath='{.status.conditions[?(@.type=="EventsExported")].reason}'
}
export_is() { [[ $(export_reason) == "$1" ]]; }
eventually_long "the sinks export (EventsExported: Exporting)" export_is Exporting

# An attack through Traefik, on a path of its own, with a password
# argument whose snippet the engine redacts, and another whose it keeps.
attack_path=/export-$RANDOM
attack="$attack_path?password=1%27%20OR%20%271%27%3D%271&q=1%27%20OR%20%271%27%3D%271"
cluster_uid=$("${KUBECTL[@]}" get namespace kube-system -o jsonpath='{.metadata.uid}')
eventually "the attack is denied through Traefik" tstatus_is 403 "$attack"

# sink_event PATH: the sink's events at PATH for the attack, as JSON lines.
sink_events() {
  sink_get stats | jq -c --arg path "$1" --arg ap "$attack_path" \
    '.requests[]? | select(.path == $path) | .events[] | select(.request.path == $ap)'
}
exported() {
  sink_events /all | head -1 | jq -e --arg ns "$NS" --arg uid "$cluster_uid" '
    .schema == "inkwall.dev/security-event/v1" and .cluster.id == $uid and .cluster.name == "kind-e2e" and
    .policy.namespace == $ns and .policy.name == "web" and .action == "deny" and .reason == "rule" and .status == 403 and
    .rule_id > 0 and (.matches | length) > 0 and (.matches | all(.rule_id > 0)) and (.request.id | length) > 0 and
    (.engine.pod | length) > 0 and .request.host == "'"$TRAEFIK_HOST"'"' >/dev/null
}
eventually "the HTTP sink gets the attack: cluster, policy, rule IDs and request ID" exported ||
  echo "      sink: $(sink_get stats | head -c 2000)"
no_password_snippet() {
  sink_events /all | head -1 | jq -e '[.matches[] | select((.variable // "") | test("password"; "i"))] | length > 0 and all(has("snippet") | not)' >/dev/null
}
check "the password argument's match has no snippet" no_password_snippet
# The other side: snippets do reach this sink, so the check above (and the
# denials sink's omit below) can't pass by exporting none.
some_snippet() { sink_events /all | head -1 | jq -e 'any(.matches[]; has("snippet"))' >/dev/null; }
check "another argument's match keeps its snippet" some_snippet
headers_from_secret() {
  sink_get stats | jq -e '[.requests[]? | select(.path == "/all")] | last | .headers.Authorization == "Bearer one" and .headers["X-Tenant"] == "e2e"' >/dev/null
}
check "the headers come from the Secret" headers_from_secret
omitted() {
  sink_events /denials | head -1 | jq -e 'has("request") and (.request | has("client_ip") | not) and
    ([.matches[] | has("snippet")] | any | not) and .action == "deny"' >/dev/null
}
eventually "the denials sink gets it without snippets or client IP" omitted
array_framing() { sink_get stats | jq -e '[.requests[]? | select(.path == "/denials")] | all(.contentType == "application/json" and .encoding == "gzip")' >/dev/null; }
check "as a gzipped JSON array" array_framing

# collector_has ATTRIBUTE: the Collector's file has the attack's record.
collector_records() {
  "${KUBECTL[@]}" -n "$EX_NS" exec deploy/otel-collector -c reader -- cat /data/logs.jsonl 2>/dev/null
}
collector_has_attack() {
  collector_records | jq -e -s --arg ap "$attack_path" --arg ns "$NS" --arg uid "$cluster_uid" '
    [.[].resourceLogs[] | . as $rl | .scopeLogs[] | select(.scope.name == "inkwall.dev/events" and .scope.version == "1") | .logRecords[] |
      (.attributes | map({(.key): .value}) | add) as $a |
      select($a["url.path"].stringValue == $ap) |
      {res: ($rl.resource.attributes | map({(.key): .value.stringValue}) | add), a: $a, name: .eventName}] |
    length >= 2 and all(.name == "inkwall.security_event" and (.res["k8s.cluster.uid"] | length) > 0 and
      .res["k8s.cluster.uid"] == $uid and .res["k8s.cluster.name"] == "kind-e2e" and .res["service.name"] == "inkwall-engine" and
      .a["inkwall.policy.namespace"].stringValue == $ns and .a["inkwall.policy.name"].stringValue == "web" and
      (.a["inkwall.request.id"].stringValue | length) > 0)' >/dev/null
}
eventually "the Collector gets it twice, over gRPC and HTTP, with the cluster, policy and request ID" collector_has_attack ||
  echo "      collector: $(collector_records | tail -c 2000)"

# The control plane gets the same events: its count grew with the sink's.
stub_has_events() { [[ $(stub_stats | sed -n 's/.*"events":\([0-9]*\).*/\1/p') -ge 2 ]]; }
check "the stub control plane gets events beside the sinks" stub_has_events
same_ids() {
  local sink_ids missing
  sink_ids=$(sink_events /all | jq -r .event_id | sort -u)
  missing=$(comm -23 <(echo "$sink_ids") <(stub_stats | jq -r '.eventIDs[]?' | sort -u))
  [[ -n $sink_ids && -z $missing ]]
}
eventually "with the same event IDs" same_ids

# The filters' other side: an event of Log (the policy in Detect mode) and
# one of a namespace the denials sink doesn't take reach /all, not it.
denials_has() { sink_events_at /denials "$1" | grep -q .; }
all_has() { sink_events_at /all "$1" | grep -q .; }
# sink_events_at PATH ATTACK_PATH: the sink's events at PATH for a path.
sink_events_at() {
  sink_get stats | jq -c --arg path "$1" --arg ap "$2" '.requests[]? | select(.path == $path) | .events[] | select(.request.path == $ap)'
}
"${KUBECTL[@]}" -n "$NS" patch wafpolicy web --type=merge -p '{"spec":{"mode":"Detect"}}' >/dev/null
log_path=/export-log-$RANDOM
eventually "Detect mode lets the attack through" tstatus_is 200 "$log_path?q=1%27%20OR%20%271%27%3D%271"
logged() { tcode "$log_path?q=1%27%20OR%20%271%27%3D%271" >/dev/null; sink_events_at /all "$log_path" | jq -e 'select(.action == "log")' | grep -q .; }
eventually "the Log event reaches the sink that takes both actions" logged
sleep 5 # a batch delay (1 s) and more
# Its probes before Detect applied were denied, and those deny events do
# reach the Deny-only sink: only the log ones mustn't.
not_denials_log() { ! sink_events_at /denials "$log_path" | jq -e 'select(.action == "log")' | grep -q .; }
check "and not the Deny-only sink" not_denials_log
"${KUBECTL[@]}" -n "$NS" patch wafpolicy web --type=merge -p '{"spec":{"mode":"Block"}}' >/dev/null
eventually "Block mode again" tstatus_is 403 "$attack"
"${KUBECTL[@]}" patch inkwallconfig default --type=json \
  -p '[{"op":"replace","path":"/spec/events/export/sinks/3/filter/policyNamespaces","value":["inkwall-elsewhere"]}]' >/dev/null
sleep 5 # the exporter reads its configuration every 2 s
ns_path=/export-ns-$RANDOM
ns_reached() { tcode "$ns_path?q=1%27%20OR%20%271%27%3D%271" >/dev/null; all_has "$ns_path"; }
eventually "an event of $NS reaches the sink that takes every namespace" ns_reached
sleep 5
not_denials_ns() { ! denials_has "$ns_path"; }
check "and not a sink filtered to another namespace" not_denials_ns

# A rotated header Secret, used without a restart.
op_pods() {
  "${KUBECTL[@]}" -n "$OPERATOR_NS" get pods -l app.kubernetes.io/name=inkwall,app.kubernetes.io/component=operator \
    -o jsonpath='{range .items[*]}{.metadata.name}:{.status.containerStatuses[0].restartCount} {end}'
}
before=$(op_pods)
if [[ -z $before ]]; then
  fail "no operator pod found by its labels: the restart check would prove nothing"
fi
"${KUBECTL[@]}" -n "$OPERATOR_NS" create secret generic e2e-sink-headers \
  --from-literal=Authorization="Bearer two" --from-literal=X-Tenant=e2e \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
rotated() {
  tcode "$attack" >/dev/null
  sink_get stats | jq -e '[.requests[]? | select(.path == "/all")] | last | .headers.Authorization == "Bearer two"' >/dev/null
}
eventually "the rotated header is sent" rotated
same_operator() { [[ $(op_pods) == "$before" ]]; }
check "without restarting the operator" same_operator

# The sink fails: ExportFailing, naming it; then it recovers.
sink_post "mode?status=503"
failing() {
  tcode "$attack" >/dev/null
  export_is ExportFailing &&
    "${KUBECTL[@]}" get inkwallconfig default -o jsonpath='{.status.conditions[?(@.type=="EventsExported")].message}' | grep -q "sink sink on "
}
eventually_long "a sink answering 503 makes EventsExported ExportFailing" failing
sink_post "mode?status=200"
eventually_long "and Exporting again once it answers" export_is Exporting

# Done: no export, and the condition goes.
"${KUBECTL[@]}" patch inkwallconfig default --type=json -p '[{"op":"remove","path":"/spec/events/export"}]' >/dev/null
trap cleanup EXIT
no_condition() { [[ -z $(export_reason) ]]; }
eventually_long "without sinks, the condition goes" no_condition
if [[ -z ${KEEP:-} ]]; then
  "${KUBECTL[@]}" -n "$OPERATOR_NS" delete secret e2e-sink-ca e2e-sink-headers --ignore-not-found >/dev/null
  "${KUBECTL[@]}" delete namespace "$EX_NS" --wait=false >/dev/null
fi
rm -f "$sink_ca"
