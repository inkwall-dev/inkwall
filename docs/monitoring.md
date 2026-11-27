# Monitoring Inkwall

This guide scrapes the operator's and the engines' [Prometheus](https://prometheus.io/docs/introduction/overview/) metrics, installs the
alerts and the [Grafana](https://grafana.com/docs/grafana/latest/) dashboard the chart ships, lists every metric, and says what to
do when an alert fires.

## Contents

- [Prerequisites](#prerequisites)
- [Turn it on](#turn-it-on)
- [Metrics](#metrics)
  - [Engine](#engine)
  - [Operator](#operator)
- [Alerts](#alerts)
  - [InkwallEngineDisconnected](#inkwallenginedisconnected)
  - [InkwallBundleRejected](#inkwallbundlerejected)
  - [InkwallRequestsUninspected](#inkwallrequestsuninspected)
  - [InkwallEvaluationSlotsSaturated](#inkwallevaluationslotssaturated)
  - [InkwallAdapterErrors](#inkwalladaptererrors)
  - [InkwallEnginesBehind](#inkwallenginesbehind)
  - [InkwallWiringFailures](#inkwallwiringfailures)
  - [InkwallBundleNearSizeLimit](#inkwallbundlenearsizelimit)
  - [InkwallBundleChangesHeld](#inkwallbundlechangesheld)
  - [InkwallNamespaceOverShare](#inkwallnamespaceovershare)
- [Checking it worked](#checking-it-worked)
- [Turning it off](#turning-it-off)

## Prerequisites

- The [Prometheus Operator](https://prometheus-operator.dev/) (for example from kube-prometheus-stack), for the ServiceMonitor,
  PodMonitor and PrometheusRule. Without it, scrape the endpoints below with your own
  configuration and load `deploy/helm/inkwall/monitoring/alerts.yaml` as a rule file.
- A Prometheus that may list and scrape pods in the proxy namespaces (`injection.proxyNamespaces`):
  the engines run there, in the proxies' pods.
- For the dashboard, Grafana with its dashboard sidecar, or import
  `deploy/helm/inkwall/monitoring/dashboard.json` by hand.

What serves metrics:

- **The operator**: `/metrics` on port 8080 (`metrics` in its pods).
- **Each engine**: `/metrics` on port 9480, named `inkwall-admin`, in the proxy pod it was injected
  into. A standalone engine serves them on `--admin-listen`.

## Turn it on

Everything is off by default. Turn on what you use:

```sh
helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> --namespace inkwall-system --reuse-values \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.podMonitor.enabled=true \
  --set metrics.prometheusRule.enabled=true \
  --set metrics.dashboard.enabled=true
```

| Value | Creates |
|---|---|
| `metrics.serviceMonitor.enabled` | A Service for the operator's metrics port, and a ServiceMonitor for it |
| `metrics.podMonitor.enabled` | A PodMonitor for every pod with an `inkwall-admin` port in the proxy namespaces (`"*"`: every namespace) |
| `metrics.prometheusRule.enabled` | A PrometheusRule with the [alerts](#alerts), each with a `runbook_url` into this page, for the chart's release |
| `metrics.dashboard.enabled` | A ConfigMap with the dashboard, labeled `grafana_dashboard: "1"` (`metrics.dashboard.labels`), in `metrics.dashboard.namespace` (default: the release's) |

- `*.labels` adds labels, such as the `release` label your Prometheus selects monitors and rules
  by; `*.interval` sets the scrape interval.
- The ServiceMonitor, PodMonitor and PrometheusRule are rendered only when the cluster serves
  `monitoring.coreos.com/v1`. `helm template` can't ask the cluster: pass
  `--api-versions monitoring.coreos.com/v1`, or set `metrics.forceMonitoringObjects=true`.
- `InkwallConfig.spec.engine.policyMetrics: true` adds `inkwall_policy_requests_total` on engines
  injected from then on (restart the proxy pods). It is off by default: one series per policy,
  action and reason.

## Metrics

Engine metrics carry `adapter` where it says so (`proxy`, `forwardauth`, `httpcheck`, `extproc`,
`spoe`); Prometheus adds `namespace` and `pod`. Every label's values are bounded.

### Engine

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inkwall_requests_total` | counter | `adapter`, `action`, `reason` | Requests checked, by action (`allow`, `deny`, `log`) and reason (`none`, `rule`, `timeout`, `error`, `canceled`, `overload`, `oversize`, `skipped`, `no-policy`, `suspended`, `websocket`). `timeout`, `error` and `overload` were not inspected. WebSocket messages are not counted here. |
| `inkwall_check_duration_seconds` | histogram | `adapter` | Time checking a request, queueing for an evaluation slot included. |
| `inkwall_responses_total` | counter | `adapter`, `action`, `reason` | Responses checked, for policies that inspect responses. |
| `inkwall_response_check_duration_seconds` | histogram | `adapter` | Time checking a response. |
| `inkwall_rule_matches_total` | counter | `adapter`, `rule_id`, `action` | Rules that matched, score-only ones included, by the verdict's action. At most 2,000 rule IDs, then `rule_id="other"`. |
| `inkwall_policy_requests_total` | counter | `adapter`, `policy`, `action`, `reason` | Opt-in (`--policy-metrics`, `InkwallConfig.spec.engine.policyMetrics`): requests by policy, as the security event names it; `none` without one (a request no policy covers, or standalone mode), `other` past `--policy-metrics-max` policies (default 500). |
| `inkwall_adapter_errors_total` | counter | `adapter`, `kind` | Requests refused without inspection: `invalid_request` (one the adapter can't read), `protocol` (an ext_proc stream or SPOE connection that breaks the protocol). |
| `inkwall_websocket_connections` | gauge | `adapter` | WebSockets the engine's proxy holds open. |
| `inkwall_websocket_messages_total` | counter | `adapter`, `action` | WebSocket messages inspected (`--websocket-messages`). |
| `inkwall_websocket_violations_total` | counter | `adapter`, `code` | WebSocket messages refused or breaking the protocol, by close code (1002, 1003, 1007, 1009). |
| `inkwall_evaluations_in_flight` | gauge | | Evaluations running now. |
| `inkwall_evaluation_slots` | gauge | | Maximum concurrent evaluations; past them, requests are shed with reason `overload`. |
| `inkwall_rule_sets` | gauge | | Compiled rule sets in memory. |
| `inkwall_rules_reloads_total` | counter | `adapter`, `result` | Standalone mode's rule reloads (`SIGHUP`, `--watch-rules`): `ok`, or `error` when the new rules don't compile and the old ones stay. |
| `inkwall_connections` | gauge | `adapter` | Client connections the standalone proxy holds open, with `--max-connections`. |
| `inkwall_connection_limit_waits_total` | counter | `adapter` | Times the standalone proxy reached `--max-connections`: the next connection waited until one closed. |
| `inkwall_operator_connected` | gauge | | 1 while the engine has its stream to the operator. |
| `inkwall_bundle_version` | gauge | | The bundle the engine enforces; 0 before the first. |
| `inkwall_bundle_updates_total` | counter | `result`, `reason` | Bundles received: `applied`, or `rejected` with a reason (`signature`, `older`, `compile`, `other`). |
| `inkwall_bundle_compile_seconds` | histogram | | Time compiling a bundle's policies. |
| `inkwall_bundle_applied_timestamp_seconds` | gauge | | When the enforced bundle was applied (Unix time): its age is `time()` minus it. |
| `inkwall_engine_events_total` | counter | | Security events recorded for the operator. |
| `inkwall_engine_events_dropped_total` | counter | | Security events dropped because the buffer was full. |
| `inkwall_security_event_logs_suppressed_total` | counter | `policy` | Security event log lines left out by the rate limit (`--event-log-rate`); the events still go to the operator. |

The engine also serves the Go runtime's `go_*` and the `process_*` metrics.

### Operator

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inkwall_operator_bundle_version` | gauge | | The bundle this replica serves. |
| `inkwall_operator_bundle_compressed_bytes` | gauge | | Its size, gzip-compressed: over 900 KiB it is split into chunks; it is never over 7,200 KiB (see `inkwall_operator_bundle_held_policies`). |
| `inkwall_operator_bundle_raw_bytes` | gauge | | Its size, signed and decompressed: it is never over 64 MiB. |
| `inkwall_operator_engines` | gauge | `state` | Connected engines by whether they run the current bundle (`current`, `behind`, `rejected`). Leader only. |
| `inkwall_operator_engines_left_out` | gauge | | Engines left out of this replica's engine report (over the ConfigMap limit). |
| `inkwall_operator_events_received_total` | counter | | Security events received from the engines. |
| `inkwall_operator_engine_events_dropped_total` | counter | | Security events the engines reported dropping. |
| `inkwall_operator_wired_targets` | gauge | `integration` | Policy targets wired to the engine. Leader only. |
| `inkwall_operator_wiring_failures` | gauge | `integration` | Policy targets that couldn't be wired (`Programmed: WiringFailed`). Leader only. |
| `inkwall_operator_policies` | gauge | `condition`, `status`, `reason` | WAFPolicies by each condition (`Accepted`, `Programmed`, `Enforced`, `Ready`), its status and reason. Leader only. |
| `inkwall_operator_signing_key_age_seconds` | gauge | | Time since the active bundle signing key began to sign. Leader only. |
| `inkwall_operator_signing_key_rotation_phase` | gauge | `phase` | 1 for the rotation's phase (`Idle`, `Publishing`, `Retiring`), 0 for the others. Leader only. |
| `inkwall_operator_bundle_publish_failures_total` | counter | `reason` | Bundles not published: `too_large` (the bundle with every change is over 7,200 KiB compressed or 64 MiB raw: the bundle published holds back changes, namespace by namespace, until it fits), `error` (retried). Leader only. |
| `inkwall_operator_bundle_held_policies` | gauge | | Policies and rule sets the published bundle holds back at their previous version, or leaves out (`Accepted=False`, `BundleTooLarge`): their namespace would be over its share of the bundle (`spec.bundle.namespaceShare`), the bundle with them over 7,200 KiB compressed or 64 MiB raw, or namespaces' changes would grow it into the cluster reserve (`spec.bundle.clusterReserve`); and ClusterWAFRuleSets whose change isn't published. 0 when every change is published. Leader only. |
| `inkwall_operator_bundle_namespace_share_percent` | gauge | `policy_namespace` | The share of the published bundle's size limit a namespace's content takes, in percent of the limit it takes most of, for the namespaces over `spec.bundle.namespaceShare` only: no series for the others, or with one namespace, so at most a few. A compressed share is measured for at most 16 namespaces, the largest first, and the gauge at most every 10 minutes, unless the share changes. The label isn't `namespace`, which Prometheus sets to the operator's. Leader only. |
| `inkwall_operator_events_forwarded_total` | counter | | Security events sent to the control plane. |
| `inkwall_operator_events_buffered` | gauge | | Security events buffered for the control plane. |
| `inkwall_operator_events_buffer_errors_total` | counter | | Batches of events that couldn't be written to the buffer. |
| `inkwall_operator_request_stats_dropped_total` | counter | `reason` | Policies' request counts dropped (`not_in_bundle`, `latency_buckets`, `evicted`). |
| `inkwall_operator_state_engines_left_out` | gauge | | Engines left out of the last ClusterState sent to the control plane. |

The operator also serves controller-runtime's `controller_runtime_*`, `workqueue_*` and
`rest_client_*` metrics.

Policies that aren't `Ready`, by reason:

```promql
sum by (reason) (inkwall_operator_policies{condition="Ready", status="False"})
```

The operator also records a Kubernetes Event on a policy when its `Ready`, `Programmed` or
`Enforced` condition changes (`Warning` while it isn't `Ready`), at most one per policy every 30
seconds:

```sh
kubectl describe wafpolicy -n shop web
kubectl get events -n shop --field-selector involvedObject.kind=WAFPolicy
```

## Alerts

`deploy/helm/inkwall/monitoring/alerts.yaml`. `hack/monitoring/alerts_test.yaml` tests each with
`promtool test rules` (`make monitoring-test`).

### InkwallEngineDisconnected

An engine has had no stream to the operator for 10 minutes. It keeps enforcing the bundle it has,
but gets no policy changes, and its events stay in its buffer.

- Check the engine's log for `operator` errors: `kubectl -n <namespace> logs <pod> -c inkwall-engine`.
- Check the operator is running and its distribution Service has endpoints:
  `kubectl -n inkwall-system get pods,endpoints`.
- A network policy between the proxy namespace and `inkwall-system` must allow the distribution
  port (9445).

### InkwallBundleRejected

An engine rejected a bundle in the last 15 minutes and keeps enforcing the one it had. `reason`:

- `signature`: the engine doesn't trust the key that signed it, usually during a key rotation
  ([Rotating the bundle signing key](key-rotation.md)) or when its trust ConfigMap is stale.
- `older`: an older bundle than the one it enforces; it resolves once the operator sends the
  current one.
- `compile`: the policies don't compile in this engine, often an engine older than the operator.
  The engine's log says why (`bundle rejected`); run engines of the operator's version.

### InkwallRequestsUninspected

An engine answers requests with its failure mode (allowed in `Detect`, 503 in `Block`) instead of
the rules: they timed out, failed, or were shed for overload. `inkwall_requests_total` says
which reason.

- `overload`: see [InkwallEvaluationSlotsSaturated](#inkwallevaluationslotssaturated).
- `timeout`: inspection takes longer than the policy's `timeout`; large bodies or a high paranoia
  level are the usual causes. Raise the engine's CPU, or the timeout.
- `error`: the engine's log says why.

### InkwallEvaluationSlotsSaturated

An engine has used at least 90% of its evaluation slots for 10 minutes. Past them, requests are
shed with reason `overload`. Give the engine more CPU (`InkwallConfig.spec.engine.resources`), or
run more proxy replicas.

### InkwallAdapterErrors

An engine has refused requests it can't read for 15 minutes (`inkwall_adapter_errors_total`).
These are answered 400 or denied, never let through. `invalid_request` from a proxy usually means
a misconfigured integration (for example a forward-auth middleware that doesn't send the
`X-Forwarded-*` headers); `protocol` an ext_proc or SPOE peer that breaks the protocol. The
engine's log names each one.

### InkwallEnginesBehind

The operator's leader has seen engines that don't run the current bundle for 15 minutes:
`behind` (still on an older one) or `rejected` (they rejected it, see
[InkwallBundleRejected](#inkwallbundlerejected)). A policy reports `Enforced=False` while its
engines are behind. Check the engines' connection to the operator, and their version.

### InkwallWiringFailures

Policy targets have failed to wire for 15 minutes: their routes are not protected. The policies
say why in `Programmed=False`, reason `WiringFailed`:
`kubectl get wafpolicies -A -o wide`.

### InkwallBundleNearSizeLimit

The bundle has been over 80% of a size limit for 10 minutes: 7,200 KiB compressed, or 64 MiB raw
(`inkwall_operator_bundle_raw_bytes`). Changes are still published, but once the bundle with every
change would leave less than `spec.bundle.namespaceShare` of the `InkwallConfig` (25% by default)
of a limit free, a namespace's changes that grow its measured share of the bundle past that share
are held back (never with one namespace, or in a first bundle that fits). Namespaces' changes that
would grow the bundle into `spec.bundle.clusterReserve` (10% of each limit by default) are held
back too: that room is kept for ClusterWAFRuleSet changes, such as a CRS upgrade, which may use it.
Past the limit, or the reserve, changes are held back namespace by namespace until it fits, the
namespace with the largest share first, cluster rule sets after every namespace. Held policies keep their previous version, or
are left out when new, held rule sets ship as they were, and both report `Accepted=False`,
`BundleTooLarge`, with the namespace's share; every other change is still published, and nothing
published is taken out. [InkwallBundleChangesHeld](#inkwallbundlechangesheld) fires while changes
are held. Rules written inline in many policies are the usual cause: put shared rules in one rule
set the policies reference.

### InkwallBundleChangesHeld

For 5 minutes, the published bundle has held back policy or rule set changes, or left out policies
because of them (`inkwall_operator_bundle_held_policies`): engines enforce their previous version,
or don't have them when new or left out. A policy is left out when its previous version, or its
rule set as it was, doesn't compile with a ClusterWAFRuleSet as it is now (a rule id a CRS upgrade
adds, say): that happens only to a namespace held over its share, measured, or whose change doesn't
fit the size limits even alone, with that ClusterWAFRuleSet's change, on the bundle in force, or in
the last resort. Another namespace's change, which adopts the ClusterWAFRuleSet's, is released
before every other namespace's change and may take part of the cluster reserve (4% of each limit,
for all such changes together) if it grows the namespace's share by at most 4% of each limit; a
larger change isn't released first and may not grow the bundle into the reserve. If such changes
don't all fit, the ClusterWAFRuleSet's change waits one build, while those that fit are published
and the other namespaces' changes wait with it (two builds at most per ClusterWAFRuleSet change).
It never waits two builds in a row that way, so then a policy of a namespace still held is left
out; the adopting changes that waited are released first then, and share another 4% of each limit
of the reserve.
`kubectl get wafpolicies,wafrulesets,clusterwafrulesets -A` shows them with `Accepted=False`, reason
`BundleTooLarge`; the message says whether the namespace is over its share of the bundle
(`spec.bundle.namespaceShare`), the bundle with them is over its limit, or namespaces' changes would
grow it into the cluster reserve (`spec.bundle.clusterReserve`), and how much the namespace takes. Shrink that namespace's policies or rule sets. Raising
`spec.bundle.namespaceShare` lets one namespace take more of the bundle, and so leaves less room
for the others' changes; lowering `spec.bundle.clusterReserve` gives the namespaces the room kept for
cluster rule sets.

### InkwallNamespaceOverShare

For 30 minutes, a namespace's content has taken more of the published bundle than its share,
`spec.bundle.namespaceShare` of the `InkwallConfig` (25% of a size limit by default;
`inkwall_operator_bundle_namespace_share_percent`, labeled `policy_namespace`). The share holds
back only a namespace's changes that grow it while the bundle is near full, and never takes out
what was published: a namespace can get there while there was room, or before the share applied.
Such a namespace leaves less room for every other namespace's changes, and for a CRS upgrade beyond
the cluster reserve. Find out why it is so large (`kubectl get wafrulesets,wafpolicies -n
<namespace>`), and shrink it: shared inline rules belong in one rule set the policies reference. A
cluster with few, large namespaces can raise `spec.bundle.namespaceShare` instead.

## Checking it worked

Prometheus' targets page lists the operator's Service and each engine pod as `up`, and this
returns the engines:

```promql
count by (namespace) (inkwall_bundle_version)
```

In Grafana the dashboard is `Inkwall`.

## Turning it off

Set the values back to `false` and upgrade: the chart deletes what it created. Nothing in the
engines or the operator changes.
