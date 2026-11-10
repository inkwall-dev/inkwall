# Monitoring Inkwall

This guide scrapes the operator's and the engines' [Prometheus](https://prometheus.io/docs/introduction/overview/) metrics, installs the
alerts and the [Grafana](https://grafana.com/docs/grafana/latest/) dashboard the chart ships, lists every metric, and says what to
do when an alert fires.

## Contents

- [Prerequisites](#prerequisites)
- [Turn it on](#turn-it-on)
- [Metrics over HTTPS](#metrics-over-https)
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

- **The operator**: `/metrics` on port 8080 (`metrics` in its pods), over plain HTTP, or over HTTPS
  with authentication and authorization ([Metrics over HTTPS](#metrics-over-https)).
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

## Metrics over HTTPS

By default the operator serves `/metrics` over plain HTTP to anything that reaches its port: the
metrics carry no secrets, and `networkPolicy.metricsFrom` can narrow who reaches it. For clusters
that require metrics endpoints behind TLS and authorization, `metrics.secure.enabled=true` serves
them over HTTPS, and only to clients whose bearer token the API server authenticates (a
[TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)) and
allows to `get` the `/metrics` non-resource URL (a
[SubjectAccessReview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access)):

```sh
helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> --namespace inkwall-system --reuse-values \
  --set metrics.secure.enabled=true
```

With it on, the chart:

- runs the operator with `--metrics-secure`, and grants it `create` on `tokenreviews` and
  `subjectaccessreviews` (the `inkwall-operator-metrics-auth` ClusterRole; not granted otherwise);
- creates the `inkwall-operator-metrics-reader` ClusterRole (`get` on `/metrics`), to bind to the
  scrapers;
- makes the ServiceMonitor scrape over HTTPS with Prometheus' service account token
  (`bearerTokenFile`).

Grant your Prometheus' service account the reader role. kube-prometheus-stack's Prometheus role
already allows `get` on `/metrics`; otherwise:

```sh
kubectl create clusterrolebinding inkwall-metrics-prometheus --clusterrole=inkwall-operator-metrics-reader \
  --serviceaccount=monitoring:prometheus-k8s
```

A scrape without a token gets 401, one whose service account lacks the permission 403. An
invalid or expired token is refused with 500 (controller-runtime's filter, which also logs it).
The API server's answers are cached: an allowed scraper for 5 minutes, a denied one for 30
seconds, a token for a minute. The port keeps its name (`metrics`) and number, so
`networkPolicy.metricsFrom` applies as before. The health probes stay on port 8081, over HTTP.

The serving certificate, `metrics.secure.certs.mode`:

| Mode | Certificate | The ServiceMonitor |
|---|---|---|
| `selfSigned` (default) | Made by the operator, in memory, each time it starts | Doesn't verify it (`insecureSkipVerify`): the scrape is encrypted, and the token still checked |
| `certManager` | Issued by [cert-manager](https://cert-manager.io/) (it must be installed) for the `inkwall-operator-metrics` Service, in the Secret `inkwall-operator-metrics-tls`; the operator reloads it when it is renewed | Verifies it, with the Secret's `ca.crt` and the Service's name |

`certManager` uses a self-signed Issuer the chart creates, unless
`metrics.secure.certs.certManager.issuerRef` names yours (`kind: ClusterIssuer`, `name: ...`). With
`selfSigned`, Prometheus would send its token to whatever answers at the operator pods'
addresses: use `certManager` where that matters. The ServiceMonitor's `bearerTokenFile` needs a
Prometheus Operator that allows it (`arbitraryFSAccessThroughSMs.deny` is `false`, the default).

Without the Prometheus Operator, scrape `https://<operator pod>:8080/metrics` with
`authorization: {credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token}` and a
`tls_config` to match the mode. To read the metrics by hand:

```sh
TOKEN=$(kubectl -n monitoring create token prometheus-k8s)
kubectl -n inkwall-system port-forward deploy/inkwall-operator 8080 &
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8080/metrics | head
```

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
| `inkwall_operator_bundle_compressed_bytes` | gauge | | Its size, gzip-compressed: over 900 KiB it is split into chunks, over 7,200 KiB it can't be published. |
| `inkwall_operator_engines` | gauge | `state` | Connected engines by whether they run the current bundle (`current`, `behind`, `rejected`). Leader only. |
| `inkwall_operator_engines_left_out` | gauge | | Engines left out of this replica's engine report (over the ConfigMap limit). |
| `inkwall_operator_events_received_total` | counter | | Security events received from the engines. |
| `inkwall_operator_engine_events_dropped_total` | counter | | Security events the engines reported dropping. |
| `inkwall_operator_wired_targets` | gauge | `integration` | Policy targets wired to the engine. Leader only. |
| `inkwall_operator_wiring_failures` | gauge | `integration` | Policy targets that couldn't be wired (`Programmed: WiringFailed`). Leader only. |
| `inkwall_operator_policies` | gauge | `condition`, `status`, `reason` | WAFPolicies by each condition (`Accepted`, `Programmed`, `Enforced`, `Ready`), its status and reason. Leader only. |
| `inkwall_operator_signing_key_age_seconds` | gauge | | Time since the active bundle signing key began to sign. Leader only. |
| `inkwall_operator_signing_key_rotation_phase` | gauge | `phase` | 1 for the rotation's phase (`Idle`, `Publishing`, `Retiring`), 0 for the others. Leader only. |
| `inkwall_operator_bundle_publish_failures_total` | counter | `reason` | Bundles not published: `too_large` (policy changes wait until it fits), `error` (retried). Leader only. |
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

The bundle is over 80% of the 7,200 KiB it can be, compressed. Past it, policy changes can't be
published (`Accepted=False`, `BundleTooLarge`). Rules written inline in many policies are the
usual cause: put shared rules in one rule set the policies reference.

## Checking it worked

Prometheus' targets page lists the operator's Service and each engine pod as `up`, and this
returns the engines:

```promql
count by (namespace) (inkwall_bundle_version)
```

In Grafana the dashboard is `Inkwall`.

## Turning it off

Set the values back to `false` and upgrade: the chart deletes what it created. Nothing in the
engines or the operator changes, except that `metrics.secure.enabled=false` serves the operator's
metrics over plain HTTP again (the operator restarts).
