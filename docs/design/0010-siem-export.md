# 0010 — Exporting Security Events to a SIEM

- Status: Draft
- Date: 2026-11-20
- Updated: 2026-11-20
- Owner: noureldin
- Depends on: [0002 — System Architecture](0002-system-architecture.md),
  [0004 — Kubernetes Operator](0004-operator.md)

Today a security event goes to the engine's log and, when a control plane is connected, to the
control plane ([0002 §5.3](0002-system-architecture.md#53-operator--saas)). Production users need
the events in their own SIEM: Splunk, Elastic, Loki, Datadog, Sentinel and the like. This document
decides where the export runs, which formats and transports v0.7.0 speaks, the `InkwallConfig`
API, the exported schema, how export lives beside the control plane, its security, what it shows
in metrics and status, and how it is tested. **Nothing here is built yet** (#723).

[Terms](../glossary.md) used here:

- **Engine:** `inkwall-engine`, the process that inspects requests and records security events.
- **Replica:** one pod of the operator's Deployment. **Leader:** the replica that holds the
  leader-election lease.
- **Event:** a `SecurityEvent` (`api/events/v1/events.proto`): one blocked or detected request.
- **SIEM:** a security information and event management system: where security teams search,
  correlate and alert on events.
- **Sink:** one export destination in `InkwallConfig.spec.events.export.sinks`: an endpoint, its
  format, TLS and credentials.
- **Collector:** an [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), which
  receives OTLP and forwards it to almost any backend.

## Contents

- [1. Goals and scope](#1-goals-and-scope)
- [2. Where export runs](#2-where-export-runs)
  - [2.1 The path events take today](#21-the-path-events-take-today)
  - [2.2 From the operator, on every replica](#22-from-the-operator-on-every-replica)
  - [2.3 Rejected: from each engine](#23-rejected-from-each-engine)
  - [2.4 Buffering, loss and restarts](#24-buffering-loss-and-restarts)
- [3. Formats and transports](#3-formats-and-transports)
  - [3.1 OTLP logs](#31-otlp-logs)
  - [3.2 JSON over HTTP](#32-json-over-http)
  - [3.3 Syslog, deferred](#33-syslog-deferred)
  - [3.4 Recipes per SIEM](#34-recipes-per-siem)
- [4. API](#4-api)
  - [4.1 Fields](#41-fields)
  - [4.2 Credentials and TLS](#42-credentials-and-tls)
  - [4.3 Batching, retries and backpressure](#43-batching-retries-and-backpressure)
  - [4.4 Filtering and redaction](#44-filtering-and-redaction)
  - [4.5 Validation](#45-validation)
- [5. Event schema](#5-event-schema)
  - [5.1 JSON](#51-json)
  - [5.2 OTLP](#52-otlp)
  - [5.3 Versioning](#53-versioning)
- [6. Beside the control plane](#6-beside-the-control-plane)
- [7. Security](#7-security)
- [8. Observability](#8-observability)
- [9. Testing](#9-testing)
- [10. Decisions](#10-decisions)
- [11. Open questions](#11-open-questions)

## 1. Goals and scope

**In v0.7.0:**

- `InkwallConfig.spec.events.export`: up to 4 sinks, each OTLP logs (gRPC or HTTP) or JSON over
  HTTP(S) ([§3](#3-formats-and-transports), [§4](#4-api)).
- Export runs in the operator, on every replica, from the events it already receives
  ([§2](#2-where-export-runs)). Engines don't change and get no egress.
- A bounded buffer per replica: a slow or down sink drops the oldest events and counts them; it
  never blocks a request, an engine's stream or the control plane's forwarding
  ([§4.3](#43-batching-retries-and-backpressure)).
- The redaction engines already apply is the most an exported event carries; a sink can only
  leave out more ([§4.4](#44-filtering-and-redaction)).
- A versioned schema with stable field names ([§5](#5-event-schema)).
- Metrics per sink, and an `EventsExported` condition on the `InkwallConfig`
  ([§8](#8-observability)).
- A guide with a recipe per common SIEM ([§3.4](#34-recipes-per-siem)), and an e2e test on kind
  against a Collector and a small HTTP sink ([§9](#9-testing)).

**Later, not in v0.7.0:**

- Syslog ([RFC 5424](https://www.rfc-editor.org/rfc/rfc5424)) over TCP or TLS
  ([§3.3](#33-syslog-deferred)).
- Exporting request counts (`RequestStats`) as OTLP metrics: Prometheus already has them.
- Sinks owned by a namespace's team rather than the cluster admin ([open question 4](#11-open-questions)).
- Export from an engine that runs without an operator (the standalone proxy). Its JSON log lines
  ([0002 §8.5](0002-system-architecture.md#85-observability)) are already shippable by any log
  agent; the guide says how.

## 2. Where export runs

### 2.1 The path events take today

1. The engine turns each verdict that isn't `allow` into a `SecurityEvent`, redacted
   (`pkg/events/events.go`, [0002 §8.3](0002-system-architecture.md#83-data-privacy)), and adds
   it to a bounded ring of 10,000 events that drops the oldest when full (`pkg/events/buffer.go`,
   `DefaultCapacity`).
2. The agent sends batches of at most 1,000 events on its `Watch` stream to whichever replica it
   is connected to (`api/agent/v1`, `WatchRequest.events`). Engines connect to any replica through
   the Service ([0004 §4.7](0004-operator.md#47-distribution-server-all-replicas)).
3. The replica stamps each event with the engine and pod of the authenticated stream, not what the
   event claims (`Server.events`, `operator/internal/distribution/server.go`), and hands the batch
   to `Server.Events`.
4. `Server.Events` is `Forwarder.Add` (`operator/manager/manager.go`, `addDistribution`). Every
   replica runs a `Forwarder` (`NeedLeaderElection` is false,
   `operator/internal/controlplane/forwarder.go`). While the control plane accepts events, it puts
   them in a bounded queue, on disk under `--events-dir` when set, and sends them on the replica's
   own events stream. Otherwise it drops them: the engines' logs are the record.

So every event already arrives, redacted and authenticated, at exactly one replica, and a hook
exists that sees each batch once.

### 2.2 From the operator, on every replica

**Decision:** export runs in the operator. Each replica exports the events of the engines
connected to it, as the `Forwarder` does for the control plane. `Server.Events` becomes a fan-out:
`Forwarder.Add` and `Exporter.Add`, both of which treat the batch as read-only.

- **No leader.** Events are already split between replicas by engine connection. Exporting from the
  leader only would need the other replicas to relay events to it: a new protocol between replicas
  ([0004 §12](0004-operator.md#12-open-questions), question 4), and a single replica carrying the
  whole cluster's events. Each replica exporting its own share scales with replicas and loses
  only its share when it stops.
- **Fan-in load.** At the scale target of 500 engines
  ([0004 §8](0004-operator.md#8-scale-targets-v1)), the operator receives at most what engines
  send: each engine's ring drops its oldest past 10,000, so a flood is cut in the engine, not in
  the operator. The new work per event is one encoding (JSON or OTLP, about 1 KiB) and its share of
  a gzip-compressed HTTP request. Target: 10,000 events per second per replica per sink at under
  half a CPU, measured by the benchmark of [§9](#9-testing) before the defaults are final.
- **Order.** Events from one engine keep their order on one replica. An engine that reconnects to
  another replica continues there, so across replicas only the event's `time` orders them. SIEMs
  sort by time anyway.

### 2.3 Rejected: from each engine

Each engine could send its events straight to the SIEM. Rejected:

- **Engines have no egress, by design.** "The control plane talks only to operators, never to
  engines. That means fewer connections, no egress from engines"
  ([0002 §3.4](0002-system-architecture.md#34-control-plane-optional), decision D4 of
  [0002 §11](0002-system-architecture.md#11-decisions-adr-log)). An engine runs in the proxy's
  pod, in the proxy's namespace; letting it reach a SIEM opens egress from every proxy pod, in
  namespaces the chart doesn't own and can't write NetworkPolicies for
  ([0004 §7](0004-operator.md#7-rbac)).
- **Credentials in every proxy pod.** The SIEM's token would have to reach each engine: either in
  the bundle, which every engine's ServiceAccount can read and which is not a secret, or as a
  Secret mounted in every proxy pod.
- **N connections.** 500 engines means 500 TLS connections and 500 small batch streams to the
  SIEM, instead of one or two per replica.
- **The hot process.** TLS, retries and encoding would run beside the inspection, competing with it
  for the engine's CPU and memory, which the latency budgets of
  [0001](0001-performance-first-architecture.md) are about.
- **Configuration.** Sink changes would have to reach the engines through the bundle, adding fields
  older engines ignore without saying so.

What the engine path would have given: events still flowing while every replica is down. The
engine's ring already holds 10,000 events while its operator is away, and a replica outage longer
than that is visible in `inkwall_engine_events_dropped_total`.

### 2.4 Buffering, loss and restarts

Each replica has **one export buffer** shared by all its sinks: a log of batches with a cursor per
sink. A batch is freed once every sink has passed it. When the buffer is full, the oldest batch is
dropped; a sink whose cursor hadn't reached it counts its events as dropped (`reason="buffer_full"`).
So a dead sink costs memory up to the bound, and a healthy sink never loses events because
another is down: it has sent them already.

- **Bound:** `--export-buffer-bytes` (default 32 MiB; chart `events.export.bufferMiB`). It is an
  operator flag, not an `InkwallConfig` field, for two reasons. The buffer is in memory, and the
  operator's memory limit (512 MiB by default, with peaks of about 518 MiB at the largest scale
  test, [0004 §8](0004-operator.md#8-scale-targets-v1)) is the chart's. And its disk copy lives in
  the `events` emptyDir, whose `sizeLimit` the chart computes
  (`deploy/helm/inkwall/templates/deployment.yaml`): a bound set in the CRD could exceed it, and
  the kubelet evicts a pod whose emptyDir passes its limit. The chart adds the export buffer to
  the emptyDir's `sizeLimit` and says to add it to `limits.memory` at large scale.
- **On disk.** The buffer is written to `--events-dir/export`, as the control plane's queue is
  (`operator/internal/controlplane/queue.go`): a file per batch, a random buffer ID, oldest
  dropped first. The writes happen on the export goroutine, not on the engine's stream. A
  container restart (a crash, an OOM kill) keeps the emptyDir, and the replica sends what was left.
  A pod deletion (a rollout, a drain) loses it.
- **Shutdown.** On SIGTERM a replica keeps serving for `--shutdown-delay` (5 s,
  `cmd/operator/main.go`); the exporter uses that time to flush what it can, then stops.
- **Delivery:** at least once per sink while the buffer holds the event. A retry after a timeout
  or a restart can send an event twice. `event_id` is a ULID, unique per event: the guide shows
  how each SIEM deduplicates on it, where it can.

Rejected:

- **A buffer per sink.** Four sinks would multiply the memory by four for the same events.
- **Sharing the control plane's queue.** Its batches are acknowledged by the control plane with
  sequence numbers and buffer IDs ([0002 §5.3](0002-system-architecture.md#53-operator--saas)),
  and it holds events only while the control plane accepts them. Tying the SIEM to that lifecycle
  would let a control plane outage, or a control plane that refuses events, decide what reaches
  the SIEM. A shared log with one more cursor is [open question 6](#11-open-questions).
- **Memory only.** Simpler, but loses the buffer on every crash, which the control plane's path
  already avoids at the same cost.

## 3. Formats and transports

**Decision:** two formats in v0.7.0: **OTLP logs** (gRPC, or HTTP with protobuf) and **JSON over
HTTP(S)** (one event per line, or a JSON array). Syslog waits ([§3.3](#33-syslog-deferred)).

### 3.1 OTLP logs

[OTLP](https://opentelemetry.io/docs/specs/otlp/) is the one protocol every major backend now takes,
directly or through a Collector, and the Collector reaches the rest. Requests are
`ExportLogsServiceRequest` messages, sent as gRPC (`LogsService/Export`) or as an HTTP `POST` of
the protobuf body (`Content-Type: application/x-protobuf`), gzip-compressed. Both report
[partial success](https://opentelemetry.io/docs/specs/otlp/#partial-success), counted as rejected
events.

The operator builds the messages with `go.opentelemetry.io/proto/otlp`, already in `go.mod`
(indirect), and its existing gRPC stack. It doesn't use the OpenTelemetry SDK's log pipeline: that
has its own batching and queue, which would sit on top of the buffer of
[§2.4](#24-buffering-loss-and-restarts) and hide its drops.

OTLP over HTTP with a JSON body is not offered: every OTLP receiver must accept protobuf, and one
encoding is less to test.

### 3.2 JSON over HTTP

A `POST` of the events in the schema of [§5.1](#51-json), gzip-compressed, in one of two framings:

- **`Lines`** ([NDJSON](https://github.com/ndjson/ndjson-spec), `application/x-ndjson`): one event
  per line. Splunk's HEC raw endpoint, Logstash's `http` input, Vector and Fluent Bit take it.
- **`Array`** (`application/json`): one JSON array. Datadog's HTTP logs intake, Sumo Logic and most
  webhook-style receivers take it.

Every attacker-controlled field is a JSON string, so a newline in a path or user agent is escaped
(`\n`) and can't start a fake event in `Lines`. The encoder's fuzz test checks it
([§9](#9-testing)).

A vendor envelope (Splunk's HEC `event` wrapper, Loki's push streams) is not built in: each would
be a format to keep and test per vendor. The vendors that need one take OTLP ([§3.4](#34-recipes-per-siem)).

### 3.3 Syslog, deferred

[RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) over TLS ([RFC 5425](https://www.rfc-editor.org/rfc/rfc5425))
is what older SIEMs (QRadar, ArcSight) collect natively. Deferred, because:

- **No acknowledgement.** A TCP or TLS syslog sender learns nothing about what the receiver
  processed: a connection that drops loses what was in flight, silently. The at-least-once
  delivery and the `failed` and `rejected` counts of [§8](#8-observability) can't be kept.
- **Size.** Receivers need only accept 2,048 octets per message (RFC 5424 §6.1), and many
  truncate there. An event with 32 matches is larger.
- **Escaping.** Events carry attacker-controlled text; structured data needs its own escaping
  (`]`, `"`, `\`) and framing (octet counting, RFC 6587), each a new place to get injection wrong.

A Collector with its [syslog exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/syslogexporter)
covers these SIEMs today ([§3.4](#34-recipes-per-siem)). Native syslog is
[open question 1](#11-open-questions), to decide from the users who ask.

### 3.4 Recipes per SIEM

The guide (`docs/siem-export.md`, written with the implementation) has one recipe per row, each
checked against the product's current documentation when written. CI tests only the Collector and
the HTTP sink ([§9](#9-testing)).

| SIEM | Sink | Notes |
|---|---|---|
| Any, through a Collector | `otlp`, gRPC or HTTP, to the Collector's OTLP receiver | The general answer: the Collector has exporters for most backends, and can batch, filter and route further |
| Splunk | `json`, `Lines`, to HEC's `/services/collector/raw?sourcetype=_json` | Header `Authorization: Splunk <token>` from the Secret. Or a Collector with the `splunk_hec` exporter |
| Elastic | `otlp` to Elastic's OTLP intake (APM Server or the Elastic Distribution of the Collector) | Or `json`, `Lines`, to Logstash's `http` input. Deduplicate by setting the document `_id` to `event_id` in the pipeline |
| Grafana Loki (3.0 and later) | `otlp`, HTTP, to `/otlp/v1/logs` | Loki keeps resource attributes as labels; the guide lists which to keep as labels (cluster, namespace), never `client.address` |
| Datadog | `otlp` to the Datadog Agent's OTLP receiver, or a Collector with the `datadog` exporter | Or `json`, `Array`, to the HTTP logs intake with `DD-API-KEY` from the Secret |
| Microsoft Sentinel | A Collector with the Azure Monitor exporter | |
| QRadar, ArcSight and other syslog receivers | A Collector with the syslog exporter | [§3.3](#33-syslog-deferred) |
| Vector, Fluent Bit, Logstash | `json`, `Lines`, to their HTTP input | Then anywhere they route |

## 4. API

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  events:
    redact: {...}                           # unchanged: applied in the engines
    export:
      clusterName: prod-eu-1                # optional, in every event
      sinks:
        - name: collector                   # DNS label: in metrics and status
          otlp:
            endpoint: grpc://otel-collector.observability:4317
          insecure: true                    # plaintext: an in-cluster Collector
        - name: splunk
          json:
            url: https://splunk.example.com:8088/services/collector/raw?sourcetype=_json
            framing: Lines
          headersSecretRef: {name: splunk-hec}    # in the operator's namespace
          tls:
            caSecretRef: {name: splunk-ca}
          batch: {maxEvents: 500, maxDelay: 5s}
          filter:
            actions: [Deny]
            policyNamespaces: [shop, payments]
          omit: [Snippets]
```

### 4.1 Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `export.clusterName` | DNS subdomain, ≤ 253 | — | A name for the cluster in every event, beside its ID ([§5](#5-event-schema)) |
| `export.sinks` | list, ≤ 4 | none | No sinks: no export (the default) |
| `sinks[].name` | DNS label, ≤ 63 | required | Unique; the `sink` label of the metrics and the name in the condition |
| `sinks[].otlp.endpoint` | URL, ≤ 512 | — | `grpcs://host:port` or `grpc://` for gRPC; `https://…` or `http://…` for HTTP, used as is (OTLP/HTTP's path, usually `/v1/logs`, is part of it) |
| `sinks[].json.url` | URL, ≤ 2048 | — | `https://…` or `http://…`, with any path and query |
| `sinks[].json.framing` | `Lines`, `Array` | `Lines` | [§3.2](#32-json-over-http) |
| `sinks[].insecure` | bool | false | Allows a plaintext `http://` or `grpc://` endpoint |
| `sinks[].tls.caSecretRef.name` | Secret name | system roots | A Secret with `ca.crt`: the CAs trusted for the server |
| `sinks[].tls.clientCertificateSecretRef.name` | Secret name | — | A `kubernetes.io/tls` Secret: the client certificate for mTLS |
| `sinks[].tls.serverName` | DNS name | the URL's host | The name checked in the server's certificate |
| `sinks[].headersSecretRef.name` | Secret name | — | Each key a header name, each value its value ([§4.2](#42-credentials-and-tls)) |
| `sinks[].batch.maxEvents` | 1–1,000 | 500 | Events per request at most |
| `sinks[].batch.maxDelay` | duration, 100ms–60s | 5s | The longest an event waits for its batch to fill |
| `sinks[].timeout` | duration, 1s–60s | 10s | One request's deadline |
| `sinks[].filter.actions` | `Deny`, `Log` (a set) | both | Which events this sink takes |
| `sinks[].filter.policyNamespaces` | namespace list, ≤ 64 | all | Only events of policies in these namespaces |
| `sinks[].omit` | `Snippets`, `ClientIP`, `UserAgent`, `RequestID` (a set) | none | Fields this sink never gets ([§4.4](#44-filtering-and-redaction)) |

Exactly one of `otlp` and `json` per sink. The export config doesn't go into the bundle: engines
need nothing from it, and bundles keep their content hash.

The sinks are under `spec.events`, beside `redact`, because both decide what leaves the cluster
and the guide documents them together. A separate CRD (`WAFEventSink`) was rejected for v0.7.0:
there is one cluster-wide answer to "where do events go", and the `InkwallConfig` is where the
cluster admin already gives it for the control plane. A namespaced kind is
[open question 4](#11-open-questions).

### 4.2 Credentials and TLS

Credentials are never in the CR. The `InkwallConfig` is read by anyone with read access to it, is
in Git in GitOps setups, and its spec travels to the control plane in `ClusterState`
([0002 §5.3](0002-system-architecture.md#53-operator--saas)).

- **Headers from a Secret.** `headersSecretRef` names a Secret whose keys are header names and
  whose values are the headers' values: `Authorization: Bearer …`, `Authorization: Splunk …`,
  `DD-API-KEY: …`. One mechanism covers bearer tokens, basic auth and API keys. For gRPC the
  headers become metadata, lower-cased. Keys that aren't HTTP tokens, and `Host`, `Content-Type`,
  `Content-Length`, `Content-Encoding`, `Transfer-Encoding` and `Connection`, are refused
  ([§4.5](#45-validation)).
- **Secrets in the operator's namespace only.** The references carry a name, no namespace. The
  operator may read Secrets only in its own namespace (`operator/webhook/certs.go`'s RBAC marker,
  [0004 §7](0004-operator.md#7-rbac)), and the control plane's enrollment token is already held to
  that rule (`ReasonTokenSecretElsewhere`, `operator/internal/controlplane/connector.go`). A
  namespace field that must always equal one value would be a trap; it was rejected.
- **Rotation.** The operator watches its namespace's Secrets already; a changed Secret takes effect
  on the next request, with no restart. A missing Secret or key stops that sink only
  ([§8](#8-observability)).
- **TLS.** TLS 1.2 or later, Go's defaults. The server's certificate is always verified: there is
  no `insecureSkipVerify`. A self-signed SIEM gets its CA in `caSecretRef`. Plaintext needs
  `insecure: true`, meant for a Collector in the cluster, and the condition's message says the sink
  is plaintext.

### 4.3 Batching, retries and backpressure

The rule of [0001 §2](0001-performance-first-architecture.md#2-where-latency-comes-from-and-how-we-kill-each-source):
drop events, never apply backpressure.

- **Add never blocks.** `Exporter.Add` runs on the goroutine that reads an engine's stream. It
  appends the batch to the buffer under a mutex and returns; a full buffer drops the oldest
  ([§2.4](#24-buffering-loss-and-restarts)). A sink that is slow, down or refusing never slows the
  stream, so engines never fill their own ring because of a SIEM, and the control plane's
  forwarding is untouched.
- **One sender per sink.** Each sink has one goroutine that reads from its cursor, filters
  ([§4.4](#44-filtering-and-redaction)), encodes up to `maxEvents` events, and sends when the batch
  is full or `maxDelay` has passed since its first event. One request in flight per sink keeps the
  order and the memory simple; at 500 events a request, that is enough for the target of
  [§2.2](#22-from-the-operator-on-every-replica). A request body is at most 4 MiB before
  compression (gRPC's default message limit), cut with `events.Split` (`pkg/events/split.go`).
- **Retries** with exponential backoff and full jitter, from 1 s to 60 s, for as long as the
  buffer holds the batch:
  - retried: connection and TLS errors, timeouts, HTTP 408, 429, 502, 503, 504; gRPC
    `UNAVAILABLE`, `RESOURCE_EXHAUSTED`, `DEADLINE_EXCEEDED`, `ABORTED`. A `Retry-After` header,
    or OTLP's `RetryInfo`, sets the next wait, capped at 5 min;
  - HTTP 401 and 403, gRPC `UNAUTHENTICATED` and `PERMISSION_DENIED`: retried at the slowest
    pace, since a fixed Secret should resume the flow without losing what waited;
  - HTTP 413: the batch is split in half and retried; a single event refused is dropped
    (`reason="too_large"`);
  - any other 4xx, gRPC `INVALID_ARGUMENT`, and OTLP's partial success: the refused events are
    dropped (`reason="rejected"`), because sending them again gets the same answer.
- **No redirects.** A 3xx is a failure, not followed ([§7](#7-security)).
- **Responses** are read up to 4 KiB, for the error class and a short message; the body is never
  logged in full or put in status.

### 4.4 Filtering and redaction

Redaction stays where it is: in the engine, before the event leaves it
([0002 §8.3](0002-system-architecture.md#83-data-privacy); `events.redact` reaches engines in the
bundle). The operator passes events on as they come, so an exported event carries no more than
what the control plane gets, and never a body, a query string, a cookie or a credential-looking
value. The exporter adds only what the operator knows: the cluster's ID and name, and the time it
received the event.

A sink can leave out more, never put back:

- **`omit`:** `Snippets` (keep the rule and variable, not the up to 64 bytes matched),
  `ClientIP`, `UserAgent`, `RequestID`. For a SIEM outside the jurisdiction where personal data
  may go, or one that only needs counts per rule.
- **`filter.actions`:** `Deny` only, for a SIEM that alerts and doesn't want `Detect`-mode noise.
- **`filter.policyNamespaces`:** only the events of some teams' policies, for a team's own SIEM.
  The namespace is the policy's (`SecurityEvent.policy` is `namespace/name`); an event with no
  policy is sent only to sinks without this filter.

Filters are applied by the sender, per sink, after the shared buffer: one buffer holds every event
once, whatever the filters.

Rejected: engine-wide `events.redact` fields for export only. Redaction is configured once and
applies to every destination; per-destination differences belong to the destination.

### 4.5 Validation

Schema and CEL, the first step of [0004 §3.1](0004-operator.md#31-validation):

- `sinks`: at most 4, names unique (the `exists_one` pattern of `targetRefs`); exactly one of
  `otlp` and `json`.
- `otlp.endpoint`: `^(grpcs?|https?)://[^/\s]+(/\S*)?$`, and no path for `grpc`/`grpcs`;
  `json.url`: `^https?://[^/\s]+(/\S*)?$`. No user info (`user:pass@`) in either: credentials go in
  the Secret.
- `http://` and `grpc://` only with `insecure: true`.
- Durations: `duration(self) >= duration('100ms') && duration(self) <= duration('60s')`, the
  pattern of `WAFPolicy`'s `timeout` (`operator/api/v1alpha1/wafpolicy_types.go`).
- `policyNamespaces`: DNS labels, a set.

What the schema can't see is checked when the sink starts and reported in the condition
([§8](#8-observability)): the Secrets exist and hold valid keys, the CA parses, the client
certificate matches its key.

## 5. Event schema

The exported event is the `SecurityEvent` of [0002 §5.4](0002-system-architecture.md#54-event-schema),
with three additions from the operator: `cluster.id` (the `kube-system` Namespace's UID, which
already identifies the cluster to the control plane, `operator/internal/controlplane/connector.go`),
`cluster.name` (`export.clusterName`, if set) and `observed_time` (when the replica received it).

Field names are stable within a schema version ([§5.3](#53-versioning)). Enums are written as the
engine's lower-case strings (`pkg/pipeline/verdict.go`: `deny`, `log`; `rule`, `ip-deny`,
`overload`, ...), never as numbers. A field the engine didn't set (an older engine) is left out,
not written as zero.

### 5.1 JSON

```json
{
  "schema": "inkwall.dev/security-event/v1",
  "event_id": "01JD3Q4Z8M2N5X7Y9A1B3C5D7E",
  "time": "2026-11-20T10:15:02.123456Z",
  "observed_time": "2026-11-20T10:15:02.401Z",
  "cluster": {"id": "6f1c…", "name": "prod-eu-1"},
  "engine": {"id": "01JD…", "namespace": "traefik", "pod": "traefik-7d9c…"},
  "policy": {"namespace": "shop", "name": "web", "bundle_version": 42},
  "action": "deny",
  "reason": "rule",
  "status": 403,
  "rule_id": 949110,
  "anomaly_score": 25,
  "matches": [{"rule_id": 942100, "variable": "ARGS:id", "snippet": "1' OR '1'='1"}],
  "phase": "request",
  "protocol": "http",
  "request": {
    "id": "a1b2c3", "method": "GET", "host": "shop.example.com", "path": "/search",
    "client_ip": "203.0.113.7", "user_agent": "curl/8.10.1"
  },
  "latency_seconds": 0.00042
}
```

| JSON field | `SecurityEvent` field |
|---|---|
| `event_id`, `time` | `event_id`, `time` (RFC 3339, UTC, microseconds) |
| `engine.id`, `.namespace`, `.pod` | `engine_id`, `pod_namespace`, `pod_name` (set by the operator from the stream) |
| `policy.namespace`, `.name`, `.bundle_version` | `policy` split at `/`, `bundle_version` |
| `action`, `reason`, `status` | `action`, `reason`, `status` |
| `rule_id`, `anomaly_score`, `matches[]` | `interrupting_rule_id` (left out when 0), `anomaly_score`, `matches` |
| `phase`, `protocol` | `phase`, `protocol` (left out when unspecified) |
| `request.*` | `request_id`, `method`, `host`, `path`, `client_ip`, `user_agent` |
| `latency_seconds` | `latency` |

`snake_case` and nesting, rather than [ECS](https://www.elastic.co/guide/en/ecs/current/index.html)
or another vendor's names: the schema is Inkwall's own, documented once, and each SIEM maps it in
its pipeline (the guide gives the mapping for ECS and Splunk's CIM). Mapping to a vendor schema in
the operator would tie the format to that vendor's releases.

### 5.2 OTLP

One `LogRecord` per event, grouped in a `ResourceLogs` per engine pod:

- **Resource:** `service.name=inkwall-engine`, `k8s.cluster.uid`, `k8s.cluster.name`,
  `k8s.namespace.name`, `k8s.pod.name`, the
  [semantic conventions](https://opentelemetry.io/docs/specs/semconv/resource/k8s/) for
  Kubernetes.
- **Scope:** `inkwall.dev/events`, version `1` (the schema version).
- **Record:** `time_unix_nano` from `time`, `observed_time_unix_nano` from `observed_time`,
  `event_name` `inkwall.security_event`, severity `WARN` for `deny` and `INFO` for `log` (the
  engine logs events at Warn, `operator/api/v1alpha1/inkwallconfig_types.go`'s `logLevel` docs),
  and a short body: `deny 403 rule 949110 GET shop.example.com/search`.
- **Attributes:** the semantic conventions where one exists: `http.request.method`,
  `server.address` (host), `url.path`, `client.address`, `user_agent.original`,
  `http.response.status_code`. The rest under `inkwall.`, with the names of §5.1:
  `inkwall.event_id`, `inkwall.policy`, `inkwall.action`, `inkwall.reason`, `inkwall.rule_id`,
  `inkwall.anomaly_score`, `inkwall.request_id`, `inkwall.bundle_version`, `inkwall.phase`,
  `inkwall.protocol`, `inkwall.latency_seconds`, and `inkwall.matches` as an array of maps.

Events' strings are valid UTF-8 already: they crossed the engine's stream as proto3 strings, which
Go's protobuf checks on marshal.

### 5.3 Versioning

- The version is in every event: `schema` in JSON, the scope version in OTLP.
- Within v1, fields are only added. A rename, a removal or a change of meaning is v2.
- New `SecurityEvent` fields (the rate limit's name, for example) appear in the export in the
  release that adds them, under new names; old fields keep theirs.
- A v2 would be opt-in per sink first (a `schemaVersion` field added then), with v1 kept for at
  least two minor releases, as the API's own fields are.
- A golden test fixes v1's field names ([§9](#9-testing)), so a rename fails CI rather than a
  user's saved searches.

## 6. Beside the control plane

**Decision:** export and the control plane are independent, and both may run at once, in every
mode.

- The fan-out of [§2.2](#22-from-the-operator-on-every-replica) gives each the same batches. Each
  has its own buffer, bound and metrics; neither waits for the other. A control plane that refuses
  events (`Welcome`) doesn't affect export, and a dead sink doesn't affect the control plane.
- In Managed mode the control plane writes policies, never the `InkwallConfig`: policy snapshots
  take only `WAFPolicy` and the rule set and IP list kinds
  ([0002 §5.3](0002-system-architecture.md#53-operator--saas)). So sinks are always the cluster
  admin's, and a control plane can't add a destination for the cluster's events. This is kept as
  a rule: if a future control plane manages the `InkwallConfig`, `spec.events.export` stays out of
  what it may write.
- The control plane sees the sinks' configuration (names, endpoints, filters; never Secrets) in
  `ClusterState`, and their health in the `EventsExported` condition, as it sees every other
  condition.

Rejected: export only in Standalone mode, as 0002 §5.3 once sketched ("in Standalone mode, events
go to logs and optionally to OTLP"). Teams with a control plane still have a SIEM, and the SIEM is
where their security team works.

## 7. Security

Only cluster admins can edit the `InkwallConfig`: it is cluster-scoped, named `default`, and the
chart grants no one else write access to it. Export still gives that role new reach from the
operator's network position, which is documented and narrowed:

- **Exfiltration.** Whoever can edit the `InkwallConfig` can send events to an address of their
  choice. They can already read the engines' logs; events carry no more ([§4.4](#44-filtering-and-redaction)).
  The guide says so, and audit logging of `InkwallConfig` changes is the control.
- **Requests from the operator's address (SSRF).** The operator can reach in-cluster Services and,
  on many clouds, the instance metadata service. The exporter only `POST`s to the configured URL,
  but a hostile endpoint could aim at an internal service and read its errors through status. So:
  - the dialer refuses loopback, link-local (`169.254.0.0/16`, `fe80::/10`, which holds the
    metadata services) and unspecified addresses, checked on the resolved address at connect time
    (a `net.Dialer.Control`), so DNS rebinding can't get around it. Private ranges stay allowed:
    in-cluster Collectors live there;
  - no redirects are followed ([§4.3](#43-batching-retries-and-backpressure));
  - status and logs carry the HTTP status, the gRPC code or an error class, and at most 128 bytes
    of the response, escaped: enough to fix a token, not enough to read a service;
  - the operator's own ServiceAccount token is never sent: headers come only from the named Secret.
- **NetworkPolicy.** The chart's egress policy is opt-in (`networkPolicy.egress.enabled`,
  `deploy/helm/inkwall/templates/networkpolicy.yaml`) and allows DNS, the API server and
  `networkPolicy.egress.extra`. The chart can't know the sinks (they are in the `InkwallConfig`, not
  its values), so with egress enabled each sink needs an entry in `extra`, as the control plane
  does today. The chart README's Network flows table gets a row: the operator to each sink, only
  when `spec.events.export` has sinks. A sink blocked by a policy shows as connection timeouts in
  the condition. Engines' egress doesn't change: none.
- **Secrets.** Read only from the operator's namespace, never logged, never in status, metrics or
  `ClusterState`. Header values are held in memory only while the sink runs.
- **Attacker-controlled content.** Paths, hosts, user agents, request IDs and snippets come from
  the client. The encoders escape them for their format (JSON strings, protobuf), and the guide
  tells SIEM users to treat them as untrusted in dashboards, as the contract already says for
  every consumer (`api/events/v1/events.proto`: "must be escaped wherever they are shown").

## 8. Observability

**Metrics** (operator, per replica; names in the style of `docs/monitoring.md`, beside
`inkwall_operator_events_forwarded_total`; `sink` is bounded by the 4 sinks):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inkwall_operator_events_exported_total` | counter | `sink` | Events the sink accepted |
| `inkwall_operator_events_export_dropped_total` | counter | `sink`, `reason` | Events never delivered: `buffer_full`, `rejected` (a 4xx or partial success), `too_large` |
| `inkwall_operator_events_export_failures_total` | counter | `sink`, `kind` | Failed requests, retried or not: `network`, `tls`, `timeout`, `auth`, `throttled`, `server`, `client` |
| `inkwall_operator_events_export_pending` | gauge | `sink` | Events in the buffer the sink hasn't sent yet |
| `inkwall_operator_events_export_buffer_bytes` | gauge | | The export buffer's size |
| `inkwall_operator_events_export_last_success_timestamp_seconds` | gauge | `sink` | When the sink last accepted a request (0: never) |
| `inkwall_operator_events_export_request_duration_seconds` | histogram | `sink` | Time per request, retries apart |

Events filtered out by a sink aren't counted: that is configuration, not loss. A new alert,
`InkwallEventExportFailing`, fires when a sink has pending events and no success for 15 minutes,
or when `buffer_full` drops continue for 15 minutes, with a runbook in `docs/monitoring.md`.
`docs/monitoring.md` must list each metric (`make docs-check`, `-metrics-doc`).

**Status.** A new condition on the `InkwallConfig`, `EventsExported`:

| Status | Reason | When |
|---|---|---|
| True | `Exporting` | Every sink on every replica succeeded in the last 5 minutes, or has had nothing to send |
| False | `ExportFailing` | A sink on some replica has failed for 5 minutes without a success; the message names the sink, the replica and the last error class |
| False | `ExportConfigInvalid` | A sink can't start: a missing Secret or key, a CA that doesn't parse, a refused header name |
| False | `ExportDropping` | A sink dropped events for a full buffer in the last 5 minutes while still succeeding (it can't keep up) |

No condition when there are no sinks. The state is per replica, and only the leader writes the
`InkwallConfig`'s status, so each replica reports its sinks' state in the engine report ConfigMap
it already publishes (`Publisher`, `operator/internal/distribution/runtime.go`;
`operator/enginereport`), and the leader's status aggregator
([0004 §4.8](0004-operator.md#48-status-aggregator)) folds them into the condition, the way it
counts engines across replicas. `docs/troubleshooting.md` gets each reason (`-reasons-doc`).

`inkwallctl status` prints the condition and each sink's pending count.

## 9. Testing

| Layer | What | Where |
|---|---|---|
| Unit | The buffer: cursors per sink, a slow sink losing only its own events, the bound in bytes, drop-oldest, reload from disk after a restart, torn files | new `operator/internal/export` |
| Unit | Each sender with a fake clock and a fake server: batching by size and delay, `Split` at 4 MiB, the retry table of [§4.3](#43-batching-retries-and-backpressure) (each status and gRPC code), `Retry-After` and `RetryInfo`, 413 halving, partial success, no redirect followed, response read capped | `operator/internal/export` |
| Unit | `Add` never blocks: a sink that never answers, with the stream's `Add` timed under `-race` | `operator/internal/export` |
| Unit | Filters and `omit`; the dialer guard (loopback, link-local, IPv4-mapped IPv6, a name that resolves to 169.254.169.254); headers from a Secret (refused names), Secret rotation | `operator/internal/export` |
| Unit | Golden files for JSON (both framings) and OTLP, from the events in `pkg/events/testdata`; a field-list golden that fails on any v1 rename; an event from an engine before 0.4.0 (no phase, no protocol) | `operator/internal/export/testdata` |
| Unit | CRD validation: each CEL rule accepted and refused; the condition's reasons from replica reports | `operator/api/v1alpha1/validation_test.go`, `operator/internal/distribution` |
| Fuzz | `FuzzEncodeJSON`: any `SecurityEvent` (from fuzzed protobuf) encodes to valid JSON, one line in `Lines` (no raw newline from any field), and decodes back to the same fields | `operator/internal/export` |
| Fuzz | `FuzzEncodeOTLP`: any event encodes, marshals and unmarshals to the same attributes | `operator/internal/export` |
| Benchmark | Encode per event (JSON, OTLP) and a full 500-event batch with gzip: allocations bounded, and the throughput target of [§2.2](#22-from-the-operator-on-every-replica) | `operator/internal/export` |
| e2e on kind | `hack/kind/export-e2e.sh`: an OTel Collector (pinned image, OTLP receivers, file exporter) and a small HTTP sink (`operator/test/eventsink`, in the style of `operator/test/stubcontrolplane`: records requests, checks headers, can be told to answer 503, 429 with `Retry-After`, or hang). An attack through Traefik reaches both with the cluster ID, policy, rule IDs and request ID; a `password` argument's snippet is absent; `omit` and filters hold; a rotated header Secret is used without restart; the condition goes `ExportFailing` and back; both a control plane stub and a sink receive the same events | `hack/kind` |
| e2e on kind | `hack/kind/networkpolicy-e2e.sh`: with egress enabled, the sink works only once listed in `extra` | `hack/kind` |
| Soak | `hack/kind/soak.sh` with a sink that fails half the time, then is down for 10 minutes: operator memory stays under its limit with the buffer full, drops are counted, the engines' `inkwall_engine_events_dropped_total` stays at 0, request p99 doesn't move, and the backlog drains once the sink is back | `hack/kind/soak.sh` |

## 10. Decisions

| # | Decision | Rejected |
|---|---|---|
| 1 | Export from the operator | From each engine (egress, credentials and connections in every proxy pod) |
| 2 | Every replica exports its own engines' events | Leader only (relay between replicas) |
| 3 | One buffer per replica, a cursor per sink, on the `events` emptyDir; at least once | A buffer per sink; sharing the control plane's queue; memory only |
| 4 | The buffer's bound is an operator flag and chart value | A bound in the `InkwallConfig` (can exceed the emptyDir and the memory limit) |
| 5 | OTLP logs (gRPC and HTTP/protobuf) and JSON over HTTP (`Lines`, `Array`) | Syslog now; OTLP/JSON; vendor envelopes |
| 6 | `spec.events.export.sinks`, at most 4 | A separate CRD now |
| 7 | Credentials as headers from a Secret in the operator's namespace | Credentials in the CR; a Secret namespace field |
| 8 | Server certificates always verified; plaintext needs `insecure: true` | `insecureSkipVerify` |
| 9 | `Add` never blocks; drop oldest and count; retries with backoff while buffered | Backpressure on the engines' streams |
| 10 | Redaction stays in the engine; a sink can only omit more | Export-only redaction settings |
| 11 | Inkwall's own versioned schema, OTLP semantic conventions where they exist | ECS or another vendor's schema in the operator |
| 12 | Export and the control plane independent; both allowed; the control plane can't add sinks | Export only in Standalone mode |
| 13 | Dialer refuses loopback and link-local; no redirects; short errors in status | Following redirects; full responses in status |
| 14 | `EventsExported` condition aggregated by the leader from replica reports; per-sink metrics | Each replica writing the condition |

## 11. Open questions

1. **Native syslog.** RFC 5424 over TLS for QRadar and ArcSight users without a Collector, with
   the delivery caveats of [§3.3](#33-syslog-deferred)?
2. **Client IP prefixes.** `omit: [ClientIP]` is all or nothing. Should a sink (or `events.redact`,
   for every destination) keep only a `/24` or `/48`, as some privacy rules ask?
3. **Request counts as OTLP metrics.** Useful for SIEMs without Prometheus, or a duplicate of the
   metrics they can scrape?
4. **Sinks per team.** A namespaced `WAFEventSink` that sends a namespace's policies' events to the
   team's SIEM, without the cluster admin. It needs the operator to read Secrets in that
   namespace, which today it can't ([§4.2](#42-credentials-and-tls)).
5. **Engines without an operator.** A flag on the standalone engine to send OTLP itself, for setups
   with no Kubernetes, or is a log agent enough?
6. **One buffer.** Should the control plane's queue become one more cursor on the export buffer, so
   a replica holds each event once?
