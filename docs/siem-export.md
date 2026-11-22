# Exporting security events to a SIEM

Every blocked or detected request is a security event. The engines log each one, and
send it to the operator. The operator can export those events to your SIEM or log pipeline,
with no control plane: as OpenTelemetry logs (OTLP, over gRPC or HTTP) or as JSON over HTTP.
This guide sets it up, gives a recipe per SIEM, and describes what an exported event holds. The
design is [0010](design/0010-siem-export.md).

## Contents

- [How it works](#how-it-works)
- [A first sink](#a-first-sink)
- [Sinks](#sinks)
  - [Credentials and TLS](#credentials-and-tls)
  - [Filters and what a sink leaves out](#filters-and-what-a-sink-leaves-out)
  - [Batching and retries](#batching-and-retries)
- [Recipes per SIEM](#recipes-per-siem)
- [The event](#the-event)
  - [JSON](#json)
  - [OTLP](#otlp)
  - [Duplicates](#duplicates)
- [Buffering and memory](#buffering-and-memory)
- [Security](#security)
- [Checking it works](#checking-it-works)
- [Without an operator](#without-an-operator)

## How it works

- **From the operator, on every replica.** Each operator replica exports the events of the
  engines connected to it. Engines get no egress and no credentials; only the operator's pods
  connect to the sinks.
- **Never in the way.** Export never slows a request, an engine or the control plane's
  forwarding. A slow or down sink fills its replica's buffer, which drops the oldest events and
  counts them (`inkwall_operator_events_export_dropped_total{reason="buffer_full"}`).
- **At least once while the replica runs.** A replica resends what a sink hasn't accepted,
  from memory or from its disk buffer, also after a container restart. Events still buffered
  when a pod is deleted (a rollout, a drain) are lost: the engines' logs keep them.
- **Beside the control plane.** Export and the control plane are independent; both may run.
  A control plane can't add or change sinks.
- **Redacted in the engine.** An exported event carries no more than the engine's log line:
  never a body, a query string, a cookie or a credential. `spec.events.redact` applies to every
  destination; a sink can only leave out more.

## A first sink

An [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) in the cluster is the
general answer: it has exporters for almost every backend.

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  events:
    export:
      clusterName: prod-eu-1
      sinks:
        - name: collector
          otlp:
            endpoint: grpc://otel-collector.observability:4317
          insecure: true          # plaintext, inside the cluster
```

The `EventsExported` condition says whether it works, within a minute:

```sh
kubectl get inkwallconfig default -o jsonpath='{.status.conditions[?(@.type=="EventsExported")]}'
inkwallctl status
```

## Sinks

At most 4 sinks, each with a unique `name` (a DNS label: the `sink` label of the metrics, and the
name in the condition). Each is `otlp` or `json`:

| Field | Default | Meaning |
|---|---|---|
| `otlp.endpoint` | | `grpcs://host:port` (or `grpc://`) for OTLP over gRPC; an `https://` (or `http://`) URL for OTLP over HTTP with protobuf, used as is: give the whole path, usually `/v1/logs` |
| `json.url` | | The `https://` (or `http://`) URL to POST to, with any path and query |
| `json.urlSecretRef` | | `{name, key}`: the URL from a Secret instead, for intakes whose URL holds a token |
| `json.framing` | `Lines` | `Lines`: one event per line (`application/x-ndjson`); `Array`: one JSON array (`application/json`) |
| `compression` | `Gzip` | `Gzip` or `None` |
| `insecure` | `false` | Allows a plaintext `http://` or `grpc://` endpoint |
| `tls.caSecretRef` | system roots | A Secret whose `ca.crt` holds the CAs trusted for the server |
| `tls.clientCertificateSecretRef` | | A `kubernetes.io/tls` Secret: a client certificate for mutual TLS |
| `tls.serverName` | the host | The name checked in the server's certificate |
| `headersSecretRef` | | A Secret whose keys are header names and values their values |
| `batch.maxEvents` | 500 | Events per request, 1 to 1,000 |
| `batch.maxDelay` | 5s | The longest an event waits for its request to fill, 100ms to 60s |
| `batch.maxInFlight` | 4 | Requests sent before the first is answered, 1 to 4 |
| `timeout` | 10s | One request's deadline, 1s to 60s |
| `filter.actions` | both | `Deny`, `Log` |
| `filter.policyNamespaces` | all | Only events of policies in these namespaces |
| `omit` | none | `Snippets`, `ClientIP`, `UserAgent`, `RequestID` |

`clusterName` names the cluster in every event, beside its ID (the `kube-system` Namespace's UID).

### Credentials and TLS

Credentials are never in the InkwallConfig, which anyone who may read it reads, which is in Git in
GitOps setups, and which goes to the control plane. They come from Secrets **in the operator's
namespace** (`inkwall-system`): the references have a name only.

- **Headers.** `headersSecretRef` names a Secret whose keys are header names: one Secret covers
  bearer tokens, basic auth and API keys. Over gRPC they are sent as metadata, lower-cased.
  The names the transport owns are refused (`Host`, `Content-Type`, `Content-Length`,
  `Content-Encoding`, `Transfer-Encoding`, `Connection`, `TE`, `Trailer`, `Upgrade`, `Proxy-*`,
  and for gRPC `grpc-*` and `*-bin`).

  ```sh
  kubectl -n inkwall-system create secret generic splunk-hec \
    --from-literal=Authorization='Splunk 1f2e...' \
    --from-literal=X-Splunk-Request-Channel=7b2a5c3e-0d6f-4f3e-9a1b-2c4d6e8f0a1b
  ```

- **TLS** is 1.2 or later, and the server's certificate is always verified; there is no way to
  skip it. A self-signed SIEM gets its CA in `tls.caSecretRef`. Plaintext needs
  `insecure: true`, meant for a Collector in the cluster, and can't have `headersSecretRef`:
  credentials never travel in clear. The `EventsExported` message names the plaintext sinks.
- **Rotation.** A changed Secret takes effect without a restart: headers within seconds, from
  the next request; a changed CA, client certificate or URL rebuilds the sink's connections, so
  the next request makes a new TLS handshake.
- A missing Secret or key stops that sink only (`ExportConfigInvalid`).

### Filters and what a sink leaves out

- `filter.actions: [Deny]` keeps `Detect` mode's noise out of a SIEM that alerts.
- `filter.policyNamespaces` sends only the events of some teams' policies: a team's own SIEM.
  The policy must be in the bundle the operator serves, so an engine can't label its events with
  another team's policy to reach its SIEM; an event with no policy goes only to sinks without
  this filter.
- `omit` leaves fields out for a sink: `Snippets` (keep each match's rule and variable, not the up
  to 64 bytes matched), `ClientIP`, `UserAgent`, `RequestID`. For a SIEM outside the jurisdiction
  personal data may go to, or one that only counts per rule.

Filtered events aren't counted as dropped: that is configuration, not loss. A sink's changes
apply to the events it hasn't sent yet too, including those waiting for a retry: a new format,
`omit` or filter takes effect on them before they are sent, and the events a new filter leaves
out are neither sent nor counted as dropped.

### Batching and retries

A sink sends when `batch.maxEvents` events wait or `batch.maxDelay` passed since the first,
with up to `batch.maxInFlight` requests at once; a request body is at most 4 MiB before
compression. Requests that fail are retried with backoff, from 1 s to 60 s, for as long as the
replica's buffer holds their events:

- Retried: connection, TLS and timeout errors; HTTP 429, 502, 503, 504; gRPC `UNAVAILABLE`,
  `DEADLINE_EXCEEDED`, `ABORTED`, `CANCELLED`, `OUT_OF_RANGE`, `DATA_LOSS`, and
  `RESOURCE_EXHAUSTED` with `RetryInfo`, or without it on a request of 1 MiB or less (a quota:
  throttled); and for `json` sinks HTTP 408 and 500 too. `Retry-After` and `RetryInfo` set the
  wait, up to 5 minutes.
- Retried with backoff, up to a minute apart: HTTP 401 and 403, gRPC `UNAUTHENTICATED` and
  `PERMISSION_DENIED`, so a fixed Secret resumes the flow without losing what waited.
- Halved: HTTP 413, and gRPC `RESOURCE_EXHAUSTED` without `RetryInfo` on a request over 1 MiB.
  A single event refused is dropped (`too_large`).
- Dropped (`rejected`): any other status or code, and the events an OTLP receiver reports
  refused (partial success).
- **Redirects aren't followed**: a 3xx drops the request as `rejected`. Give the sink its final
  URL, the one a `curl -L` of it ends at (`http` to `https`, a trailing slash, a load balancer's
  regional host).

## Recipes per SIEM

Each was checked against the product's documentation in November 2026. CI tests the
Collector and a plain HTTP intake ([below](#checking-it-works)), not the products.

| SIEM | Sink |
|---|---|
| [Any, through a Collector](#any-through-a-collector) | `otlp` to the Collector's OTLP receiver |
| [Splunk](#splunk) | `json`, `Lines`, to HEC's raw endpoint; or a Collector with `splunk_hec` |
| [Elastic](#elastic) | `otlp` to Elastic's OTLP intake; or `json` to Logstash |
| [Grafana Loki](#grafana-loki) | `otlp`, HTTP, to `/otlp/v1/logs` |
| [Datadog](#datadog) | `otlp` to the Datadog Agent; or a Collector with `datadog` |
| [Sumo Logic](#sumo-logic) | `json`, `Lines`, to an HTTP source, its URL from a Secret |
| [Microsoft Sentinel](#microsoft-sentinel) | A Collector sending OTLP to Azure Monitor |
| [QRadar, ArcSight, syslog](#qradar-arcsight-and-other-syslog-receivers) | A Collector with the `syslog` exporter |
| [Vector, Fluent Bit, Logstash](#vector-fluent-bit-and-logstash) | `json` to their HTTP input |

### Any, through a Collector

```yaml
sinks:
  - name: collector
    otlp: {endpoint: "grpc://otel-collector.observability:4317"}   # or http://...:4318/v1/logs
    insecure: true
```

The Collector's `otlp` receiver listens on 4317 (gRPC) and 4318 (HTTP, `/v1/logs`); in a pod,
bind it to `0.0.0.0`. Over TLS, use `grpcs://` or `https://` and `tls.caSecretRef`. Then route
anywhere: the Collector batches, filters and exports further.

### Splunk

To the HTTP Event Collector's raw endpoint, one JSON event per line:

```yaml
sinks:
  - name: splunk
    json:
      url: https://splunk.example.com:8088/services/collector/raw?sourcetype=_json
      framing: Lines
    headersSecretRef: {name: splunk-hec}     # Authorization: Splunk <token>, X-Splunk-Request-Channel
    tls: {caSecretRef: {name: splunk-ca}}
```

- The token goes in `Authorization: Splunk <token>`. Send `X-Splunk-Request-Channel` (any
  GUID) too: Splunk requires it on the raw endpoint when the token has indexer
  acknowledgement on.
- Splunk's documentation doesn't promise gzip on HEC: if yours refuses gzipped bodies, set
  `compression: None`.
- Or a Collector with the [`splunk_hec` exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/splunkhecexporter)
  (`token`, `endpoint: https://splunk:8088/services/collector`).
- Deduplicate on `event_id` in a search (`| dedup event_id`). For Splunk's CIM, map the fields of
  [the event](#the-event) in `props.conf`: `src` = `request.client_ip`, `dest` = `request.host`,
  `http_method` = `request.method`, `uri_path` = `request.path`, `http_user_agent` =
  `request.user_agent`, `status` = `status`, `action` = `action` (`deny`: blocked), `signature_id`
  = `rule_id`.

### Elastic

- **Elastic Cloud (Serverless, Hosted)**: its managed OTLP endpoint, the URL from the Cloud
  console, with an API key:

  ```yaml
  sinks:
    - name: elastic
      otlp: {endpoint: "https://<deployment>.ingest.<region>.elastic.cloud/v1/logs"}   # as the console gives it, with /v1/logs
      headersSecretRef: {name: elastic-key}   # Authorization: ApiKey <key>
  ```

- **Self-managed**: Elastic Agent (the Elastic Distribution of the OpenTelemetry Collector)
  as an OTLP gateway, or APM Server's OTLP intake (`Authorization: Bearer <secret token>` or
  `ApiKey <key>`).
- **Or Logstash's `http` input**, which doesn't map NDJSON by default:

  ```ruby
  input  { http { port => 8080 additional_codecs => { "application/x-ndjson" => "json_lines" } } }
  output { elasticsearch { hosts => ["https://es:9200"] document_id => "%{[event_id]}" action => "create" } }
  ```

  `document_id` from `event_id` deduplicates: a resent event is a conflict, which Logstash logs
  and drops. For ECS, map `request.client_ip` to `source.ip`, `request.host` to `url.domain`,
  `request.path` to `url.path`, `request.method` to `http.request.method`, `status` to
  `http.response.status_code`, `request.user_agent` to `user_agent.original`, `rule_id` to
  `rule.id`, `action` to `event.outcome`.

### Grafana Loki

Loki 3 takes OTLP natively; the sink uses the URL as is, so give the whole path:

```yaml
sinks:
  - name: loki
    otlp: {endpoint: "https://loki.example.com/otlp/v1/logs"}
    headersSecretRef: {name: loki-auth}     # e.g. Authorization: Basic ..., X-Scope-OrgID
```

Loki makes a default list of resource attributes index labels, `k8s.pod.name` among them,
whose cardinality grows with every rollout of a proxy. Keep the pod as structured metadata
instead, per tenant:

```yaml
limits_config:
  otlp_config:
    resource_attributes:
      attributes_config:
        - action: structured_metadata
          attributes: [k8s.pod.name]
```

or for every tenant, by leaving it out of `distributor.otlp_config.default_resource_attributes_as_index_labels`.
Grafana Cloud's endpoint is `https://otlp-gateway-<region>.grafana.net/otlp/v1/logs`, with the
Basic `Authorization` header its OpenTelemetry tile gives.

### Datadog

- **The Datadog Agent's OTLP receiver**, with logs on (`DD_LOGS_ENABLED=true`,
  `DD_OTLP_CONFIG_LOGS_ENABLED=true`, and the receiver on
  `DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT=0.0.0.0:4317`):

  ```yaml
  sinks:
    - name: datadog
      otlp: {endpoint: "grpc://datadog-agent.datadog:4317"}
      insecure: true
  ```

- Or a Collector with the [`datadog` exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/datadogexporter)
  (`api.key`, `api.site`).
- The HTTP logs intake (`https://http-intake.logs.<site>/api/v2/logs`, `json`, `Array`,
  `headersSecretRef` with `DD-API-KEY`) takes the events too, but Datadog expects a `message` in
  each, which they don't have: prefer OTLP, whose records have a body, or add one in a pipeline.

### Sumo Logic

An HTTP Logs and Metrics Source: its URL holds its token, so give it from a Secret. One event per
line is the framing Sumo Logic documents:

```yaml
sinks:
  - name: sumo
    json:
      urlSecretRef: {name: sumo-source, key: url}
      framing: Lines
```

```sh
kubectl -n inkwall-system create secret generic sumo-source --from-literal=url='https://endpoint4.collection.sumologic.com/receiver/v1/http/<token>'
```

### Microsoft Sentinel

Sentinel reads its Log Analytics workspace. Azure Monitor takes OTLP natively into a data
collection rule: run a Collector with the `otlphttp` exporter and the `azure_auth` extension
(Entra ID, the identity given *Monitoring Metrics Publisher* on the rule), to
`https://<data collection endpoint>/datacollectionRules/<rule's immutable ID>/streams/Microsoft-OTLP-Logs/otlp/v1/logs`
([Azure's guide](https://learn.microsoft.com/en-us/azure/azure-monitor/containers/opentelemetry-protocol-ingestion)),
and point an `otlp` sink at the Collector. The Collector's `azuremonitor` exporter writes to
Application Insights instead: not what Sentinel's analytics rules read.

### QRadar, ArcSight and other syslog receivers

A Collector with the [`syslog` exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/syslogexporter)
(alpha): `protocol: rfc5424`, `network: tcp`, TLS on by default. An `otlp` sink feeds the
Collector. Inkwall doesn't speak syslog itself: a syslog sender learns nothing about what was
received, and receivers may cut messages at 2,048 bytes ([design 0010 §3.3](design/0010-siem-export.md#33-syslog-deferred)).

### Vector, Fluent Bit and Logstash

- **Vector**: the `http_server` source, `decoding.codec: json`, `framing.method: newline_delimited`;
  `json` sink, `Lines`. It decompresses gzip.
- **Fluent Bit**: the `http` input (port 9880) takes `application/json` only: `json` sink,
  `framing: Array`. A JSON array becomes one record per event.
- **Logstash**: [above](#elastic).

## The event

Version 1 of Inkwall's own schema: field names are only added within it, and a rename or a
removal would be a version 2, opt-in per sink. `snake_case`, rather than a vendor's schema: map
it in the SIEM's pipeline (the recipes above give ECS and Splunk CIM).

### JSON

```json
{
  "schema": "inkwall.dev/security-event/v1",
  "event_id": "01JD3Q4Z8M2N5X7Y9A1B3C5D7E",
  "time": "2026-11-20T10:15:02.123456Z",
  "observed_time": "2026-11-20T10:15:02.401337Z",
  "cluster": {"id": "6f1c0d2e-…", "name": "prod-eu-1"},
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
  "request": {"id": "a1b2c3", "method": "GET", "host": "shop.example.com", "path": "/search",
              "client_ip": "203.0.113.7", "user_agent": "curl/8.10.1"},
  "latency_seconds": 0.00042
}
```

| Field | Meaning |
|---|---|
| `event_id` | Unique per event (a ULID): deduplicate on it |
| `time`, `observed_time` | When the engine recorded it, and when the operator received it (RFC 3339, UTC); `time` is `observed_time` from an engine that didn't set it |
| `cluster.id`, `cluster.name` | The `kube-system` Namespace's UID, and `clusterName` when set |
| `engine.id`, `.namespace`, `.pod` | The engine and its pod |
| `policy.namespace`, `.name`, `.bundle_version` | The policy that decided, and the bundle; namespace and name left out for an event with no policy, or one the bundle doesn't have |
| `action`, `reason`, `status` | `deny` or `log`; why (`rule`, `ip-deny`, `rate-limit`, `overload`, ... as the engine logs them, [troubleshooting](troubleshooting.md)); the status the client got (0: forwarded) |
| `rule_id`, `anomaly_score` | The rule that interrupted the request, and the CRS anomaly score; left out at 0 |
| `matches[]` | Every rule that matched: `rule_id`, `variable`, and `snippet` (at most 64 bytes, redacted, left out when there is none) |
| `phase`, `protocol` | `request`, `response`, `websocket-message`; `http`, `grpc`, `websocket`; left out from engines too old to say |
| `rate_limit`, `sampled_count` | With `reason: rate-limit`: the limit's name, and how many limited requests the event stands for (left out at 1); with `reason: geo-deny` or `geo-unavailable`, `sampled_count` too ([geo blocking](geo-blocking.md#metrics-alerts-and-events)) |
| `llm.*` | With `reason: llm` ([LLM APIs](llm-apis.md#metrics-and-events)): `check`, `format`, `model`, `role`, `message_index`, `offset`, `estimated_tokens`; never the prompt |
| `request.*` | `id`, `method`, `host`, `path` (no query string), `client_ip`, `country` (the client's, when the engine holds a [country table](geo-blocking.md): the code or `unknown`; left out with `client_ip` by `omit: [ClientIP]`), `user_agent` |
| `latency_seconds` | Time spent inspecting |

Strings and fields that are empty or zero are left out, but for `event_id`, `action`, `reason`,
`status` and `policy.bundle_version`, always there.

### OTLP

One `LogRecord` per event, in a `ResourceLogs` per engine pod:

- Resource: `service.name` (`inkwall-engine`), `k8s.cluster.uid`, `k8s.cluster.name`,
  `k8s.namespace.name`, `k8s.pod.name`.
- Scope: `inkwall.dev/events`, version `1`.
- Record: `event_name` `inkwall.security_event`, severity `WARN` for `deny` and `INFO` for `log`,
  a short body (`deny 403 rule 949110 GET shop.example.com/search`), and attributes:
  `http.request.method`, `server.address`, `url.path`, `client.address`, `client.geo.country.iso_code`, `user_agent.original`,
  `http.response.status_code`, and `inkwall.event_id`, `inkwall.engine.id`,
  `inkwall.policy.namespace`, `inkwall.policy.name`, `inkwall.policy.bundle_version`,
  `inkwall.action`, `inkwall.reason`, `inkwall.rule_id`, `inkwall.anomaly_score`,
  `inkwall.matches` (maps of `rule_id`, `variable`, `snippet`), `inkwall.request.id`,
  `inkwall.phase`, `inkwall.protocol`, `inkwall.rate_limit`, `inkwall.sampled_count`,
  `inkwall.llm.check`, `inkwall.llm.format`, `inkwall.llm.model`, `inkwall.llm.role`,
  `inkwall.llm.message_index`, `inkwall.llm.offset`, `inkwall.llm.estimated_tokens`,
  `inkwall.latency_seconds`.

### Duplicates

An event can arrive twice: an engine resends a batch after a failed send, and a sink's request
that timed out may have been taken. Deduplicate on `event_id` where the SIEM can (Elastic's
document `_id`, Splunk's `dedup`), or count distinct IDs.

**Trust.** The operator stamps `engine.*` and the pod from the engine's authenticated stream; the
pod's namespace and name are authenticated when the engine connects with a pod-bound token, and
are otherwise what the engine said. Paths, hosts, user agents, request IDs and snippets come from
the client: escape them wherever they are shown, as every consumer of the events must.

## Buffering and memory

Each replica has one buffer, shared by its sinks, in memory up to
`events.export.bufferMiB` (32) and on disk, in the chart's `events` emptyDir, up to
`events.export.diskMiB` (512). The disk part survives container restarts, not pod deletion.
At 10,000 events a second, the memory covers a sink's outage of about 3 seconds and the disk
about 50; at 1,000 a second, about 8 minutes. On shutdown a replica sends what it holds for up
to 15 seconds (`--export-flush-timeout`); the chart's `terminationGracePeriodSeconds` (30) leaves
room for it.

The memory limit must hold the buffer: the chart's default (1 GiB) and the formula are in its
`values.yaml`. Alert on the engines' own drops too
(`inkwall_operator_engine_events_dropped_total`): a gap no sink sees.

The operator's flags for the export, which the chart sets from its values (others through
`operator.extraArgs`):

| Flag | Default | Chart value | Meaning |
|---|---|---|---|
| `--export-buffer-bytes` | 32 MiB | `events.export.bufferMiB` | The buffer's memory bound: the newest batches; without `--events-dir`, the whole buffer |
| `--export-disk-bytes` | 512 MiB | `events.export.diskMiB` | The buffer's disk bound, under `--events-dir/export` |
| `--export-flush-timeout` | 15s | | How long the sinks may send what is buffered on shutdown |
| `--export-status-window` | 5m | | How long a sink fails before `EventsExported` says `ExportFailing`, and how recently a sink dropped events for it to say `ExportDropping` |

## Security

- **Who.** Only cluster admins may edit the InkwallConfig, so only they choose where events go.
  Audit its changes: whoever can edit it can send the events (no more than the engines' logs
  hold) to an address of their choice.
- **The operator's address.** The operator never connects to loopback, link-local (most clouds'
  metadata services) or the metadata addresses outside it (`fd00:ec2::254`, `100.100.100.200`),
  however a name resolves, and in IPv4-mapped or NAT64 form: `ExportAddressRefused`. Other
  private ranges are allowed, for in-cluster Collectors. It follows no redirects and no
  `HTTPS_PROXY`, and status and logs carry at most 128 bytes of a sink's answer.
- **NetworkPolicy.** With the chart's `networkPolicy.egress.enabled`, list each sink in
  `networkPolicy.egress.extra`: the chart can't know them. A blocked sink shows as timeouts in
  the condition.
- **Secrets** stay in the operator's namespace and never reach logs, status, metrics or the
  control plane, which sees each sink's endpoint cut to its scheme, host and port.

## Checking it works

- `inkwallctl status` prints the `EventsExported` condition and each sink's pending events per
  replica; `ExportFailing` names the sink, the replica and the last error class. The reasons are
  in [troubleshooting](troubleshooting.md).
- The metrics are in [monitoring](monitoring.md#operator), and the
  [`InkwallEventExportFailing`](monitoring.md#inkwalleventexportfailing) alert fires when a sink
  with events waiting accepts nothing for about 17 minutes, or its full buffer drops events for
  15.
- CI's end-to-end test (`hack/kind/export-e2e.sh`) exports an attack through Traefik to a
  Collector and to an HTTP intake, and checks the fields, the redaction, the filters, a rotated
  Secret and the condition.

## Without an operator

The standalone proxy's engine logs each event as a JSON line (`"msg":"security event"`): ship
its logs with any log agent (Vector, Fluent Bit, the Collector's `filelog` receiver).
