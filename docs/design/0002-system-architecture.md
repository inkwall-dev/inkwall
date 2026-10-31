# 0002 — System Architecture

- Status: Draft
- Date: 2026-09-27
- Updated: 2026-10-30
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md)

Inkwall is a [web application firewall](https://owasp.org/www-community/Web_Application_Firewall) (WAF) for [Kubernetes](https://kubernetes.io/docs/concepts/overview/). This document describes its
components, the protocols between them, and how each proxy is integrated. The performance rules
of [0001](0001-performance-first-architecture.md) apply throughout. Today the engine, the operator
and the [Traefik](https://doc.traefik.io/traefik/) integration are built; the other proxies and the hosted control plane are not.

## Contents

- [1. Scope](#1-scope)
  - [1.1 Goals](#11-goals)
  - [1.2 Non-goals (for v1)](#12-non-goals-for-v1)
  - [1.3 Glossary](#13-glossary)
- [2. System context](#2-system-context)
- [3. Components](#3-components)
  - [3.1 `inkwall-engine` (data plane)](#31-inkwall-engine-data-plane)
  - [3.2 Adapters](#32-adapters)
  - [3.3 `inkwall-operator` (local control)](#33-inkwall-operator-local-control)
  - [3.4 Control plane (optional)](#34-control-plane-optional)
  - [3.5 `inkwallctl` (CLI)](#35-inkwallctl-cli)
- [4. Configuration model](#4-configuration-model)
  - [4.1 Sources of truth](#41-sources-of-truth)
  - [4.2 CRDs (`waf.inkwall.dev/v1alpha1`)](#42-crds-wafinkwalldevv1alpha1)
  - [4.3 Bundle format](#43-bundle-format)
- [5. Protocols](#5-protocols)
  - [5.1 Engine check API (for Lua, generic HTTP clients, and tests)](#51-engine-check-api-for-lua-generic-http-clients-and-tests)
  - [5.2 Engine ↔ operator (bundle distribution)](#52-engine--operator-bundle-distribution)
  - [5.3 Operator ↔ SaaS](#53-operator--saas)
  - [5.4 Event schema](#54-event-schema)
- [6. Proxy integrations](#6-proxy-integrations)
  - [6.1 Envoy (raw Envoy, Envoy Gateway, Istio, Contour)](#61-envoy-raw-envoy-envoy-gateway-istio-contour)
  - [6.2 ingress-nginx](#62-ingress-nginx)
  - [6.3 Traefik](#63-traefik)
  - [6.4 HAProxy (HAProxy Kubernetes Ingress Controller, HAProxy Ingress)](#64-haproxy-haproxy-kubernetes-ingress-controller-haproxy-ingress)
  - [6.5 Caddy](#65-caddy)
  - [6.6 Standalone reverse proxy (universal fallback)](#66-standalone-reverse-proxy-universal-fallback)
  - [6.7 Integration support matrix (v1 target)](#67-integration-support-matrix-v1-target)
- [7. Request flows](#7-request-flows)
  - [7.1 Block mode (Envoy example)](#71-block-mode-envoy-example)
  - [7.2 Detect mode](#72-detect-mode)
  - [7.3 Engine unavailable](#73-engine-unavailable)
  - [7.4 Policy change (GitOps mode)](#74-policy-change-gitops-mode)
  - [7.5 Cluster enrollment (Managed / GitOps mode)](#75-cluster-enrollment-managed--gitops-mode)
- [8. Cross-cutting concerns](#8-cross-cutting-concerns)
  - [8.1 Security of Inkwall itself](#81-security-of-inkwall-itself)
  - [8.2 Client IP correctness](#82-client-ip-correctness)
  - [8.3 Data privacy](#83-data-privacy)
  - [8.4 Multi-tenancy](#84-multi-tenancy)
  - [8.5 Observability](#85-observability)
  - [8.6 Versioning and compatibility](#86-versioning-and-compatibility)
- [9. Repository layout](#9-repository-layout)
- [10. Testing architecture](#10-testing-architecture)
- [11. Decisions (ADR log)](#11-decisions-adr-log)
- [12. Open questions](#12-open-questions)

---

## 1. Scope

### 1.1 Goals

1. One WAF engine, written in [Go](https://go.dev/), behind any ingress proxy ([Envoy](https://www.envoyproxy.io/docs/envoy/latest/), Traefik, [ingress-nginx](https://kubernetes.github.io/ingress-nginx/),
   [HAProxy](https://docs.haproxy.org/), [Caddy](https://caddyserver.com/docs/)), or as a standalone [reverse proxy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling#forward_and_reverse_proxies).
2. Kubernetes-native: installed with [Helm](https://helm.sh/docs/), configured with [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/), managed with [GitOps](https://opengitops.dev/).
3. An optional hosted control plane. The open-source data plane never depends on it.
4. The performance budgets of [0001](0001-performance-first-architecture.md) block a release.

**Built (v0.1.0):** Traefik [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) for [`Ingress`](https://kubernetes.io/docs/concepts/services-networking/ingress/) targets, and the standalone reverse proxy.
**Built since:** Traefik [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) targets, and the operator's side of the optional control
plane ([§3.4](#34-control-plane-optional)).

### 1.2 Non-goals (for v1)

- L3/L4 DDoS protection: that is the CDN's job.
- [TLS](https://www.rfc-editor.org/rfc/rfc8446) termination: that is the proxy's job.
- Proxying production traffic in Kubernetes mode.
- Non-HTTP protocols. [gRPC](https://grpc.io/docs/) and [WebSocket](https://www.rfc-editor.org/rfc/rfc6455) upgrades are inspected as HTTP only.

### 1.3 Glossary

The project's terms (engine, proxy, adapter, integration, injection, wiring, operator, leader,
policy, bundle, policy snapshot, control plane, cluster mode, enforcement mode, failure mode,
verdict) are defined in the [glossary](../glossary.md#inkwall-terms), with the outside concepts
these documents use. "Standalone" alone always means the cluster mode: see
[Standalone](../glossary.md#standalone).

---

## 2. System context

![System overview](../diagrams/system-overview.svg)

Inkwall has three planes:

| Plane | Components | Latency sensitivity | Availability requirement |
|---|---|---|---|
| **Data plane** | engine, adapters | µs, every request | Works when all else is down |
| **Local control** | operator | seconds | Down for hours: the engine keeps its last-known-good bundle |
| **Global control** | control plane | seconds to minutes | Down for days: clusters keep enforcing |

**Rule:** no call on the request path crosses a plane boundary.

---

## 3. Components

### 3.1 `inkwall-engine` (data plane)

The engine is a static Go binary in a [distroless](https://github.com/GoogleContainerTools/distroless) image. It runs in one of four ways:

- as a **[sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)** in the [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)'s [pod](https://kubernetes.io/docs/concepts/workloads/pods/) (the default);
- as a **standalone [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)** behind a [Service](https://kubernetes.io/docs/concepts/services-networking/service/) (simpler, but slower);
- as a **reverse proxy** in front of the application;
- as an in-process **library** (Caddy).

![Engine internals](../diagrams/engine-internals.svg)

A request moves through a pipeline of tiers, cheapest first
([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first)):

1. The adapter turns the proxy's message into a pooled `Request`.
2. T0, the router, matches the route and its skip list.
3. T1 checks IP lists and rate limits.
4. T2 runs the header and URI rules.
5. T3 runs the body rules.
6. The result is a `Verdict`: action, status, rule IDs, score, policy and bundle version, and
   reason.

The compiled policy sits in an [`atomic.Pointer[Snapshot]`](https://pkg.go.dev/sync/atomic#Pointer), so reads take no lock.

| Package | Responsibility | Status |
|---|---|---|
| `pkg/request` | Canonical `Request`, zero-copy headers | built |
| `pkg/router` | `(host, path, method)` → policy | built |
| `pkg/pipeline` | Tiers, deadline, `Verdict` | built |
| `pkg/rules` | `Evaluator` interface; [Coraza](https://coraza.io/) implementation | built |
| `pkg/clientip` | Client IP ([§8.2](#82-client-ip-correctness)) | built |
| `pkg/agent`, `pkg/policy` | Bundle stream, verify, compile, swap ([§5.2](#52-engine--operator-bundle-distribution)) | built |
| `pkg/telemetry` | Metrics, tracing, [`slog`](https://pkg.go.dev/log/slog) | built |
| `pkg/adapters/*` | One per listener | `forwardauth`, `httpcheck`, `proxy`, `extproc` built; `extauthz`, `spoe` not yet |
| `pkg/events` | Redacted security events, bounded buffer ([§5.4](#54-event-schema)) | built |
| `pkg/ratelimit`, `pkg/iplist` | [Token buckets](https://en.wikipedia.org/wiki/Token_bucket), [CIDR](https://www.rfc-editor.org/rfc/rfc4632) trie | not yet |

Lifecycle:

1. Listeners start not ready.
2. The engine loads a bundle: from its disk cache, or else from the bundle [Secret](https://kubernetes.io/docs/concepts/configuration/secret/).
3. It becomes ready after the first successful compile.
4. Updates compile in the background and swap in atomically. A failed compile keeps the old
   compiled policy, and the engine NACKs the bundle.
5. Shutdown drains in-flight requests, within a time bound.

**Built:** with no bundle yet, `--bootstrap allow|deny` decides what happens to requests. It comes
from `spec.engine.bootstrapMode` (default `allow`). The engine stays unready for up to
`--bootstrap-timeout`, so the proxy sends no traffic before a bundle arrives.

### 3.2 Adapters

An adapter is an engine listener (`pkg/adapters/<name>`) that translates a proxy's messages to a
`Request` and the `Verdict` back. The proxy side is configuration rendered by the operator, or a
plugin. See [0006 — Adapter Protocols Primer](0006-adapter-protocols.md) and
[§6](#6-proxy-integrations).

### 3.3 `inkwall-operator` (local control)

The [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) is built on [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime). It runs 2 replicas with [leader election](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election). Details are
in [0004 — Kubernetes Operator](0004-operator.md).

| Controller | Does |
|---|---|
| **Discovery** | Finds ingress controllers and the adapter for each |
| **Injection** | Adds the sidecar and its socket volume, through the controller's extension point or a Pod [webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) (never a Deployment patch) |
| **Wiring** | Renders proxy configuration (Traefik [`Middleware`](https://doc.traefik.io/traefik/middlewares/overview/), [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/), [`EnvoyExtensionPolicy`](https://gateway.envoyproxy.io/docs/api/extension_types/#envoyextensionpolicy), ...) |
| **Resolver + bundle builder** | Resolves targets to host, path and method; builds, signs and versions the bundle |
| **Distribution** | Streams bundles to engines and tracks their versions |
| **Upstream sync** | Holds the cluster's single connection to the control plane: pulls policies in [Managed mode](../glossary.md#cluster-mode), pushes state in GitOps mode, forwards events |
| **Status** | Sets `Accepted`, `Programmed`, and `Enforced` (all engines ACKed) |

The operator is never on the request path. While it is down, engines keep their compiled policy,
and new pods load their cache or the bundle Secret
([0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)).

**Built:** injection, Traefik wiring, the resolver, the bundle builder, distribution, status, and
upstream sync (GitOps and Managed modes, [§5.3](#53-operator--saas)).
**Not yet:** other proxies.

### 3.4 Control plane (optional)

The control plane is a separate product and out of scope here. The open-source code depends only
on three parts of it: the operator ↔ control plane stream ([§5.3](#53-operator--saas)),
enrollment ([§7.5](#75-cluster-enrollment-managed--gitops-mode)) and the cluster modes
([§4.1](#41-sources-of-truth)). Enforcement works without it.

The control plane talks only to operators, never to engines. That means fewer connections, no
egress from engines, and the same path for air-gapped clusters.

**Built:** the operator's side (enrollment, GitOps and Managed modes, events;
[0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)), tested against a stub. The control
plane itself is not in this repository.

### 3.5 `inkwallctl` (CLI)

Three commands are built:

- `test` replays a request or a [HAR](https://w3c.github.io/web-performance/specs/HAR/Overview.html) file and shows the rules that match. It runs offline, for CI.
  It checks one of three things: the policy set by its flags; `WAFPolicy` objects (`--policy`,
  resolved with the operator's resolver and compiled as the engine compiles a bundle); or a bundle
  (`--bundle`, with its signature checked against `--bundle-key`).
- `bench` benchmarks the engine on a fixed corpus.
- `migrate ingress-nginx` converts ingress-nginx's ModSecurity annotations and ConfigMap settings
  into `WAFPolicy` and `WAFRuleSet` objects targeting the Ingresses, or the HTTPRoutes or
  IngressRoutes that replace them (`--target`), and lists what it can't convert ([migrating from ingress-nginx](../migrating-from-ingress-nginx.md)). It only reads.

Planned: `status` (engine versions, drift).

---

## 4. Configuration model

### 4.1 Sources of truth

Each cluster runs in one cluster mode, which decides where policies come from:

| Mode | Source of truth | Control plane's role |
|---|---|---|
| **Standalone** | CRDs | none |
| **GitOps** | CRDs in Git | read-only mirror, analytics |
| **Managed** | Control plane | the operator writes its policies as CRDs; the webhook rejects other edits |

There is one mode per cluster. Ownership is never mixed per route, because conflicts would be
ambiguous.

### 4.2 CRDs (`waf.inkwall.dev/v1alpha1`)

Reference: [`operator/api/v1alpha1`](../../operator/api/v1alpha1).

- **`InkwallConfig`** (a cluster singleton): `mode`, `controlPlane`, `engine`, `integrations` and
  `events`. `engine` holds the image, resources, `bootstrapMode` and `socketDir`. Its resources
  have no CPU limit, since throttling hurts p99 latency.
- **`WAFPolicy`**:

  ```yaml
  spec:
    targetRefs: [{kind: Ingress, name: shop}]
    mode: Detect                  # Detect | Block | BlockHighConfidence
    failureMode: Open             # Open | Closed
    timeout: 250ms
    skip: {paths: ["/healthz"]}
    ruleSets: [{ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}, paranoiaLevel: 1}]
    exclusions: [{ruleIDs: [942100], when: {path: /api/search, argument: q}}]
    body: {inspect: true, maxBytes: 65536, onOversize: InspectPrefix}   # | Allow | Deny
  ```

  The most specific target wins: an [HTTPRoute](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) rule, then an HTTPRoute, then an Ingress, then the
  namespace default. Ties are rejected (`Accepted=False, reason=Conflict`).
- **`WAFRuleSet` / `ClusterWAFRuleSet`:** `builtin: crs-v4` (pinned), inline `seclang`, or
  `configMapRef`.
- **`WAFIPList` / `ClusterWAFIPList`:** CIDRs, or a URL that the operator fetches (never the
  engine).

**Built:** `InkwallConfig`, `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet`; `Ingress` and
Traefik `IngressRoute` targets; `HTTPRoute` targets resolved, with the precedence above (no proxy
wires them yet, [0004 §4.5](0004-operator.md#45-resolver)).
**Not yet:** IP lists, the policy fields `rateLimits` and `ipLists`, wiring `HTTPRoute` targets,
`BlockHighConfidence`, the `InspectPrefix` oversize action, and `InkwallConfig.events`.

### 4.3 Bundle format

A bundle holds all of a cluster's policies with their resolved routes, the rule sets they use
(each once), and a monotonic `version`. The operator resolves routes to `(host, path, method)`, so
the engine needs no Kubernetes knowledge. A bundle is immutable and signed with [Ed25519](https://www.rfc-editor.org/rfc/rfc8032).

**Built ([`api/bundle/v1`](../../api/bundle/v1/bundle.proto)):**

- A `SignedBundle` holds the serialized `Bundle` bytes, a signature over exactly those bytes, and
  the ID of the signing key. The signature covers bytes, not the decoded message, because [protobuf](https://protobuf.dev/)
  encoding isn't canonical.
- The engine verifies the signature with the key that the ID names, before decoding.
- Engines trust several keys while the operator rotates its key
  ([0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)).
- `Bundle` has a `content_hash` and `suspended` (an emergency switch).

**Not yet:** IP lists, rate limits.

---

## 5. Protocols

### 5.1 Engine check API (for Lua, generic HTTP clients, and tests)

[`api/engine/v1/engine.proto`](../../api/engine/v1/engine.proto) defines a `CheckRequest` and a
`CheckResponse`:

- `CheckRequest`: method, authority, raw URI, headers, `client_ip` and `peer_ip`, and an optional
  body. The IPs are text, so JSON clients can write them.
- `CheckResponse`: action, status, headers, rule IDs and reason.

Envoy will use its native [`ext_authz`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) and [`ext_proc`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) services instead.

**Built:** `POST /v1/check`, in protobuf or JSON. **Not yet:** the gRPC `CheckService`, and the
Envoy services.

### 5.2 Engine ↔ operator (bundle distribution)

Each engine holds one long-lived stream, `BundleService.Watch`. The operator pushes full bundles,
not deltas: that is simpler, idempotent, and bundles are small. The engine answers each with an
ACK or a NACK.

**Built ([`api/agent/v1`](../../api/agent/v1/agent.proto), [`pkg/agent`](../../pkg/agent),
[`pkg/policy`](../../pkg/policy), `--operator`):**

- The messages are `WatchRequest` and `WatchResponse`; the payload is a `SignedBundle`.
- The engine verifies a bundle, compiles it, swaps it in, writes it to `--bundle-cache`, and ACKs.
  It refuses a bundle with an older version, unless that bundle was created later (the operator
  lost its sequence). A failure NACKs and keeps the old bundle.
- `Hello` and `Heartbeat` carry the IDs of the keys the engine trusts (`--bundle-key`, re-read
  every 10 s). So the operator signs with a new key only once every engine has it. A bundle
  rejected for an unknown key is asked for again, on a new stream, once the keys change.
- The engine reconnects with jittered backoff. With no cache, it reads the bundle Secret from the
  API server (`--bundle-secret`, over plain HTTPS, without [client-go](https://github.com/kubernetes/client-go)).
- Matching uses host, cleaned path and method, most specific first. A request for a host no policy
  covers is not inspected. A request for a covered host that matches no path gets that host's most
  general policy, so normalization differences can't skip inspection.
- Engines send their security events on the same stream, in `EventBatch`es of up to 1,000
  (`pkg/events`, [§5.4](#54-event-schema)). The operator drops and counts the events beyond that.
- With each heartbeat, engines also send how many requests each policy allowed, denied and
  detected, with a latency histogram (`RequestStats`, [§5.4](#54-event-schema)). Only the policies
  whose counts changed are sent, in messages of at most 32 KiB. The counts are cumulative over the
  stream, and a new stream starts from zero. The operator adds up the differences between reports,
  for the policies of its bundle only, so an engine that restarts or moves to another replica is
  never counted twice.

**Not yet:** directives (the field is reserved).

### 5.3 Operator ↔ SaaS

The operator talks to the control plane through
[`api/controlplane/v1`](../../api/controlplane/v1/controlplane.proto) (`ControlPlaneService`),
over [mTLS](https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2). The cluster's identity is its client certificate
([§7.5](#75-cluster-enrollment-managed--gitops-mode)), never a message field.

There are two kinds of stream:

- One **primary stream** per cluster, from the leader. It carries state, policies, directives and
  certificates. When the leader moves, the newer primary stream wins.
- One **events stream** per replica, for the security events and request counts of the engines
  connected to that replica. Engines connect to any replica.

[gRPC status codes](https://grpc.io/docs/guides/status-codes/) tell the operator what to do: re-enroll (`UNAUTHENTICATED`), stop
(`PERMISSION_DENIED`), back off (`RESOURCE_EXHAUSTED`), or reconnect.

Messages on `Connect`:

- Up (operator to control plane): `Hello` (versions, mode, last policy version, capabilities);
  `ClusterState` (a full snapshot of every Inkwall object with its conditions, the integrations,
  the engines and the bundle version); `EventBatch` ([§5.4](#54-event-schema)); `RequestStatsUpload`
  (request counts per policy); `Heartbeat`; `PolicyAck` / `PolicyNack`; `RenewCertificate`.
- Down (control plane to operator): `Welcome` (the heartbeat interval, and whether events and
  request counts are accepted); `PolicySnapshot` (Managed mode); the renewed `Certificate`;
  `Directive` (for example, resync).

Rules of the contract:

- **Managed mode carries policy objects, not signed bundles.** The operator writes them as CRDs
  ([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)) and signs bundles with the
  cluster's own key, so engines trust only that key.
- Objects travel as their JSON spec. Integrations, kinds and condition reasons travel as strings.
  So new CRD fields, proxies and target kinds need no contract change. There are no
  proxy-specific fields.
- Both sides compress messages ([gzip](https://www.rfc-editor.org/rfc/rfc1952)) and accept messages up to 16 MiB.
- In Managed mode, rule sets come inline (`seclang`, `builtin`): the control plane can't create
  the ConfigMap that a `configMapRef` needs.
- Events are delivered at least once, per replica. Each `EventUpload` names its buffer and a
  sequence number. `EventsAck` frees that buffer up to that number. Unacknowledged batches are
  resent after a reconnect, and event IDs (never sequence numbers) remove duplicates. The bounded
  disk queue drops the oldest events when full, and the next batch says how many.
- Request counts go only to a control plane whose `Welcome` accepts them; an older one never gets
  them. Each replica sums its engines' counts per policy and sends them every 10 s: the policies
  that changed, and all of them first on a new stream. They are cumulative since the replica
  started counting (`since`), so a lost upload loses nothing, and the cluster's counts are the sum
  over its replicas. A count lower than the previous one is a reset (a replica forgot a policy no
  longer in its bundle): it counts from zero. They are per policy, never per route or client.
- A policy snapshot is all or nothing: the operator first does a [server-side dry run](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run) of every
  object. The cluster's `InkwallConfig` decides the mode, and a cluster not in Managed mode
  refuses policy snapshots. Only `WAFPolicy` and the rule set kinds are accepted.
- The operator sets the source label itself (`inkwall.dev/source: saas`). It deletes the labelled
  objects that a policy snapshot no longer has, and records the last version applied. That version
  is sent in `Hello`, and an older policy snapshot is refused.
- In Managed mode the [validating webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) lets only the operator write the labelled objects. It
  fails closed.
- In Standalone mode, events go to logs and optionally to [OTLP](https://opentelemetry.io/docs/specs/otlp/). Not yet: only the engine's log.

**Built:** the contract (#86), enrollment and the primary stream, state sync (`ClusterState`), the
events streams with each replica's disk buffer, request counts per policy (#119), and Managed mode (policy snapshots written as
CRDs, pruned and acknowledged; the webhook guard). All of it is tested on [kind](https://kind.sigs.k8s.io/) against a stub
control plane ([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)).

### 5.4 Event schema

A `SecurityEvent` ([`api/events/v1`](../../api/events/v1/events.proto)) holds: IDs, the engine and
pod, the policy and bundle version, action, reason, matches (rule, variable, redacted snippet),
score, method, host, path (without the query), client IP, user agent, request ID, status and
latency.

The same message goes from engine to operator (`agent.v1` `Watch`) and from operator to control
plane. Both carry it in an `EventBatch`, with a count of dropped events.

`RequestStats` ([`api/events/v1`](../../api/events/v1/stats.proto)) counts requests per policy:
allowed, denied and detected, and a latency histogram (time spent inspecting, in the buckets of
`inkwall_check_duration_seconds`: 50 µs to about 0.8 s, doubling). Requests no policy covers aren't
counted. There are no per-route or per-client counts.

**Built:** the schema. Engines produce redacted events and send them to their operator replica,
which forwards them to the control plane on its events stream (#91, #92). Request counts take the
same path (#119).

---

## 6. Proxy integrations

Every integration follows the same rules. It sends only what the policy needs, over a persistent
connection (a Unix socket where possible). Its timeout is just above the engine's deadline. On an
error it applies the failure mode. It passes the client IP and the request ID. The socket
directory is a shared [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) at `/var/run/inkwall`. (Traefik, built, is the exception to the
timeout and failure-mode rules: the operator's ForwardAuth Middleware sets no timeout and has no
failure-mode setting; [§7.3](#73-engine-unavailable).)

### 6.1 Envoy (raw Envoy, Envoy Gateway, Istio, Contour)

The engine serves `ext_proc` (preferred) or `ext_authz`, over gRPC on a [Unix socket](https://man7.org/linux/man-pages/man7/unix.7.html). Each product
is configured its own way:

- [Envoy Gateway](https://gateway.envoyproxy.io/): a `Backend` and an `EnvoyExtensionPolicy`.
- [Istio](https://istio.io/latest/docs/): an [`EnvoyFilter`](https://istio.io/latest/docs/reference/config/networking/envoy-filter/).
- [Contour](https://projectcontour.io/docs/): an `ExtensionService`.

Detect mode uses `observability_mode`. Envoy's [Go filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/golang_filter) needs a contrib build, so it is
experimental.

**Built:** the engine's side, `inkwall-engine ext-proc` ([0006 §2](0006-adapter-protocols.md#2-ext_proc-envoy-external-processing)).
Envoy Gateway will use `ext_proc`, not `ext_authz`. **Not yet:** the operator's Envoy Gateway
configuration.

### 6.2 ingress-nginx

Two options, neither of which needs snippets:

- A. A [Lua](https://github.com/openresty/lua-nginx-module) plugin (the default, with body support) calls `/v1/check` over a Unix socket and skips
  unprotected routes.
- B. [`global-auth-url`](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#global-auth-url): no code, but a subrequest per request and no bodies.

ingress-nginx is retired upstream (2026), so this is for existing users only. **Not yet** built.

### 6.3 Traefik

**A. ForwardAuth middleware (v1):**

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: inkwall-waf, namespace: shop}
spec:
  forwardAuth:
    address: http://127.0.0.1:9001/v1/forward-auth
    trustForwardHeader: false   # required, see below
    forwardBody: true           # required for body inspection (Traefik v3)
    maxBodySize: 10485760       # the largest body.maxBytes
    maxResponseBodySize: 65536  # the engine's answer (Traefik v3.7+)
    authResponseHeaders: ["X-Request-Id"]
```

The Middleware is attached with the `traefik.ingress.kubernetes.io/router.middlewares` [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/)
on an `Ingress`, or in each route's `middlewares` on an `IngressRoute`
([0004 §4.4](0004-operator.md#44-wiring-controller)). The adapter rebuilds the request from
`X-Forwarded-Method` and `X-Forwarded-Uri`.

- **`trustForwardHeader: false`** is required. With `true`, Traefik keeps a client-sent
  `X-Forwarded-Uri` from `trustedIPs` peers, so the engine would inspect the attacker's URI
  (verified on v3.7.13).
- **`forwardBody: true`** is required, or bodies go uninspected.
- Missing or invalid forwarded headers get a 400, even in detect mode: the engine can't inspect
  the request, so it can't allow it.
- Limitation: Traefik itself rejects bodies over `maxBodySize`, whatever `body.onOversize` says.
  The operator sets it to 10 MiB, the largest inspectable body.
- Limitation: ForwardAuth has no timeout or failure setting. An unreachable engine gets a 500
  from Traefik in both modes ([§7.3](#73-engine-unavailable)).

**Client IP behind a load balancer.** Behind a load balancer, Traefik's peer is the load balancer
or a node, and the engine would see that as the client. The load balancer's [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
can't help: the engine sees it only with `trustForwardHeader: true`, which lets the client choose
`X-Forwarded-Uri` (above).

So the address comes from the connection, in one of two ways:

- The load balancer sends a [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) header (v1 or v2). Traefik accepts it only from the load
  balancer's CIDRs (`entryPoints.<name>.proxyProtocol.trustedIPs`, never `0.0.0.0/0`).
- [`externalTrafficPolicy: Local`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip) keeps the source address.

Traefik uses that address as the remote address, and ForwardAuth sends it as `X-Forwarded-For`.
The engine trusts `X-Forwarded-For` from loopback only ([§8.2](#82-client-ip-correctness)). No
engine change was needed. The setup for each load balancer is in [client IP](../client-ip.md).
The kind e2e test checks that a PROXY address is used, that a client-sent `X-Forwarded-For` is
ignored, and that an untrusted PROXY header is ignored (verified on v3.7.13).

**B. Traefik plugin (later):** Traefik runs [plugins](https://plugins.traefik.io/) in [Yaegi](https://github.com/traefik/yaegi), which can't run Coraza well. So the
plugin would be a thin client to the sidecar (or use [http-wasm](https://http-wasm.io/)).

**Built:** A, for `Ingress` and `IngressRoute` targets. **Not yet:** B.

### 6.4 HAProxy (HAProxy Kubernetes Ingress Controller, HAProxy Ingress)

HAProxy uses [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt): the engine is the agent (SPOA), over a Unix socket. An `http-request deny` rule
acts on the variable `txn.inkwall.action`. To fail closed, an extra rule denies with 503 when the
variable is unset. Body inspection needs `http-buffer-request`, enabled only when a policy needs
it.

**Not yet** built.

### 6.5 Caddy

An in-process handler, `http.handlers.inkwall`, in a separate Go module `adapters/caddy`, built
into Caddy with [`xcaddy`](https://github.com/caddyserver/xcaddy).

**Not yet** built.

### 6.6 Standalone reverse proxy (universal fallback)

```sh
inkwall-engine proxy --listen :8080 --upstream http://app:80 --bundle bundle.pb
```

For use outside Kubernetes and with unsupported proxies. It is also the test reference that every
adapter must match.

**Built.**

### 6.7 Integration support matrix (v1 target)

| Proxy | Adapter | Headers | Body | Response | Detect (async) | Transport |
|---|---|---|---|---|---|---|
| Envoy / Envoy Gateway / Istio | ext_proc | ✅ | ✅ streamed | ✅ | ✅ | gRPC over Unix socket |
| Envoy | ext_authz | ✅ | ✅ buffered | ❌ | ❌ | gRPC over Unix socket |
| ingress-nginx | Lua plugin | ✅ | ✅ | ❌ | ✅ (mirror) | HTTP over Unix socket |
| ingress-nginx | global-auth-url | ✅ | ❌ | ❌ | ❌ | localhost HTTP |
| Traefik | ForwardAuth | ✅ | ⚠️ v3 `forwardBody` | ❌ | ❌ | localhost HTTP |
| HAProxy | SPOE | ✅ | ✅ | ❌ | ✅ (async group) | SPOP over Unix socket |
| Caddy | module | ✅ | ✅ | ✅ | ✅ | in-process |
| Any | reverse proxy | ✅ | ✅ | ✅ | ✅ | TCP |

Built: Traefik ForwardAuth and the reverse proxy; the engine's ext_proc listener, without the
operator's Envoy configuration yet.

---

## 7. Request flows

See the [verdict lifecycle](../diagrams/verdict-lifecycle.svg) diagram.

### 7.1 Block mode (Envoy example)

This is the design flow; the Envoy integration is not built yet.

1. The proxy sends the request headers to the engine.
2. The router picks the policy.
3. A rule matches and the [anomaly score](https://coreruleset.org/docs/concepts/anomaly_scoring/) reaches the threshold.
4. The engine answers 403 and emits a security event.

### 7.2 Detect mode

By design, the proxy forwards the request without waiting. The engine logs matches with the
action `LOG`. Built today, every adapter still waits for the verdict: in detect mode the engine
inspects inline and always allows (`pkg/pipeline`).

### 7.3 Engine unavailable

- **Engine unreachable** (timeout or refused connection): by design, the proxy applies the
  failure mode. The engine can't count a request it never received. A proxy-side failure
  counter is a target, not built yet.
- **Engine unreachable, with Traefik (built):** Traefik's ForwardAuth has no timeout, failure or
  fallback setting, so Inkwall's failure mode does not apply. On any error calling the engine,
  Traefik answers **500** with an empty body and doesn't forward the request, in **both** modes
  (`pkg/middlewares/auth/forward.go` in v3.7). Measured on kind with v3.7.13:

  | Engine | Detect mode | Block mode |
  |---|---|---|
  | Refused (crashed, restarting) | 500 in a few ms, app not reached | 500 in a few ms, app not reached |
  | Hung (no answer) | 500 after 30 s, app not reached | 500 after 30 s, app not reached |

  So an engine outage fails closed whatever the mode and failure mode, with Traefik's 500
  rather than the engine's 503: against the policy in detect mode ("never blocks") and with
  `failureMode: Open`. What limits an outage: the engine is a native sidecar, so Traefik starts only once the engine is ready (startup probe); the kubelet restarts a
  crashed engine at once (then with back-off), and a hung one when its liveness probe fails
  (30 s); while the engine isn't ready, neither is Traefik's pod, so a Service sends it no new
  connections. Traefik still serves the connections it has. The kind e2e test checks the refused
  case.
- **Engine reachable, deadline passed:** the engine applies the failure mode itself. Failing
  closed, it answers 503 (`pkg/pipeline`). It counts the request in
  `inkwall_requests_total{reason="timeout"}`. The reasons `timeout`, `error` and `overload` all
  mean "not inspected".

### 7.4 Policy change (GitOps mode)

1. [Argo CD](https://argo-cd.readthedocs.io/en/stable/) applies a `WAFPolicy`.
2. The operator builds and signs a bundle.
3. Engines swap it in and ACK.
4. The policy reports `Enforced=True "every engine runs bundle N or later"`.

### 7.5 Cluster enrollment (Managed / GitOps mode)

1. The user gets a one-time enrollment token (TTL 1 h).
2. The operator generates a key and calls `Enroll(token, CSR)` over server-authenticated TLS.
3. The control plane burns the token and returns a 24 h client certificate bound to the cluster's
   `cluster_id`.
4. The operator stores the certificate in a Secret, and renews it over the stream
   (`RenewCertificate` → `Certificate`).

A retry with the same token and public key within the TTL returns the same certificate, so a lost
response doesn't cost a new token. Renewal needs the current certificate: a cluster offline longer
than the certificate's lifetime enrolls again with a new token. Keys are [ECDSA P-256](https://csrc.nist.gov/pubs/fips/186-5/final) or Ed25519.

**Built:** the contract, and the operator's side
([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)).

---

## 8. Cross-cutting concerns

### 8.1 Security of Inkwall itself

- Images are distroless and run non-root, with a read-only filesystem, no [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) and the
  [seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/) profile `RuntimeDefault`.
- The Unix socket has mode `0660`. TCP listeners need mTLS or must listen on localhost.
  **Built:** the injected engine's check listener is on localhost (`127.0.0.1:9001`). Its admin
  listener (`:9480`: metrics and health, plus pprof only with `--pprof`) is plain HTTP.
  **Not yet:** the socket mode, mTLS.
- Bundles are signed, so editing the bundle Secret can't disable the WAF without the signing key.
- The operator's [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) is scoped ([0004 §7](0004-operator.md#7-rbac)).
- Supply chain: [goreleaser](https://goreleaser.com/), [cosign](https://docs.sigstore.dev/cosign/signing/overview/), an [SBOM](https://www.cisa.gov/sbom) ([syft](https://github.com/anchore/syft)), [SLSA provenance](https://slsa.dev/spec/v1.0/provenance), [`govulncheck`](https://go.dev/doc/security/vuln/) and [Trivy](https://trivy.dev/) in
  CI, pinned [GitHub Actions](https://docs.github.com/en/actions), and `SECURITY.md`. **Built:** all but Trivy. Actions are pinned by
  version tag, not by commit.

### 8.2 Client IP correctness

A wrong client IP makes rate limits and IP lists worse than none. The engine takes the first of:

1. the proxy's resolved client IP;
2. `X-Forwarded-For`, walked from right to left, skipping only `trustedProxies`;
3. the peer IP.

Behind a load balancer, the proxy must learn the client address first: through the PROXY protocol
or `externalTrafficPolicy: Local` ([§6.3](#63-traefik)).

### 8.3 Data privacy

Bodies never leave the engine. Events carry only a redacted snippet of at most 64 bytes. Headers
listed in `events.redact` (default `Authorization`, `Cookie`, `Set-Cookie`) and query strings are
dropped. This is enforced before anything leaves the cluster.

**Built** in the engine (`pkg/events`), with a fixed list: `Authorization`, `Cookie`,
`Set-Cookie`, `Proxy-Authorization`, and the cookie variables. A configurable `events.redact` is
not built yet.

### 8.4 Multi-tenancy

One engine per ingress pod serves all of that pod's policies. Rule sets shared between policies
compile once. The enrollment certificate ([§7.5](#75-cluster-enrollment-managed--gitops-mode))
binds a cluster to its tenant in the control plane.

### 8.5 Observability

Target:

- [Prometheus](https://prometheus.io/docs/introduction/overview/) `inkwall_*` metrics: requests, check latency, rule matches (with bounded
  cardinality), proxy-side adapter failures, bundle version and age, dropped events, rate-limit
  decisions.
- Optional sampled [OpenTelemetry](https://opentelemetry.io/docs/) tracing (one engine span).
- `slog` JSON logs, at most one line per security event.
- A [Grafana](https://grafana.com/docs/grafana/latest/) dashboard and alerts in the Helm chart.

**Built:**

- Engine: `inkwall_requests_total`, `_check_duration_seconds`, `_bundle_version`,
  `_bundle_updates_total`, `_operator_connected`, `_evaluations_in_flight`, `_evaluation_slots`,
  `_engine_events_total`, `_engine_events_dropped_total`.
- Operator: `inkwall_operator_bundle_version`, `_operator_bundle_compressed_bytes`,
  `_operator_engines{state}`, `_operator_events_received_total`,
  `_operator_engine_events_dropped_total`, and, toward the control plane,
  `_operator_events_forwarded_total`, `_operator_events_buffered`,
  `_operator_events_buffer_errors_total`.

**Not yet:** an adapter failure metric (see [§7.3](#73-engine-unavailable)), rule-match and
rate-limit metrics, bundle age, tracing, the dashboard and alerts.

### 8.6 Versioning and compatibility

- The data plane follows [semver](https://semver.org/).
- CRDs move from `v1alpha1` to `v1beta1` to `v1`, with [conversion webhooks](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion).
- The protocol version is sent in `Hello`. The operator supports engines one minor version behind
  (N-1).
- Each release pins a version of the [OWASP Core Rule Set](https://coreruleset.org/) (CRS) as a builtin rule set, so
  upgrades never silently change detection.
- Tested on the last 3 Kubernetes minor versions (`docs/compatibility.md`).

**Not yet:** a version matrix and `docs/compatibility.md` (CI's kind e2e test runs kind's newest
Kubernetes, and [envtest](https://book.kubebuilder.io/reference/envtest) runs 1.29), and conversion webhooks (only `v1alpha1` exists).

---

## 9. Repository layout

| Path | Contents |
|---|---|
| `cmd/` | The engine, the operator and `inkwallctl` |
| `api/` | [Protobuf](https://protobuf.dev/) APIs (built with [buf](https://buf.build/docs/)) |
| `pkg/` | The engine |
| `operator/` | The operator ([0004 §10](0004-operator.md#10-code-layout)) |
| `deploy/helm/` | The Helm chart |
| `hack/kind/` | The kind cluster setup and the kind e2e and upgrade tests |
| `test/` | Test suites and tools |
| `docs/design/` | These design documents |

Planned: `adapters/caddy` and `adapters/traefik-plugin` as separate [Go modules](https://go.dev/ref/mod) (keeping their
dependencies out of the engine), `adapters/nginx-lua`, and `rules/crs/`.

---

## 10. Testing architecture

One shared request corpus drives every level.

| Level | Tool | What it proves | Runs |
|---|---|---|---|
| Unit | `go test` | Package logic | every PR |
| [Fuzz](https://go.dev/doc/security/fuzz/) | `go test -fuzz` | Parsers of untrusted input never panic and keep their properties | nightly; seeds every PR |
| Rule conformance | [go-ftw](https://github.com/coreruleset/go-ftw) + CRS tests | Detection matches CRS | every PR |
| Adapter parity | [testcontainers-go](https://golang.testcontainers.org/) | Adapters match the reverse proxy | every PR |
| E2E | kind + [e2e-framework](https://github.com/kubernetes-sigs/e2e-framework) | Wiring, enforcement, status, failure modes | every PR |
| Performance | [`testing.B`](https://pkg.go.dev/testing#B), [k6](https://grafana.com/docs/k6/latest/) | 0001 budgets | every PR / nightly |
| Upgrade | kind | N-1 → N with no dropped requests | release |
| Soak / chaos | kind + k6 | 24 h stability; engine kill → the proxy fails open | weekly |

**Built (fuzz):** a Go fuzz target for every parser of untrusted input. Each checks a property, not
only that nothing panics:

- the adapters:
  - `FuzzForwardAuth`: only the method and URI the proxy forwarded are inspected, without its
    `X-Forwarded-*` headers;
  - `FuzzCheck`;
  - `FuzzProxy`: a request is refused with 400, or inspected in origin form with a valid Host, and
    what reaches the upstream was inspected, with the same path, query, Host and body;
- the request target and request ID checks the adapters share;
- client IP resolution from `X-Forwarded-For`;
- bundle key files;
- bundle signatures (`FuzzApply`, `FuzzSecretBundle`): nothing but the trusted key's own signature
  of the exact bytes reaches compilation;
- event redaction (`FuzzNew`): valid UTF-8, within the field limits, with no query strings or
  credential snippets;
- `inkwallctl test`'s URL, raw HTTP and HAR input.

Their seed corpora (`testdata/fuzz/`) run in every `make test`. `.github/workflows/fuzz.yaml` runs
each target for 5 minutes nightly and uploads the failing inputs.

**Built (other levels):**

- rule conformance (`make crs-test`, go-ftw);
- E2E and upgrade tests on kind (`make kind-e2e`, `make kind-upgrade`; shell scripts in
  `hack/kind`, on every PR). The upgrade test runs `helm upgrade` from the last release and checks
  that routes stay protected;
- benchmarks (`testing.B`, and the CI `bench` gate;
  [0001 §8](0001-performance-first-architecture.md#8-proving-it-the-performance-test-harness)).

**Not yet:** adapter parity, e2e-framework, k6, soak and chaos tests.

---

## 11. Decisions (ADR log)

Other docs cite these decisions by ID (D1–D9).

| # | Decision | Alternatives considered | Why |
|---|---|---|---|
| D1 | One engine + thin adapters | A WAF per proxy | One core, consistent verdicts |
| D2 | Coraza + CRS behind an interface | Own engine; [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity) | Mature and Go-native; a custom engine stays possible |
| D3 | Sidecar over a Unix socket | Central Deployment; [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) | No network hop ([0001](0001-performance-first-architecture.md)) |
| D4 | The control plane talks to operators only | Control plane → every engine | Fewer connections, no engine egress |
| D5 | Full-snapshot signed bundles | Deltas; unsigned ConfigMaps | Simple, idempotent, tamper-resistant |
| D6 | The operator resolves routes | The engine watches Kubernetes | The engine stays usable outside Kubernetes |
| D7 | Detect mode by default | Block by default | No false-positive outages during onboarding |
| D8 | Fails open in detect mode, fails closed in block mode | Fails open everywhere | A fail-open block mode is bypassable by padding a request past the deadline |
| D9 | One source of truth per cluster | Merge control plane + CRD per route | No ambiguous conflicts |

## 12. Open questions

1. An optional [Hyperscan](https://github.com/intel/hyperscan) ([cgo](https://pkg.go.dev/cmd/cgo)) build?
2. Envoy's Go filter: supported or experimental?
3. Default body cap: 8 KB, 64 KB, or per content type?
4. Distributed rate limiting: gossip or [Redis](https://redis.io/docs/latest/)?
5. A bot challenge in v1? It needs response rewriting, which only ext_proc, Caddy and the reverse
   proxy can do.
