# 0002 — System Architecture

- Status: Draft
- Date: 2026-09-27
- Updated: 2026-10-30
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md)

Inkwall is a web application firewall (WAF) for Kubernetes. This document describes its
components, the protocols between them, and how each proxy is integrated. The performance rules
of [0001](0001-performance-first-architecture.md) apply throughout. Today the engine, the operator
and the Traefik integration are built; the other proxies and the hosted control plane are not.

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

1. One WAF engine, written in Go, behind any ingress proxy (Envoy, Traefik, ingress-nginx,
   HAProxy, Caddy), or as a standalone reverse proxy.
2. Kubernetes-native: installed with Helm, configured with CRDs, managed with GitOps.
3. An optional hosted control plane. The open-source data plane never depends on it.
4. The performance budgets of [0001](0001-performance-first-architecture.md) block a release.

**Built (v0.1.0):** Traefik ForwardAuth for `Ingress` targets, and the standalone reverse proxy.
**Built since:** Traefik `IngressRoute` targets, and the operator's side of the optional control
plane ([§3.4](#34-control-plane-optional)).

### 1.2 Non-goals (for v1)

- L3/L4 DDoS protection: that is the CDN's job.
- TLS termination: that is the proxy's job.
- Proxying production traffic in Kubernetes mode.
- Non-HTTP protocols. gRPC and WebSocket upgrades are inspected as HTTP only.

### 1.3 Glossary

| Term | Meaning |
|---|---|
| **Engine** | `inkwall-engine`: the process that inspects requests and returns verdicts |
| **Proxy** | The ingress controller's data-plane process (Traefik, Envoy, ...) that asks the engine for a verdict. "Ingress controller" means the Kubernetes product as a whole |
| **Adapter** | An engine listener that speaks one proxy protocol (forward-auth, `/v1/check`, reverse proxy, ...), plus the proxy-side configuration or plugin that calls it |
| **Integration** | The operator's support for one proxy: finding its pods, injection and wiring |
| **Injection** | Adding the engine to proxy pods as a sidecar (a container in the same pod) |
| **Wiring** | Configuring the proxy to call the engine on protected routes. For Traefik: the `inkwall-waf` Middleware and the references to it |
| **Operator** | `inkwall-operator`: reconciles the CRDs, injects engines, wires proxies and distributes bundles |
| **Leader** | The operator replica that holds the leader-election lease |
| **Policy** | A `WAFPolicy` object: mode, rule sets, limits and exclusions for a set of routes |
| **Bundle** | A policy bundle: the immutable, versioned, signed snapshot of all of a cluster's policies, built by the operator and enforced by every engine |
| **Policy snapshot** | A `PolicySnapshot`: the policy objects the control plane sends in Managed mode. Not a bundle |
| **Control plane** | The optional hosted service: API, UI, policy store, analytics. A separate product, not in this repository |
| **Cluster mode** | `InkwallConfig.spec.mode`. **Standalone**: no control plane. **GitOps**: policies are CRDs (from Git), mirrored to the control plane. **Managed**: the control plane owns the policies, and the operator writes them as CRDs |
| **Enforcement mode** | Per policy. **Detect mode** logs what it would block. **Block mode** rejects it |
| **Failure mode** | What happens to a request that can't be inspected: the engine **fails open** (lets it through) or **fails closed** (rejects it with 503) |
| **Verdict** | The engine's answer: allow, deny (or log, in detect mode), plus metadata |

"Standalone" alone always means the cluster mode. The engine without an operator is the
**standalone reverse proxy** (`inkwall-engine proxy`), a **standalone Deployment** behind a
Service, or an engine **configured by flags**. With an operator, the engine is in **bundle mode**:
its policies come from the operator's bundles.

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

The engine is a static Go binary in a distroless image. It runs in one of four ways:

- as a **sidecar** in the ingress controller's pod (the default);
- as a **standalone Deployment** behind a Service (simpler, but slower);
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

The compiled policy sits in an `atomic.Pointer[Snapshot]`, so reads take no lock.

| Package | Responsibility | Status |
|---|---|---|
| `pkg/request` | Canonical `Request`, zero-copy headers | built |
| `pkg/router` | `(host, path, method)` → policy | built |
| `pkg/pipeline` | Tiers, deadline, `Verdict` | built |
| `pkg/rules` | `Evaluator` interface; Coraza implementation | built |
| `pkg/clientip` | Client IP ([§8.2](#82-client-ip-correctness)) | built |
| `pkg/agent`, `pkg/policy` | Bundle stream, verify, compile, swap ([§5.2](#52-engine--operator-bundle-distribution)) | built |
| `pkg/telemetry` | Metrics, tracing, `slog` | built |
| `pkg/adapters/*` | One per listener | `forwardauth`, `httpcheck`, `proxy` built; `extauthz`, `extproc`, `spoe` not yet |
| `pkg/events` | Redacted security events, bounded buffer ([§5.4](#54-event-schema)) | built |
| `pkg/ratelimit`, `pkg/iplist` | Token buckets, CIDR trie | not yet |

Lifecycle:

1. Listeners start not ready.
2. The engine loads a bundle: from its disk cache, or else from the bundle Secret.
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

The operator is built on controller-runtime. It runs 2 replicas with leader election. Details are
in [0004 — Kubernetes Operator](0004-operator.md).

| Controller | Does |
|---|---|
| **Discovery** | Finds ingress controllers and the adapter for each |
| **Injection** | Adds the sidecar and its socket volume, through the controller's extension point or a Pod webhook (never a Deployment patch) |
| **Wiring** | Renders proxy configuration (Traefik `Middleware`, ConfigMaps, `EnvoyExtensionPolicy`, ...) |
| **Resolver + bundle builder** | Resolves targets to host, path and method; builds, signs and versions the bundle |
| **Distribution** | Streams bundles to engines and tracks their versions |
| **Upstream sync** | Holds the cluster's single connection to the control plane: pulls policies in Managed mode, pushes state in GitOps mode, forwards events |
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

Two commands are built:

- `test` replays a request or a HAR file and shows the rules that match. It runs offline, for CI.
  It checks one of three things: the policy set by its flags; `WAFPolicy` objects (`--policy`,
  resolved with the operator's resolver and compiled as the engine compiles a bundle); or a bundle
  (`--bundle`, with its signature checked against `--bundle-key`).
- `bench` benchmarks the engine on a fixed corpus.

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

  The most specific target wins: an HTTPRoute rule, then an HTTPRoute, then an Ingress, then the
  namespace default. Ties are rejected (`Accepted=False, reason=Conflict`).
- **`WAFRuleSet` / `ClusterWAFRuleSet`:** `builtin: crs-v4` (pinned), inline `seclang`, or
  `configMapRef`.
- **`WAFIPList` / `ClusterWAFIPList`:** CIDRs, or a URL that the operator fetches (never the
  engine).

**Built:** `InkwallConfig`, `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet`; `Ingress` and
Traefik `IngressRoute` targets.
**Not yet:** IP lists, the policy fields `rateLimits` and `ipLists`, `HTTPRoute` targets,
`BlockHighConfidence`, the `InspectPrefix` oversize action, and `InkwallConfig.events`.

### 4.3 Bundle format

A bundle holds all of a cluster's policies with their resolved routes, the rule sets they use
(each once), and a monotonic `version`. The operator resolves routes to `(host, path, method)`, so
the engine needs no Kubernetes knowledge. A bundle is immutable and signed with Ed25519.

**Built ([`api/bundle/v1`](../../api/bundle/v1/bundle.proto)):**

- A `SignedBundle` holds the serialized `Bundle` bytes, a signature over exactly those bytes, and
  the ID of the signing key. The signature covers bytes, not the decoded message, because protobuf
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

Envoy will use its native `ext_authz` and `ext_proc` services instead.

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
  API server (`--bundle-secret`, over plain HTTPS, without client-go).
- Matching uses host, cleaned path and method, most specific first. A request for a host no policy
  covers is not inspected. A request for a covered host that matches no path gets that host's most
  general policy, so normalization differences can't skip inspection.
- Engines send their security events on the same stream, in `EventBatch`es of up to 1,000
  (`pkg/events`, [§5.4](#54-event-schema)).

**Not yet:** directives (the field is reserved).

### 5.3 Operator ↔ SaaS

The operator talks to the control plane through
[`api/controlplane/v1`](../../api/controlplane/v1/controlplane.proto) (`ControlPlaneService`),
over mTLS. The cluster's identity is its client certificate
([§7.5](#75-cluster-enrollment-managed--gitops-mode)), never a message field.

There are two kinds of stream:

- One **primary stream** per cluster, from the leader. It carries state, policies, directives and
  certificates. When the leader moves, the newer primary stream wins.
- One **events stream** per replica, for the engines connected to that replica. Engines connect to
  any replica.

gRPC status codes tell the operator what to do: re-enroll (`UNAUTHENTICATED`), stop
(`PERMISSION_DENIED`), back off (`RESOURCE_EXHAUSTED`), or reconnect.

Messages on `Connect`:

- Up (operator to control plane): `Hello` (versions, mode, last policy version, capabilities);
  `ClusterState` (a full snapshot of every Inkwall object with its conditions, the integrations,
  the engines and the bundle version); `EventBatch` ([§5.4](#54-event-schema)); `Heartbeat`;
  `PolicyAck` / `PolicyNack`; `RenewCertificate`.
- Down (control plane to operator): `Welcome` (the heartbeat interval, and whether events are
  accepted); `PolicySnapshot` (Managed mode); the renewed `Certificate`; `Directive` (for example,
  resync).

Rules of the contract:

- **Managed mode carries policy objects, not signed bundles.** The operator writes them as CRDs
  ([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)) and signs bundles with the
  cluster's own key, so engines trust only that key.
- Objects travel as their JSON spec. Integrations, kinds and condition reasons travel as strings.
  So new CRD fields, proxies and target kinds need no contract change. There are no
  proxy-specific fields.
- Both sides compress messages (gzip) and accept messages up to 16 MiB.
- In Managed mode, rule sets come inline (`seclang`, `builtin`): the control plane can't create
  the ConfigMap that a `configMapRef` needs.
- Events are delivered at least once, per replica. Each `EventUpload` names its buffer and a
  sequence number. `EventsAck` frees that buffer up to that number. Unacknowledged batches are
  resent after a reconnect, and event IDs (never sequence numbers) remove duplicates. The bounded
  disk queue drops the oldest events when full, and the next batch says how many.
- A policy snapshot is all or nothing: the operator first does a server-side dry run of every
  object. The cluster's `InkwallConfig` decides the mode, and a cluster not in Managed mode
  refuses policy snapshots. Only `WAFPolicy` and the rule set kinds are accepted.
- The operator sets the source label itself (`inkwall.dev/source: saas`). It deletes the labelled
  objects that a policy snapshot no longer has, and records the last version applied. That version
  is sent in `Hello`, and an older policy snapshot is refused.
- In Managed mode the validating webhook lets only the operator write the labelled objects. It
  fails closed.
- In Standalone mode, events go to logs and optionally to OTLP. Not yet: only the engine's log.

**Built:** the contract (#86), enrollment and the primary stream, state sync (`ClusterState`), the
events streams with each replica's disk buffer, and Managed mode (policy snapshots written as
CRDs, pruned and acknowledged; the webhook guard). All of it is tested on kind against a stub
control plane ([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)).

### 5.4 Event schema

A `SecurityEvent` ([`api/events/v1`](../../api/events/v1/events.proto)) holds: IDs, the engine and
pod, the policy and bundle version, action, reason, matches (rule, variable, redacted snippet),
score, method, host, path (without the query), client IP, user agent, request ID, status and
latency.

The same message goes from engine to operator (`agent.v1` `Watch`) and from operator to control
plane. Both carry it in an `EventBatch`, with a count of dropped events.

**Built:** the schema. Engines produce redacted events and send them to their operator replica,
which forwards them to the control plane on its events stream (#91, #92).

---

## 6. Proxy integrations

Every integration follows the same rules. It sends only what the policy needs, over a persistent
connection (a Unix socket where possible). Its timeout is just above the engine's deadline. On an
error it applies the failure mode. It passes the client IP and the request ID. The socket
directory is a shared `emptyDir` at `/var/run/inkwall`. (Traefik, built, is the exception to the
timeout and failure-mode rules: the operator's ForwardAuth Middleware sets no timeout and has no
failure-mode setting; [§7.3](#73-engine-unavailable).)

### 6.1 Envoy (raw Envoy, Envoy Gateway, Istio, Contour)

The engine serves `ext_proc` (preferred) or `ext_authz`, over gRPC on a Unix socket. Each product
is configured its own way:

- Envoy Gateway: a `Backend` and an `EnvoyExtensionPolicy`.
- Istio: an `EnvoyFilter`.
- Contour: an `ExtensionService`.

Detect mode uses `observability_mode`. Envoy's Go filter needs a contrib build, so it is
experimental.

**Not yet** built.

### 6.2 ingress-nginx

Two options, neither of which needs snippets:

- A. A Lua plugin (the default, with body support) calls `/v1/check` over a Unix socket and skips
  unprotected routes.
- B. `global-auth-url`: no code, but a subrequest per request and no bodies.

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

The Middleware is attached with the `traefik.ingress.kubernetes.io/router.middlewares` annotation
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

**Client IP behind a load balancer.** Behind a load balancer, Traefik's peer is the load balancer
or a node, and the engine would see that as the client. The load balancer's `X-Forwarded-For`
can't help: the engine sees it only with `trustForwardHeader: true`, which lets the client choose
`X-Forwarded-Uri` (above).

So the address comes from the connection, in one of two ways:

- The load balancer sends a PROXY protocol header (v1 or v2). Traefik accepts it only from the load
  balancer's CIDRs (`entryPoints.<name>.proxyProtocol.trustedIPs`, never `0.0.0.0/0`).
- `externalTrafficPolicy: Local` keeps the source address.

Traefik uses that address as the remote address, and ForwardAuth sends it as `X-Forwarded-For`.
The engine trusts `X-Forwarded-For` from loopback only ([§8.2](#82-client-ip-correctness)). No
engine change was needed. The setup for each load balancer is in [client IP](../client-ip.md).
The kind e2e test checks that a PROXY address is used, that a client-sent `X-Forwarded-For` is
ignored, and that an untrusted PROXY header is ignored (verified on v3.7.13).

**B. Traefik plugin (later):** Traefik runs plugins in Yaegi, which can't run Coraza well. So the
plugin would be a thin client to the sidecar (or use http-wasm).

**Built:** A, for `Ingress` and `IngressRoute` targets. **Not yet:** B.

### 6.4 HAProxy (HAProxy Kubernetes Ingress Controller, HAProxy Ingress)

HAProxy uses SPOE: the engine is the agent (SPOA), over a Unix socket. An `http-request deny` rule
acts on the variable `txn.inkwall.action`. To fail closed, an extra rule denies with 503 when the
variable is unset. Body inspection needs `http-buffer-request`, enabled only when a policy needs
it.

**Not yet** built.

### 6.5 Caddy

An in-process handler, `http.handlers.inkwall`, in a separate Go module `adapters/caddy`, built
into Caddy with `xcaddy`.

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

Built: Traefik ForwardAuth and the reverse proxy.

---

## 7. Request flows

See the [verdict lifecycle](../diagrams/verdict-lifecycle.svg) diagram.

### 7.1 Block mode (Envoy example)

This is the design flow; the Envoy integration is not built yet.

1. The proxy sends the request headers to the engine.
2. The router picks the policy.
3. A rule matches and the anomaly score reaches the threshold.
4. The engine answers 403 and emits a security event.

### 7.2 Detect mode

By design, the proxy forwards the request without waiting. The engine logs matches with the
action `LOG`. Built today, every adapter still waits for the verdict: in detect mode the engine
inspects inline and always allows (`pkg/pipeline`).

### 7.3 Engine unavailable

- **Engine unreachable** (timeout or refused connection): by design, the proxy applies the
  failure mode. With Traefik (built), ForwardAuth decides on its own, so Inkwall's failure mode
  does not apply. The engine can't count a request it never received. A proxy-side failure
  counter is a target, not built yet.
- **Engine reachable, deadline passed:** the engine applies the failure mode itself. Failing
  closed, it answers 503 (`pkg/pipeline`). It counts the request in
  `inkwall_requests_total{reason="timeout"}`. The reasons `timeout`, `error` and `overload` all
  mean "not inspected".

### 7.4 Policy change (GitOps mode)

1. Argo CD applies a `WAFPolicy`.
2. The operator builds and signs a bundle.
3. Engines swap it in and ACK.
4. The policy reports `Enforced=True "6/6 engines on bundle N"`.

### 7.5 Cluster enrollment (Managed / GitOps mode)

1. The user gets a one-time enrollment token (TTL 1 h).
2. The operator generates a key and calls `Enroll(token, CSR)` over server-authenticated TLS.
3. The control plane burns the token and returns a 24 h client certificate bound to the cluster's
   `cluster_id`.
4. The operator stores the certificate in a Secret, and renews it over the stream
   (`RenewCertificate` → `Certificate`).

A retry with the same token and public key within the TTL returns the same certificate, so a lost
response doesn't cost a new token. Renewal needs the current certificate: a cluster offline longer
than the certificate's lifetime enrolls again with a new token. Keys are ECDSA P-256 or Ed25519.

**Built:** the contract, and the operator's side
([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)).

---

## 8. Cross-cutting concerns

### 8.1 Security of Inkwall itself

- Images are distroless and run non-root, with a read-only filesystem, no capabilities and the
  seccomp profile `RuntimeDefault`.
- The Unix socket has mode `0660`. TCP listeners need mTLS or must listen on localhost.
  **Built:** the injected engine's check listener is on localhost (`127.0.0.1:9001`). Its admin
  listener (`:9480`: metrics and health, plus pprof only with `--pprof`) is plain HTTP.
  **Not yet:** the socket mode, mTLS.
- Bundles are signed, so editing the bundle Secret can't disable the WAF without the signing key.
- The operator's RBAC is scoped ([0004 §7](0004-operator.md#7-rbac)).
- Supply chain: goreleaser, cosign, an SBOM (syft), SLSA provenance, `govulncheck` and Trivy in
  CI, pinned GitHub Actions, and `SECURITY.md`. **Built:** all but Trivy. Actions are pinned by
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

- Prometheus `inkwall_*` metrics: requests, check latency, rule matches (with bounded
  cardinality), proxy-side adapter failures, bundle version and age, dropped events, rate-limit
  decisions.
- Optional sampled OpenTelemetry tracing (one engine span).
- `slog` JSON logs, at most one line per security event.
- A Grafana dashboard and alerts in the Helm chart.

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

- The data plane follows semver.
- CRDs move from `v1alpha1` to `v1beta1` to `v1`, with conversion webhooks.
- The protocol version is sent in `Hello`. The operator supports engines one minor version behind
  (N-1).
- Each release pins a version of the OWASP Core Rule Set (CRS) as a builtin rule set, so
  upgrades never silently change detection.
- Tested on the last 3 Kubernetes minor versions (`docs/compatibility.md`).

**Not yet:** a version matrix and `docs/compatibility.md` (CI's kind e2e test runs kind's newest
Kubernetes, and envtest runs 1.29), and conversion webhooks (only `v1alpha1` exists).

---

## 9. Repository layout

| Path | Contents |
|---|---|
| `cmd/` | The engine, the operator and `inkwallctl` |
| `api/` | Protobuf APIs (built with buf) |
| `pkg/` | The engine |
| `operator/` | The operator ([0004 §10](0004-operator.md#10-code-layout)) |
| `deploy/helm/` | The Helm chart |
| `hack/kind/` | The kind cluster setup and the kind e2e and upgrade tests |
| `test/` | Test suites and tools |
| `docs/design/` | These design documents |

Planned: `adapters/caddy` and `adapters/traefik-plugin` as separate Go modules (keeping their
dependencies out of the engine), `adapters/nginx-lua`, and `rules/crs/`.

---

## 10. Testing architecture

One shared request corpus drives every level.

| Level | Tool | What it proves | Runs |
|---|---|---|---|
| Unit | `go test` | Package logic | every PR |
| Fuzz | `go test -fuzz` | Parsers of untrusted input never panic and keep their properties | nightly; seeds every PR |
| Rule conformance | go-ftw + CRS tests | Detection matches CRS | every PR |
| Adapter parity | testcontainers-go | Adapters match the reverse proxy | every PR |
| E2E | kind + e2e-framework | Wiring, enforcement, status, failure modes | every PR |
| Performance | `testing.B`, k6 | 0001 budgets | every PR / nightly |
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
| D2 | Coraza + CRS behind an interface | Own engine; libmodsecurity | Mature and Go-native; a custom engine stays possible |
| D3 | Sidecar over a Unix socket | Central Deployment; DaemonSet | No network hop ([0001](0001-performance-first-architecture.md)) |
| D4 | The control plane talks to operators only | Control plane → every engine | Fewer connections, no engine egress |
| D5 | Full-snapshot signed bundles | Deltas; unsigned ConfigMaps | Simple, idempotent, tamper-resistant |
| D6 | The operator resolves routes | The engine watches Kubernetes | The engine stays usable outside Kubernetes |
| D7 | Detect mode by default | Block by default | No false-positive outages during onboarding |
| D8 | Fails open in detect mode, fails closed in block mode | Fails open everywhere | A fail-open block mode is bypassable by padding a request past the deadline |
| D9 | One source of truth per cluster | Merge control plane + CRD per route | No ambiguous conflicts |

## 12. Open questions

1. An optional Hyperscan (cgo) build?
2. Envoy's Go filter: supported or experimental?
3. Default body cap: 8 KB, 64 KB, or per content type?
4. Distributed rate limiting: gossip or Redis?
5. A bot challenge in v1? It needs response rewriting, which only ext_proc, Caddy and the reverse
   proxy can do.
