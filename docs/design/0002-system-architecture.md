# 0002 — System Architecture

- Status: Draft
- Date: 2026-09-27
- Updated: 2026-11-04
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
  - [8.7 gRPC messages](#87-grpc-messages)
- [9. Repository layout](#9-repository-layout)
- [10. Testing architecture](#10-testing-architecture)
- [11. Decisions (ADR log)](#11-decisions-adr-log)
- [12. Open questions](#12-open-questions)

---

## 1. Scope

### 1.1 Goals

1. One WAF engine, written in [Go](https://go.dev/), behind any ingress proxy ([Envoy](https://www.envoyproxy.io/docs/envoy/latest/), Traefik,
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
| `pkg/adapters/*` | One per listener | `forwardauth`, `httpcheck`, `proxy`, `extproc`, `spoe` built; `extauthz` not yet |
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

**Built:** injection, proxy discovery, Traefik and Envoy Gateway wiring, the resolver, the bundle
builder, distribution, status, and upstream sync (GitOps and Managed modes, security events and
request counts, [§5.3](#53-operator--saas)).
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
  `events`. `engine` holds the image, resources and `bootstrapMode`; its `socketDir` is deprecated and ignored. Its resources
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
    responses: {inspect: true, maxBytes: 65536, onOversize: Deny}       # | Allow
  ```

  **CRS settings (#352).** A CRS binding's `crs` block sets `tx.allowed_methods`,
  `tx.allowed_request_content_type`, `tx.detection_paranoia_level` and
  `tx.outbound_anomaly_score_threshold`. The engine sets them on each transaction before phase 1,
  as it does the paranoia level ([0004 §8](0004-operator.md#8-scale-targets-v1)), so they add no
  compiled rule set, and SecLang that sets the same variables still wins. A request that the rules
  between the blocking and the detection paranoia level would have blocked (the CRS's detection
  score reaches the threshold, the blocking score doesn't) gets the verdict `log` with reason
  `none`, in either mode. It is a security event, and it is never denied. The reason stays `none`
  so that the decisions taken on clean requests (an oversize body with `onOversize: Deny`, a
  WebSocket handshake that breaks the policy) still apply. Without a detection level above the
  blocking one, nothing changes: a request scored below the threshold stays `allow`.

  **Rule set placement (#423).** A SecLang rule set's binding takes `placement: BeforeCRS` or
  `AfterCRS` (the default). The bundle carries it on the binding (`RuleSetBinding.placement`,
  unset for `AfterCRS`, so existing bundles don't change), and the engine compiles the rule sets
  placed before the CRS, in order, as `DirectivesBeforeCRS`: the standalone engine's
  `--rules-before-crs`. They run before the CRS's initialization (REQUEST-901), so a variable they
  set with `setvar` is one the CRS keeps, and a `ctl:ruleRemoveById` turns a CRS rule off before it
  runs. `AfterCRS` rules come too late for both in the CRS's own phase. A policy binding the same
  rule set before and another after the CRS compiles two rule sets. What can't run before the CRS
  is refused when the bundle is built ([0004 §3.1](0004-operator.md#31-validation)). An engine
  before 0.6.0 ignores the field and loads the rule set after the CRS, so the policy is
  `Enforced=False` (`EnginesOutdated`) while one runs it.

  The most specific target wins: an [HTTPRoute](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) rule, then an HTTPRoute, then an Ingress, then the
  namespace default. Ties are rejected (`Accepted=False, reason=Conflict`).
- **`WAFRuleSet` / `ClusterWAFRuleSet`:** `builtin: crs-v4` (pinned), inline `seclang`, or
  `configMapRef`.
- **`WAFIPList` / `ClusterWAFIPList`:** CIDRs, or a URL that the operator fetches (never the
  engine).

  **Built (#358):** the namespaced `WAFIPList` with CIDR entries, named by
  `WAFPolicy.spec.ipLists: {allow, deny}` in the policy's namespace. The operator resolves the
  lists into each policy's `ip_lists` in the bundle (an unknown or invalid list makes the policy
  `Accepted=False`, `InvalidRef`). The engine checks the resolved client IP before anything else,
  skip paths and rules included, as sorted, merged ranges with a binary search (`pkg/iplist`:
  about 60 ns at 10,000 prefixes, no allocation). A client in a deny list is denied with 403 and
  reason `ip-deny` (logged in `Detect` mode). One in an allow list and not in a deny list is let
  through uninspected, its body unread, with reason `ip-allow`: counted in the metrics, not a
  security event, since allowed clients would flood the events. Deny wins over allow, so an
  allowed range can't open a hole in a denied one. An engine before 0.5.0 ignores the lists, so
  the policy is `Enforced=False` (`EnginesOutdated`) meanwhile. Not built: `ClusterWAFIPList`,
  lists fetched from a URL.

**Built:** `InkwallConfig`, `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet`; `Ingress` and
Traefik `IngressRoute` targets; `HTTPRoute` targets resolved, with the precedence above
([0004 §4.5](0004-operator.md#45-resolver)), and wired through Envoy Gateway or Traefik's Gateway
API provider ([0004 §4.4](0004-operator.md#44-wiring-controller)).
**Not yet:** cluster-wide and fetched IP lists, the policy field `rateLimits`, wiring other controllers'
`HTTPRoute` targets, `BlockHighConfidence`, the `InspectPrefix` oversize action, and
`InkwallConfig.events`.

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
- `policy_versions` is the operator's bookkeeping: for each policy, the first bundle that enforces
  it as it is ([0004 §4.8](0004-operator.md#48-status-aggregator)). It is not part of `content_hash`, and engines ignore it.

**Not yet:** IP lists, rate limits.

---

## 5. Protocols

### 5.1 Engine check API (for Lua, generic HTTP clients, and tests)

[`api/engine/v1/engine.proto`](../../api/engine/v1/engine.proto) defines a `CheckRequest` and a
`CheckResponse`:

- `CheckRequest`: method, authority, raw URI, headers, `client_ip` and `peer_ip`, and an optional
  body. The IPs are text, so JSON clients can write them.
- `CheckResponse`: action, status, headers, rule IDs and reason, and where the rules matched
  (`matches`: rule and variable name, never the value) and the anomaly score.

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
- `Heartbeat` also carries the receipts of the operator's probes the engine verified where Envoy
  discards its answer (`probe_receipts`, since v0.6.0): the proof of `Detect`-mode Istio routes
  ([§6.1](#61-envoy-raw-envoy-envoy-gateway-istio-contour), #475).
- The engine reconnects with jittered backoff. With no cache, it reads the bundle Secret from the
  API server (`--bundle-secret`, over plain HTTPS, without [client-go](https://github.com/kubernetes/client-go)).
- Matching uses host, cleaned path and method, most specific first. An exact host wins over a
  wildcard, and a longer wildcard over a shorter one. A wildcard (`*.example.com`) matches one
  label from an Ingress, as Ingress defines, and subdomains at any depth (`a.b.example.com`) from an
  HTTPRoute, as the [Gateway API](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) defines
  (the bundle's `wildcard_any_depth`; engines before 0.3.0 ignore it and match one label). Neither
  matches `example.com` itself. A request for a host no policy covers is not inspected. A request for a covered host that matches no path gets that host's most
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
error it applies the failure mode. It passes the client IP and the request ID. A Unix socket
lives in an [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) the
engine and the proxy share, at a path the integration fixes (Envoy Gateway:
`/var/run/inkwall-socket`). (Traefik, built, is the exception to the
timeout and failure-mode rules: the operator's ForwardAuth Middleware sets no timeout and has no
failure-mode setting; [§7.3](#73-engine-unavailable).)

**WebSocket (#276, decided for v0.4.0).** Every integration sees the handshake as a request, before
the proxy upgrades the connection, and none sees the messages after it. So:

- **The handshake is a request.** The engine inspects it with the policy's rules at every adapter,
  and a denial is the adapter's usual answer (403), sent before the upgrade. The engine tells a
  handshake by any one of `Upgrade: websocket`, `Sec-WebSocket-Key` or `Sec-WebSocket-Version`,
  since Traefik's ForwardAuth drops the first and HTTP/2 has no key. The Core Rule Set raises
  nothing on a browser's handshake at any paranoia level (tested on the pipeline and each adapter),
  so there is no WebSocket exclusion.
- **Origin and required headers are the engine's, not the proxy's.** A `WAFPolicy`'s
  `spec.webSocket` (allowed origins, against cross-site WebSocket hijacking; required headers) is
  compiled into the bundle and checked by the engine before the rules: one implementation for
  every proxy, with `Detect` mode and events like any rule. Proxy features (Envoy Gateway's CORS,
  Traefik middlewares) differ per proxy and don't apply to WebSocket handshakes alike. The
  webhook compiles the field with the engine's code. An engine before 0.4.0 ignores the field, so
  the operator doesn't report a policy that sets it `Enforced` while one runs it
  ([0004 §4.8](0004-operator.md#48-status-aggregator)).
- **An upgrade has no body to wait for.** ext_proc decides a bodiless upgrade on its headers and
  tells Envoy to stop sending the stream ([0006 §2](0006-adapter-protocols.md#2-ext_proc-envoy-external-processing)).
- **Messages are not inspected, and nothing claims they are.** Only a hook on the stream after the
  upgrade could, and Traefik's ForwardAuth has none: it asks once, before the upgrade. Message
  inspection (frame parsing, size limits, text frames as arguments, a close code on a denial) is the
  second part of #276, and must state per proxy where it happens.

**WebSocket messages through Envoy (#276, open: what was tried).** The plan was ext_proc in
`STREAMED` mode for upgrades only: the engine answers an upgrade's headers with a `mode_override`
(`request_body_mode: STREAMED`), which Envoy Gateway allows per `EnvoyExtensionPolicy`
(`processingMode.allowModeOverride`, in its API at v1.9.3), and parses the frames Envoy sends as
body chunks. Tried on Envoy v1.39.6 (the raw Envoy sample's version) with an ext_proc probe and
`hack/wsecho`:

| ext_proc request body mode for the upgrade | Handshake | Frames seen by the engine |
|---|---|---|
| `BUFFERED_PARTIAL`, answered `CONTINUE` (0.3.1) | Held until a timeout | No |
| `CONTINUE_AND_REPLACE` (0.4.0, 0.3.2) | Upgrades | No |
| `mode_override` to `NONE` | Upgrades | No |
| `STREAMED` (configured, or `mode_override`), `FULL_DUPLEX_STREAMED` | Held until a timeout | Only from a client that sends a frame before the `101` |
| `mode_override` to `STREAMED` on the `101`'s response headers | Upgrades | No (a request mode can't change once its headers are past) |

Envoy passes the upgraded data to ext_proc as body chunks, but in a streamed mode it holds the
request headers until the first chunk, and a client sends its first frame only after the `101`: the
handshake deadlocks. So ext_proc can't inspect WebSocket messages for a compliant client, on any
route, whatever Envoy Gateway allows.

**Decided for v0.4.0:** WebSocket messages are inspected only by the engine's reverse proxy
(`inkwall-engine proxy`), which copies the upgraded connection itself: it parses the client's
frames, holds a message until it is inspected, and in `Block` mode closes the connection with 1008
([0006 §6](0006-adapter-protocols.md#6-reverse-proxy-standalone-mode)). Routes wired through
ext_proc (Envoy Gateway, raw Envoy) and Traefik inspect the handshake only, and no `WAFPolicy`
field asks for message inspection, so nothing claims it there.

**Built (#363):** a message is evaluated in its own scope: a `GET` of the handshake's path (for
exclusions and path rules) with the handshake's request ID and client IP, fixed clean `Accept`
and `User-Agent` headers, and the message as arguments. The handshake's query arguments and
headers were inspected with it and aren't evaluated again, so its score doesn't add to every
message's, and each message skips the header rules' work (`BenchmarkWebSocketMessage`: about 40%
less time and 35% fewer allocations). A SecLang rule on headers or query arguments sees none with
a message. Messages are counted apart from requests (`inkwall_websocket_messages_total`, #356).

The options weighed:

1. **The engine's reverse proxy:** chosen. It works for the standalone proxy, with its own flags,
   and is the reference for the others. On Envoy Gateway it would have to be in the request path,
   a hop the operator can't add without changing the user's routes or their backends.
2. **Envoy's Lua filter:** not pursued. It sees the frames (`bodyChunks()`) without holding the
   handshake, but doesn't hold a chunk while the script runs, so a frame is forwarded before it is
   inspected: detect only at best, and unproven.
3. **A change in Envoy's ext_proc,** continuing an upgrade's headers in a streamed mode as for any
   request whose body comes later: then the planned design works unchanged, with a `WAFPolicy`
   field and status that says where it isn't done (Traefik). Tracked for v1.0.0 in #313.

### 6.1 Envoy (raw Envoy, Envoy Gateway, Istio, Contour)

The engine serves `ext_proc` (preferred) or `ext_authz`, over gRPC on a [Unix socket](https://man7.org/linux/man-pages/man7/unix.7.html). Each product
is configured its own way:

- [Envoy Gateway](https://gateway.envoyproxy.io/): a `Backend` and an `EnvoyExtensionPolicy`.
- [Istio](https://istio.io/latest/docs/): an [`EnvoyFilter`](https://istio.io/latest/docs/reference/config/networking/envoy-filter/).
- [Contour](https://projectcontour.io/docs/): an `ExtensionService`.

Detect mode uses `observability_mode`. Envoy's [Go filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/golang_filter) needs a contrib build, so it is
experimental.

**Built:** the engine's side, `inkwall-engine ext-proc` ([0006 §2](0006-adapter-protocols.md#2-ext_proc-envoy-external-processing)), and
Envoy Gateway, with `ext_proc`, not `ext_authz`: the engine joins the Envoy pods through the
Gateway's `EnvoyProxy`, and each protected HTTPRoute gets an `EnvoyExtensionPolicy` calling it
through a `Backend` on a Unix socket ([0004 §4.4](0004-operator.md#44-wiring-controller)).
Raw Envoy, configured by its user: no operator integration, since there is no API object to wire.
The user adds the `ext_proc` filter to `envoy.yaml` and runs the engine next to Envoy, with the
policy from flags or, in a cluster with the operator, from its bundles: the user grants the read
access and keeps the trust ConfigMap that injection sets up for the integrations
([raw Envoy](../raw-envoy.md)). Its policies target an `Ingress` of a class no controller serves,
so they report `Programmed=False` (`ControllerUnsupported`), as the operator wires nothing.
`make raw-envoy-e2e` (Docker) and `make kind-e2e-raw-envoy` run the samples.

**Built (v0.4.0, #281): Istio**, for the HTTPRoutes of its Gateway API implementation (GatewayClass
controller `istio.io/gateway-controller`), with `ext_proc` through an `EnvoyFilter`. Decided:

- **No native ext_proc in Istio.** Its `MeshConfig.extensionProviders` have
  `envoyExtAuthzHttp` and `envoyExtAuthzGrpc` (ext_authz, used by `AuthorizationPolicy`
  `CUSTOM`), tracing and access-log providers, and no ext_proc one (checked in `istio/api` for
  1.31 and master); a `WasmPlugin` runs Wasm, not ext_proc. So the operator writes the filter
  itself, in an `EnvoyFilter`, as raw Envoy's users do in `envoy.yaml`.
- **Discovery.** Istio's GatewayClasses (`istio` by default) are `Full` in `status.proxies`;
  its Gateway pods carry `gateway.istio.io/managed=istio.io-gateway-controller` and
  `gateway.networking.k8s.io/gateway-name=<gateway>`. Istio runs a Gateway's pods in the Gateway's
  namespace, so that namespace must be a proxy namespace (`istio-ingress` and `istio-system` are
  defaults).
- **Engine placement: Istio's own customization, not the Pod webhook.** Istio renders each
  Gateway's Deployment and overlays it with the `deployment` key of the ConfigMap the Gateway's
  `spec.infrastructure.parametersRef` names, and rolls the pods when it changes. The engine goes there as a native sidecar, with the `emptyDir` holding its Unix socket
  (`/var/run/inkwall-socket/extproc.sock`) also mounted in `istio-proxy`: into the user's
  ConfigMap, keeping their entries, or into one the operator makes and names in the Gateway, as for
  Envoy Gateway's `EnvoyProxy`. Istio's Envoy runs as UID 1337, so the engine makes the socket
  writable by every user; the `emptyDir` keeps it to the pod.
- **Wiring.** One `EnvoyFilter` per Gateway with protected routes (`workloadSelector` on its
  pods): a `STATIC` cluster on the socket (HTTP/2), and per protected HTTPRoute an
  `envoy.filters.http.ext_proc` filter inserted before the router, `disabled: true`, enabled by
  `typed_per_filter_config` on the Envoy routes of its protected rules only. Istio names an Envoy
  route after its HTTPRoute rule (`name`, or `<namespace>.<route>.<index>` for an unnamed rule), so
  a protected rule whose name another HTTPRoute of the Gateway also gives a rule would select that
  route's traffic too: refused (`WiringFailed`, rename one). Unprotected routes cost nothing (the
  filter is off there). The settings are Envoy Gateway's: the request headers with
  `request.protocol`, the body `BUFFERED_PARTIAL` when a policy inspects it (`STREAMED` in detect
  mode), no response; `message_timeout` the longest policy timeout plus 500 ms;
  `failure_mode_allow` when every policy fails open; `observability_mode` when every policy is in
  detect mode and fails open; `status_on_error` 503, as the engine answers a request it can't
  inspect; and, when Envoy holds a body, the listener's `per_connection_buffer_limit_bytes` raised to
  10 MiB, the largest `body.maxBytes`.
- **Status.** A route is wired on a Gateway once every running pod of it has the engine; it is
  `Programmed` once that holds on all its Gateways and Istio has accepted it (its parent status,
  `Accepted=True` from `istio.io/gateway-controller`) on each, and the operator's probe has
  reached the engine through every pod on every listener the route is attached to (#372): Istio
  reports nothing on an `EnvoyFilter` and accepts patches that match no Envoy route. Until then it
  is `Pending` (or `PendingRestart`, `SidecarMissing`, `Unverified`), never `Ready`.
- **The probe** (#372, the same `Prober` as HAProxy's, §6.4, with a target builder per
  integration): per Gateway, a target per protected rule (VirtualService http route) and per
  listener (server) the route is on, from the rule's first match the probe can make (exact or
  prefix path, exact headers and query parameters, the method), with the route's host (a wildcard
  made concrete, `inkwall-probe.<suffix>`) on the listener's port, over TLS for HTTPS (`SIMPLE`).
  The ext_proc adapter answers it with Envoy's local reply, 200 and the answer's MAC (0006 §2). A
  rule whose matches are all regular expressions, or a mutual-TLS or passthrough server, can't be
  probed: `NotProbeable`. In detect mode Envoy discards the answer: such a route is proven by
  the engine's receipt instead (below).
- **Detect mode: proof by receipt** (decided for v0.6.0, #475). In observability mode Envoy
  forwards the request without waiting and ignores the engine's reply, so the probe's answer never
  comes back. The engine, on a probe whose MAC it verifies in observability mode, keeps a
  *receipt* instead: an HMAC-SHA256 under the probe key of the purpose `receipt`, the nonce, host
  and URI, cut to 128 bits (32 hex digits, `pkg/haproxyprobe`). It keeps at most 16, none older
  than a minute, each once, and sends them with every heartbeat (`Heartbeat.probe_receipts`); the
  replica keeps the last ones in the engine's record of its engine report (0004 §4.7), which the
  leader's `Prober` reads. A route whose policies are all in `Detect` mode is `Programmed` once,
  for every pod and target, the engine *of the probed pod* (its pod from the stream's
  authenticated token, or the `Hello` when the token isn't bound to a pod) reported the receipt of
  *that* probe; none within 30 s fails the probe (`Unverified`, "reported no receipt"), retried
  every 20 s as any failed probe. At most 8 probes per pod wait for a receipt at once, under the
  16 an engine keeps.
  - **What a receipt proves, and what it doesn't.** It proves that the engine in that pod got the
    request through the route's filter on that listener: it sees the route's traffic there, which
    is all `Detect` mode does with it (it logs, never blocks). That is what `Programmed` means for
    a `Detect` route. It proves nothing about blocking: a route with a policy in `Block` mode is
    proven only by the answer coming back, and the receipt flag is part of each result's key, so a
    route that moves between modes is probed again, not proven by the other mode's result.
  - **Forged or replayed receipts prove nothing.** The receipt is under the probe key, with its
    own purpose: neither the request's MAC nor the answer (the parts a party on the network sees)
    is one, so whoever sees the probe can't make its receipt. The operator expects one receipt per
    probe, for its fresh random nonce, only while that probe waits, and only from the probed pod's
    engine: a receipt of an earlier probe, another pod's, under another key, or in a report older
    than 30 s matches nothing. Engines report only over their authenticated stream (0004 §4.7),
    whose limits refuse more than 16 receipts or one that isn't 32 lowercase hex digits. An engine
    has the key, so a compromised engine could vouch for its own pod's routes: it can already
    pass that pod's traffic uninspected, so this adds nothing to what it can do.
  - **The probe reaches the app** in `Detect` mode, Envoy forwarding it. So it is sent only as
    `GET` or `HEAD` without a body: a rule whose match is for another method is `NotProbeable` in
    `Detect` mode. And the engine inspects a probe in observability mode as any request (it
    answers one uninspected only in `Block` mode, where Envoy doesn't forward it): a probe's
    header, which binds only the host and URI, then can't carry a request past the engine's log.
    The TLS rules (#507, #511) are unchanged: no header or query values over TLS, the certificate
    not checked, the MAC (here the receipt) the proof.
  - **Rejected:** proving `Detect` routes by the answer (Envoy discards it); by the engine's
    request counts or security events (they don't name the probe, and can't be told from forged
    traffic); a receipt without a MAC (a ConfigMap writer, or anyone who saw the nonce, could make
    it); switching the route to `Block` for the probe (it changes what the user's traffic gets).
  An Istio older than 1.28 (from the `istio-proxy` image tag) is `WiringFailed`: its Envoy (before
  1.36) would reject `status_on_error` and keep serving without the filter. Without the
  `EnvoyFilter` CRD nothing is wired (`WiringFailed`). Without its ClusterRole,
  `inkwall-operator-istio` (`rbac.integrations.istio`), the integration is disabled
  (`IntegrationDisabled`).
- **Tested** with Istio 1.31.3 (its `base` and `istiod` charts, the Gateway API's standard CRDs
  v1.7.0, no mesh): envtest with a stand-in `EnvoyFilter` CRD, and `make kind-e2e-istio`.
- **Mesh sidecars** (ext_proc in every workload's Envoy) are out of scope: the `EnvoyFilter`
  targets gateway pods only.

**Built (v0.4.0, #281): Istio's own API**, `VirtualService` targets bound to Istio `Gateway` objects
(`networking.istio.io`), a second integration, `istio-ingress`, with its own ClusterRole
(`inkwall-operator-istio-ingress`, `rbac.integrations.istioIngress`). Decided:

- **Engine placement: the Pod webhook, as for Traefik.** The ingress gateway is the user's
  Deployment (Istio's `gateway` Helm chart), and Istio has no API to add a container to it; patching
  the Deployment would drift from the user's Helm release and need write access to every
  Deployment. A Pod webhook entry of its own, `istio-ingress.pods.waf.inkwall.dev`, selects pods
  labelled `istio: ingressgateway` (the chart's default, overridable in `InkwallConfig`) in the
  proxy namespaces: a webhook's `objectSelector` can't select either of two label sets, so each
  injected proxy has its own entry, both kept by the operator. It adds the engine and mounts its
  socket directory in `istio-proxy`, and is called again (`reinvocationPolicy: IfNeeded`) to
  restore that mount if Istio's own injector rewrites the container. Pods that ran before get the
  engine when restarted (`PendingRestart`), and keep it after unwiring until restarted.
- **Wiring.** An Istio Gateway selects pods in any namespace, and several Gateways may select the
  same pods; Envoy rejects two HTTP filters of one name. So the `EnvoyFilter` objects are per
  namespace of gateway pods, `inkwall-istio-ingress` (the cluster) and 32 shards (#424), with the
  integration's labels as `workloadSelector`, and one ext_proc filter per protected VirtualService (`inkwall.ext_proc.vs.<namespace>.<name>`),
  turned on by `typed_per_filter_config` on its Envoy routes, with the same settings as for
  HTTPRoutes. Istio names those routes after the http route's `name` (then `.` and a named match's
  `name`; checked in Istio 1.31.3's `route.go` and on kind): an unnamed http route can't be selected
  (`WiringFailed`), and a name another VirtualService on the same pods uses is refused.
- **Routes.** The resolver turns hosts × http matches into the engine's routes: `exact` and
  `prefix` uris (a prefix by whole segments; longer paths of its last segment get the host's most
  general policy, as any path of a protected host the routes miss) and an `exact` method. Regex
  uris, `ignoreUriCase`, header, query and the other match conditions, delegates, short host names
  and VirtualServices without http routes are refused (`TargetUnsupported`), never ignored.
- **Status.** A VirtualService is `Programmed` once every running pod its Gateways select has the
  engine and the socket mount, and the `EnvoyFilter` has it. The operator lists the pods a
  Gateway selects uncached: one the webhook can't inject (outside the proxy namespaces, other
  labels) would serve the route uninspected, so it is `WiringFailed`. Istio reports nothing on
  an `EnvoyFilter`, nor by default on a VirtualService: with its status on, a `Reconciled`
  condition that isn't `True` is `Pending`. Bound only to the mesh: `ControllerUnsupported`;
  also to the mesh: `Programmed`, with a message that the mesh traffic isn't inspected.

Response inspection (v0.4.0, [0006 §2](0006-adapter-protocols.md#response-inspection-v040)):
the engine's ext_proc adapter inspects the response headers and body for policies that ask, and
replaces a response that leaks in block mode; built for raw Envoy (flags or bundle) and Envoy
Gateway and Istio (`WAFPolicy.spec.responses`; Istio's HTTPRoutes and VirtualServices since 0.5.0,
#374). **Not yet:** Contour.

### 6.2 ingress-nginx

No integration is planned: [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) is retired upstream (2026). Inkwall's answer
for its users is migration: `inkwallctl migrate ingress-nginx` turns its ModSecurity annotations
and ConfigMap settings into `WAFPolicy` objects for Traefik or Envoy Gateway
([migrating from ingress-nginx](../migrating-from-ingress-nginx.md), [§3.5](#35-inkwallctl-cli)).

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
- Limitation: ForwardAuth never sees the response, so Traefik can't inspect responses
  ([0006 §2](0006-adapter-protocols.md#response-inspection-v040)): the engine's forward-auth
  adapter has no response flags, and a policy with `responses.inspect` on a Traefik route is
  `Programmed=False` (`ResponsesNotInspected`).
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

**Built:** A, for `Ingress`, `IngressRoute` and, through Traefik's Gateway API provider, `HTTPRoute`
targets (an `ExtensionRef` filter to the Middleware). **Not yet:** B.

### 6.4 HAProxy (HAProxy Kubernetes Ingress Controller, HAProxy Ingress)

HAProxy uses [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt): the engine is the agent (SPOA), over a Unix socket. `http-request deny` rules
act on the variables `txn.inkwall.action` and `txn.inkwall.status`. HAProxy sets no variable when
the agent doesn't answer, so the policy's failure mode maps onto one rule: failing closed (the
default in block mode) denies with 503 when `txn.inkwall.action` is unset, failing open leaves
that rule out. `option spop-check` marks a stopped engine down, and `timeout processing` is the
engine's deadline plus 500 ms. Body inspection needs `http-buffer-request`, and a `tune.bufsize`
above the body limit. Decided for v0.4.0 ([#282](https://github.com/inkwall-dev/inkwall/issues/282)); the protocol is in
[0006 §4](0006-adapter-protocols.md#4-spoe-haproxy-stream-processing-offload-engine).

**The operator's wiring of the HAProxy Kubernetes Ingress Controller** (decided for v0.4.0,
[#282](https://github.com/inkwall-dev/inkwall/issues/282); verified on kind with controller v3.2.19, chart 1.54.4, HAProxy 3.2.26):

- **Version.** `mode spop` needs HAProxy 3.1, which ships with controller 3.1 and later
  (`haproxytech/kubernetes-ingress:3.1` is HAProxy 3.1.14, `3.2` is 3.2.26). Older controllers
  aren't supported.
- **Discovery.** IngressClasses whose controller is `haproxy.org/ingress-controller/<class>`, the
  controller's `--ingress.class` (`haproxy` by default; verified: the chart's IngressClass for
  another class names it). The
  controller's pods are found as Traefik's are, by a proxy pod selector, and the integration is
  turned on by `rbac.integrations.haproxy` (`auto`, `true` or `false`).
- **Agent backend: the auxiliary configuration file.** The controller runs HAProxy with
  `-f haproxy.cfg -f haproxy-aux.cfg` when a file is mounted at
  `/usr/local/etc/haproxy/haproxy-aux.cfg` (verified). The Pod webhook mounts, from an
  operator-owned ConfigMap in the proxy's namespace, that file (the `mode spop` backend
  `inkwall-engine`, `option spop-check`, the server on the engine's Unix socket) and `spoe.conf`
  (under `/usr/local/etc/inkwall`), and adds the engine as a native sidecar on a Unix socket in an
  `emptyDir`. The chart runs HAProxy as uid 1000 (`haproxy`), so the engine runs with the HAProxy
  container's `runAsUser`/`runAsGroup`, to share the socket (verified). HAProxy warns that the backend
  implicitly uses the controller's `haproxytech` defaults; a `defaults` section of our own in the
  file should silence it (not verified yet).
- **Per route: the Ingress annotations.** The operator sets, on each protected Ingress,
  `haproxy.org/standalone-backend: "true"` and `haproxy.org/backend-config-snippet` with
  `option http-buffer-request`, `filter spoe engine inkwall config /usr/local/etc/inkwall/spoe.conf`
  and the deny rules (the fail-closed rule in `Block`, and in `Detect` when the failure mode is
  closed). `spoe.conf`'s message uses `event on-backend-http-request` (verified: an attack in
  the query or a body gets 403 on the protected Ingress's host, and passes on another Ingress to
  the same Service; with the engine unreachable, the protected host gets 503 at once).
  - `standalone-backend` is required: without it, Ingresses to the same Service share one
    backend, and the controller applies the backend annotations of only one of them, with a
    warning in its log (verified).
  - A `backend-config-snippet` on the Service is kept: the controller puts it before the
    Ingress's (verified). A user's own snippet on the Ingress would be kept too, after
    ours, between markers the operator owns (not verified yet).
- **Engine missing means uninspected.** On a controller pod without the mounted files, HAProxy's
  configuration check fails on `filter spoe`, and the controller logs `unable to Sync HAProxy
  configuration`, drops the snippet and serves the route uninspected; other changes still sync
  (verified). So the annotations are written only once every running pod of the controller has
  the engine and the files; pods that predate the integration are `PendingRestart`, as for
  Traefik. A controller run with `--disable-config-snippets` covering backends can't be wired
  (`Programmed=False`).
- **Status: a probe proves each pod** (decided). The controller reports nothing per Ingress
  about its snippets: it drops a snippet that fails HAProxy's check with a log line only. So a
  protected HAProxy route is `Programmed=False`, reason `Unverified`, until a probe proves that
  the filter is in force on **every** pod of the controller; `Programmed=True` only then.
  - **Who probes:** the operator, to each controller pod directly (its pod IP and the HTTP
    container port, not the Service), so each pod is proven on its own, and the operator reads
    the answer itself without a new engine-to-operator message. The operator must be able to reach
    the controller pods' HTTP port: a NetworkPolicy that blocks it leaves the routes
    `Unverified`, and the docs say so.
  - **The request:** a `GET` without a body to the route's host, with the header
    `X-Inkwall-Probe: <nonce>.<MAC>`: a random nonce per probe, and an HMAC-SHA256 of the nonce,
    host and URI under a probe key. The path is the reserved
    `<prefix>/.well-known/inkwall-probe/<nonce>` under each `Prefix` (and `ImplementationSpecific`)
    path of the Ingress, so the probe reaches no real page when the filter isn't there; an `Exact`
    path is probed as itself, with the query `?inkwall-probe=<nonce>`, as nothing else reaches that
    backend. The key is derived from the bundle signing key (an HMAC of a fixed label under it), so
    it needs no Secret of its own, and reaches the engines in the bundle (`probe_key`, part of
    `content_hash`: a new key is a new bundle).
  - **The answer:** the SPOE adapter checks the MAC before inspection, and answers
    `action=deny` (403) with the variable `probe` set to another HMAC of them under the key. The
    route's snippet answers that, first among its rules, with `http-request return status 299` and
    the header `X-Inkwall-Probe` carrying it. The probe never reaches the app when the filter is
    active. A wrong MAC is inspected as any request.
  - **Proof:** status 299 with the expected MAC proves that this pod runs the snippet, the
    filter and the engine. Anything else is evidence that the route is not protected on that
    pod, and the status names the pod and what came back (e.g. a 404 from the app).
  - **Rate:** once per route and pod when the route, the policy or the pod changes, and every
    5 minutes after; at most a few probes at a time. Only `GET` without a body. The probe path is
    in the docs, so it can be recognised in access logs.
  - **Static checks** stay, each failure with its own reason, before any probe: the annotations
    as written (`standalone-backend` included), every running controller pod with the engine and
    the mounted files (otherwise `PendingRestart`), and no `--disable-config-snippets` covering
    backends.
  - `Detect` mode is reported as wired, not as blocking: `Ready` follows `Programmed` and
    `Enforced` as for the other proxies.
- **HAProxy's buffer below `body.maxBytes`** (decided for v0.4.0, [#345](https://github.com/inkwall-dev/inkwall/issues/345)): HAProxy sends the
  engine at most `tune.bufsize` less `tune.maxrewrite` of a request (about 15 KiB by default), so
  a larger body is handled as oversized (`body.onOversize`) whatever `body.maxBytes` says. The
  operator reads `tune.bufsize` and `tune.maxrewrite` from the `global-config-snippet` of the
  ConfigMap each controller pod names (`--configmap`), or takes HAProxy's defaults, and when a
  policy on a wired Ingress inspects more than the smallest pod's buffer allows (`body.maxBytes`,
  64 KiB when unset), says so in `Programmed`'s message, naming the effective limit and the docs.
  It is a note, not a reason: `Programmed` and `Ready` don't change, as the body still fails safe
  (it isn't missing protection), and the probe still decides `Programmed` (`Unverified`). A
  separate condition type was rejected: another type for one proxy's limit, which `Ready` would
  have to ignore. The operator doesn't change `tune.bufsize` (#336: memory per connection).

**Built:** the agent, `inkwall-engine spoe`, with a configuration written by hand
([protecting HAProxy](../haproxy.md)), and the operator's wiring above (v0.4.0, [#333](https://github.com/inkwall-dev/inkwall/pull/333),
[0004 §4.4](0004-operator.md#44-wiring-controller)).

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
| Traefik | ForwardAuth | ✅ | ⚠️ v3 `forwardBody` | ❌ | ❌ | localhost HTTP |
| HAProxy | SPOE | ✅ | ✅ | ❌ | ✅ (async group) | SPOP over Unix socket |
| Caddy | module | ✅ | ✅ | ✅ | ✅ | in-process |
| Any | reverse proxy | ✅ | ✅ | ✅ | ✅ | TCP |

Built: Traefik ForwardAuth, the reverse proxy, and ext_proc through Envoy Gateway, Istio and raw
Envoy. Responses: inspected by ext_proc (v0.4.0: raw Envoy and Envoy Gateway, not Istio yet); the
reverse proxy's ✅ is a target, it doesn't inspect them yet.

---

## 7. Request flows

See the [verdict lifecycle](../diagrams/verdict-lifecycle.svg) diagram.

### 7.1 Block mode (Envoy example)

Built with Envoy Gateway, through ext_proc ([§6.1](#61-envoy-raw-envoy-envoy-gateway-istio-contour)).

1. The proxy sends the request headers to the engine.
2. The router picks the policy.
3. A rule matches and the [anomaly score](https://coreruleset.org/docs/concepts/anomaly_scoring/) reaches the threshold.
4. The engine answers 403 and emits a security event.

### 7.2 Detect mode

By design, the proxy forwards the request without waiting. The engine logs matches with the
action `LOG`. Built today, Envoy Gateway doesn't wait: a route whose policies are all in detect
mode and fail open gets ext_proc's `observability_mode`. The other adapters still wait for the
verdict: in detect mode the engine inspects inline and always allows (`pkg/pipeline`).

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

**Built (#364):** behind an HTTP load balancer, the InkwallConfig's `spec.engine.clientIP` lists
`trustedProxies` (CIDRs) and `trustedHops` for the injected engines, which always trust the loopback
as well. The walk skips the proxy's own entries, then `trustedHops` entries whatever their address,
then trusted CIDRs. Entries may carry a port. `trustedHops` applies only behind a trusted peer, so
an untrusted peer stays the client, and the webhook rejects a prefix the engine would refuse and
warns of one that trusts every address.

The engine can also read RFC 7239 `Forwarded` (`--client-ip-header=forwarded`), but the
InkwallConfig doesn't offer it. Envoy and Istio's Envoy append their TCP peer to `X-Forwarded-For`,
never to `Forwarded`. In `Forwarded` the rightmost entry would be one the client may have written
itself, with nothing appended by the proxy beside the engine to anchor the walk, so trusting it
would let clients choose their address. It is for a standalone engine behind a proxy that sets or
replaces the header.

### 8.3 Data privacy

Bodies never leave the engine. Events carry only a redacted snippet of at most 64 bytes. Headers
listed in `events.redact` (default `Authorization`, `Cookie`, `Set-Cookie`) and query strings are
dropped. This is enforced before anything leaves the cluster.

**Built** in the engine (`pkg/events`, #355). A match leaves no snippet when it is on:

- a cookie (`REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `RESPONSE_COOKIES`), the response body,
  or the `Authorization`, `Cookie`, `Set-Cookie` or `Proxy-Authorization` header;
- an argument (`ARGS`, `ARGS_GET`, `ARGS_POST`, `FILES`, `MULTIPART_PART_HEADERS`) or a header
  whose name looks like a credential (`events.Sensitive`): lower-cased and without `-`, `_` and
  `.`, it contains `pass`, `pwd`, `secret`, `token`, `apikey`, `auth`, `session`, `sessid`,
  `jwt`, `bearer`, `credential`, `privatekey`, `card`, `ccnum`, `cvv` or `cvc`, or it has `ssn`
  between non-letters. It errs on the side of redacting (`author` matches): a missing snippet
  costs a little tuning context, a leaked password can't be taken back. It is substring search,
  not a regular expression: an alternation with case folding cost about 1 ms per 4 KiB name in
  Go's `regexp`, on every match of every event; this is linear and about 40 times cheaper;
- a raw query string, URI, request line or body (`QUERY_STRING`, `REQUEST_URI`,
  `REQUEST_URI_RAW`, `REQUEST_LINE`, `REQUEST_BODY`, `FULL_REQUEST`) whose snippet contains such
  a name. A value comes after its name, so a snippet that shows part of a value holds its whole
  name: checking the 64-byte snippet is enough, and bounded however large the body;
- what `InkwallConfig.spec.events.redact` adds: `headers` (exact names, any case), `arguments`
  (parts of argument names, any case, also checked against raw query strings and bodies) and
  `snippets: false` (no snippets at all).

`events.redact` travels in the bundle (`Bundle.events`, an `EventsConfig`), so every engine
applies the same settings with the policy it enforces, and a change reaches them within seconds.
The defaults leave `Bundle.events` unset, so bundles keep their content hash. Argument patterns
are substrings, not regular expressions: they can't fail to compile on an engine or cost
backtracking per match, and the CRD validates them like exclusion arguments. Redaction is only
in the engine: the operator passes events on as they come. An engine without an operator records
no events, so it has no redaction settings; its log lines never carry snippets.

### 8.4 Multi-tenancy

One engine per ingress pod serves all of that pod's policies. Rule sets shared between policies
compile once. A policy's CRS paranoia level, anomaly threshold, body limits and exclusions don't
make a rule set of their own: the engine applies them to each transaction
([0004 §8](0004-operator.md#8-scale-targets-v1)). The enrollment certificate ([§7.5](#75-cluster-enrollment-managed--gitops-mode))
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

- Engine: `inkwall_requests_total`, `_check_duration_seconds`, `inkwall_responses_total`,
  `_response_check_duration_seconds` (policies that inspect responses), `_bundle_version`,
  `_bundle_updates_total`, `_operator_connected`, `_evaluations_in_flight`, `_evaluation_slots`,
  `_engine_events_total`, `_engine_events_dropped_total`,
  `inkwall_security_event_logs_suppressed_total{policy}`.
- Engine, since #356:
  - `inkwall_rule_matches_total{rule_id,action}`: every rule that matched, by the verdict's
    action. Rule IDs come from the loaded rules, and at most 2,000 get their own series; the rest
    count as `rule_id="other"`.
  - `inkwall_policy_requests_total{policy,action,reason}`, opt-in (`--policy-metrics`,
    `InkwallConfig.spec.engine.policyMetrics`): at most `--policy-metrics-max` policies (default
    500) per engine, the rest under `policy="other"`, `none` for requests no policy covers. Off by
    default because it multiplies `inkwall_requests_total`'s series by the policies.
  - `inkwall_bundle_updates_total{result,reason}`: rejected bundles by `reason` (`signature`,
    `older`, `compile`, `other`); `inkwall_bundle_compile_seconds`; `inkwall_rule_sets` (compiled
    rule sets in memory); `inkwall_bundle_applied_timestamp_seconds` (bundle age is `time()` minus
    it).
  - `inkwall_adapter_errors_total{adapter,kind}`: requests an adapter refused without inspecting
    them, `invalid_request` (one it can't read) or `protocol` (an ext_proc stream or SPOE
    connection that breaks the protocol).
  - `inkwall_websocket_connections`, `inkwall_websocket_messages_total{action}` and
    `inkwall_websocket_violations_total{code}` (the engine's proxy). WebSocket messages are counted
    there, not in `inkwall_requests_total`: a request count that grows with chat traffic would
    hide what the requests do.
  - Events say what they are about: `protocol` (`http`, `grpc`, `websocket`) and the phase
    `PHASE_WEBSOCKET_MESSAGE`; operators before v0.5.0 ignore both.
- Engine logs (#354): JSON, at `--log-level` (default `info`; `InkwallConfig.spec.engine.logLevel`
  for injected engines). A security event line has the verdict, `rule_ids`, `anomaly_score` and
  `matches`: each rule with the variable it matched (`ARGS:q`), bounded as in events (32 matches,
  128-byte names). Never the matched value: logs end up in places events' redaction
  ([§8.3](#83-data-privacy)) doesn't reach. Lines are rate-limited by a token bucket per (policy,
  rule, reason), `--event-log-rate` lines per second in bursts of as many (default 10); the
  next line through says how many were `suppressed`. Events to the operator aren't limited. The
  check API's `CheckResponse` carries the same `matches` and `anomaly_score`.
- Operator: `inkwall_operator_bundle_version`, `_operator_bundle_compressed_bytes`,
  `_operator_engines{state}`, `_operator_engines_left_out`, `_operator_events_received_total`,
  `_operator_engine_events_dropped_total`, `_operator_wired_targets{integration}`,
  `_operator_wiring_failures{integration}`, and, toward the control plane,
  `_operator_events_forwarded_total`, `_operator_events_buffered`,
  `_operator_events_buffer_errors_total`, `_operator_request_stats_dropped_total{reason}`,
  `_operator_state_engines_left_out`.

- The monitoring kit (#381, [Monitoring](../monitoring.md)): the chart's ServiceMonitor (operator),
  PodMonitor (engines, by their `inkwall-admin` port in the proxy namespaces), PrometheusRule
  (alerts with runbooks, unit-tested with `promtool`) and Grafana dashboard, all opt-in. The
  Prometheus Operator's objects render only when the cluster serves `monitoring.coreos.com/v1`,
  so enabling them on a cluster without its CRDs doesn't fail the install. Docs check that
  `docs/monitoring.md` lists every registered metric, and a test that the dashboard and alerts
  use only registered ones.

**Not yet:** a proxy-side adapter failure metric (see [§7.3](#73-engine-unavailable)),
rate-limit metrics, tracing.

### 8.6 Versioning and compatibility

- The data plane follows [semver](https://semver.org/).
- CRDs move from `v1alpha1` to `v1beta1` to `v1`, with [conversion webhooks](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion).
- The protocol version is sent in `Hello`. The operator supports engines one minor version behind
  (N-1).
- Each release pins a version of the [OWASP Core Rule Set](https://coreruleset.org/) (CRS) as a builtin rule set, so
  upgrades never silently change detection.
- Tested on the last 3 Kubernetes minor versions (`docs/compatibility.md`).

**Not yet:** a version matrix and `docs/compatibility.md` (CI's kind e2e test runs kind's newest
Kubernetes; the local kind cluster, the upgrade test and [envtest](https://book.kubebuilder.io/reference/envtest) run 1.34; the chart
allows 1.29 and later), and conversion webhooks (only `v1alpha1` exists).

### 8.7 gRPC messages

A gRPC call's messages are binary [protobuf](https://protobuf.dev/programming-guides/encoding/),
which text rules can't read: since v0.3.1 a call is inspected on its path and metadata only
([gRPC](../grpc.md)). Reading the messages is decided here (v0.4.0, [#275](https://github.com/inkwall-dev/inkwall/issues/275)).

**What is read.** The body, up to the policy's `body.maxBytes`, split into gRPC messages (5-byte
prefix); a gRPC-Web text body is decoded from base64 first (groups of four characters, padding
allowed at the end of each piece the client encoded, no line breaks; a cut body up to its last
whole group), and one that isn't base64 of messages isn't a gRPC call. Each message is read as protobuf without its schema (`pkg/grpcwire`): a
length-delimited field whose bytes are a whole protobuf message is read as one, to a depth of 16;
one whose bytes are printable UTF-8 (no control characters but tab, CR, LF) is text. Some bytes
are both, and give both: an attacker could otherwise write an attack that also parses as a
message, to have it read only as one. Numbers, fixed-width fields and binary bytes give nothing.
Each text field becomes a form argument (`ARGS_POST`) named by its path of field numbers (`2.1`:
field 1 of the message in field 2), so CRS's argument rules and custom rules on `ARGS` see it.
The raw body stays out of the rules (`REQUEST_BODY` is empty), and rule 920420 stays removed for
the call. Schemas (a `FileDescriptorSet` in the policy, or server reflection) would name the
fields and tell strings from bytes; they are left for later, since the schema-less reading
already sees every string a client sends.

**Limits.** At most 4,096 text fields (more: handled as unread, below); the policy's argument
limit (1,000 by default, rule 200005) applies to them as to a form or JSON body, and denies
more (400). Gzip messages decompress to at most 1 MiB per call.

**Compression** (the compressed flag, with the call's `grpc-encoding`): `gzip`, the one encoding
every gRPC library has, is decompressed. Another encoding (`deflate`, `snappy`, `zstd`) or none
can't be read.

**What can't be read** — a message cut at `body.maxBytes` (every long client stream), compressed
other than with gzip, not protobuf, or past the limits — is handled as an oversized body, by the
policy's `body.onOversize`: denied (413, gRPC `RESOURCE_EXHAUSTED`) in `Block` mode by default,
logged in `Detect` mode. Failing safe here means a client can't hide an attack behind an encoding
the engine doesn't read; a policy with long client streams sets `onOversize: Allow`, and the
messages read before the cut are still inspected.

**False positives**, measured with CRS at paranoia level 1 (`TestGRPCMessagesFalsePositives`):

- 82 real protobuf messages (every `FileDescriptorProto` linked into the engine: Envoy's,
  gRPC's, protobuf's own; nested, with names, paths, options): none denied by CRS; one has more
  than 1,000 strings and hits the argument limit.
- Everyday text (names with apostrophes, non-Latin scripts, addresses, URLs with queries,
  sentences, JSON, ids, tokens, timestamps): no rule matches.
- Binary: fields of random bytes are sometimes printable UTF-8, and a short run like `|W` or
  `` `W `` matches a command or SQL injection rule (932250, 932340, 942190). About 1 message in
  10,000, with four random fields of 1–24 bytes each; a random 16-byte id or hash is printable
  less than once in a million.

So the text the messages carry gives the false positives a form with the same values would, and
binary fields add a small rate of their own, too high to turn on for every gRPC route in `Block`
mode without the user's say. **Decision:** reading the messages is off by default and opt-in per
policy (`WAFPolicy` `spec.body.grpcMessages: Inspect`, bundle `BodyConfig.grpc_messages`, the
engine's `--grpc-messages`). With it off, nothing changes from v0.3.1. Detect mode needs nothing
of its own: a policy turns it on in `Detect` first, reads the events, and excludes the binary
fields that match (`when: {argument: "3"}`) before `Block`. Short binary fields could be skipped later (text under 4 bytes
that isn't all letters and digits), at the cost of short attack strings like `'--`.

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
dependencies out of the engine), and `rules/crs/`.

---

## 10. Testing architecture

One shared request corpus drives every level.

| Level | Tool | What it proves | Runs |
|---|---|---|---|
| Unit | `go test` | Package logic | every PR |
| [Fuzz](https://go.dev/doc/security/fuzz/) | `go test -fuzz` | Parsers of untrusted input never panic and keep their properties | nightly; seeds every PR |
| Rule conformance | [go-ftw](https://github.com/coreruleset/go-ftw) + CRS tests | Detection matches CRS | every PR |
| Adapter parity | `go test`, in-process stand-ins for each proxy | Adapters match the reverse proxy | every PR |
| E2E | kind + [e2e-framework](https://github.com/kubernetes-sigs/e2e-framework) | Wiring, enforcement, status, failure modes | every PR |
| Performance | [`testing.B`](https://pkg.go.dev/testing#B), [k6](https://grafana.com/docs/k6/latest/) | 0001 budgets | every PR / nightly |
| Upgrade | kind | N-1 → N with no dropped requests | release |
| Soak / chaos | kind + k6 | 24 h stability; engine kill → the proxy fails open | weekly |

**Built (fuzz):** a Go fuzz target for every parser of untrusted input, 24 in all, each listed in
`.github/workflows/fuzz.yaml`. Each checks a property, not only that nothing panics:

- the adapters:
  - forward-auth (`FuzzForwardAuth`): only the method and URI the proxy forwarded are inspected,
    without its `X-Forwarded-*` headers;
  - the check API (`FuzzCheck` in `httpcheck`): exactly the request a `CheckRequest` describes is
    inspected, and answered in the same encoding;
  - the reverse proxy (`FuzzProxy`): a request is refused with 400, or inspected in origin form
    with a valid Host, and what reaches the upstream was inspected, with the same path, query,
    Host and body;
  - ext_proc (`FuzzExtProc`, `FuzzExtProcResponse`): a request, and a response, are inspected
    exactly once, at most the body limit of the body, whatever Envoy sends or leaves out, and a
    denial carries header values Envoy accepts;
  - SPOE (`FuzzSPOE`, `FuzzVarint`): a request the agent accepts is one it can inspect, its body
    counted complete only when it is all there;
- the request target, request ID and gRPC denial checks the adapters share (`FuzzURIPath`,
  `FuzzRequestID`, `FuzzGRPCDenial`);
- the HAProxy probe (`FuzzCheck` in `haproxyprobe`): only a probe made with the key is answered;
- gRPC messages (`FuzzMessages`, `FuzzGRPCText`): the rules get valid UTF-8 text from the body,
  within the limits, and a cut body is never taken as read whole;
- WebSocket (`FuzzReader`, `FuzzTracker`, `FuzzWebSocketOrigin`): frames keep the protocol's
  rules and no message keeps more than the limit; an origin that passes is an allowed one;
- client IP resolution from `X-Forwarded-For` (`FuzzResolve`);
- bundle key files (`FuzzParse`);
- bundle signatures (`FuzzApply`, `FuzzSecretBundle`): nothing but the trusted key's own signature
  of the exact bytes reaches compilation;
- event redaction (`FuzzNew`): valid UTF-8, within the field limits, with no query strings or
  credential snippets;
- `inkwallctl test`'s URL, raw HTTP, HAR and suite input (`FuzzSplitURL`, `FuzzFromRawHTTP`,
  `FuzzFromHAR`, `FuzzParseSuite`).

Their seed corpora (`testdata/fuzz/`) run in every `make test`. `.github/workflows/fuzz.yaml` runs
each target for 5 minutes nightly and uploads the failing inputs, encrypted. Its matrix is every
`func Fuzz` of the tests (`hack/ci/fuzz-targets.sh`, checked by `hack/ci`'s test), so a new target
is fuzzed without editing the workflow, and each target keeps the corpus it grows in Go's fuzz
cache from night to night (`actions/cache`).

A nightly stress run (`.github/workflows/stress.yaml`, `make stress-test`, #395) looks for timing
flakes: the adapters', agent's, pipeline's and operator's tests with the race detector, shuffled
(the seed printed first), 10 times, on `GOMAXPROCS=2` with CPU hogs alongside. The SPOE, ext_proc
and agent packages check every `make test` for goroutines a test leaves running
([goleak](https://github.com/uber-go/goleak)).

A scheduled workflow (fuzz, docs-links, stress) that fails opens one issue for it, labeled
`ci-scheduled-failure` and pinned, or comments on the open one; the next passing run closes it
(`hack/ci/report-scheduled.sh`, in a `report` job that alone may write issues). The fuzz issue
names the failing targets only: a crash may be a vulnerability, reported privately.

**Built (other levels):**

- rule conformance (`make crs-test`, go-ftw): the CRS's regression tests through the reverse
  proxy at each paranoia level, and through ForwardAuth, ext_proc and SPOE (each behind an
  in-process stand-in for its proxy) at level 4, with the response rules' tests through ext_proc.
  A test one adapter fails while the reverse proxy passes it fails the suite, unless it is listed
  as a difference with its reason (`test/crs/crs_test.go`): today, the `Content-Length: 0` the
  adapters add to an empty POST, and requests without a Host, which Envoy answers itself;
- adapter parity (`TestAdapterParity` in `test/crs`, in `make test`): a corpus of clean traffic,
  attacks, odd hosts and encodings, HTTP/1.0, chunked and large bodies, gRPC and a WebSocket
  handshake goes through the reverse proxy, ForwardAuth, ext_proc, SPOE and `/v1/check`, each
  behind the stand-in for its proxy the CRS suite uses, against one pipeline. For each adapter it
  compares the request the rules saw (method, scheme, host, URI, protocol, headers, body, client
  IP), the verdict (action, status, reason, rule IDs) and the client's answer (status, and a
  denial's `X-Request-Id`) with the reverse proxy's. A difference fails the test, naming the
  adapter, the case and the field, unless `parityDifferences` lists it with its reason: today,
  ForwardAuth's HTTP/1.1 subrequest (the client's version isn't sent) and its own framing headers,
  and how each proxy answers a denied gRPC call;
- E2E and upgrade tests on kind (`make kind-e2e`, `make kind-upgrade`; shell scripts in
  `hack/kind`, on every PR). The upgrade test runs `helm upgrade` from the last release and checks
  that routes stay protected;
- benchmarks (`testing.B`, and the CI `bench` gate;
  [0001 §8](0001-performance-first-architecture.md#8-proving-it-the-performance-test-harness)).

**Not yet:** e2e-framework, k6, soak and chaos tests.

---

## 11. Decisions (ADR log)

Other docs cite these decisions by ID (D1–D9).

| # | Decision | Alternatives considered | Why |
|---|---|---|---|
| D1 | One engine + thin adapters | A WAF per proxy | One core, consistent verdicts |
| D2 | Coraza + CRS behind an interface | Own engine; [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity) | Mature and Go-native; a custom engine stays possible |
| D3 | Sidecar over a Unix socket, or loopback TCP where the proxy needs it (Traefik: `127.0.0.1:9001`) | Central Deployment; [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) | No network hop ([0001](0001-performance-first-architecture.md)) |
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
