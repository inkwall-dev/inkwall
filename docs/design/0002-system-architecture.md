# 0002 — System Architecture

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md)

Components, protocols and proxy integrations. 0001's performance rules apply.

---

## 1. Scope

### 1.1 Goals

1. One Go WAF engine behind any ingress (Envoy, Traefik, ingress-nginx, HAProxy, Caddy) or as a
   standalone reverse proxy.
2. Kubernetes-native: Helm, CRDs, GitOps.
3. Optional SaaS control plane; the open-source data plane never depends on it.
4. 0001 performance budgets are release blockers.

**Built (v0.1.0):** Traefik ForwardAuth for `Ingress` targets; standalone reverse proxy.

### 1.2 Non-goals (for v1)

L3/L4 DDoS (CDN's job); TLS termination (the proxy's job); proxying production traffic in
Kubernetes mode; non-HTTP protocols (gRPC and WebSocket upgrades are inspected as HTTP only).

### 1.3 Glossary

| Term | Meaning |
|---|---|
| **Engine** | `inkwall-engine`: evaluates requests, returns verdicts |
| **Adapter** | Engine listener + proxy-side config or plugin |
| **Operator** | `inkwall-operator`: reconciles CRDs, wires proxies, distributes policy |
| **Control plane (CP)** | The SaaS: API, UI, policy store, analytics |
| **Policy** | Mode, rule sets, limits, exclusions for a set of routes |
| **Bundle** | Immutable, versioned snapshot of a cluster's policies |
| **Verdict** | Allow, deny or challenge, plus metadata |

---

## 2. System context

![System overview](../diagrams/system-overview.svg)

| Plane | Components | Latency sensitivity | Availability requirement |
|---|---|---|---|
| **Data plane** | engine, adapters | µs, every request | Works when all else is down |
| **Local control** | operator | seconds | Down for hours: engine keeps last-known-good |
| **Global control** | SaaS CP | seconds to minutes | Down for days: clusters keep enforcing |

**Rule:** no request-path call crosses a plane boundary.

---

## 3. Components

### 3.1 `inkwall-engine` (data plane)

Static Go binary, distroless. Runs as a **sidecar** in the ingress pod (default), a **standalone
Deployment** (simpler, slower), a **reverse proxy**, or an in-process **library** (Caddy).

![Engine internals](../diagrams/engine-internals.svg)

Pipeline: adapter → pooled `Request` → T0 router → T1 IP/rate → T2 headers → T3 body → `Verdict`
(action, status, rule IDs, score, policy + bundle version, reason). The compiled policy sits in an
`atomic.Pointer[Snapshot]`.

| Package | Responsibility | v0.1.0 |
|---|---|---|
| `pkg/request` | Canonical `Request`, zero-copy headers | built |
| `pkg/router` | `(host, path, method)` → policy | built |
| `pkg/pipeline` | Tiers, deadline, `Verdict` | built |
| `pkg/rules` | `Evaluator` interface; Coraza impl | built |
| `pkg/clientip` | Client IP (§8.2) | built |
| `pkg/agent`, `pkg/policy` | Bundle stream, verify, compile, swap (§5.2) | built |
| `pkg/telemetry` | Metrics, tracing, `slog` | built |
| `pkg/adapters/*` | One per listener | `forwardauth`, `httpcheck`, `proxy` built; `extauthz`, `extproc`, `spoe` not yet |
| `pkg/ratelimit`, `pkg/iplist`, `pkg/events` | Token buckets, CIDR trie, events | not yet |

Lifecycle: listeners start not ready → load bundle (disk cache, else bundle Secret) → ready after
the first successful compile → updates compile in the background and swap atomically; a failed
compile keeps the old snapshot and NACKs → shutdown drains (bounded).

**Built:** with no bundle yet, `--bootstrap allow|deny` (from `spec.engine.bootstrapMode`, default
allow) decides; the engine stays unready up to `--bootstrap-timeout` so the proxy sends no traffic
before a bundle arrives.

### 3.2 Adapters

An engine listener (`pkg/adapters/<name>`) translating proxy messages to `Request`/`Verdict`, plus
proxy config rendered by the operator or a plugin. See
[0006 — Adapter Protocols Primer](0006-adapter-protocols.md) and §6.

### 3.3 `inkwall-operator` (local control)

controller-runtime, leader election, 2 replicas. Details: [0004 — Kubernetes Operator](0004-operator.md).

| Controller | Does |
|---|---|
| **Discovery** | Finds ingress controllers and the adapter for each |
| **Injection** | Adds sidecar + socket volume via extension point or Pod webhook (never a Deployment patch) |
| **Wiring** | Renders proxy config (Traefik `Middleware`, ConfigMaps, `EnvoyExtensionPolicy`, ...) |
| **Resolver + bundle builder** | Resolves targets to host/path/method; builds, signs, versions the bundle |
| **Distribution** | Streams bundles to engines; tracks their versions |
| **Upstream sync** | Single SaaS connection (pull in Managed, push in GitOps, forward events) |
| **Status** | `Accepted`, `Programmed`, `Enforced` (all engines ACKed) |

Never on the request path. While it is down, engines keep their snapshot and new pods use their
cache or the bundle Secret (0004 §4.6).

**Built:** injection, Traefik wiring, resolver, bundle builder, distribution, status, upstream sync
(GitOps and Managed, §5.3).
**Not yet:** other proxies.

### 3.4 Control plane (optional)

Separate product; out of scope here. OSS depends only on the operator ↔ CP stream (§5.3),
enrollment (§7.5) and modes (§4.1); enforcement works without it. It talks only to operators,
never engines: fewer connections, no engine egress, air-gap uses the same path. **Not yet** built.

### 3.5 `inkwallctl` (CLI)

`test` (replay a request/HAR, show matches) and `bench` (benchmark corpus) are built. Planned:
`bundle build/verify` (offline, for CI) and `status` (engine versions, drift).

---

## 4. Configuration model

### 4.1 Sources of truth

| Mode | Source of truth | SaaS role |
|---|---|---|
| **Standalone** | CRDs | none |
| **GitOps** | CRDs in Git | read-only mirror, analytics |
| **Managed** | SaaS | operator materializes it; webhook rejects CRD edits |

One mode per cluster; no mixed ownership per route (conflicts would be ambiguous).

### 4.2 CRDs (`waf.inkwall.dev/v1alpha1`)

Reference: [`operator/api/v1alpha1`](../../operator/api/v1alpha1).

- **`InkwallConfig`** (cluster singleton): `mode`, `controlPlane`, `engine` (image, resources with
  no CPU limit since throttling hurts p99, `bootstrapMode`, `socketDir`), `integrations`, `events`.
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

  Most specific target wins (HTTPRoute rule > HTTPRoute > Ingress > namespace default); ties are
  rejected (`Accepted=False, reason=Conflict`).
- **`WAFRuleSet` / `ClusterWAFRuleSet`:** `builtin: crs-v4` (pinned), inline `seclang`, or
  `configMapRef`.
- **`WAFIPList` / `ClusterWAFIPList`:** CIDRs, or a URL fetched by the operator (never the engine).

**Built:** `InkwallConfig`, `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet`.
**Not yet:** IP lists, policy `rateLimits`/`ipLists`, `HTTPRoute` targets.

### 4.3 Bundle format

All of a cluster's policies with resolved routes, deduplicated rule sets, a monotonic `version`.
The operator resolves routes to `(host, path, method)`, so the engine needs no Kubernetes
knowledge. Immutable; ed25519-signed.

**Built ([`api/bundle/v1`](../../api/bundle/v1/bundle.proto)):** a `SignedBundle` holds the
serialized `Bundle` bytes, a signature over exactly those bytes (protobuf encoding isn't canonical)
and the signing key's ID; the engine verifies with the key that ID names, before decoding. Engines
trust several keys while the operator rotates its key (0004 §4.6). `Bundle` has `content_hash` and
`suspended` (emergency switch). **Not yet:** IP lists, rate limits.

---

## 5. Protocols

### 5.1 Engine check API (for Lua, generic HTTP clients, and tests)

[`api/engine/v1/engine.proto`](../../api/engine/v1/engine.proto): `CheckRequest` (method, authority,
raw URI, headers, `client_ip`/`peer_ip` as text so JSON clients can write them, optional body) →
`CheckResponse` (action, status, headers, rule IDs, reason). Envoy will get its native `ext_authz`
and `ext_proc` services instead.

**Built:** `POST /v1/check`, protobuf or JSON. **Not yet:** gRPC `CheckService`, Envoy services.

### 5.2 Engine ↔ operator (bundle distribution)

`BundleService.Watch`: one long-lived stream per engine; the operator pushes full bundles (not
deltas: simpler, idempotent, small), the engine ACKs or NACKs.

**Built ([`api/agent/v1`](../../api/agent/v1/agent.proto), [`pkg/agent`](../../pkg/agent),
[`pkg/policy`](../../pkg/policy), `--operator`):**

- Messages `WatchRequest`/`WatchResponse`; payload `SignedBundle`.
- Engine verifies, refuses an older version unless created later (operator lost its sequence),
  compiles, swaps, writes `--bundle-cache`, ACKs. Failure NACKs and keeps the old bundle.
- `Hello` and `Heartbeat` carry the IDs of the keys the engine trusts (`--bundle-key`, re-read
  every 10 s), so the operator signs with a new key only once every engine has it. A bundle
  rejected for an unknown key is asked for again (a new stream) once the keys change.
- Reconnects with jittered backoff. With no cache it reads the bundle Secret from the API server
  (`--bundle-secret`, plain HTTPS, no client-go).
- Matching: host, cleaned path, method, most specific first. Uncovered host: not inspected. Covered
  host, no path match: the host's most general policy, so normalization differences can't skip
  inspection.

**Not yet:** event batches, directives (fields reserved).

### 5.3 Operator ↔ SaaS

[`api/controlplane/v1`](../../api/controlplane/v1/controlplane.proto) (`ControlPlaneService`), over
mTLS; the cluster's identity is its client certificate (§7.5), never a message field. Two stream
roles: one **primary** stream per cluster from the leader (state, policies, directives,
certificates; when the leader moves, the newer primary wins), and one **events** stream per replica,
for the engines connected to it (engines connect to any replica). gRPC status codes say what the
operator does: re-enroll (`UNAUTHENTICATED`), stop (`PERMISSION_DENIED`), back off
(`RESOURCE_EXHAUSTED`) or reconnect.

- `Connect`, up: `Hello` (versions, mode, last policy version, capabilities), `ClusterState` (a
  full snapshot: every Inkwall object with its conditions, integrations, engines, bundle version),
  `EventBatch` (§5.4), `Heartbeat`, `PolicyAck`/`PolicyNack`, `RenewCertificate`.
- `Connect`, down: `Welcome` (heartbeat interval, whether events are accepted), `PolicySnapshot`
  (Managed mode), the renewed `Certificate`, `Directive` (e.g. resync).
- **Managed mode carries policy objects, not signed bundles**: the operator writes them as CRDs
  (0004 §4.9) and signs bundles with the cluster's own key, so engines trust only that key.
- Objects travel as their JSON spec, and integrations, kinds and condition reasons as strings: new
  CRD fields, proxies and target kinds need no contract change. No proxy-specific fields.
- Both sides compress (gzip) and accept messages up to 16 MiB. In Managed mode, rule sets come
  inline (`seclang`, `builtin`): the control plane can't create the ConfigMap a `configMapRef` needs.
- Events: at-least-once, per replica. Each `EventUpload` names its buffer and a sequence;
  `EventsAck` frees that buffer up to it, unacknowledged batches are resent after a reconnect, and
  event IDs (never sequences) remove duplicates. The bounded
  disk queue drops the oldest when full, and the next batch says how many.
- A `PolicySnapshot` is all or nothing (server-side dry run of every object first); the cluster's
  `InkwallConfig` decides the mode, and a cluster not in Managed mode refuses snapshots. Only
  `WAFPolicy` and the rule set kinds are accepted, and the operator sets the source label itself
  (`inkwall.dev/source: saas`), deletes the labelled objects a snapshot no longer has, and records
  the last version applied (sent in `Hello`; an older snapshot is refused). In Managed mode the
  validating webhook lets only the operator write the labelled objects, fail closed.
  Standalone: events go to logs and optionally OTLP.

**Built:** the contract (#86), enrollment and the primary stream, state sync (`ClusterState`),
events streams with each replica's disk buffer, and Managed mode (policy snapshots written as CRDs,
pruned, acknowledged; the webhook guard), tested on kind against a stub control plane (0004 §4.9).

### 5.4 Event schema

`SecurityEvent` ([`api/events/v1`](../../api/events/v1/events.proto)): IDs, engine and pod, policy
and bundle version, action, reason, matches (rule, variable, redacted snippet), score, method, host,
path (no query), client IP, user agent, request ID, status, latency. The same message goes engine →
operator (`agent.v1` `Watch`) and operator → control plane, in `EventBatch` with a count of dropped
events. **Built:** the schema; engines produce redacted events and send them to their operator
replica, which forwards them to the control plane on its events stream (#91, #92).

---

## 6. Proxy integrations

Every integration sends only what the policy needs, over a persistent connection (UDS where
possible), with a timeout just above the engine deadline; applies the failure mode on error; passes
client IP and request ID. Socket dir: shared `emptyDir` at `/var/run/inkwall`.

### 6.1 Envoy (raw Envoy, Envoy Gateway, Istio, Contour)

`ext_proc` (preferred) or `ext_authz` over UDS gRPC. Envoy Gateway: `Backend` +
`EnvoyExtensionPolicy`; Istio: `EnvoyFilter`; Contour: `ExtensionService`. Detect mode uses
`observability_mode`. The contrib Go filter needs a contrib build: experimental. **Not yet** built.

### 6.2 ingress-nginx

A. Lua plugin (default, body support) calling `/v1/check` over UDS, skipping unprotected routes.
B. `global-auth-url` (no code; subrequest per request; no bodies). Neither needs snippets.
ingress-nginx is retired upstream (2026): existing users only. **Not yet** built.

### 6.3 Traefik

**A. ForwardAuth middleware (v1):**

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: inkwall, namespace: shop}
spec:
  forwardAuth:
    address: http://127.0.0.1:9001/v1/forward-auth
    trustForwardHeader: false   # required, see below
    forwardBody: true           # required for body inspection (Traefik v3)
    maxBodySize: 1048576        # above the engine's body limit
    authResponseHeaders: ["X-Request-Id"]
```

Attached with the `traefik.ingress.kubernetes.io/router.middlewares` annotation. The adapter
rebuilds the request from `X-Forwarded-Method`/`-Uri`.

- **`trustForwardHeader: false`**: with `true`, Traefik keeps client-sent `X-Forwarded-Uri` from
  `trustedIPs` peers, so the engine inspects an attacker's URI (verified on v3.7.13).
- **`forwardBody: true`**, or bodies go uninspected.
- Missing or invalid forwarded headers → 400, even in detect mode (can't inspect, can't allow).
- Limitation: Traefik itself rejects bodies over `maxBodySize` (operator sets 10 MiB, the largest
  inspectable body), whatever `body.onOversize` says.
- Limitation: behind a load balancer the engine sees the LB as client IP.

**B. Traefik plugin (later):** Yaegi can't run Coraza well, so it would be a thin client to the
sidecar (or http-wasm).

**Built:** A, for `Ingress` targets. **Not yet:** B.

### 6.4 HAProxy (HAProxy Kubernetes Ingress Controller, HAProxy Ingress)

SPOE, engine as SPOA over UDS; `http-request deny` acts on `txn.inkwall.action`. Fail-closed adds a
503 deny when the variable is unset. Body needs `http-buffer-request`, enabled only when required.
**Not yet** built.

### 6.5 Caddy

In-process handler `http.handlers.inkwall` in a separate module `adapters/caddy`, built with
`xcaddy`. **Not yet** built.

### 6.6 Standalone reverse proxy (universal fallback)

`inkwall-engine proxy --listen :8080 --upstream http://app:80 --bundle bundle.pb`. For
non-Kubernetes and unsupported proxies; also the test reference every adapter must match.
**Built.**

### 6.7 Integration support matrix (v1 target)

| Proxy | Adapter | Headers | Body | Response | Detect (async) | Transport |
|---|---|---|---|---|---|---|
| Envoy / EG / Istio | ext_proc | ✅ | ✅ streamed | ✅ | ✅ | UDS gRPC |
| Envoy | ext_authz | ✅ | ✅ buffered | ❌ | ❌ | UDS gRPC |
| ingress-nginx | Lua plugin | ✅ | ✅ | ❌ | ✅ (mirror) | UDS HTTP |
| ingress-nginx | global-auth-url | ✅ | ❌ | ❌ | ❌ | localhost HTTP |
| Traefik | ForwardAuth | ✅ | ⚠️ v3 `forwardBody` | ❌ | ❌ | localhost HTTP |
| HAProxy | SPOE | ✅ | ✅ | ❌ | ✅ (async group) | UDS SPOP |
| Caddy | module | ✅ | ✅ | ✅ | ✅ | in-process |
| Any | reverse proxy | ✅ | ✅ | ✅ | ✅ | TCP |

Built: Traefik ForwardAuth, reverse proxy.

---

## 7. Request flows

See the [verdict lifecycle](../diagrams/verdict-lifecycle.svg).

### 7.1 Block mode (Envoy example)

Headers → router picks policy → rule matches, score ≥ threshold → 403 and an event.

### 7.2 Detect mode

Proxy forwards without waiting; engine logs matches as `LOG`.

### 7.3 Engine unavailable

Timeout or refused connect → proxy applies the failure mode; `inkwall_adapter_failures_total`++.

### 7.4 Policy change (GitOps mode)

Argo CD applies `WAFPolicy` → operator builds and signs bundle → engines swap and ACK →
`Enforced=True "6/6 engines on bundle N"`.

### 7.5 Cluster enrollment (Managed / GitOps mode)

One-time token (TTL 1h) → operator generates a key and calls `Enroll(token, CSR)` over
server-authenticated TLS → the control plane burns the token and returns a 24h client certificate
bound to its `cluster_id` → the operator stores it in a Secret and renews it over the stream
(`RenewCertificate` → `Certificate`). A retry with the same token and public key within the TTL
returns the same certificate, so a lost response doesn't cost a new token. Renewal needs the current
certificate: a cluster offline longer than its lifetime enrolls again with a new token. Keys: ECDSA
P-256 or Ed25519. **Built:** the contract, and the operator side
(0004 §4.9).

---

## 8. Cross-cutting concerns

### 8.1 Security of Inkwall itself

- Distroless, non-root, read-only FS, no capabilities, seccomp `RuntimeDefault`.
- UDS socket `0660`; TCP listeners need mTLS or localhost.
- Signed bundles: editing the bundle Secret can't disable the WAF without the key.
- Scoped operator RBAC (0004 §7).
- Supply chain: goreleaser, cosign, SBOM (syft), SLSA provenance, `govulncheck` and Trivy in CI,
  pinned Actions; `SECURITY.md`.

### 8.2 Client IP correctness

A wrong IP makes rate limits and IP lists worse than none. Order: the proxy's resolved client IP;
`X-Forwarded-For` walked right to left, skipping only `trustedProxies`; the peer IP.

### 8.3 Data privacy

Bodies never leave the engine; events carry only a redacted snippet (≤ 64 bytes). `events.redact`
headers (default `Authorization`, `Cookie`, `Set-Cookie`) and query strings are dropped. Enforced
before anything leaves the cluster.

### 8.4 Multi-tenancy

One engine per ingress pod serves all its policies; shared rule sets compile once. The enrollment
cert (§7.5) binds a cluster to its CP tenant.

### 8.5 Observability

Target: Prometheus `inkwall_*` metrics (requests, check latency, rule matches with bounded
cardinality, adapter failures, bundle version/age, dropped events, rate-limit decisions); optional
sampled OTel tracing (one engine span); `slog` JSON, one line per security event at most; Grafana
dashboard and alerts in Helm.

**Built:** `inkwall_requests_total`, `_check_duration_seconds`, `_bundle_version`,
`_bundle_updates_total`, `_operator_connected`, `_evaluations_in_flight`, `_evaluation_slots`.

### 8.6 Versioning and compatibility

Semver data plane; CRDs `v1alpha1` → `v1beta1` → `v1` with conversion webhooks. Protocol versioned
in hello; operator supports engines at N-1 minor. CRS pinned per release as a builtin, so upgrades
never silently change detection. Tested on the last 3 Kubernetes minors (`docs/compatibility.md`).

---

## 9. Repository layout

`cmd/` (engine, operator, inkwallctl), `api/` (protobuf, buf), `pkg/` (engine), `operator/`
(0004 §10), `deploy/helm/`, `test/`, `docs/design/`. Planned: `adapters/caddy` and
`adapters/traefik-plugin` as separate Go modules (keeps their dependencies out of the engine),
`adapters/nginx-lua`, `rules/crs/`, `deploy/kind/`.

---

## 10. Testing architecture

One shared request corpus drives every level.

| Level | Tool | What it proves | Runs |
|---|---|---|---|
| Unit | `go test` | Package logic | every PR |
| Fuzz | `go test -fuzz` | No panics, bounded allocation | nightly |
| Rule conformance | go-ftw + CRS tests | Detection matches CRS | every PR |
| Adapter parity | testcontainers-go | Adapters match the reverse proxy | every PR |
| E2E | kind + e2e-framework | Wiring, enforcement, status, failure modes | every PR |
| Performance | `testing.B`, k6 | 0001 budgets | every PR / nightly |
| Upgrade | kind | N-1 → N with no drops | release |
| Soak / chaos | kind + k6 | 24h stability; engine kill → fail-open | weekly |

---

## 11. Decisions (ADR log)

| # | Decision | Alternatives considered | Why |
|---|---|---|---|
| D1 | One engine + thin adapters | WAF per proxy | One core, consistent verdicts |
| D2 | Coraza + CRS behind an interface | Own engine; libmodsecurity | Mature, Go-native; custom engine still possible |
| D3 | Sidecar over UDS | Central Deployment; DaemonSet | No network hop (0001) |
| D4 | SaaS talks to operators only | SaaS → every engine | Fewer connections, no engine egress |
| D5 | Full-snapshot signed bundles | Deltas; unsigned ConfigMaps | Simple, idempotent, tamper-resistant |
| D6 | Operator resolves routes | Engine watches Kubernetes | Engine stays usable outside Kubernetes |
| D7 | Detect mode default | Block by default | No false-positive outages on onboarding |
| D8 | Fail open in detect, closed in block | Fail open everywhere | Fail-open block is bypassable by padding past the deadline |
| D9 | One source of truth per cluster | Merge SaaS + CRD per route | No ambiguous conflicts |

## 12. Open questions

1. Optional Hyperscan (cgo) build?
2. Envoy Go filter: supported or experimental?
3. Default body cap: 8 KB, 64 KB, per content type?
4. Distributed rate limiting: gossip or Redis?
5. Bot challenge in v1? Needs response rewriting (ext_proc, Caddy, reverse proxy only).
