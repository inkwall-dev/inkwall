# 0002 — System Architecture

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md)

This document describes every component of Inkwall, how they talk to each other, the data they own,
and how each supported proxy is integrated. Performance rules from 0001 are treated as constraints
here and are not repeated in full.

---

## 1. Scope

### 1.1 Goals

1. One WAF engine, written in Go, that protects HTTP traffic behind **any** ingress / gateway:
   Envoy (Envoy Gateway, Istio, Contour), Traefik, ingress-nginx, HAProxy, Caddy, and a standalone
   reverse-proxy mode for everything else.
2. Kubernetes-native: install with Helm, configure with CRDs, works with GitOps.
3. Optional SaaS control plane: multi-tenant policy management, attack analytics, fleet view.
4. Open source data plane (engine, adapters, operator, CLI). The control plane is a separate,
   optional product; the data plane never depends on it.
5. Performance budgets from 0001 are release blockers.

### 1.2 Non-goals (for v1)

- L3/L4 DDoS mitigation (volumetric attacks are the cloud provider's / CDN's job).
- TLS termination (the proxy terminates TLS; Inkwall sees plaintext HTTP).
- Being a proxy for production traffic in Kubernetes mode (the ingress stays the proxy).
- Non-HTTP protocols. gRPC and WebSocket upgrade requests are inspected at the HTTP layer only.

### 1.3 Glossary

| Term | Meaning |
|---|---|
| **Engine** | `inkwall-engine`, the process that evaluates requests and returns verdicts |
| **Adapter** | The glue between a proxy and the engine (a listener in the engine plus proxy-side config or plugin) |
| **Operator** | `inkwall-operator`, the Kubernetes controller that reconciles CRDs, wires proxies and distributes policy |
| **Control plane (CP)** | The SaaS: API, UI, policy store, analytics |
| **Policy** | What to enforce for a set of routes: mode, rule sets, limits, exclusions |
| **Bundle** | An immutable, versioned, compiled-ready snapshot of all policies for one cluster |
| **Verdict** | The engine's decision: allow, deny, challenge, plus metadata |

---

## 2. System context

```
                         ┌──────────────────────────────────────────────┐
   Users / CI ──HTTPS──▶ │     Inkwall Control Plane (SaaS, optional)   │
   (UI, API, inkwallctl) │  policy management · analytics · intel       │
                         └───────────────▲───────────────┬──────────────┘
                                         │ events        │ bundles
                                         │ (gRPC, mTLS)  │ (gRPC stream, mTLS)
 ┌───────────────────────── Kubernetes cluster ──────────┼──────────────────────────────┐
 │                                        ┌──────────────┴───────────────┐              │
 │   kubectl / GitOps ──CRDs──▶ kube-api ◀┤      inkwall-operator        │              │
 │                                        │ reconcile · wire · distribute│              │
 │                                        └──────────────┬───────────────┘              │
 │                                                       │ bundles (gRPC stream)        │
 │   ┌───────────────── ingress controller pod ──────────┼───────────────┐              │
 │   │  ┌───────────────┐   UDS / in-process   ┌─────────▼─────────┐     │              │
 │ ──┼─▶│ proxy (Envoy/ │ ───────────────────▶ │  inkwall-engine   │     │              │
 │   │  │ nginx/HAProxy │ ◀─── verdict ─────── │  (sidecar)        │     │              │
 │   │  │ /Traefik)     │                      └───────────────────┘     │              │
 │   │  └───────┬───────┘                                                │              │
 │   └──────────┼────────────────────────────────────────────────────────┘              │
 │              ▼                                                                       │
 │         application Services                                                         │
 └──────────────────────────────────────────────────────────────────────────────────────┘
```

Three planes:

| Plane | Components | Latency sensitivity | Availability requirement |
|---|---|---|---|
| **Data plane** | engine, adapters | µs, on every request | Must keep working when everything else is down |
| **Local control** | operator | seconds | Can be down for hours; the engine keeps last-known-good |
| **Global control** | SaaS CP | seconds to minutes | Can be down for days; clusters keep enforcing |

**Rule:** no call on the request path ever crosses a plane boundary.

---

## 3. Components

### 3.1 `inkwall-engine` (data plane)

A single static Go binary, distroless image, runs as:

- a **sidecar** in the ingress controller pod (default),
- a **standalone Deployment** behind a Service (simpler, slower),
- a **reverse proxy** in front of an app (non-Kubernetes or unsupported proxies),
- a **library** embedded in-process (Caddy module, and later the Envoy Go filter).

#### Internal structure

```
                ┌───────────────────────── inkwall-engine ─────────────────────────┐
 listeners      │ grpc: ext_authz v3 │ grpc: ext_proc v3 │ http: forward-auth  │   │
 (adapters)     │ spoe agent         │ http: /v1/check (Lua, generic)          │   │
                │ reverse proxy      │                                         │   │
                ├────────────────────┴─────────┬───────────────────────────────┘   │
 normalize      │  Request (canonical, pooled) │                                   │
                ├──────────────────────────────▼───────────────────────────────────┤
 pipeline       │ T0 router ─▶ T1 ip/rate ─▶ T2 headers ─▶ T3 body ─▶ verdict      │
                │   (radix)     (trie/buckets)  (rules)      (rules)               │
                ├──────────────────────────────────────────────────────────────────│
 state          │ atomic.Pointer[Snapshot]  · rate-limit shards · reputation cache │
                ├──────────────────────────────────────────────────────────────────│
 background     │ bundle client (operator/file) · event shipper · metrics · pprof  │
                └──────────────────────────────────────────────────────────────────┘
```

#### Packages

| Package | Responsibility |
|---|---|
| `pkg/request` | Canonical `Request` type, pooling, header access without copying |
| `pkg/router` | Maps `(host, path, method)` to a compiled route policy (radix tree, built at load) |
| `pkg/pipeline` | Runs tiers T0–T4, enforces the per-request deadline, produces `Verdict` |
| `pkg/rules` | `Evaluator` interface; `coraza` implementation; later a prefilter implementation |
| `pkg/ratelimit` | Sharded token buckets, key extraction (IP, header, JWT claim, path) |
| `pkg/iplist` | CIDR trie for allow/deny/reputation, IPv4 and IPv6 |
| `pkg/clientip` | Trusted-proxy aware client IP resolution (see §8.2) |
| `pkg/snapshot` | Compiled, immutable view of a bundle; atomic swap |
| `pkg/bundle` | Bundle loading from operator stream, file, or CP; validation; last-known-good cache |
| `pkg/events` | Ring buffer, redaction, batching, shipping (OTLP / CP) |
| `pkg/adapters/*` | One package per listener: `extauthz`, `extproc`, `forwardauth`, `spoe`, `httpcheck`, `proxy` |
| `pkg/telemetry` | Prometheus metrics, OTel tracing (sampled), structured logs (slog) |

#### Core types

```go
// pkg/request
type Request struct {
    ID        string          // from proxy (x-request-id) or generated
    Proto     string          // HTTP/1.1, HTTP/2, HTTP/3
    Method    string
    Scheme    string
    Host      string
    RawURI    string          // un-normalized, exactly as received
    Headers   HeaderView      // zero-copy view over adapter-native headers
    ClientIP  netip.Addr      // resolved via pkg/clientip
    PeerIP    netip.Addr      // direct TCP peer of the proxy
    Body      BodySource      // nil, buffered, or streaming; capped by policy
    RouteHint string          // optional: ingress/route name the proxy matched
}

// pkg/pipeline
type Action uint8
const (
    ActionAllow Action = iota
    ActionDeny
    ActionChallenge
    ActionLog      // detect mode: matched but not enforced
)

type Verdict struct {
    Action       Action
    Status       int              // e.g. 403, 429
    Headers      []Header         // to add to response (e.g. Retry-After)
    RuleIDs      []uint32         // matched rules
    AnomalyScore int
    PolicyRef    PolicyRef        // policy + bundle version that decided
    Reason       Reason           // enum: rule, ratelimit, iplist, timeout, error
}

// pkg/rules
type Evaluator interface {
    // EvaluateHeaders runs phase 1-2. Returns early on interruption.
    EvaluateHeaders(ctx context.Context, tx *Tx, r *request.Request) Result
    // EvaluateBody runs phase 2 body rules on a chunk. Called 0..n times.
    EvaluateBody(ctx context.Context, tx *Tx, chunk []byte, last bool) Result
    // EvaluateResponse is optional (T4).
    EvaluateResponse(ctx context.Context, tx *Tx, resp *request.Response) Result
}
```

#### Lifecycle

1. Start: load config (flags/env/file), open listeners in **not-ready** state.
2. Load a bundle: from the disk cache (last-known-good) immediately, or from the bundle Secret on a
   fresh pod, then subscribe to the operator for updates.
3. Compile bundle → `Snapshot` (rules, router, lists). Mark **ready** only after the first
   successful compile.
4. On update: compile in the background; if it succeeds, `atomic.Store`; if it fails, keep the old
   snapshot, report a NACK with the error.
5. Shutdown: stop accepting, drain in-flight requests (bounded), flush events.

If no bundle has ever been loaded, the engine answers according to its **bootstrap mode** flag:
`allow-all` (default) or `deny-all`.

### 3.2 Adapters

Each adapter has two halves:

1. **Engine side**: a listener in `pkg/adapters/<name>` that converts proxy-native messages into
   `request.Request` and `Verdict` back into proxy-native responses.
2. **Proxy side**: configuration (rendered by the operator) or a plugin that sends the request to
   the engine.

How each protocol works (ext_authz, ext_proc, forward-auth, SPOE, `/v1/check`, reverse proxy):
[0006 — Adapter Protocols Primer](0006-adapter-protocols.md). Concrete configuration per proxy is
in §6.

### 3.3 `inkwall-operator` (local control)

Built with controller-runtime (kubebuilder layout). Runs as a Deployment with leader election
(2 replicas). Full design: [0004 — Kubernetes Operator](0004-operator.md). Responsibilities:

| Controller | Watches | Does |
|---|---|---|
| **Discovery** | IngressClass, GatewayClass, controller Deployments | Detects which ingress controllers are installed and which adapter to use for each |
| **Injection** | `InkwallConfig`, controller workloads | Adds the engine sidecar + shared socket volume to ingress controller pods via the controller's native extension point or a Pod mutating webhook (never a Deployment patch) |
| **Wiring** | `WAFPolicy`, Ingress, HTTPRoute | Renders proxy-side config: ConfigMap keys, Traefik `Middleware`, `EnvoyExtensionPolicy`, HAProxy config |
| **Resolver + bundle builder** | `WAFPolicy`, `WAFRuleSet`, `WAFIPList`, routes | Validates, resolves targets to host/path/method, builds a signed **bundle**, bumps its version |
| **Distribution** | engine connections | Serves bundles over a gRPC stream to all engines in the cluster; tracks which version each engine runs |
| **Upstream sync** | `InkwallConfig.spec.controlPlane` | Holds the single connection to the SaaS: pulls bundles (Managed mode) or pushes CRD state (GitOps mode); forwards events |
| **Status** | all of the above | Writes `status.conditions` on CRDs: `Accepted`, `Programmed`, `Enforced` (all engines ACKed) |

The operator is **never** on the request path. If it is down, engines keep their snapshot, and new
engine pods start from their disk cache, or from the bundle Secret the operator keeps for exactly
this case (0004 §4.6).

### 3.4 Control plane (optional)

The hosted control plane (SaaS) adds multi-cluster policy management, attack analytics, and threat
intelligence feeds. It is a separate product and its internals are out of scope for this
repository. What the open-source components depend on is only its **interface**:

- the operator ↔ control plane stream (§5.3),
- cluster enrollment (§7.5),
- the Standalone / GitOps / Managed modes (§4.1).

Every enforcement feature works without it.

The SaaS talks only to **operators** (one connection per cluster), never directly to engines. That
keeps SaaS connection counts low, keeps engines free of internet egress, and makes air-gapped /
GitOps-only installs the same code path minus one hop.

### 3.5 `inkwallctl` (CLI)

- `inkwallctl test` replays a request or HAR file against a local engine and shows which rules match.
- `inkwallctl bundle build/verify` compiles CRDs or YAML into a bundle offline (used in CI to reject
  bad policy before merge).
- `inkwallctl status` shows cluster, engines, bundle versions, drift.
- `inkwallctl bench` runs the standard benchmark corpus against an engine.

---

## 4. Configuration model

### 4.1 Sources of truth

A cluster runs in exactly one mode, set in `InkwallConfig`:

| Mode | Source of truth | SaaS role |
|---|---|---|
| **Standalone** | CRDs | none (fully offline, pure OSS) |
| **GitOps** | CRDs (in Git) | read-only mirror: analytics, UI shows policy but cannot edit |
| **Managed** | SaaS | operator materializes SaaS policy locally; CRD edits are rejected by webhook |

Mixed ownership per route is not supported in v1; it makes conflict resolution ambiguous.

### 4.2 CRDs (`waf.inkwall.dev/v1alpha1`)

#### `InkwallConfig` (cluster-scoped, singleton)

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  mode: Standalone            # Standalone | GitOps | Managed
  controlPlane:               # ignored in Standalone
    endpoint: grpcs://agents.inkwall.example.com:443
    enrollmentSecretRef: {name: inkwall-enrollment, namespace: inkwall-system}
  engine:
    image: ghcr.io/inkwall-dev/inkwall-engine:v0.1.0
    resources:
      requests: {cpu: "500m", memory: 256Mi}
      limits:   {memory: 512Mi}      # no CPU limit by default: throttling = p99 latency
    bootstrapMode: AllowAll
    socketDir: /var/run/inkwall
  integrations:               # auto-discovered; can be pinned
  - controller: ingress-nginx
    selector: {matchLabels: {app.kubernetes.io/name: ingress-nginx}}
    adapter: LuaPlugin        # LuaPlugin | AuthURL
  - controller: envoy-gateway
    adapter: ExtProc
  events:
    sampleAllowed: 0.0        # fraction of allowed requests to log
    redact: [authorization, cookie, set-cookie]
```

#### `WAFPolicy` (namespaced)

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: shop
  namespace: shop
spec:
  targetRefs:                         # what this protects
  - kind: Ingress
    name: shop
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: shop-api
  mode: Detect                        # Detect | Block | BlockHighConfidence
  failureMode: Open                   # Open | Closed
  timeout: 250ms
  skip:                               # T0: never inspected
    paths: ["/healthz", "/static/*"]
    methods: []
  ruleSets:
  - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
    paranoiaLevel: 1
    inboundAnomalyThreshold: 5
  - ref: {kind: WAFRuleSet, name: shop-custom, namespace: shop}
  exclusions:                         # false-positive tuning
  - ruleIDs: [942100]
    when: {path: "/api/search", argument: "q"}
  body:
    inspect: true
    maxBytes: 65536
    contentTypes: [application/json, application/x-www-form-urlencoded, multipart/form-data]
    onOversize: InspectPrefix         # InspectPrefix | Allow | Deny
  response:
    inspect: false
  rateLimits:
  - name: login
    match: {path: "/api/login", methods: [POST]}
    key: ClientIP                     # ClientIP | Header:<name> | JWTClaim:<claim>
    limit: 10
    window: 1m
    action: Deny                      # 429 with Retry-After
  ipLists:
    allow: [{ref: {kind: ClusterWAFIPList, name: office}}]
    deny:  [{ref: {kind: ClusterWAFIPList, name: inkwall-reputation}}]
status:
  observedGeneration: 3
  bundleVersion: 42
  conditions:
  - {type: Accepted,   status: "True"}
  - {type: Programmed, status: "True", message: "ingress-nginx: plugin enabled"}
  - {type: Enforced,   status: "True", message: "6/6 engines on bundle 42"}
```

Policy precedence when several policies target the same route: the most specific target wins
(HTTPRoute rule > HTTPRoute > Ingress > namespace default). A conflict with equal specificity is
rejected with `Accepted=False, reason=Conflict`.

#### `WAFRuleSet` (namespaced or cluster-scoped `ClusterWAFRuleSet`)

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: ClusterWAFRuleSet
metadata:
  name: owasp-crs-v4
spec:
  source:
    builtin: crs-v4            # shipped inside the engine image, version-pinned
  # or:
  # source:
  #   seclang: |
  #     SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100001,phase:1,deny,status:403"
  # or:
  #   configMapRef: {name: my-rules, key: rules.conf}
```

#### `WAFIPList` (namespaced or `ClusterWAFIPList`)

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: ClusterWAFIPList
metadata:
  name: office
spec:
  cidrs: ["203.0.113.0/24", "2001:db8::/32"]
  # or source: {url: https://..., refresh: 1h}   (fetched by operator, never by engine)
```

### 4.3 Bundle format

The operator (or the control plane, in Managed mode) compiles all policies for one cluster into a **bundle**:

```protobuf
// api/bundle/v1/bundle.proto
message Bundle {
  uint64 version = 1;                 // monotonic per cluster
  string cluster_id = 2;
  google.protobuf.Timestamp created_at = 3;
  repeated Policy policies = 4;
  repeated RuleSet rule_sets = 5;     // deduplicated, referenced by id
  repeated IPList ip_lists = 6;
  bytes signature = 7;                // ed25519 over the rest; verified by engine
}

message Policy {
  string id = 1;                      // namespace/name
  repeated RouteMatch routes = 2;     // resolved from targetRefs: host + path prefix/exact + method
  Mode mode = 3;
  FailureMode failure_mode = 4;
  google.protobuf.Duration timeout = 5;
  repeated RuleSetRef rule_sets = 6;
  repeated Exclusion exclusions = 7;
  BodyConfig body = 8;
  repeated RateLimit rate_limits = 9;
  IPListRefs ip_lists = 10;
}
```

Routes are resolved to concrete `(host, path, method)` matches **by the operator**, so the engine
does not need Kubernetes knowledge. Bundles are immutable; every change produces a new version.

---

## 5. Protocols

### 5.1 Engine check API (for Lua, generic HTTP clients, and tests)

```protobuf
// api/engine/v1/engine.proto
service CheckService {
  rpc Check(CheckRequest) returns (CheckResponse);
}

message CheckRequest {
  string request_id = 1;
  string method = 2;
  string scheme = 3;
  string authority = 4;
  string raw_uri = 5;
  repeated Header headers = 6;
  bytes client_ip = 7;       // 4 or 16 bytes
  bytes peer_ip = 8;
  bytes body = 9;            // optional, already capped by the proxy
  bool body_truncated = 10;
  string route_hint = 11;
}

message CheckResponse {
  Action action = 1;
  uint32 status = 2;
  repeated Header response_headers = 3;
  repeated uint32 rule_ids = 4;
}
```

The same message is exposed as `POST /v1/check` with a compact binary (protobuf) or JSON body, for
proxies without gRPC clients.

For Envoy the engine implements the **native** `envoy.service.auth.v3.Authorization` and
`envoy.service.ext_proc.v3.ExternalProcessor` services directly; there is no translation proxy.

### 5.2 Engine ↔ operator (bundle distribution)

```protobuf
// api/agent/v1/agent.proto
service BundleService {
  // Engine opens one long-lived stream. Server pushes; engine ACKs/NACKs.
  rpc Watch(stream EngineMessage) returns (stream OperatorMessage);
}

message EngineMessage {
  oneof msg {
    Hello hello = 1;           // engine id, pod, node, current bundle version, engine version
    Ack ack = 2;               // bundle version applied
    Nack nack = 3;             // bundle version + error
    Heartbeat heartbeat = 4;   // load, snapshot age, dropped events
    EventBatch events = 5;     // security events (see §5.4), batched by the engine
  }
}

message OperatorMessage {
  oneof msg {
    bundle.v1.Bundle bundle = 1;   // full snapshot (bundles are small: KBs to low MBs)
    Directive directive = 2;       // e.g. rotate logs, dump profile
  }
}
```

Full snapshots, not deltas, in v1: simpler, idempotent, and bundles are small. Deltas can come later
(xDS-style) if bundle size grows.

### 5.3 Operator ↔ SaaS

Same pattern, one stream per cluster over mTLS:

- Down: `Bundle` (Managed mode), IP reputation lists, directives.
- Up: `ClusterState` (CRDs in GitOps mode, discovered integrations, engine versions), `EventBatch`,
  `Heartbeat`.

Events are shipped by the engine to the operator over the same `Watch` stream (`EventBatch`), and
the operator batches them to the SaaS. When the SaaS is unreachable the operator buffers to a
bounded disk queue, then drops the oldest events.

In **Standalone** mode there is no SaaS: the operator exports events as structured logs and,
optionally, to a user-provided OTLP endpoint, so they land in the user's existing log / SIEM stack.

### 5.4 Event schema

```protobuf
message SecurityEvent {
  google.protobuf.Timestamp ts = 1;
  string request_id = 2;
  string cluster_id = 3;
  string policy_id = 4;
  uint64 bundle_version = 5;
  Action action = 6;            // including LOG for detect mode
  Reason reason = 7;
  repeated RuleMatch matches = 8;   // rule id, variable (e.g. ARGS:q), redacted matched snippet
  int32 anomaly_score = 9;
  string method = 10;
  string host = 11;
  string path = 12;             // query string removed or redacted per policy
  bytes client_ip = 13;
  string user_agent = 14;
  uint32 status = 15;
  uint32 latency_us = 16;       // engine time spent
}
```

---

## 6. Proxy integrations

Every integration follows the same contract:

1. Send only what the active policy needs (headers only unless body inspection is on).
2. Use a persistent connection to the engine (UDS where supported).
3. Enforce a proxy-side timeout slightly above the engine deadline.
4. Apply the policy's failure mode if the engine errors or times out.
5. Pass the real client IP and a request ID.

The shared socket directory is an `emptyDir` volume mounted into both containers at
`/var/run/inkwall`.

### 6.1 Envoy (raw Envoy, Envoy Gateway, Istio, Contour)

**Mechanism:** `ext_proc` filter (preferred) or `ext_authz` (simpler, headers + optional buffered body).

Raw Envoy:

```yaml
http_filters:
- name: envoy.filters.http.ext_proc
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
    grpc_service:
      envoy_grpc: {cluster_name: inkwall}
      timeout: 0.025s
    failure_mode_allow: true
    message_timeout: 0.025s
    processing_mode:
      request_header_mode: SEND
      request_body_mode: NONE          # STREAMED or BUFFERED_PARTIAL when body inspection is on
      response_header_mode: SKIP
      response_body_mode: NONE
- name: envoy.filters.http.router
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

clusters:
- name: inkwall
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config: {http2_protocol_options: {}}
  load_assignment:
    cluster_name: inkwall
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            pipe: {path: /var/run/inkwall/engine.sock}
```

Envoy Gateway (rendered by the operator):

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: Backend
metadata: {name: inkwall-engine, namespace: shop}
spec:
  endpoints:
  - unix: {path: /var/run/inkwall/engine.sock}
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata: {name: inkwall-shop, namespace: shop}
spec:
  targetRefs:
  - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: shop-api}
  extProc:
  - backendRefs:
    - {group: gateway.envoyproxy.io, kind: Backend, name: inkwall-engine}
    messageTimeout: 25ms
    failOpen: true
```

The sidecar is added to Envoy Gateway's proxy pods through the `EnvoyProxy` resource's
deployment patch. Istio uses an `EnvoyFilter` inserting the same `ext_proc` filter; Contour uses
its `ExtensionService`.

**Detect mode:** `ext_proc` with `observability_mode: true`, where Envoy does not wait for the
response.

**Future:** Envoy's contrib Golang HTTP filter runs the engine in-process. It requires an Envoy
build with contrib extensions, so it stays experimental.

### 6.2 ingress-nginx

Two adapters, chosen per install.

**A. Lua plugin (default, supports body):**

ingress-nginx loads Lua plugins from `/etc/nginx/lua/plugins/<name>/main.lua` and enables them with
the `plugins` ConfigMap key. The operator mounts the plugin (from a ConfigMap) and sets:

```yaml
# ingress-nginx controller ConfigMap
data:
  plugins: "inkwall"
```

```lua
-- /etc/nginx/lua/plugins/inkwall/main.lua (sketch)
local http = require("resty.http")
local _M = {}

function _M.rewrite()
  if not protected_route(ngx.var.host, ngx.var.uri) then return end  -- local route set: unprotected routes skip the socket call
  local httpc = http.new()
  httpc:set_timeouts(5, 25, 25)                       -- connect, send, read (ms)
  local ok, err = httpc:connect("unix:/var/run/inkwall/engine.sock")
  if not ok then return fail_mode_exit() end          -- applies the route's failure mode from the cached route set (default: open)
  local res, err = httpc:request({
    method = "POST",
    path = "/v1/check",
    headers = { ["Content-Type"] = "application/x-protobuf" },
    body = encode_check_request(ngx.var, ngx.req.get_headers(100)),  -- body read only if policy needs it
  })
  if res and res.status == 200 then
    local verdict = decode(res:read_body())
    httpc:set_keepalive(60000, 256)
    if verdict.action == "DENY" then
      return ngx.exit(verdict.status)
    end
  end
end

return _M
```

The plugin keeps a per-worker cache of "does this host+path need the body?", pushed via a small
`/v1/routes` endpoint, so `ngx.req.read_body()` is called only when required.

**B. Global auth URL (headers only, zero code in nginx):**

```yaml
data:
  global-auth-url: "http://127.0.0.1:9001/v1/forward-auth"
  global-auth-response-headers: "X-Inkwall-Action"
```

Works because the engine sidecar shares the pod's network namespace. It costs an `auth_request`
subrequest per request and cannot inspect bodies.

**Notes:**

- Snippet annotations are disabled by default in current ingress-nginx for security reasons;
  both adapters work without them.
- ingress-nginx is retired upstream (2026). It is supported for existing users, but new
  investment goes to Gateway API implementations.

### 6.3 Traefik

**A. ForwardAuth middleware (v1):**

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: inkwall, namespace: shop}
spec:
  forwardAuth:
    address: http://127.0.0.1:9001/v1/forward-auth
    trustForwardHeader: true
    authResponseHeaders: ["X-Inkwall-Action"]
    # forwardBody: true      # recent Traefik v3 versions; enable only when body inspection is on
    # maxBodySize: 65536
```

The operator attaches it to protected routes (IngressRoute `middlewares`, or the
`traefik.ingress.kubernetes.io/router.middlewares` annotation for Ingress).

ForwardAuth does not send the original method and URI as-is; they arrive as `X-Forwarded-Method`
and `X-Forwarded-Uri`. The `forwardauth` adapter reconstructs the request from these headers.

**B. Traefik plugin (later):** Yaegi-interpreted Go plugins can't run Coraza efficiently (no cgo,
interpreter overhead), so the plugin is a **thin client** that sends a compact binary check request
to the sidecar over a pooled connection. The engine stays in the sidecar. A WASM (http-wasm) plugin
is an alternative to evaluate.

### 6.4 HAProxy (HAProxy Kubernetes Ingress Controller, HAProxy Ingress)

**Mechanism:** SPOE. The engine implements the SPOA side of the SPOP protocol.

```
# haproxy.cfg (rendered into the controller's config via its extension points)
frontend https
    filter spoe engine inkwall config /etc/haproxy/inkwall-spoe.conf
    http-request send-spoe-group inkwall check
    http-request deny deny_status 403 if { var(txn.inkwall.action) -m str deny }
    http-request deny deny_status 429 if { var(txn.inkwall.action) -m str ratelimit }

backend inkwall-spoa
    mode tcp
    timeout connect 5ms
    timeout server 30s
    server engine unix@/var/run/inkwall/spoa.sock
```

```
# /etc/haproxy/inkwall-spoe.conf
[inkwall]
spoe-agent inkwall-agent
    groups check
    option var-prefix inkwall
    option set-on-error error
    timeout hello 100ms
    timeout idle 30s
    timeout processing 25ms
    use-backend inkwall-spoa

spoe-message check-request
    args id=unique-id method=method path=path query=query ver=req.ver ip=src headers=req.hdrs_bin body=req.body

spoe-group check
    messages check-request
```

Body inspection requires `option http-buffer-request` on the frontend; the operator enables it only
when some policy needs bodies. SPOP pipelines many requests over few connections, which keeps it
efficient. If the agent errors or times out the variable stays unset: with a fail-open policy no
deny rule matches and the request passes; with fail-closed (the block-mode default) the operator
also renders `http-request deny deny_status 503 unless { var(txn.inkwall.action) -m found }`.

### 6.5 Caddy

**Mechanism:** a native Caddy HTTP handler module, in-process. The adapter is a separate Go module
(`adapters/caddy`) built into Caddy with `xcaddy`:

```go
func init() {
    caddy.RegisterModule(Inkwall{})
    httpcaddyfile.RegisterHandlerDirective("inkwall", parseCaddyfile)
}

type Inkwall struct {
    BundlePath string `json:"bundle_path,omitempty"`
    Operator   string `json:"operator,omitempty"`   // optional bundle stream
    engine     *engine.Engine
}

func (Inkwall) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{ID: "http.handlers.inkwall", New: func() caddy.Module { return new(Inkwall) }}
}

func (o *Inkwall) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    v := o.engine.CheckHTTP(r)               // zero-copy wrap of *http.Request
    if v.Action == pipeline.ActionDeny {
        return caddyhttp.Error(v.Status, nil)
    }
    return next.ServeHTTP(w, r)
}
```

```caddyfile
{
    order inkwall first
}
shop.example.com {
    inkwall {
        bundle_path /etc/inkwall/bundle.pb
    }
    reverse_proxy app:8080
}
```

Build: `xcaddy build --with github.com/inkwall-dev/inkwall/adapters/caddy`.

### 6.6 Standalone reverse proxy (universal fallback)

`inkwall-engine proxy --listen :8080 --upstream http://app:80 --bundle bundle.pb` puts the engine in
front of any service. It is used for non-Kubernetes deployments, unsupported proxies, and as the
reference implementation in tests (every other adapter must produce the same verdicts as this one).

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

---

## 7. Request flows

### 7.1 Block mode (Envoy example)

```
client      envoy                       engine (sidecar)
  │ HTTPS     │                               │
  │──────────▶│ TLS terminate, route match    │
  │           │── ProcessingRequest(headers) ─▶│ router → policy "shop/shop" (block)
  │           │                               │ T1 ip/rate: pass
  │           │                               │ T2 rules: 942100 matched, score 5 ≥ 5
  │           │◀─ ImmediateResponse(403) ─────│ event → ring buffer
  │◀── 403 ───│                               │
```

### 7.2 Detect mode

```
client      envoy                       engine
  │──────────▶│── headers (observability) ───▶│ (evaluated asynchronously)
  │           │── forward to upstream ──────▶ app
  │◀── 200 ───│                               │ matched → event action=LOG
```

### 7.3 Engine unavailable

```
client      proxy                       engine
  │──────────▶│── check ─────────────────────X (timeout 25ms / connect refused)
  │           │ failure mode = open → forward to upstream
  │◀── 200 ───│  metric inkwall_adapter_failures_total{reason="timeout"}++
```

### 7.4 Policy change (GitOps mode)

```
git push → Argo CD applies WAFPolicy
  operator: validate → build bundle v43 → sign
  operator ─ Bundle v43 ─▶ engines (stream)
  engines: compile in background → atomic swap → Ack v43
  operator: status Enforced=True "6/6 engines on bundle 43"
  operator ─ ClusterState ─▶ SaaS (mirror for UI)
```

### 7.5 Cluster enrollment (Managed / GitOps mode)

```
1. User creates cluster in SaaS UI → gets one-time enrollment token (TTL 1h).
2. helm install inkwall --set controlPlane.enrollmentToken=...
3. Operator generates a keypair, sends CSR + token to the control plane's agent endpoint.
4. SaaS validates token, issues a short-lived client cert (24h) bound to cluster_id.
5. Operator stores cert in a Secret and rotates it before expiry over the mTLS stream.
6. Token is burned; a leaked token after first use is useless.
```

---

## 8. Cross-cutting concerns

### 8.1 Security of Inkwall itself

- Engine and operator images: distroless, non-root, read-only root filesystem, no shell, dropped
  capabilities, seccomp `RuntimeDefault`.
- The UDS socket is created with `0660` and a shared group; only containers in the pod can reach it.
- TCP listeners (standalone mode) require mTLS or bind to localhost.
- Bundles are **signed** (ed25519). Engines reject unsigned or badly signed bundles, so someone
  able to edit the bundle Secret can't disable the WAF without the signing key.
- Operator RBAC is scoped: write only to its own CRDs, the resources it wires (Middlewares,
  EnvoyExtensionPolicies, specific ConfigMaps), and, only with opt-in automatic rollout, a patch on
  discovered ingress controller workloads (full table: 0004 §7).
- Supply chain: reproducible builds with goreleaser, cosign-signed images, SBOM (syft), SLSA
  provenance, `govulncheck` and Trivy in CI, pinned GitHub Actions.
- `SECURITY.md` with a private disclosure address and response SLA.

### 8.2 Client IP correctness

A WAF that keys rate limits and IP lists on the wrong IP is worse than none. `pkg/clientip`
resolves the client IP from:

1. The proxy's own resolved client IP when the adapter provides it (Envoy `x-envoy-external-address`
   when configured, HAProxy `src` after `PROXY` protocol, nginx `$remote_addr` after `real_ip`).
2. Otherwise `X-Forwarded-For` / `Forwarded`, walked **right to left** and skipping only CIDRs in
   `trustedProxies`.
3. Otherwise the peer IP.

`trustedProxies` is set per cluster (e.g. the cloud load balancer ranges).

### 8.3 Data privacy

- Request bodies never leave the engine. Events carry only the matched variable name and a
  redacted snippet (max 64 bytes, configurable masking).
- Headers in `events.redact` are always dropped (default: `Authorization`, `Cookie`, `Set-Cookie`).
- Query strings are removed from event paths by default.
- These guarantees are enforced in the engine and operator, before anything leaves the cluster,
  so they hold regardless of where events are sent.

### 8.4 Multi-tenancy

One engine per ingress controller pod serves every policy for that controller. The router picks the
policy per request, and rule sets shared by many policies are compiled once and shared in memory.

Towards the control plane, each cluster is identified by the client certificate issued at
enrollment (§7.5), which binds the cluster to its tenant.

### 8.5 Observability

Metrics (Prometheus, prefix `inkwall_`):

| Metric | Type | Labels |
|---|---|---|
| `inkwall_requests_total` | counter | adapter, policy, action, reason |
| `inkwall_check_duration_seconds` | histogram (µs buckets) | adapter, tier_reached |
| `inkwall_rule_matches_total` | counter | policy, rule_id (top-N only, to bound cardinality) |
| `inkwall_adapter_failures_total` | counter | adapter, reason |
| `inkwall_bundle_version` | gauge | — |
| `inkwall_bundle_age_seconds` | gauge | — |
| `inkwall_events_dropped_total` | counter | reason |
| `inkwall_ratelimit_decisions_total` | counter | policy, limit, result |

- Tracing: OpenTelemetry, off by default, head-sampled, propagated from the proxy's `traceparent`.
  Only the engine's own span is added, never a span per rule.
- Logs: `slog` JSON, one line per security event at most. No per-request logs in the hot path.
- A Grafana dashboard and PrometheusRules (latency budget burn, bundle drift, failure rate) ship in
  the Helm chart.

### 8.6 Versioning and compatibility

- Semver for the data plane. CRDs start at `v1alpha1` and move to `v1beta1` and then `v1` with
  conversion webhooks.
- Engine ↔ operator protocol is versioned in `Hello`. The operator supports engines at N-1 minor.
- CRS version is pinned per release and exposed as a `ClusterWAFRuleSet` builtin (`crs-v4`,
  `crs-v4.x`), so upgrading Inkwall never silently changes detection.
- Tested matrix: the last 3 Kubernetes minors, and for each proxy the versions listed in
  `docs/compatibility.md`.

---

## 9. Repository layout

```
inkwall/
├── cmd/
│   ├── engine/                 # inkwall-engine main
│   ├── operator/               # inkwall-operator main
│   └── inkwallctl/             # CLI
├── api/                        # protobuf (buf managed)
│   ├── engine/v1/
│   ├── agent/v1/
│   └── bundle/v1/
├── pkg/                        # engine packages (see §3.1)
├── operator/                   # full layout: 0004 §10
│   ├── api/v1alpha1/           # CRD Go types (kubebuilder markers)
│   ├── internal/               # discovery, injection, wiring, resolver, bundle, distribution, status
│   ├── integrations/           # one package per proxy: envoygateway, istio, ingressnginx, traefik, haproxy, caddy
│   └── webhook/
├── adapters/
│   ├── caddy/                  # separate go.mod
│   ├── traefik-plugin/         # separate go.mod (Yaegi constraints)
│   └── nginx-lua/              # Lua plugin + tests
├── rules/crs/                  # vendored, pinned CRS
├── deploy/
│   ├── helm/inkwall/
│   └── kind/                   # kind configs, controller installs per proxy
├── test/
│   ├── e2e/                    # e2e-framework suites, one per integration
│   ├── ftw/                    # go-ftw configs + CRS regression overrides
│   ├── corpus/                 # benign + attack request corpus (shared by all tests)
│   └── perf/                   # k6 scripts, benchmark baselines
├── docs/
│   └── design/                 # ADRs and design docs (this file)
├── .github/workflows/
├── Makefile
├── .goreleaser.yaml
├── buf.yaml
├── LICENSE  README.md  CONTRIBUTING.md  SECURITY.md  CODE_OF_CONDUCT.md  GOVERNANCE.md
```

Separate Go modules for Caddy and the Traefik plugin keep their dependency trees (Caddy, Yaegi
limits) out of the engine binary.

---

## 10. Testing architecture

One shared **request corpus** (`test/corpus`) drives every test level, so an attack blocked at one
level is tested the same way at every other level.

| Level | Tool | What it proves | Runs |
|---|---|---|---|
| Unit | `go test` | Package logic, parsers | every PR |
| Fuzz | `go test -fuzz` | Parsers never panic, no unbounded allocation | nightly |
| Rule conformance | go-ftw + CRS tests | Engine detection matches CRS expectations | every PR |
| Adapter parity | testcontainers-go | Each proxy + adapter returns the same verdict as the reference reverse proxy for the whole corpus | every PR |
| E2E | kind + e2e-framework | Operator installs, wires, enforces, reports status; failure modes | every PR (matrix) |
| Performance | `testing.B` + benchstat, k6 | Budgets from 0001 | every PR (micro), nightly (e2e) |
| Upgrade | kind | Upgrade N-1 → N with traffic flowing, no dropped requests | release |
| Soak / chaos | kind + k6 | 24h memory/GC stability, engine kill → fail-open | weekly |

---

## 11. Decisions (ADR log)

| # | Decision | Alternatives considered | Why |
|---|---|---|---|
| D1 | One engine + thin adapters | Separate WAF per proxy | One detection core, one test suite, consistent verdicts |
| D2 | Coraza + CRS as the initial rule engine, behind an interface | Write own engine; libmodsecurity via cgo | Mature, Go-native, ModSecurity-compatible; interface keeps a custom engine possible |
| D3 | Sidecar over UDS as the default topology | Central Deployment; DaemonSet | No network hop; see 0001 |
| D4 | SaaS talks to operators only | SaaS → every engine | Fewer connections, no engine egress, air-gap friendly |
| D5 | Full-snapshot signed bundles | Deltas; unsigned ConfigMaps | Simple, idempotent, tamper-resistant |
| D6 | Operator resolves routes to host/path | Engine watches Kubernetes | Engine stays K8s-agnostic and reusable outside K8s |
| D7 | Detect mode default for new routes | Block by default | Zero latency and no false-positive outages on onboarding |
| D8 | Fail open in detect mode, fail closed in block mode | Fail open everywhere | Detect mode must never take down traffic; a fail-open block mode is bypassable by padding a request past the deadline |
| D9 | One source of truth per cluster | Merge SaaS + CRD per route | Avoids ambiguous conflicts |

## 12. Open questions

1. Hyperscan (cgo) optional build vs pure Go only (from 0001).
2. Is the Envoy Go filter a supported mode or experimental?
3. Default body cap: 8 KB, 64 KB, or per content type?
4. Distributed rate limiting backend: gossip between engines vs Redis.
5. Bot challenge (JS / proof-of-work) in v1 or later? It needs response rewriting, which only
   ext_proc, Caddy and reverse-proxy mode support.
