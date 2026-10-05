# 0004 — Kubernetes Operator

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin
- Depends on: [0001](0001-performance-first-architecture.md), [0002](0002-system-architecture.md)

The operator is what makes Inkwall Kubernetes-native: install once, and every ingress and
gateway in the cluster is protected with the same policy, with no proxy-specific configuration by
the user. This document details how it works. The CRD shapes are in 0002 §4.2 and are extended here.

---

## 1. Goals and non-goals

### Goals

1. **Zero proxy knowledge for users.** A user writes `WAFPolicy` against an `Ingress` or
   `HTTPRoute`; the operator does the rest.
2. **Never on the request path.** Operator downtime never affects traffic (0002 §2).
3. **GitOps-friendly.** Don't mutate user-owned objects when avoidable; when unavoidable, touch
   the minimum number of fields and document how to ignore them in Argo CD / Flux.
4. **Safe by default.** In detect mode every step can fail without dropping traffic. In block mode
   nothing is forwarded uninspected, so failures surface as rejected requests and conditions
   rather than silent gaps. Every change is reversible by uninstalling.
5. **Observable.** Every CRD tells the user exactly how far its policy got: accepted → programmed
   into the proxy → enforced by every engine.

### Non-goals

- Installing or upgrading the ingress controllers themselves.
- Managing TLS, DNS, or routes.
- Restarting user workloads without explicit opt-in.

---

## 2. Overview

```
                 ┌────────────────────────── inkwall-operator (Deployment, 2 replicas) ──────────────────────────┐
                 │                                                                                               │
  IngressClass ─▶│ Discovery ──▶ Integration registry ──┬──▶ Injection (native patch / Pod webhook)              │
  GatewayClass   │                                      └──▶ Wiring (render proxy-side objects, SSA)             │
  Deployments    │                                                                                               │
                 │ WAFPolicy ─┐                                                                                  │
  WAFRuleSet ───▶│ Resolver ──┼─▶ Bundle builder ─▶ bundle Secret ──────────▶ Distribution server (gRPC, all    │──▶ engines
  WAFIPList      │ Ingress ───┘   (leader only)       (signed, versioned)        replicas serve)                 │
  HTTPRoute      │                                                                                               │
                 │ Status aggregator ◀── ACK/NACK + heartbeats from engines                                      │
                 │ Upstream sync ◀──▶ SaaS (Managed / GitOps modes, leader only)                                 │
                 │ Admission webhooks: validate CRDs (compile SecLang), inject sidecar, reject edits in Managed  │
                 └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

Tooling: kubebuilder v4 layout, controller-runtime, server-side apply (SSA) everywhere, CEL
validation in CRDs, `cert-controller` (or cert-manager when present) for webhook certificates.

---

## 3. API (`waf.inkwall.dev/v1alpha1`)

| Kind | Scope | Owner | Purpose |
|---|---|---|---|
| `InkwallConfig` | Cluster (singleton `default`) | platform team | Mode, engine settings, integrations, SaaS connection |
| `WAFPolicy` | Namespace | app team | What to enforce on which routes |
| `WAFRuleSet` / `ClusterWAFRuleSet` | Namespace / Cluster | security / platform | Rules (builtin CRS, SecLang, ConfigMap) |
| `WAFIPList` / `ClusterWAFIPList` | Namespace / Cluster | security / platform | CIDR lists, static or fetched by URL |
| `WAFPolicyDefault` | Namespace | platform team | Default policy applied to every route in a namespace that has no `WAFPolicy` (optional) |

Full examples: 0002 §4.2.

### 3.1 Validation

Validation happens at three levels, cheapest first:

1. **OpenAPI schema + CEL** in the CRD (no webhook needed): enums, ranges
   (`timeout <= 1s`, `body.maxBytes <= 10Mi`), mutual exclusion (`source.builtin` xor
   `source.seclang` xor `source.configMapRef`), `targetRefs` kinds allowed.
2. **Validating webhook** for things CEL can't check:
   - compile SecLang with the same Coraza version the engine uses, and reject parse errors with the
     line number,
   - reject an unknown `builtin` rule set,
   - in `Managed` mode, reject create/update/delete of policy CRDs not made by the operator itself.
   The webhook has a 2 s timeout and `failurePolicy: Fail` for WAF CRDs only (a bad rule must not
   slip in because the webhook was briefly down; users retry).
3. **Resolver** (async, reported in status): references that exist at admission time but not later,
   conflicts between policies, targets served by a controller Inkwall can't wire.

### 3.2 Status contract

Every `WAFPolicy` carries these conditions (kstatus-compatible, so `kubectl wait` and Argo CD
health checks work):

| Condition | True when | Typical False reasons |
|---|---|---|
| `Accepted` | Spec is valid and references resolve | `InvalidRef`, `Conflict`, `RuleCompileError` |
| `Programmed` | Every targeted route's proxy has Inkwall wired | `ControllerUnsupported`, `SidecarMissing`, `WiringFailed`, `PendingRestart` |
| `Enforced` | Every engine serving the targets ACKed a bundle containing this generation | `EnginesBehind` (with `3/6` in message), `EngineNack` |
| `Ready` | All three above are True | — |

Also in status: `bundleVersion`, `observedGeneration`, and a per-target list:

```yaml
status:
  targets:
  - ref: {kind: HTTPRoute, name: shop-api}
    controller: envoy-gateway
    gateway: infra/public
    programmed: true
    engines: {ready: 3, total: 3}
```

`InkwallConfig.status` holds the cluster view: discovered integrations, engine count per
integration, bundle version per engine (aggregated counts, not a list of pods), SaaS connection
state.

---

## 4. Controllers

All controllers are idempotent level-triggered reconcilers. Objects the operator creates carry the
label `app.kubernetes.io/managed-by: inkwall-operator` and, where namespacing allows, an owner
reference to the policy or `InkwallConfig` that caused them, so garbage collection cleans up.

### 4.1 Discovery controller

Watches `IngressClass`, `GatewayClass`, and workloads with well-known labels.

1. For each `IngressClass.spec.controller` / `GatewayClass.spec.controllerName`, look up the
   integration in a **built-in registry** (controller-name → integration). Known entries cover
   ingress-nginx, Traefik (Ingress and Gateway API), Envoy Gateway, Istio, Contour, HAProxy
   (both controllers) and Caddy. Exact controller-name strings live in code with a test per
   controller version in the e2e matrix.
2. Find the data-plane workloads for that class: for Ingress controllers, the Deployment/DaemonSet
   matched by `InkwallConfig.spec.integrations[].selector` or the default label selector for that
   controller; for Gateway API, the proxy workloads created per `Gateway` (e.g. Envoy Gateway creates
   one Envoy Deployment per Gateway).
3. Produce an `IntegrationInstance`:

```go
type IntegrationInstance struct {
    Integration  string              // "ingress-nginx", "envoy-gateway", ...
    ClassName    string              // IngressClass or GatewayClass name
    Gateways     []types.NamespacedName  // Gateway API only
    Workloads    []WorkloadRef       // pods that must run the engine
    Adapter      AdapterKind         // ExtProc | ExtAuthz | LuaPlugin | AuthURL | ForwardAuth | SPOE | Module
    Version      string              // controller version, from image tag or labels
    Supported    SupportLevel        // Full | Partial (e.g. no body) | Unsupported
}
```

4. Write the result to `InkwallConfig.status.integrations`. Unknown controllers are listed as
   `Unsupported` so users see them instead of silently getting no protection.

### 4.2 Integration interface

Every proxy is a Go implementation of one interface. Adding a proxy means adding one package under
`operator/integrations/<name>/`, with no changes to controllers.

```go
type Integration interface {
    Name() string
    // Match reports whether this integration handles a controller name.
    Match(controllerName string) bool
    // Discover finds workloads and versions for a class.
    Discover(ctx context.Context, c client.Reader, class ClassRef) (*IntegrationInstance, error)
    // Injection describes how the engine sidecar gets into the proxy pods.
    Injection(inst *IntegrationInstance, cfg *v1alpha1.InkwallConfig) (InjectionPlan, error)
    // Render returns the desired proxy-side objects for the policies that target this instance.
    // It must be pure: same inputs → same objects (golden-file tested).
    Render(inst *IntegrationInstance, policies []ResolvedPolicy, cfg *v1alpha1.InkwallConfig) ([]client.Object, error)
    // Health reads proxy state to confirm the wiring is live (e.g. Envoy Gateway policy status).
    Health(ctx context.Context, c client.Reader, inst *IntegrationInstance) (Programmed, error)
}
```

### 4.3 Injection controller

Gets the engine into the proxy pods as a sidecar sharing a socket directory.

**Strategy order: native extension point first, Pod webhook as fallback.** Patching the ingress
controller's Deployment directly is avoided because Helm / Argo CD would revert it on their next
sync (drift fight).

| Integration | Mechanism |
|---|---|
| Envoy Gateway | `EnvoyProxy` resource: deployment patch adding the sidecar + volume, referenced from the `GatewayClass` / `Gateway` `parametersRef` |
| Istio gateways | Pod webhook (gateway pods are injected by Istio itself; Inkwall adds its container on top) |
| ingress-nginx, Traefik, HAProxy | Pod webhook on pods matching the integration selector |
| Caddy | Not needed: the engine is compiled in (module) |
| Any, user preference | `injection: Manual`: the operator prints the exact Helm values for the controller's chart (`extraContainers`, `extraVolumes`) and only verifies |

**Pod webhook details:**

- `MutatingWebhookConfiguration` scoped by `objectSelector` on the controller's **own**
  well-known labels plus a `namespaceSelector` (the operator can't add its own labels to pod
  templates without patching the Deployment, which is what we avoid). The webhook then checks the
  pod's owner against discovery results before mutating, and ignores everything else.
- The engine is added as a **native sidecar** (`initContainers` with `restartPolicy: Always`,
  Kubernetes ≥ 1.29): it starts and becomes ready **before** the proxy container and stops **after**
  it, so there is no window where the proxy runs without its engine at startup or shutdown.
- `failurePolicy` follows the enforcement mode of the policies a controller serves. **Detect only:**
  `Ignore` — if the operator is down, ingress pods still start without the engine (uninspected) and
  the Injection controller reports `SidecarMissing`. **Any policy in block mode:** `Fail` — a pod
  started without its engine would have its proxy hook fail closed and reject all traffic, so pod
  creation is refused instead; existing pods keep serving while the operator is down.
- Adds: the engine container, an `emptyDir` at `/var/run/inkwall`, a projected ServiceAccount token
  (audience `inkwall-operator`) for bundle stream auth, the operator's CA bundle (to verify the
  distribution server's TLS), and the bundle-signing public key.
- The sidecar runs with the **ingress controller's** ServiceAccount (it shares the pod). For
  cold-start reads of the bundle Secret (§4.6), the operator creates a `Role` + `RoleBinding` in
  `inkwall-system` granting that ServiceAccount `get` on the `inkwall-bundle` Secret only.

**Rollout:** injection only takes effect when pods are recreated. By default
(`rollout: Manual`) the operator sets `Programmed=False, reason=PendingRestart` and tells the user
which workload to restart. With `rollout: Automatic`, it triggers a rolling restart
(`kubectl rollout restart`-style annotation on the pod template, reported as a deliberate,
opt-in drift) and respects PodDisruptionBudgets.

**Engine upgrades** follow the same path: a new engine image marks instances `EngineOutdated` and
restarts only on opt-in.

### 4.4 Wiring controller

Renders and applies the proxy-side objects that send traffic to the engine.

**Principle: hook globally once, decide per route locally.** The engine already knows which routes
have which policy (bundle router), so the proxy-side hook can usually be global, touching very few
objects. For performance (0001), unprotected routes must still pay ~nothing, so each integration
either attaches per route natively or does a local skip check inside the proxy:

| Integration | Objects the operator writes | Per-route cost for unprotected routes |
|---|---|---|
| Envoy Gateway | `Backend` (unix socket) + `EnvoyExtensionPolicy` per protected `HTTPRoute` (operator-owned, in the route's namespace) | 0: filter only attached to protected routes |
| Istio | `EnvoyFilter` scoped to the gateway workload, with route-level config | ~0: per-route disable config |
| ingress-nginx | Lua plugin `ConfigMap` + `plugins` key in the controller ConfigMap | ~0: plugin checks a per-worker route set in memory, no socket call |
| Traefik | `Middleware` per namespace (operator-owned) + attachment to protected routes | 0 when attached per route |
| HAProxy | SPOE config + a map file of protected hosts/paths used in an ACL before `send-spoe-group` | ~0: map lookup |
| Caddy | nothing (bundle delivered to the module) | 0 |

Prerequisite: the Envoy Gateway `Backend` resource (used for the unix socket) must be enabled in
the Envoy Gateway configuration; Discovery checks this and reports `WiringFailed` with the fix if
it isn't.

**Touching user-owned objects** is unavoidable in three places:

1. **Envoy Gateway `EnvoyProxy`.** When the user's `GatewayClass` / `Gateway` already references
   their own `EnvoyProxy`, the sidecar patch must be added to that object (SSA, owning only the
   patch entry it adds). When none is referenced, the operator creates its own and references it,
   which also edits the `GatewayClass`/`Gateway` `parametersRef`; in that case `injection: Manual`
   instructions are offered as the alternative.
2. **ingress-nginx controller ConfigMap `plugins` key.** Applied with SSA, owning only
   `data.plugins`. If the user already has plugins, the operator merges its name into the
   comma-separated list and records the original value in an annotation for uninstall.
3. **Traefik route attachment** for Ingress objects
   (`traefik.ingress.kubernetes.io/router.middlewares`). Options, in order of preference:
   - Traefik `IngressRoute`/Gateway API `HTTPRoute`: attach via operator-owned objects where the
     API allows (Gateway API `ExtensionRef` filter needs a route edit, so same issue),
   - a mutating webhook on `Ingress` that adds the annotation at admission (GitOps tools doing
     three-way diffs don't flag fields absent from Git),
   - or an entry-point-level middleware configured once through Traefik's Helm values
     (`injection: Manual` style instructions), with the engine skipping unprotected routes.

Every field the operator writes on a non-operator object is listed in `docs/gitops.md` with
ready-to-paste Argo CD `ignoreDifferences` and Flux equivalents.

**Apply semantics:**

- Server-side apply, field manager `inkwall-operator`, `force: true` only on objects the operator
  created.
- Desired-state diffing: objects that the renderer no longer returns and that carry the
  managed-by label are deleted (prune).
- Renderers are pure functions and are golden-file tested per controller version.

### 4.5 Resolver

Turns the policy CRDs plus Kubernetes routing objects into `ResolvedPolicy` values: concrete
`(host, pathMatch, method)` sets, as the engine only understands host/path/method (0002 D6).

1. For each `WAFPolicy.targetRefs`, read the `Ingress` / `HTTPRoute` and expand its rules into
   `RouteMatch` entries: hosts × paths (prefix / exact / regex where the controller supports it).
2. For `HTTPRoute`, also resolve the parent `Gateway` listeners to know which integration
   instances serve it (a route can attach to several Gateways served by different controllers:
   each one gets wired).
3. Apply precedence (most specific target wins, 0002 §4.2). Equal specificity → both policies get
   `Accepted=False, reason=Conflict`, and the previous bundle stays in effect for those routes.
4. Merge `WAFPolicyDefault` for unprotected routes in namespaces that have one.
5. Resolve rule set and IP list references (cross-namespace references require the target to allow
   it, similar to Gateway API `ReferenceGrant`).

Watches: routes and Gateways changes re-trigger resolution for the policies that target them
(index by target).

### 4.6 Bundle builder (leader only)

1. Debounce changes (default 1 s) so a GitOps sync of 200 objects produces one bundle, not 200.
2. Build the `Bundle` proto (0002 §4.3) from all `ResolvedPolicy` values, rule sets (builtin
   rules are referenced by name + version, not embedded), and IP lists.
3. Compute a content hash. If it equals the current bundle's hash, stop (no version bump).
4. Bump `version` (monotonic). The current version is stored in the bundle object itself, so a new
   leader continues the sequence instead of restarting at 1.
5. Sign with the cluster's ed25519 key (a Secret generated at install; the public key is mounted
   into engines by the injection step).
6. Write the bundle to a `Secret` (`inkwall-bundle`, compressed). Secrets and ConfigMaps are limited
   to 1 MiB; if the compressed bundle exceeds ~900 KiB it is split into numbered chunks with a
   manifest. Most bundles are far below this because CRS is referenced, not embedded.

The bundle object doubles as the **cold-start source**: an engine that can't reach the operator
loads it from the Kubernetes API (read-only RBAC on that one object) or from its on-disk cache.

### 4.7 Distribution server (all replicas)

- gRPC `BundleService.Watch` (0002 §5.2) exposed through a ClusterIP Service `inkwall-operator:9443`.
- **Every replica** serves streams: each watches the bundle Secret and pushes new versions to its
  connected engines. Only building is leader-only. A replica failure just makes its engines
  reconnect to the other replica.
- Engine authentication: the engine presents its projected ServiceAccount token; the operator
  validates it with `TokenReview` (cached) and checks the pod belongs to a discovered integration.
  Transport is TLS with the webhook serving certificate.
- Push fan-out is bounded (e.g. 50 concurrent sends) so a new bundle to 500 engines doesn't spike
  the operator.
- Engines report ACK/NACK and heartbeats; the replica aggregates counts in memory and the leader
  merges them (via a small aggregation endpoint between replicas, or through a status ConfigMap
  written at most every few seconds).

### 4.8 Status aggregator

Combines resolver results, wiring health, and engine ACKs into the conditions of §3.2. Writes are
rate-limited (at most one status update per object per 2 s) to avoid API server churn at scale.

Metrics: `inkwall_operator_bundle_version`, `inkwall_operator_engines{integration,state}`,
`inkwall_operator_reconcile_duration_seconds{controller}`,
`inkwall_operator_policies{condition,status}`, `inkwall_operator_bundle_bytes`.

### 4.9 Upstream sync (leader only)

- `Standalone`: disabled.
- `GitOps`: pushes a snapshot of CRDs, discovered integrations, and aggregate status to the SaaS;
  forwards event batches. Never writes CRDs.
- `Managed`: receives bundles and policy objects from the SaaS, writes them as CRDs labeled
  `inkwall.dev/source: saas` (so `kubectl get wafpolicy` still shows the truth), and the validating
  webhook rejects edits from anyone else.

Enrollment and certificate rotation: 0002 §7.5.

---

## 5. Uninstall and disable

Removal must never leave a proxy pointing at a missing engine with fail-closed behaviour.

1. `WAFPolicy` deleted → finalizer `waf.inkwall.dev/unwire` runs: remove its routes from the next
   bundle, remove its per-route wiring, then release the finalizer.
2. `InkwallConfig` deleted (or `helm uninstall`, via a pre-delete hook job) →
   1. push a bundle with every policy in allow-all mode,
   2. remove all wiring objects and restore recorded values (`plugins` key, annotations),
   3. wait for proxies to reload (integration `Health` reports unwired),
   4. remove the webhook configurations, so new pods start without the sidecar,
   5. existing pods keep an idle sidecar until their next restart; that is harmless because nothing
      calls it.
3. Emergency switch: `InkwallConfig.spec.suspend: true` pushes an allow-all bundle to all engines
   within seconds without removing anything.

---

## 6. Failure modes

| Failure | Effect on traffic | Detection | Recovery |
|---|---|---|---|
| Operator down (both replicas) | None: engines keep last bundle | Engines' `bundle_age_seconds` grows; operator absent | Restart; engines reconnect and resync |
| Leader down, follower up | None | Leader election | Follower takes over building within the lease duration (~15 s) |
| Webhook down, ingress pod restarts | Detect mode: pod starts **without** engine (uninspected). Block mode: pod creation is refused; existing pods keep serving | `SidecarMissing` condition, alert | Restart pod after operator recovers |
| Invalid rule committed | Rejected at admission | Webhook error returned to `kubectl` / Argo CD sync | Fix the rule |
| Rule valid at admission, engine can't compile (version skew) | Engine keeps previous bundle | NACK → `Enforced=False, reason=EngineNack` | Upgrade engines or fix the rule |
| Bundle Secret deleted | None | Builder recreates it on next reconcile | Automatic |
| Signing key rotated | None | New public key rolled out before first bundle signed with it (engines accept both during overlap) | Automatic |
| Controller upgraded to an unknown version | Wiring may break | Integration `Health` fails, `Programmed=False` | Integration update / pin |
| API server unavailable | None | — | Automatic |

---

## 7. RBAC

Least privilege, split by concern (one `ClusterRole` per controller, aggregated in the Helm chart):

| Resources | Verbs | Why |
|---|---|---|
| `waf.inkwall.dev/*` | get, list, watch, update (status), patch (finalizers) | Own CRDs |
| `ingressclasses`, `gatewayclasses`, `gateways`, `httproutes`, `ingresses` | get, list, watch | Discovery and resolution |
| `ingresses` | patch (annotations only, Traefik fallback) | Opt-in; disabled unless that integration needs it |
| `deployments`, `daemonsets`, `pods` | get, list, watch | Discovery, injection verification |
| `deployments`, `daemonsets` | patch (pod template restart annotation only) | Only with `rollout: Automatic`; omitted otherwise |
| `roles`, `rolebindings` | create, update in `inkwall-system` | Grant ingress ServiceAccounts `get` on the bundle Secret (§4.3) |
| `pods` (webhook) | — (webhooks need no RBAC) | Injection |
| `envoyextensionpolicies`, `backends`, `envoyproxies` (gateway.envoyproxy.io) | full on objects it creates | Envoy Gateway wiring |
| `envoyfilters` (networking.istio.io) | full on objects it creates | Istio wiring |
| `middlewares` (traefik.io) | full on objects it creates | Traefik wiring |
| `configmaps` | full in `inkwall-system`; get + patch on the specific controller ConfigMaps discovered | Plugin / SPOE config |
| `secrets` | full in `inkwall-system` only | Bundle, signing key, certs |
| `tokenreviews` | create | Engine authentication |
| `leases` | full in `inkwall-system` | Leader election |
| `events` | create, patch | User-visible events |

Rules for resources of integrations that aren't installed are omitted by the Helm chart when the
CRDs are absent at install time (rendered from `.Capabilities.APIVersions`).

---

## 8. Scale targets (v1)

| Dimension | Target |
|---|---|
| `WAFPolicy` objects | 5,000 |
| Routes resolved | 50,000 |
| Engines per cluster | 500 |
| Policy change → enforced on all engines (p95) | < 10 s |
| Operator memory at max scale | < 512 MiB |
| Bundle size at max scale (compressed) | < 900 KiB, or chunked |

Verified with a kind-based scale test using fake engines (a lightweight client that speaks the
bundle protocol and ACKs) so 500 "engines" fit on a laptop.

---

## 9. Testing

| Level | Tool | Covers |
|---|---|---|
| Unit | `go test` | Resolver precedence, bundle hashing/versioning, conflict detection |
| Golden files | `go test` with `testdata/` | Every `Integration.Render` output per controller version; review diffs in PRs |
| Controller | `envtest` (real API server, no kubelet) | Reconcile loops, finalizers, status conditions, SSA field ownership, webhook validation |
| E2E | kind + e2e-framework, matrix per controller | Discovery → injection → wiring → attack blocked → status `Ready`; uninstall leaves no traces and no errors |
| Chaos | kind | Kill operator / leader mid-rollout; delete bundle Secret; webhook down during ingress restart |
| Scale | kind + fake engines | §8 targets |
| Upgrade | kind | Operator N-1 → N and CRD version conversion with traffic flowing |

---

## 10. Code layout

```
operator/
├── api/v1alpha1/               # CRD types, kubebuilder markers, CEL rules
├── cmd/                        # (main in cmd/operator at repo root)
├── internal/
│   ├── discovery/
│   ├── injection/              # webhook + native patch strategies
│   ├── wiring/
│   ├── resolver/
│   ├── bundle/                 # builder, signer, store (Secret chunking)
│   ├── distribution/           # gRPC BundleService server, auth
│   ├── status/
│   └── upstream/               # SaaS sync
├── integrations/
│   ├── registry.go
│   ├── envoygateway/
│   ├── istio/
│   ├── ingressnginx/
│   ├── traefik/
│   ├── haproxy/
│   └── caddy/
├── webhook/                    # validating + mutating handlers
├── config/                     # kustomize bases generated by kubebuilder (CRDs, RBAC, webhooks)
└── test/
    ├── envtest/
    └── fakeengine/
```

The Helm chart in `deploy/helm/inkwall` is the supported install; kustomize bases are for
development.

---

## 11. Milestones

| # | Milestone | Exit criteria |
|---|---|---|
| O1 | Scaffold + CRDs + validation | `kubebuilder` project, CRDs with CEL, validating webhook compiles SecLang, envtest green |
| O2 | Resolver + bundle builder + distribution | Engine in standalone Deployment receives signed bundles; `Enforced` condition works |
| O3 | Envoy Gateway integration | End-to-end on kind: one `WAFPolicy`, attack blocked, `Ready=True` |
| O4 | Pod-webhook injection + ingress-nginx, Traefik, HAProxy | Same attack blocked through all four controllers in one cluster |
| O5 | Uninstall, suspend, chaos, scale tests | §5 and §6 verified in CI |
| O6 | Upstream sync (GitOps, Managed) | Cluster enrolls with a SaaS stub; policy round-trip |

## 12. Open questions

1. Minimum Kubernetes version: native sidecars need ≥ 1.29 (GA in 1.33). Support older clusters
   with a regular sidecar and a documented startup race, or require ≥ 1.29?
2. Traefik attachment for plain `Ingress`: Ingress mutating webhook vs entry-point middleware as
   the default?
3. Should the operator also manage **standalone** engine Deployments (for controllers where
   injection is impossible), or leave that to Helm values?
4. Aggregation between operator replicas: direct gRPC between replicas vs status ConfigMap?
