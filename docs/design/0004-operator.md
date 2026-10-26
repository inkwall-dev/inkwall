# 0004 — Kubernetes Operator

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin
- Depends on: [0001](0001-performance-first-architecture.md), [0002](0002-system-architecture.md)

The operator injects the engine next to each proxy, wires the proxy to it, and pushes signed policy
bundles. CRD shapes: 0002 §4.2.

**Built (v0.1.0):** Traefik with `Ingress` targets (ForwardAuth). **Not yet:** other proxies,
`HTTPRoute` / `IngressRoute` targets, ordered uninstall (O5), GitOps/Managed modes.

## 1. Goals and non-goals

1. **No proxy knowledge for users:** they write a `WAFPolicy` against an `Ingress` or `HTTPRoute`.
2. **Never on the request path:** operator downtime never affects traffic (0002 §2).
3. **GitOps-friendly:** avoid mutating user-owned objects; when unavoidable, touch the fewest
   fields and document how to ignore them.
4. **Safe by default:** in detect mode any step can fail without dropping traffic; in block mode
   nothing passes uninspected, so failures show as rejected requests and conditions, not silent
   gaps. Uninstall reverses every change.
5. **Observable:** each policy reports accepted → programmed → enforced.

Non-goals: installing ingress controllers; managing TLS, DNS or routes; unasked restarts.

## 2. Overview

One Deployment, 2 replicas. Discovery feeds **Injection** (sidecar) and **Wiring** (proxy
objects). **Resolver** → **Bundle builder** (leader) → signed bundle Secret → **Distribution**
(gRPC, every replica) → engines, whose ACKs feed the **Status aggregator**. **Upstream sync** talks
to the SaaS. **Admission webhooks** validate CRDs and inject the sidecar.

Tooling: kubebuilder v4 layout, controller-runtime, server-side apply, CEL in CRDs, cert-controller
(or cert-manager) for webhook certificates.

## 3. API (`waf.inkwall.dev/v1alpha1`)

| Kind | Scope | Purpose |
|---|---|---|
| `InkwallConfig` | Cluster, singleton `default` | Mode, engine, integrations, SaaS, `suspend` |
| `WAFPolicy` | Namespace | What to enforce on which routes |
| `WAFRuleSet` / `ClusterWAFRuleSet` | Namespace / Cluster | Rules: builtin CRS, SecLang, ConfigMap |
| `WAFIPList` / `ClusterWAFIPList` | Namespace / Cluster | CIDR lists (planned) |
| `WAFPolicyDefault` | Namespace | Default for routes with no policy (planned) |

A field is added only once the engine honours it: adding to `v1alpha1` later is compatible,
removing is not. **Not yet:** IP lists and `spec.ipLists`, `spec.rateLimits`, `spec.response`,
`BlockHighConfidence`, `body.contentTypes`, the `InspectPrefix` oversize action,
`InkwallConfig.spec.events`, `WAFPolicyDefault`.

### 3.1 Validation

Cheapest first:

1. **Schema + CEL:** enums, ranges (`timeout <= 1s`, `body.maxBytes <= 10Mi`), exactly one rule
   source, allowed `targetRefs` kinds.
2. **Validating webhook** (2 s timeout, `failurePolicy: Fail` for WAF CRDs only, so a bad rule
   can't slip in while it is down):
   - compiles SecLang with the engine's Coraza, after CRS, and returns the failing line; rejects
     unknown `builtin` sets;
   - allows only rule directives (`SecRule`, `SecAction`, `SecMarker`, `SecRuleRemoveBy*`,
     `SecRuleUpdate*`): engine-wide settings and file writes (`SecRuleEngine`, body limits,
     `SecAuditLog`, `SecDebugLog`, `Include`) stay Inkwall's, since app teams write rule sets;
   - accepts updates that leave the spec unchanged, so objects a newer engine rejects stay deletable;
   - certificate self-signed and rotated by the operator, CA injected; cert-manager optional.
   - Not yet: rejecting non-operator edits in `Managed` mode (§4.9).
3. **Resolver** (async, in status): dangling references, conflicts, unwirable targets.

### 3.2 Status contract

`WAFPolicy` conditions (kstatus-compatible, for `kubectl wait` and Argo CD health):

| Condition | True when | False reasons |
|---|---|---|
| `Accepted` | Spec valid, references resolve | `InvalidRef`, `Conflict`, `RuleCompileError` |
| `Programmed` | Every target's proxy is wired | `ControllerUnsupported`, `SidecarMissing`, `WiringFailed`, `PendingRestart`, `NoTargets` |
| `Enforced` | Every serving engine ACKed a bundle with this generation | `EnginesBehind` (`3/6`), `EngineNack`, `NoEngines`, `NotInBundle` |
| `Ready` | The three above are True | first failing condition's reason |

Status also has `bundleVersion` and `observedGeneration`. **Not yet:** per-target status
(`targets[]` with controller, gateway, programmed, engine counts) and the `InkwallConfig.status`
cluster view (integrations, engine counts, bundle versions, SaaS state); it has only
`observedGeneration` and `conditions` today.

## 4. Controllers

Idempotent, level-triggered reconcilers. Created objects carry
`app.kubernetes.io/managed-by: inkwall-operator` and, where namespacing allows, an owner reference
for garbage collection.

### 4.1 Discovery controller

Planned: watch `IngressClass` / `GatewayClass`, map controller names to integrations (registry
tested per controller version), find their data-plane workloads, and list them in
`InkwallConfig.status` as `Full | Partial | Unsupported`, so unknown controllers are visible rather
than silently unprotected.

**Built:** no controller. [`operator/integrations`](../../operator/integrations/integrations.go)
lists Traefik only (controller `traefik.io/ingress-controller`, pods `app.kubernetes.io/name=traefik`,
adapter `forward-auth`).

### 4.2 Integration interface

Planned: one package per proxy under `operator/integrations/<name>/` implementing `Name`, `Match`,
`Discover`, `Injection`, `Render` (pure, golden-file tested) and `Health`, so adding a proxy changes
no controller. **Built:** a plain `Integration` struct; injection and wiring are Traefik-specific.

### 4.3 Injection controller

Puts the engine into proxy pods as a sidecar sharing a socket directory.

- **Native extension point first** (Envoy Gateway `EnvoyProxy`; Caddy compiles the engine in),
  **Pod webhook otherwise** (Istio, ingress-nginx, Traefik, HAProxy), or `injection: Manual`
  (operator prints Helm values and only verifies). Never patch the controller's Deployment:
  Helm / Argo CD would revert it.
- **Native sidecar** (`restartPolicy: Always` init container, Kubernetes ≥ 1.29): starts before and
  stops after the proxy, so the proxy never runs without it.
- **`failurePolicy` follows the mode:** `Ignore` when all policies detect (pods start uninspected,
  `SidecarMissing`); `Fail` when any blocks, since a pod without its engine would reject all
  traffic. Existing pods keep serving.
- **The sidecar uses the proxy's ServiceAccount**, which gets `get` on the bundle Secret only, for
  cold start (§4.6).
- **Rollout:** injection applies to new pods only. `rollout: Manual` (default) reports
  `PendingRestart` naming the workload; `rollout: Automatic` would restart it respecting PDBs.
  Engine upgrades follow the same path.

**Built (v0.1.0)** (`operator/internal/injection`, `operator/webhook/inject.go`):

- Webhook `inkwall-operator-mutating` sees only Traefik pods (`app.kubernetes.io/name=traefik`) at
  creation. Installed `Ignore`; the leader sets `Fail` while any policy blocks and re-applies it
  after a Helm upgrade, patching with the `resourceVersion` so it never overwrites a fresh CA bundle.
  If `InkwallConfig` can't be read, the engine is injected with defaults, not left out.
- Opt-out: the label `waf.inkwall.dev/inject: "false"` is excluded by `objectSelector`, so those
  pods start even while the webhook fails closed and the operator is down (the way to scale the
  proxy before it returns). The same-named annotation works only while the webhook answers. Pods
  with an `inkwall-engine` container are left alone.
- `InkwallConfig.spec.integrations[].selector` (non-empty) replaces Traefik's label everywhere
  (pod cache, webhook, controllers, `objectSelector`). Read at startup; on change each replica
  restarts after a random delay up to 30 s. Selectors for unknown controllers are logged and ignored.
- Injected: engine as first init container, startup probe (proxy starts once it serves),
  `forward-auth` in bundle mode, projected token (audience `inkwall-operator`) and trust ConfigMap
  in one read-only directory, `emptyDir` bundle cache, non-root, read-only root filesystem. Image
  and resources from `InkwallConfig.spec.engine`, else `--engine-image`.
- The leader keeps an `inkwall-trust` ConfigMap (`ca.crt`, `ed25519.pub`) in each namespace with
  proxy pods (removed with the last one), and a `Role` + `RoleBinding` `inkwall-bundle-reader` for
  each proxy ServiceAccount. It deletes only ConfigMaps it labeled.
- **Not yet:** `rollout: Automatic`; pods running before the operator are injected on restart.

### 4.4 Wiring controller

**Hook globally once, decide per route locally:** the engine's router knows which routes have a
policy, so the proxy hook touches few objects, and unprotected routes cost ~0 (0001) by per-route
attachment or a local skip check.

| Proxy | Operator writes | Unprotected-route cost |
|---|---|---|
| Envoy Gateway | `Backend` (unix socket) + `EnvoyExtensionPolicy` per protected `HTTPRoute` | 0 |
| Istio | gateway-scoped `EnvoyFilter` | ~0 (per-route disable) |
| ingress-nginx | Lua plugin ConfigMap + `plugins` key | ~0 (in-memory route set) |
| Traefik | `Middleware` per namespace, attached to protected routes | 0 |
| HAProxy | SPOE config + map of protected routes in an ACL | ~0 (map lookup) |
| Caddy | nothing | 0 |

User-owned objects touched (minimum fields, SSA): Envoy Gateway `EnvoyProxy` (sidecar patch, or an
operator-made one plus `parametersRef`); ingress-nginx `data.plugins` (merged, original saved for
uninstall); Traefik's `router.middlewares` annotation on `Ingress`. Every such field is to be listed
in `docs/gitops.md` with Argo CD / Flux ignore rules.

Apply: field manager `inkwall-operator`, `force` only on own objects, prune managed-by objects no
longer rendered.

**Built (v0.1.0)** (`operator/internal/wiring`, Traefik):

- Each targeted Ingress Traefik serves (by `ingressClassName`, legacy `kubernetes.io/ingress.class`
  or the default class) is wired, accepted or not; until its rules are in a bundle the engine
  passes its routes (`no-policy`).
- One ForwardAuth `Middleware` `inkwall-waf` per such namespace (`trustForwardHeader: false`,
  `forwardBody: true`, `maxBodySize` 10 MiB = largest `body.maxBytes`), removed when unused. A
  same-named one the operator didn't create is left alone (`WiringFailed`).
- The annotation gets the operator's Middleware first, user entries kept in order;
  `waf.inkwall.dev/wired` records it; unprotecting removes only that entry. Level-based, no
  finalizers.
- `Programmed=True` when all the policy's Traefik Ingresses are wired and every running Traefik pod
  has the engine. Else `ControllerUnsupported` (other controller or kind), `WiringFailed` (no
  Traefik CRDs, name clash), `PendingRestart` (pods older than the webhook, listed),
  `SidecarMissing` (no Traefik pod, or pods without the engine: operator down in detect mode or
  opted out, listed), `NoTargets`.
- **Not yet:** `IngressRoute` / `HTTPRoute` targets, `docs/gitops.md`, matching engines to the pods
  serving a policy's class (all engines count for `Enforced`). Traefik attachment default is open
  (§12).

### 4.5 Resolver

Turns policies and routes into `(host, pathMatch, method)` sets, all the engine matches on (0002
D6): expand hosts × paths; for `HTTPRoute`, wire every Gateway's integration; most specific target
wins (0002 §4.2); apply `WAFPolicyDefault`; resolve rule set and IP list references. Re-runs when a
targeted route changes (indexed by target).

**Built (v0.1.0)** (`operator/internal/resolver`, Ingress):

- **Conflicts:** the oldest policy (creation time, then name) wins, others get `Conflict`, as in
  Gateway API; rejecting both would leave the route unprotected. Identical routes from two Ingresses
  go to the older policy too.
- **Errors fall back:** an unresolvable policy keeps its version in the current bundle, so a bad edit
  never weakens protection; a never-resolved one is left out. A missing target is not an error.
- ConfigMap rules come only from ConfigMaps labeled `waf.inkwall.dev/rules=true` (smaller cache).
- `ImplementationSpecific` paths are prefixes (as Traefik and ingress-nginx do). A default backend
  is covered only for an Ingress without rules.
- Cross-namespace `WAFRuleSet` references are rejected until a grant exists; use `ClusterWAFRuleSet`.

### 4.6 Bundle builder (leader only)

1. Debounce 1 s, so a 200-object GitOps sync makes one bundle.
2. Build the `Bundle` proto (0002 §4.3); builtin rules referenced by name + version, not embedded.
3. Same content hash as the current bundle → stop.
4. Bump the monotonic version, continued from the stored bundle across leader changes.
5. Sign with the cluster ed25519 key.
6. Store gzipped in Secret `inkwall-bundle`, which is also the engines' cold-start source.

**Built (v0.1.0)** (`operator/internal/bundle`, `pkg/agent`):

- The Secret holds the `SignedBundle` and public key; the key is generated on first use into
  `inkwall-bundle-signing-key`.
- The hash skips version and creation time. The version continues from the Secret, or the leader's
  memory if it was deleted. Cluster ID = `kube-system` Namespace UID.
- Engine cold start: on-disk cache, else the Secret (`--bundle-secret`) via a second projected token
  for the API server and `kube-root-ca.crt`; verified like a streamed bundle.
- **Not yet:** chunking (Secrets cap at 1 MiB). A bundle over 900 KiB compressed is not published;
  the current one stays.

### 4.7 Distribution server (all replicas)

gRPC `BundleService.Watch` (0002 §5.2) via Service `inkwall-operator`. Every replica serves streams
from the Secret (only building is leader-only), so losing one just moves its engines.

**Built (v0.1.0)** (`operator/internal/distribution`):

- Port 9445 (`--distribution-port`), TLS with the webhook certificate (also names the Service),
  verified by engines with the operator CA.
- **Auth:** `TokenReview` (audience `inkwall-operator`), then a `SubjectAccessReview` that the
  engine's ServiceAccount may `get` the bundle Secret (§4.3 grant). Cached 1 min.
- First message must be `Hello`; engines already current aren't resent. Streams silent for 30 s
  close. At most 50 concurrent sends.
- **Aggregation via ConfigMaps:** each replica writes its engines to `inkwall-engines-<pod>` (owned
  by its Pod) on change and every 10 s; the leader merges every 2 s, drops reports older than 30 s,
  counts a moved engine once.

### 4.8 Status aggregator

Turns resolver, wiring and ACK results into §3.2 conditions; writes only on change, at most once per
object per 2 s.

**Built (v0.1.0):** `Enforced=True` when every connected engine runs a bundle ≥ the policy's
`status.bundleVersion`; else `NoEngines`, `EnginesBehind` (`1/3 engines on bundle 42`),
`EngineNack` (first error) or `NotInBundle`. Metrics: `inkwall_operator_bundle_version`,
`inkwall_operator_engines{state}`. **Not yet:** `integration` label, reconcile duration, policy
condition counts, bundle bytes.

### 4.9 Upstream sync (leader only)

**Not yet;** only `Standalone`. `GitOps` would push CRD snapshots and status to the SaaS and never
write CRDs. `Managed` would write SaaS policies as CRDs labeled `inkwall.dev/source: saas` and reject
other edits. Enrollment: 0002 §7.5.

## 5. Uninstall and disable

Removal must never leave a proxy failing closed on a missing engine.

**Built (v0.1.0):** `InkwallConfig.spec.suspend: true` puts every engine in allow-all within
seconds, removing nothing. Unprotected Ingresses are unwired level-based (§4.4).

**Not yet (O5):** a `waf.inkwall.dev/unwire` finalizer on `WAFPolicy`; on `InkwallConfig` delete or
`helm uninstall` (pre-delete hook): allow-all bundle → remove wiring and restore saved values →
wait until unwired → remove webhooks. Leftover sidecars stay idle until restart.

## 6. Failure modes

| Failure | Traffic | Detection | Recovery |
|---|---|---|---|
| Operator down | None: engines keep last bundle | `bundle_age_seconds` grows | Restart; engines resync |
| Leader down | None | Leader election | Follower builds within ~15 s |
| Operator rollout | None: stopping replica serves for `--shutdown-delay` (5 s), not ready | — | Engines reconnect |
| Webhook down, proxy pod created | Detect: starts uninspected. Block: refused; running pods serve | `SidecarMissing` | Restart pod after recovery, or label it `waf.inkwall.dev/inject: "false"` to scale (uninspected) |
| Invalid rule | Rejected at admission | Error to `kubectl` / Argo CD | Fix the rule |
| Engine can't compile (skew) | Engine keeps previous bundle | `EngineNack` | Upgrade engines or fix rule |
| Bundle Secret deleted | None | Builder recreates it | Automatic |
| Signing key rotated | None | New key rolled out first; both accepted during overlap | Automatic |
| Unknown controller version | Wiring may break | `Programmed=False` | Update or pin integration |
| API server down | None | — | Automatic |

Runbook: [When the operator is down](../../deploy/helm/inkwall/README.md#when-the-operator-is-down).

## 7. RBAC

Least privilege. Built rules ([`role.yaml`](../../operator/config/rbac/role.yaml)): a `ClusterRole` plus a
`Role` in `inkwall-system`.

| Resources | Verbs | Why |
|---|---|---|
| `waf.inkwall.dev/*` | read; update status | Own CRDs |
| `ingressclasses`, `ingresses`, `pods` | read | Resolution, injection checks |
| `ingresses` | patch | Traefik annotation |
| `middlewares` (traefik.io) | full | Traefik wiring |
| `configmaps` | full, cluster-wide | `inkwall-trust` per namespace, engine reports |
| `secrets` | in `inkwall-system` | Bundle, signing key, certs |
| `roles`, `rolebindings` | in `inkwall-system` | Bundle Secret grant (§4.3) |
| `tokenreviews`, `subjectaccessreviews` | create | Engine auth (§4.7) |
| webhook configurations | patch | `failurePolicy`, CA bundle |
| `namespaces/kube-system` | get | Cluster ID |
| `leases`, `events` | write | Leader election, events |

**Not yet:** one `ClusterRole` per controller, aggregated by the chart, with rules for absent
proxies omitted (`.Capabilities.APIVersions`); Gateway API, Envoy Gateway, Istio and controller-ConfigMap rules;
`deployments` restart patch only with `rollout: Automatic`.

## 8. Scale targets (v1)

| Dimension | Target |
|---|---|
| `WAFPolicy` objects | 5,000 |
| Routes resolved | 50,000 |
| Engines per cluster | 500 |
| Change → enforced everywhere (p95) | < 10 s |
| Operator memory | < 512 MiB |
| Bundle (compressed) | < 900 KiB, or chunked |

To verify on kind with fake engines that speak the bundle protocol.

## 9. Testing

Unit tests (resolver, bundle hashing/versioning, conflicts); golden files for `Render` per
controller version; envtest (`operator/test/testenv`) for reconcilers, conditions, SSA ownership and
webhooks; kind e2e (injection → wiring → attack blocked → `Ready`, clean uninstall). Planned: chaos
(kill leader, delete Secret, webhook down), scale with fake engines (§8), upgrade N-1 → N with
traffic.

## 10. Code layout

```
operator/
├── api/v1alpha1/       # CRD types, CEL rules
├── integrations/       # known proxies (Traefik)
├── internal/
│   ├── bundle/         # builder, signer
│   ├── controller/     # reconcilers
│   ├── distribution/   # BundleService server, auth, status
│   ├── injection/
│   ├── resolver/
│   └── wiring/
├── manager/
├── webhook/            # validating + mutating handlers
├── config/             # kubebuilder kustomize bases
└── test/               # testenv, fakeengine
```

`main` is in `cmd/operator`. Planned: `internal/discovery`, `internal/upstream`, one package per
proxy under `integrations/`. The Helm chart `deploy/helm/inkwall` is the supported install;
kustomize is for development.

## 11. Milestones

| # | Milestone | Exit criteria |
|---|---|---|
| O1 | Scaffold + CRDs + validation | CRDs with CEL, webhook compiles SecLang, envtest green |
| O2 | Resolver + bundle + distribution | Standalone engine gets signed bundles; `Enforced` works |
| O3 | Envoy Gateway | kind: one `WAFPolicy`, attack blocked, `Ready=True` |
| O4 | Pod webhook + ingress-nginx, Traefik, HAProxy | Same attack blocked via all four in one cluster |
| O5 | Uninstall, suspend, chaos, scale | §5 and §6 verified in CI |
| O6 | Upstream sync | Enroll with a SaaS stub; policy round-trip |

## 12. Open questions

1. Require Kubernetes ≥ 1.29 for native sidecars, or support older clusters with a regular sidecar
   and a documented startup race?
2. Traefik on plain `Ingress`: Ingress mutating webhook (current: operator patches the annotation)
   or an entry-point middleware as default?
3. Manage standalone engine Deployments where injection is impossible, or leave it to Helm?
4. Replica aggregation: gRPC between replicas or ConfigMaps (v0.1.0 uses ConfigMaps)?
