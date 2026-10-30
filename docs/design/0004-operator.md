# 0004 — Kubernetes Operator

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin
- Depends on: [0001](0001-performance-first-architecture.md), [0002](0002-system-architecture.md)

The operator injects the engine next to each proxy, wires the proxy to it, and pushes signed policy
bundles. CRD shapes: 0002 §4.2.

**Built (v0.1.0):** Traefik with `Ingress` targets (ForwardAuth). **Built since:** Traefik
`IngressRoute` targets, the `waf.inkwall.dev/unwire` finalizer and unwiring with injection off
(§5). **Not yet:** other proxies, `HTTPRoute` targets, GitOps/Managed modes.

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
| `InkwallConfig` | Cluster, singleton `default` | Mode, engine, integrations, SaaS, `suspend`, signing key rotation |
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
| `Programmed` | Every target's proxy is wired | `ControllerUnsupported`, `SidecarMissing`, `WiringFailed`, `PendingRestart`, `NoTargets`, `InjectionDisabled` |
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
- The leader keeps an `inkwall-trust` ConfigMap (`ca.crt`; `trusted-keys.pub`, every bundle key
  engines must accept, which the engine reads; `ed25519.pub`, the active key, for older engines) in
  each namespace with proxy pods (removed with the last one), and a `Role` + `RoleBinding`
  `inkwall-bundle-reader` for each proxy ServiceAccount. It deletes only ConfigMaps it labeled.
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
uninstall); Traefik's `router.middlewares` annotation on `Ingress`, and `spec.routes[*].middlewares`
on `IngressRoute`. Every such field is to be listed in `docs/gitops.md` with Argo CD / Flux ignore
rules.

Apply: field manager `inkwall-operator`, `force` only on own objects, prune managed-by objects no
longer rendered.

**Built (v0.1.0)** (`operator/internal/wiring`, Traefik):

- Each targeted Ingress Traefik serves (by `ingressClassName`, legacy `kubernetes.io/ingress.class`
  or the default class), and each targeted `IngressRoute` (`traefik.io/v1alpha1`), is wired,
  accepted or not; until its rules are in a bundle the engine passes its routes (`no-policy`).
- One ForwardAuth `Middleware` `inkwall-waf` per such namespace (`trustForwardHeader: false`,
  `forwardBody: true`, `maxBodySize` 10 MiB = largest `body.maxBytes`, `maxResponseBodySize` 64 KiB
  for the engine's answer; left out on Traefik before v3.7, whose CRD has no such field), removed
  when unused. A
  same-named one the operator didn't create is left alone (`WiringFailed`). The operator doesn't
  configure Traefik's entry points: behind a load balancer the user turns on the PROXY protocol
  there for the client IP ([client IP](../client-ip.md)).
- The annotation gets the operator's Middleware first, user entries kept in order;
  `waf.inkwall.dev/wired` records it; unprotecting removes only that entry. Level-based; the
  `waf.inkwall.dev/unwire` finalizer only makes a policy deleted while the operator is down wait
  for it (§5).
- An IngressRoute gets `{name: inkwall-waf}` first in every route's `middlewares`, the user's kept
  in order, and `waf.inkwall.dev/wired: inkwall-waf`; unprotecting removes the entries naming it in
  the route's namespace (a same-named one elsewhere is the user's), and an emptied list. The
  reference has no namespace: Traefik resolves it in the IngressRoute's, where the Middleware is,
  so it works with `allowCrossNamespace` off (the default).
  `spec.routes` is one list to a merge patch, so the patch carries the `resourceVersion` and a
  conflict retries.
- Wired only while a Traefik pod the webhook selects runs, with injection on: otherwise new
  Traefik pods would get no engine to call, so everything is unwired (`SidecarMissing`, or
  `InjectionDisabled`, §5). A Traefik scaled to 0 is wired again when its first injected pod is
  created, a second after.
- Works without Traefik's CRDs: no wiring, no crash. The leader looks for the IngressRoute CRD every
  30 s and, once installed, the bundle builder and the wiring watch IngressRoutes
  (`operator/internal/crdwatch`); the wiring's resync (1 min) notices a Middleware CRD installed
  later.
- `Programmed=True` when all the policy's Traefik Ingresses and IngressRoutes are wired and every
  running Traefik pod has the engine. Else `ControllerUnsupported` (other controller or kind),
  `WiringFailed` (no Traefik CRDs, name clash, an IngressRoute that can't be written),
  `PendingRestart` (pods older than the webhook, listed), `SidecarMissing` (no Traefik pod
  selected, or pods without the engine: operator down in detect mode or opted out, listed),
  `NoTargets`, `InjectionDisabled`.
- **Not yet:** `HTTPRoute` targets, `docs/gitops.md`, matching engines to the pods serving a
  policy's class (all engines count for `Enforced`), IngressRoutes nested with `parentRefs`. Traefik
  attachment default is open (§12).

### 4.5 Resolver

Turns policies and routes into `(host, pathMatch, method)` sets, all the engine matches on (0002
D6): expand hosts × paths; for `HTTPRoute`, wire every Gateway's integration; most specific target
wins (0002 §4.2); apply `WAFPolicyDefault`; resolve rule set and IP list references. Re-runs when a
targeted route changes (indexed by target).

**Built (v0.1.0)** (`operator/resolver`, Ingress; IngressRoute since):

- **Conflicts:** the oldest policy (creation time, then name) wins, others get `Conflict`, as in
  Gateway API; rejecting both would leave the route unprotected. Identical routes from two Ingresses
  go to the older policy too.
- **Errors fall back:** an unresolvable policy keeps its version in the current bundle, so a bad edit
  never weakens protection; a never-resolved one is left out. A missing target is not an error.
- ConfigMap rules come only from ConfigMaps labeled `waf.inkwall.dev/rules=true` (smaller cache).
- `ImplementationSpecific` paths are prefixes (as Traefik and ingress-nginx do). A default backend
  is covered only for an Ingress without rules.
- An IngressRoute's routes come from each route's `match`: `Host`, `Path` (exact) and `PathPrefix`,
  one string each (`` `…` `` or `"…"`), joined by `&&`, in parentheses or not. No `Host` is any host,
  no path is `/`. Anything else (`||`, `!`, `HostRegexp`, `Method`, `Header`, `Query`, `ClientIP`,
  two Hosts or two paths, several values) is `Accepted=False` (`TargetUnsupported`), naming the
  route (`spec.routes[1]`), its rule and what can't be read; the previous version stays in force.
  Traefik's `PathPrefix` is a string prefix, read element-wise: other paths of a covered host get
  its most general policy in the engine, so none goes uninspected.
- Cross-namespace `WAFRuleSet` references are rejected until a grant exists; use `ClusterWAFRuleSet`.

### 4.6 Bundle builder (leader only)

1. Debounce 1 s, so a 200-object GitOps sync makes one bundle.
2. Build the `Bundle` proto (0002 §4.3); builtin rules referenced by name + version, not embedded.
3. Same content hash as the current bundle → stop.
4. Bump the monotonic version, continued from the stored bundle across leader changes.
5. Sign with the cluster ed25519 key.
6. Store gzipped in Secret `inkwall-bundle`, which is also the engines' cold-start source; split
   into chunk Secrets if it doesn't fit in one.

**Built (v0.1.0)** (`operator/bundle`, `pkg/agent`):

- The Secret holds the `SignedBundle` and public key; the key is generated on first use into
  `inkwall-bundle-signing-key`.
- The hash skips version and creation time. The version continues from the Secret, or the leader's
  memory if it was deleted. Cluster ID = `kube-system` Namespace UID.
- Engine cold start: on-disk cache, else the Secret (`--bundle-secret`) via a second projected token
  for the API server and `kube-root-ca.crt`; verified like a streamed bundle.
- **Chunks** (`pkg/bundlesecret`; Secrets cap at 1 MiB): a bundle up to 900 KiB compressed is
  `bundle.pb.gz` in `inkwall-bundle`, as before, so older engines read it. A larger one is split
  into Secrets of 900 KiB, `inkwall-bundle-a-0`… or `inkwall-bundle-b-0`…, labeled
  `waf.inkwall.dev/bundle-chunk`, and `inkwall-bundle` holds `manifest.json` instead (SHA-256 and
  size of the compressed bundle, chunk names). The chunks are written to the set the current
  manifest doesn't use, then the manifest; chunks it doesn't list are deleted after, at every
  build. A reader never sees a manifest before its chunks, and checks the hash, so one that read
  the manifest just before the next bundle replaced its chunks fails and retries. At most 8 chunks
  (7.2 MiB) and 64 MiB decompressed; over that, a bundle is not published and the current one
  stays. The builder warns when it publishes a bundle over 75% of that;
  `inkwall_operator_bundle_compressed_bytes` is the size each replica serves. A chunk deleted or
  edited makes the builder publish the bundle again, as a new version (with no previous version
  for an unresolvable policy to fall back on). `inkwall-bundle-reader` grants `get` on every chunk
  name, and so must the Role of an engine configured by hand with `--bundle-secret`. The stream
  carries the bundle whole: engines accept messages up to 65 MiB (gRPC's default was 4 MiB).
- **Compatibility:** an engine without chunk support finds no `bundle.pb.gz` in a chunked Secret,
  so it keeps its cache, or waits for the operator; it never applies part of a bundle. Such
  engines also refuse a streamed bundle over 4 MiB decompressed, and keep their last one. An
  operator without chunk support can't read a chunked Secret and builds nothing: before rolling
  back, delete `inkwall-bundle` and its chunks (`-l waf.inkwall.dev/bundle-chunk`); engines accept
  bundles of the restarted version sequence, as they are newer.

**Built: signing key rotation** (`operator/bundle/keyring.go`, `pkg/agent`,
`pkg/bundlekey`). Requested by a new value of the `waf.inkwall.dev/rotate-signing-key` annotation on
the `InkwallConfig` (GitOps-friendly, next to the rest of the cluster's configuration, and no write
access to the operator's Secrets needed), or due after `spec.signingKey.rotationInterval` (≥ 1h).
The keys and the rotation's state live in `inkwall-bundle-signing-key`, so a new leader continues it:

1. **Publishing:** a new key is generated and added to `trusted-keys.pub` (the trust ConfigMaps
   follow); the old key still signs. Engines re-read their key file every 10 s and report the key
   IDs they trust in `Hello` and `Heartbeat`.
2. **Switch** once at least a grace period (1 min, the kubelet's ConfigMap update delay) has passed
   and every connected engine reports the new key; a new leader first waits for the replicas'
   reports (30 s). The current content is signed again with the new key, as a new version, so
   engines cache a bundle the new key signed. The old public key stays trusted.
3. **Retire** the old key once the grace has passed again and every connected engine runs a
   bundle signed with the new key: `trusted-keys.pub` has the one key.

An engine that reports no keys (older than rotation) blocks the switch until it is replaced; the
operator logs the engines it waits for. The phase is the Secret's
`waf.inkwall.dev/rotation-phase` annotation (`Publishing`, `Retiring`); the bundle Secret's
`waf.inkwall.dev/key-id` names the key that signed it. A deleted signing key Secret is recreated
with the keys in the leader's memory. Tested: unit (multi-key verification, reload, the state
machine), envtest (an engine that gets the key late holds the switch; no NACK) and kind (Traefik's
injected engine and a hand-configured one; no NACK, no restart).

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
`inkwall_operator_engines{state}`, `inkwall_operator_bundle_compressed_bytes` (§4.6). **Not yet:**
`integration` label, reconcile duration, policy condition counts.

### 4.9 Upstream sync (leader only)

`GitOps` pushes CRD snapshots and status to the control plane and never writes CRDs. `Managed`
writes its policies as CRDs labeled `inkwall.dev/source: saas` and rejects other edits. Contract:
0002 §5.3, §7.5.

**Built (`operator/internal/controlplane`):** enrollment and the primary stream, leader only, idle in
`Standalone` (the default). The leader reads the token from
`spec.controlPlane.enrollmentSecretRef` (it must be in the operator's namespace, key `token`),
generates an ECDSA P-256 key and enrolls; a retry after a lost response reuses the key. The
certificate and key go in the `inkwall-control-plane-identity` Secret (`kubernetes.io/tls`, plus
`cluster-id`). It then holds the primary stream (Hello, Welcome, heartbeats), renews the certificate
two thirds into its lifetime. `--control-plane-ca` trusts a private CA.
`InkwallConfig` reports `ControlPlaneConnected`: `Connected`, or `EnrollmentTokenMissing`,
`EnrollmentTokenNotInOperatorNamespace`, `EnrollmentTokenRejected` (waits for a new token),
`EnrollFailed`, `CertificateRejected` and `CertificateExpired` (the identity is deleted; waits for a
new token),
`ClusterDisabled` (waits for a configuration change), `Unreachable`, `InvalidEndpoint`.

Tested on kind against a stub control plane (`operator/test/stubcontrolplane`, built on
`operator/test/fakecontrolplane`; never a real one): enroll, connect, heartbeats, state sync,
events, a Managed round trip (a policy sent through the stub's `POST /snapshot` is written, blocks
through Traefik, is acknowledged and comes back `Enforced`; `kubectl edit`, `patch`, label removal and
delete are refused; a bad snapshot changes nothing; an empty one prunes), and a used token refused.
Chart values `controlPlane.caBundle` and `controlPlane.enrollmentToken` supply the CA and
the token.

**Built:** the leader sends `ClusterState` after `Welcome`, on any change (checked every 5 s), on
`Resync` and every 5 min, reading only. Every replica forwards its engines' security events on
its own events stream while the control plane accepts them, from a bounded disk buffer
(`--events-dir`, an `emptyDir`; when full, the oldest are dropped and counted), resending what
wasn't acknowledged after a reconnect or a restart. `inkwall_operator_events_buffered` follows the
buffer, outages included. The events stream reconnects with jittered backoff bounded at 10 s (the
leader's: 1 min), so the backlog drains soon after an outage.

**Built: Managed mode.** The leader applies each `PolicySnapshot` beside the stream, all or nothing:
it refuses (`PolicyNack`, nothing written) a cluster not in `Managed` mode, version 0 or a version
older than the last applied, any kind but `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet`, a rule
set with `configMapRef`, an object without the namespace its kind needs or listed twice, and an
existing object it didn't write (no source label: it never takes one over). Then it dry-runs
(`dryRun: All`, strict field validation, so the CRD schema and the validating webhook see each
object, and an unknown field is refused rather than dropped) every create, update and the deletes;
one refused object refuses the snapshot. A dry run that can't be done (the API server or the webhook
unreachable) isn't a refusal: the stream is dropped and the snapshot comes again. Only then it
writes them, rule sets first, labelled `inkwall.dev/source: saas` (set by the operator: the
snapshot's own value is ignored), deletes the labelled objects the snapshot no longer has (policies
first), records the version on the identity Secret (`waf.inkwall.dev/policy-version`, sent in
`Hello`) and answers `PolicyAck`. A write that
fails after the dry run is retried for about 15 s; then the stream is dropped, and the control plane
sends the snapshot again on reconnect (`Hello` has the older version). The same version again is
applied again (idempotent) and acknowledged; a snapshot still waiting when a newer one arrives is
refused as superseded. Nothing new feeds the engines: the bundle builder signs these CRDs with the
cluster's key like any other, and `ClusterState` reports their `Enforced` back.

The validating webhook guards them: in `Managed` mode, only the operator (its identity from a
`SelfSubjectReview` at start-up) may create, change or delete an object labelled
`inkwall.dev/source: saas`, or add or remove that label; the namespace controller may still delete
them with their namespace. It fails closed, also when it can't read the mode. Deletes reach it only
for labelled objects (an `objectSelector`), so deleting anything else never needs the operator. Out
of `Managed` mode they are ordinary objects again, which their owners can edit or delete (the
operator no longer writes them); whoever can edit the `InkwallConfig` can leave `Managed` mode.

## 5. Uninstall and disable

Removal must never leave a proxy failing closed on a missing engine.

**Built (v0.1.0):** `InkwallConfig.spec.suspend: true` puts every engine in allow-all within
seconds, removing nothing. Unprotected Ingresses and IngressRoutes are unwired level-based (§4.4).
`helm uninstall` runs a pre-delete hook, `inkwall-operator unwire` (`operator/manager/unwire.go`):
scale the operator to 0 and wait for its pods (a draining replica still wires), set the Pod webhook
to `Ignore`, then remove Inkwall's Middleware from every wired Ingress and IngressRoute (keeping the
user's) and delete the Middlewares it created. `WAFPolicy` objects stay; sidecars leave as proxy
pods restart. Tested on kind: after the uninstall, a restarted Traefik serves the routes (an
Ingress and an IngressRoute) without the engine.

**Built since (O5)** (`operator/internal/wiring`):

- **Finalizer `waf.inkwall.dev/unwire`** on every `WAFPolicy`, added by the wiring controller (on
  the leader) before its routes are wired; a policy it can't add it to yet is wired anyway (unwiring
  would drop its protection), and retried. A deleted policy is no longer wired; the finalizer goes
  once none of its targets is still wired for it alone, read from the API server (the cache may lag
  a wiring just done). A route that can't be written holds it, retried, and keeps its namespace's
  Middleware; a target that doesn't exist, or whose CRD doesn't, holds nothing; a target another
  policy protects stays wired. Deleted while the operator is down, the policy, its routes' wiring
  and enforcement stay until it is back. Patches carry the `resourceVersion`, so another
  controller's finalizer is never dropped.
- **Injection off** (`--inject=false`, `injection.enabled=false`, which removes the Pod webhook):
  the wiring controller still runs and unwires every route it wired, deletes its Middlewares,
  removes the finalizer from every policy and reports `Programmed=False` (`InjectionDisabled`).
  Likewise, no Traefik pod selected (§4.4): an `InkwallConfig` selector that doesn't match Traefik's
  pods, or deleted when they don't have the default labels. Deleting an `InkwallConfig` doesn't
  unwire by itself: without one the operator uses the defaults, and keeps wiring the routes of the
  pods they still select.
- **Uninstall:** the hook runs with injection off too. It also sets the `WAFPolicy` webhook to
  `Ignore` (no replica answers it, and it would refuse the update) and removes the finalizer from
  every policy, so deleting one, or its namespace, never waits for an operator that is gone.
  Without the hook (`--no-hooks`, `uninstall.unwire=false`) the chart README says how to.
- Tested on kind: a policy deleted while the operator is scaled to 0 stays, wired, until it is
  back; `helm upgrade --set injection.enabled=false` unwires, and Traefik serves the routes
  uninspected, also from a new pod; an `InkwallConfig` selecting other pods unwires, deleting it
  wires again.

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
| Bundle chunk deleted or edited | None; new engines can't cold start from the Secret meanwhile | Builder logs it | Automatic: published again |
| Bundle over 7.2 MiB compressed | None: the current bundle stays; changes are not published | Builder error; warning past 75%, `inkwall_operator_bundle_compressed_bytes` | Shrink the policies (fewer, or smaller rule sets) |
| Signing key rotated | None: signs with the new key only once every connected engine trusts it | Secret's `rotation-phase`; operator logs the engines it waits for | Automatic (§4.6); replace engines older than rotation |
| Unknown controller version | Wiring may break | `Programmed=False` | Update or pin integration |
| API server down | None | — | Automatic |

Runbook: [When the operator is down](../../deploy/helm/inkwall/README.md#when-the-operator-is-down).

## 7. RBAC

Least privilege. Built rules ([`role.yaml`](../../operator/config/rbac/role.yaml)): a `ClusterRole` plus a
`Role` in `inkwall-system`.

| Resources | Verbs | Why |
|---|---|---|
| `waf.inkwall.dev/*` | read; update status | Own CRDs |
| `wafpolicies` | update, patch | The `waf.inkwall.dev/unwire` finalizer (§5) |
| `wafpolicies`, `wafrulesets`, `clusterwafrulesets` | create, update, delete | Managed mode (§4.9); the webhook keeps others off them |
| `ingressclasses`, `ingresses`, `pods` | read | Resolution, injection checks |
| `ingresses` | patch | Traefik annotation |
| `ingressroutes` (traefik.io) | read, patch | Traefik routes' `middlewares` |
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
| Bundle (compressed) | < 900 KiB in one Secret; up to 7.2 MiB in chunks |

**Measured** (#115) by `make scale-test SCALE=full` (`operator/test/scale`): the operator, with its
production defaults (1 s debounce, 2 s engine reports, unthrottled client), runs in the test process
against envtest's API server and etcd (Kubernetes 1.29), which are separate processes and not
counted. Each policy targets its own route object, half Ingresses and half IngressRoutes, with 10
routes each (2 hosts × 5 path prefixes). Fake engines (`operator/test/fakeengine`, 5 s heartbeats,
one token each) run in a child process, also not counted; they verify and decode every bundle. After
a sync of all objects at once, 10 edits of one policy each, the operator idle between them, are timed
until every engine acks the new bundle. Memory is this process's: Go heap (`runtime.MemStats`, the
peak sampled every 250 ms, garbage included) and peak RSS (`VmHWM`), the harness's share being small.
Reconcile is the bundle reconciler's mean during the edits (controller-runtime's histogram), resolve
is `resolver.Resolve` alone. One run per size on a 12-thread i7-1255U with 16 GiB, API server,
operator and engines sharing it, so times are pessimistic:

| Policies / routes | Engines | Peak RSS | Peak heap | Bundle gzip (raw) | Reconcile | Resolve | Initial sync | Change → all engines, p50 / max |
|---|---|---|---|---|---|---|---|---|
| 100 / 1,000 | 50 | 139 MiB | 116 MiB | 3 KiB (37 KiB) | 0.16 s | 1 ms | 1.0 s | 1.0 / 1.0 s |
| 100 / 1,000 | 500 | 198 MiB | 135 MiB | 3 KiB (37 KiB) | 0.32 s | 1 ms | 1.1 s | 1.1 / 1.1 s |
| 1,000 / 10,000 | 50 | 178 MiB | 146 MiB | 26 KiB (381 KiB) | 1.5 s | 12 ms | 0.6 s | 1.1 / 1.1 s |
| 1,000 / 10,000 | 500 | **1,004 MiB** | 918 MiB | 26 KiB (381 KiB) | 2.5 s | 8 ms | 1.0 s | 1.5 / 1.6 s |
| 5,000 / 50,000 | 50 | 507 MiB | 432 MiB | 134 KiB (1.9 MiB) | 8.7 s | 41 ms | 21.6 s | 1.4 / 1.5 s |
| 5,000 / 50,000 | 500 | **2,038 MiB** | 1,836 MiB | 134 KiB (1.9 MiB) | 19 s | 54 ms | 25.5 s | 4.0 / **47.2 s** |

Initial sync is from the last object created to every engine having all policies; with 10 edits the
p95 is the slowest. Against the targets:

- **Bundle size: met.** 134 KiB compressed at 5,000 policies, far under 900 KiB. Uncompressed it is
  1.9 MiB, nearly half of gRPC's default 4 MiB receive limit, which engines keep.
- **Change → every engine: met up to 5,000 × 50** (1.5 s), not at 5,000 × 500: 4 s typically, but
  one edit took 47 s. Waiting for one of the 50 send slots counts against a stream's 30 s idle
  timeout, while its heartbeats aren't read, so engines were disconnected ("no message from the
  engine in 30s") and got the bundle again after reconnecting.
- **Operator memory: not met with 500 engines.** The heap grows with engines × bundle size, as each
  stream marshals the bundle itself (gRPC buffers, ~20% of all bytes allocated at 1,000 × 500); the
  live heap after a GC is under 100 MiB at every size. 5,000 × 50 is just under 512 MiB.
- **Not a target yet, but slow:** each new bundle writes the `status.bundleVersion` of every policy
  (then `Enforced`), so a reconcile takes 9–19 s at 5,000 policies; changes during it wait, and the
  initial sync takes 20–25 s.

**Engine memory per policy.** A compiled Coraza WAF with the CRS keeps about 2.1 MiB of heap and
takes 10–15 ms to compile. Policies with the same rule sets and CRS settings share one, whatever
their exclusions: exclusions are applied to each request (the transaction-level
`ctl:ruleRemoveById` / `ruleRemoveTargetById`, paths decided on `REQUEST_FILENAME` as before), not
compiled into the rule set (#42). `BenchmarkCompile` (`pkg/policy`, in the CI bench gate) compiles
a bundle of CRS policies that differ only in exclusions, from an empty cache (i7-1255U, medians):

| Policies | Before: time | Before: live heap | After: time | After: live heap |
|---|---|---|---|---|
| 1 | 10 ms | 2.1 MiB | 10 ms | 2.1 MiB |
| 100 | 0.89 s | 205 MiB | 11 ms | 2.2 MiB |
| 1,000 | 9.3 s | 2.0 GiB | 15 ms | 2.9 MiB |

Rule sets whose own SecLang negates `ARGS` targets (`!ARGS:q`) take no argument exclusion per
request: Coraza 3.8.1 adds a transaction's target exclusions to the rule's own negations in place,
so concurrent requests could get each other's. A policy with argument exclusions on such rules
gets compiled rule sets of its own, with them compiled in (`SecRuleUpdateTargetById` after the
user's rules): one for requests on no path exclusion, plus at most one per path exclusion with an
argument, the request's chosen by its path (`argsNegation` in `pkg/rules/coraza`). The CRS and
Inkwall's own rules negate no `ARGS` targets (`TestCRSNegatesNoArgs`).

Applying exclusions per request changes three things from v0.1.0:

- An argument exclusion (`when.argument`, without a path) also covers the rules chained to the
  excluded rule, as one with a path already did. With rule sets that negate `ARGS` targets
  themselves it is compiled in and covers the rule only, as before.
- A rule ID no rule has, in an argument exclusion without a path, is ignored as in every other
  exclusion, instead of failing the bundle (`SecRuleUpdateTargetById` rejected it, and the engine
  kept its previous set).
- A rule set whose own SecLang negates `ARGS` targets falls back to rule sets per policy, above.

## 9. Testing

Unit tests (resolver, bundle hashing/versioning, conflicts); golden files for `Render` per
controller version; envtest (`operator/test/testenv`) for reconcilers, conditions, SSA ownership and
webhooks; kind e2e (injection → wiring → attack blocked → `Ready`, clean uninstall). Scale with fake engines in
envtest (`make scale-test`, §8; 100 policies × 50 engines in CI). Planned: chaos (kill leader, delete
Secret, webhook down), upgrade N-1 → N with traffic.

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
