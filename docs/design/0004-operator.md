# 0004 — Kubernetes Operator

- Status: Draft
- Date: 2026-09-27
- Updated: 2026-10-31
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md),
  [0002 — System Architecture](0002-system-architecture.md)

The [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) (`inkwall-operator`) connects Inkwall to a cluster's proxies. It injects the engine
next to each proxy, wires the proxy to call it, and pushes signed [policy bundles](../glossary.md#bundle) to every engine.
It is never on the request path. The [CRD](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) shapes are in
[0002 §4.2](0002-system-architecture.md#42-crds-wafinkwalldevv1alpha1).

[Terms](../glossary.md) used throughout:

- **Engine:** `inkwall-engine`, the process that inspects requests and returns verdicts.
- **Proxy:** the [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)'s data-plane process ([Traefik](https://doc.traefik.io/traefik/), [Envoy](https://www.envoyproxy.io/docs/envoy/latest/), ...) that asks the
  engine for a verdict.
- **Integration:** the operator's support for one proxy: finding its pods, injection and wiring.
- **Injection:** adding the engine to proxy [pods](https://kubernetes.io/docs/concepts/workloads/pods/) as a [sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/), a container in the same pod.
- **Wiring:** configuring the proxy to call the engine on protected routes. For Traefik, that is
  the `inkwall-waf` [Middleware](https://doc.traefik.io/traefik/middlewares/overview/) and the references to it.
- **Policy:** a `WAFPolicy` object: mode, rule sets, limits and exclusions for some routes.
- **Bundle** (policy bundle): the immutable, versioned, signed snapshot of all of a cluster's
  policies. The operator builds it; every engine enforces it.
- **Leader:** the operator replica that holds the [leader-election lease](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election).
- **Control plane:** the optional hosted service that manages clusters. It is a separate product,
  not in this repository.
- **Cluster modes** (`InkwallConfig.spec.mode`): **Standalone** (the default) connects to no
  control plane. In **GitOps** mode the policies are CRDs, typically applied from Git, and the
  operator mirrors them to the control plane. In **Managed** mode the control plane owns the
  policies, and the operator writes them as CRDs.
- **Policy snapshot:** a `PolicySnapshot`, the policy objects the control plane sends in Managed
  mode. It is not a bundle.
- **Enforcement modes:** in **detect mode** the engine only logs what it would block; in **block
  mode** it rejects attacks.
- **Failure mode:** what happens to a request that can't be inspected. The engine either **fails
  open** (lets it through) or **fails closed** (rejects it).
- **CRS:** the [OWASP Core Rule Set](https://coreruleset.org/) (CRS), the rules the engine runs through [Coraza](https://coraza.io/), the [Go](https://go.dev/) WAF
  library.

**Built (v0.1.0):** Traefik with [`Ingress`](https://kubernetes.io/docs/concepts/services-networking/ingress/) targets ([ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)).

**Built since:** Traefik [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) targets; the `waf.inkwall.dev/unwire` [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/) and
unwiring with injection off ([§5](#5-uninstall-and-disable)); signing key rotation and bundle
chunks ([§4.6](#46-bundle-builder-leader-only)); the operator side of the optional control plane:
enrollment, GitOps and Managed modes, and security events ([§4.9](#49-upstream-sync-leader-only));
the discovery controller ([§4.1](#41-discovery-controller)) and the wiring's `Integration` interface
([§4.2](#42-integration-interface)).

**Not yet:** other proxies, wiring [`HTTPRoute`](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) targets (the resolver reads them,
[§4.5](#45-resolver)).

## Contents

- [1. Goals and non-goals](#1-goals-and-non-goals)
- [2. Overview](#2-overview)
- [3. API (`waf.inkwall.dev/v1alpha1`)](#3-api-wafinkwalldevv1alpha1)
  - [3.1 Validation](#31-validation)
  - [3.2 Status contract](#32-status-contract)
- [4. Controllers](#4-controllers)
  - [4.1 Discovery controller](#41-discovery-controller)
  - [4.2 Integration interface](#42-integration-interface)
  - [4.3 Injection controller](#43-injection-controller)
  - [4.4 Wiring controller](#44-wiring-controller)
  - [4.5 Resolver](#45-resolver)
  - [4.6 Bundle builder (leader only)](#46-bundle-builder-leader-only)
  - [4.7 Distribution server (all replicas)](#47-distribution-server-all-replicas)
  - [4.8 Status aggregator](#48-status-aggregator)
  - [4.9 Upstream sync (leader only)](#49-upstream-sync-leader-only)
- [5. Uninstall and disable](#5-uninstall-and-disable)
- [6. Failure modes](#6-failure-modes)
- [7. RBAC](#7-rbac)
- [8. Scale targets (v1)](#8-scale-targets-v1)
- [9. Testing](#9-testing)
- [10. Code layout](#10-code-layout)
- [11. Milestones](#11-milestones)
- [12. Open questions](#12-open-questions)

## 1. Goals and non-goals

1. **No proxy knowledge for users:** they write a `WAFPolicy` against an `Ingress` or `HTTPRoute`.
2. **Never on the request path:** operator downtime never affects traffic
   ([0002 §2](0002-system-architecture.md#2-system-context)).
3. **GitOps-friendly:** avoid changing objects the user owns. When that is unavoidable, touch the
   fewest fields and document how to ignore them.
4. **Safe by default:** in detect mode, any step can fail without dropping traffic. In block mode,
   nothing passes uninspected, so failures show as rejected requests and conditions, not as silent
   gaps. Uninstalling reverses every change.
5. **Observable:** each policy reports its progress: accepted, then programmed, then enforced.

Non-goals: installing ingress controllers; managing TLS, DNS or routes; restarting workloads
without being asked.

## 2. Overview

The operator is one [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) with 2 replicas. Its parts:

- **Discovery** finds the proxies. It feeds **Injection**, which adds the engine sidecar, and
  **Wiring**, which writes the proxy objects.
- The **Resolver** turns policies into routes. The **Bundle builder**, on the leader, turns them
  into a signed bundle and stores it in a [Secret](https://kubernetes.io/docs/concepts/configuration/secret/).
- **Distribution**, a [gRPC](https://grpc.io/docs/) server on every replica, streams the bundle to the engines. Their
  acknowledgements (ACKs) feed the **Status aggregator**.
- **Upstream sync** talks to the control plane.
- **[Admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)** validate the CRDs and inject the sidecar.

Tooling: the [kubebuilder](https://book.kubebuilder.io/) v4 layout, [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime), [JSON merge patches](https://www.rfc-editor.org/rfc/rfc7386) on user-owned objects
([§4.4](#44-wiring-controller)), [CEL rules](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-rules) in the CRDs, and [cert-controller](https://github.com/open-policy-agent/cert-controller) (or [cert-manager](https://cert-manager.io/docs/)) for
the webhook certificates.

## 3. API (`waf.inkwall.dev/v1alpha1`)

| Kind | Scope | Purpose |
|---|---|---|
| `InkwallConfig` | Cluster, singleton `default` | Mode, engine, integrations, control plane, `suspend`, signing key rotation |
| `WAFPolicy` | Namespace | What to enforce on which routes |
| `WAFRuleSet` / `ClusterWAFRuleSet` | Namespace / Cluster | Rules: builtin CRS, [SecLang](https://coraza.io/docs/seclang/), [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) |
| `WAFIPList` / `ClusterWAFIPList` | Namespace / Cluster | [CIDR](https://www.rfc-editor.org/rfc/rfc4632) lists (planned) |
| `WAFPolicyDefault` | Namespace | Default for routes with no policy (planned) |

A field is added only once the engine honours it. Adding a field to `v1alpha1` later is
compatible; removing one is not.

**Not yet:** IP lists and `spec.ipLists`, `spec.rateLimits`, `spec.response`,
`BlockHighConfidence`, `body.contentTypes`, the `InspectPrefix` oversize action,
`InkwallConfig.spec.events`, `WAFPolicyDefault`.

### 3.1 Validation

Validation runs in three steps, cheapest first:

1. **Schema and CEL:** enums, ranges (`timeout <= 1s`, `body.maxBytes <= 10Mi`), exactly one rule
   source, and the allowed `targetRefs` kinds.
2. **Validating webhook.** It has a 2 s timeout and [`failurePolicy: Fail`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy) for the WAF CRDs only, so
   a bad rule can't slip in while the webhook is down. It:
   - compiles SecLang with the engine's Coraza, after the CRS, and returns the failing line; it
     rejects unknown `builtin` sets;
   - allows only rule directives (`SecRule`, `SecAction`, `SecMarker`, `SecRuleRemoveBy*`,
     `SecRuleUpdate*`). Engine-wide settings and file writes (`SecRuleEngine`, body limits,
     `SecAuditLog`, `SecDebugLog`, `Include`) stay Inkwall's, since app teams write rule sets;
   - accepts updates that leave the spec unchanged, so objects a newer engine rejects can still be
     deleted;
   - uses a self-signed certificate that the operator rotates, with the CA injected; cert-manager
     is optional;
   - in Managed mode, rejects edits of the control plane's objects by anyone but the operator
     (`operator/webhook/source.go`, [§4.9](#49-upstream-sync-leader-only)).
3. **Resolver** (asynchronous, reported in status): dangling references, conflicts, and targets
   that can't be wired.

### 3.2 Status contract

`WAFPolicy` conditions are [kstatus-compatible](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md), so [`kubectl wait`](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_wait/) and [Argo CD health checks](https://argo-cd.readthedocs.io/en/stable/operator-manual/health/) work:

| Condition | True when | False reasons |
|---|---|---|
| `Accepted` | Spec valid, references resolve | `InvalidRef`, `Conflict`, `RuleCompileError`, `TargetUnsupported` |
| `Programmed` | Every target's proxy is wired | `ControllerUnsupported`, `SidecarMissing`, `WiringFailed`, `PendingRestart`, `NoTargets`, `InjectionDisabled` |
| `Enforced` | Every serving engine ACKed a bundle with this generation | `EnginesBehind` (`3/6`), `EngineNack`, `NoEngines`, `NotInBundle` |
| `Ready` | The three above are True | first failing condition's reason |

Status also has `bundleVersion` and `observedGeneration`. `bundleVersion` is the first bundle that
enforces the policy as it is now; later bundles do too, until one changes the policy. A bundle that
changes only other policies doesn't change it (#149): before v0.3.0 it was the newest bundle, so
every bundle rewrote every policy's status.

`InkwallConfig.status` has `observedGeneration`, `conditions` (`ControlPlaneConnected`,
[§4.9](#49-upstream-sync-leader-only)) and `proxies`, the discovered proxy controllers
([§4.1](#41-discovery-controller)).

**Not yet:** per-target status (`targets[]` with controller, gateway, programmed and engine
counts), and the rest of the cluster view in `InkwallConfig.status` (engine counts, bundle
versions, control plane state).

## 4. Controllers

The [controllers](https://kubernetes.io/docs/concepts/architecture/controller/) are idempotent, level-triggered reconcilers. Objects they create carry
`app.kubernetes.io/managed-by: inkwall-operator` and, where namespacing allows, an [owner reference](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/)
for [garbage collection](https://kubernetes.io/docs/concepts/architecture/garbage-collection/).

### 4.1 Discovery controller

The discovery controller watches [`IngressClass`](https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class) and [`GatewayClass`](https://gateway-api.sigs.k8s.io/reference/api-types/gatewayclass/), maps controller names to
integrations, and lists them in `InkwallConfig.status.proxies`. Unknown controllers are then
visible rather than silently unprotected.

**Built** (`operator/internal/discovery`, leader only):

- [`operator/integrations`](../../operator/integrations/integrations.go) lists Traefik only:
  IngressClass controller `traefik.io/ingress-controller`, GatewayClass controller
  `traefik.io/gateway-controller`, pods `app.kubernetes.io/name=traefik`, adapter `forward-auth`.
  (An adapter is the engine listener that speaks one proxy's protocol; see
  [0006](0006-adapter-protocols.md).)
- One entry per controller: its `controllerName`, its `integration` (empty when Inkwall has none),
  its `ingressClasses` and `gatewayClasses`, and `support`:
  - `Full`: the integration's wiring takes the routes of all its classes: `Ingress` for an
    IngressClass, `HTTPRoute` for a GatewayClass;
  - `Partial`: of some of them; the `message` says which it doesn't;
  - `Unsupported`: of none, or no integration. Today that includes Traefik's GatewayClasses.
- It writes the status only when it changes, and only into an existing `InkwallConfig` `default`:
  the operator doesn't create one.
- Without the Gateway API's CRDs, GatewayClasses are left out; the leader looks for their CRD
  every 30 s (`operator/internal/crdwatch`).

**Not yet:** finding each controller's data-plane workloads from its classes (the pods are found by
label selectors, [§4.3](#43-injection-controller)); a registry tested per controller version.

### 4.2 Integration interface

Planned: one package per proxy under `operator/integrations/<name>/`, implementing `Name`,
`Match`, `Discover`, `Injection`, `Render` (pure, tested with golden files) and `Health`. Adding a
proxy would then change no controller.

**Built:** two halves. `integrations.Integration`, a plain struct, describes a proxy to discovery
and injection: its class controllers, pod selector and adapter. The wiring goes through the
`Integration` interface in [`operator/internal/wiring`](../../operator/internal/wiring/integration.go),
one implementation per proxy (`Traefik`):

| Method | Does |
|---|---|
| `Name` | The integration's name, and the `integration` label of the wiring metrics ([§4.8](#48-status-aggregator)) |
| `Kinds` | The target kinds it wires, by group and kind; several integrations may share one |
| `Watch` | Adds the watches its wiring reads: routes, classes, its pods, its own objects |
| `Wire` | Wires the targets its proxy serves, unwires the rest, and returns a state per target: served by another proxy (with why), failed (with why), or wired; plus its pods |
| `Wired` | Whether a target is still wired, read uncached, before a deleted policy is released |
| `Unwire` | Removes all of its wiring at uninstall ([§5](#5-uninstall-and-disable)) |

The wiring controller owns what every proxy shares: the finalizer, collecting the targets of the
live policies, the `Programmed` condition (a target counts for the integration whose proxy serves
it; if none does, it is `ControllerUnsupported` with the first integration's reason) and the
sidecar checks on each integration's pods. Each integration's RBAC markers sit next to its code.

An `HTTPRoute` integration (Traefik's Gateway API, Envoy Gateway) adds its `HTTPRoute` kind,
serves the routes whose parent Gateway has one of its GatewayClasses, wires each one (for example, Traefik's
Middleware through an `ExtensionRef` filter, or Envoy Gateway's `EnvoyExtensionPolicy`), and is
added to `wiring.Integrations`. Discovery then reports its GatewayClasses `Full`.

**Not yet:** injection behind the interface (it is Traefik's Pod webhook); `Render` and golden
files; `Health`.

### 4.3 Injection controller

Injection puts the engine into proxy pods as a sidecar that shares a socket directory with the
proxy.

- **Native extension point first, Pod webhook otherwise.** [Envoy Gateway](https://gateway.envoyproxy.io/) has an extension point
  (`EnvoyProxy`), and [Caddy](https://caddyserver.com/docs/) compiles the engine in. [Istio](https://istio.io/latest/docs/), [ingress-nginx](https://kubernetes.github.io/ingress-nginx/), Traefik and [HAProxy](https://docs.haproxy.org/) get
  a Pod webhook. With `injection: Manual`, the operator prints [Helm](https://helm.sh/docs/) values and only verifies.
  It never patches the controller's Deployment: Helm or [Argo CD](https://argo-cd.readthedocs.io/en/stable/) would revert it.
- **Native sidecar** (an [init container](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/) with `restartPolicy: Always`, Kubernetes ≥ 1.29). It
  starts before the proxy and stops after it, so the proxy never runs without it.
- **The webhook's `failurePolicy` follows the enforcement mode.** It is `Ignore` when every policy
  is in detect mode: pods then start uninspected, reported as `SidecarMissing`. It is `Fail` when
  any policy blocks, since a pod without its engine would reject all traffic. Pods already running
  keep serving.
- **The sidecar uses the proxy's [ServiceAccount](https://kubernetes.io/docs/concepts/security/service-accounts/).** That account gets `get` on the bundle Secret
  only, for cold start ([§4.6](#46-bundle-builder-leader-only)).
- **Rollout:** injection applies to new pods only. With `rollout: Manual` (the default), the
  operator reports `PendingRestart` and names the workload. `rollout: Automatic` would restart it,
  respecting [PodDisruptionBudgets](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#pod-disruption-budgets). Engine upgrades follow the same path.

**Built (v0.1.0)** (`operator/internal/injection`, `operator/webhook/inject.go`):

- **The webhook.** `inkwall-operator-mutating` sees only Traefik pods
  (`app.kubernetes.io/name=traefik`), at creation. It is installed with `Ignore`. The leader sets
  `Fail` while any policy blocks, and sets it again after a Helm upgrade. It patches with the
  [`resourceVersion`](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions), so it never overwrites a fresh CA bundle. If `InkwallConfig` can't be read,
  the engine is injected with defaults rather than left out.
- **Opting out.** Pods labelled `waf.inkwall.dev/inject: "false"` are excluded by the webhook's
  [`objectSelector`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-objectselector). They start even while the webhook fails closed and the operator is down: this
  is how to scale the proxy before the operator returns. The annotation of the same name works only
  while the webhook answers. Pods that already have an `inkwall-engine` container are left alone.
- **Custom selectors.** A non-empty `InkwallConfig.spec.integrations[].selector` replaces Traefik's
  label everywhere: the pod cache, the webhook, the controllers and the `objectSelector`. It is read
  at startup. When it changes, each replica restarts after a random delay of up to 30 s
  (`--selector-restart-max-delay`). Selectors for unknown controllers are logged and ignored.
- **What is injected:**
  - the engine as the first init container, with a [startup probe](https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/), so the proxy starts once the
    engine serves;
  - the `forward-auth` adapter in bundle mode (policies come from the operator's bundles);
  - a [projected token](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken) (audience `inkwall-operator`) and the trust ConfigMap, in one read-only
    directory;
  - an [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) bundle cache;
  - non-root, with a read-only root filesystem;
  - image and resources from `InkwallConfig.spec.engine`, else from `--engine-image`.
- **Trust and access per namespace.** The leader keeps an `inkwall-trust` ConfigMap in each
  namespace with proxy pods, and removes it with the last one. It holds `ca.crt`,
  `trusted-keys.pub` (every bundle key engines must accept; the engine reads this) and
  `ed25519.pub` (the active key, for older engines). The leader also keeps a [`Role` and
  `RoleBinding`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), `inkwall-bundle-reader`, for each proxy ServiceAccount. It deletes only ConfigMaps
  it labelled.
- **Not yet:** `rollout: Automatic`. Pods that were running before the operator are injected when
  they restart.

### 4.4 Wiring controller

**Hook in globally once, decide per route locally.** The engine's router knows which routes have a
policy. So the proxy hook touches few objects, and unprotected routes cost about nothing
([0001](0001-performance-first-architecture.md)), through per-route attachment or a local skip
check.

| Proxy | Operator writes | Unprotected-route cost |
|---|---|---|
| Envoy Gateway | `Backend` ([Unix socket](https://man7.org/linux/man-pages/man7/unix.7.html)) + [`EnvoyExtensionPolicy`](https://gateway.envoyproxy.io/docs/api/extension_types/#envoyextensionpolicy) per protected `HTTPRoute` | 0 |
| Istio | gateway-scoped [`EnvoyFilter`](https://istio.io/latest/docs/reference/config/networking/envoy-filter/) | ~0 (per-route disable) |
| ingress-nginx | [Lua](https://github.com/openresty/lua-nginx-module) plugin ConfigMap + `plugins` key | ~0 (in-memory route set) |
| Traefik | `Middleware` per namespace, attached to protected routes | 0 |
| HAProxy | [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt) config + map of protected routes in an ACL | ~0 (map lookup) |
| Caddy | nothing | 0 |

User-owned objects touched, with the fewest fields:

- Envoy Gateway's `EnvoyProxy`: a sidecar patch, or an operator-made one plus `parametersRef`.
- ingress-nginx's `data.plugins`: merged, with the original saved for uninstall.
- Traefik's `router.middlewares` [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) on an `Ingress`, and `spec.routes[*].middlewares` on
  an `IngressRoute`.
- The `waf.inkwall.dev/unwire` finalizer on a `WAFPolicy` ([§5](#5-uninstall-and-disable)).

Of the chart's own objects, the operator changes the Pod webhook's `failurePolicy` and
`objectSelector` ([§4.3](#43-injection-controller)), and the `caBundle` of both webhook
configurations. Each field the operator writes today is listed in [GitOps](../gitops.md), with
Argo CD and [Flux](https://fluxcd.io/flux/) ignore rules.

How it writes: JSON merge patches on user-owned objects, not [server-side apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/). Where a patch sends
a whole list, it carries the `resourceVersion`. The [field manager](https://kubernetes.io/docs/reference/using-api/server-side-apply/#managers) is `inkwall-operator`, taken from
the binary's user agent; only the webhook certificate rotator sets it explicitly. Objects the
operator creates carry `app.kubernetes.io/managed-by: inkwall-operator` and are deleted once no
longer needed.

**Built (v0.1.0)** (`operator/internal/wiring`, Traefik):

- **What is wired.** Each targeted Ingress that Traefik serves is wired, whether its policy is
  accepted or not. Traefik serves it by `ingressClassName`, the legacy `kubernetes.io/ingress.class`,
  or the default class. Each targeted `IngressRoute` (`traefik.io/v1alpha1`) is wired too. Until a
  route's rules are in a bundle, the engine passes it (reason `no-policy`).
- **The Middleware.** There is one ForwardAuth `Middleware`, `inkwall-waf`, per such namespace,
  removed when unused. It sets:
  - `trustForwardHeader: false`;
  - `forwardBody: true`;
  - `maxBodySize` 10 MiB, the largest `body.maxBytes`;
  - `maxResponseBodySize` 64 KiB for the engine's answer. This is left out on Traefik before v3.7,
    whose CRD has no such field.

  A Middleware of the same name that the operator didn't create is left alone (`WiringFailed`).
  The operator doesn't configure Traefik's [entry points](https://doc.traefik.io/traefik/routing/entrypoints/). Behind a load balancer, the user turns on
  the [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) there, so the engine sees the client IP ([client IP](../client-ip.md)).
- **Ingress.** The annotation gets the operator's Middleware first, with the user's entries kept in
  order. `waf.inkwall.dev/wired` records it. Unprotecting removes only that entry. Wiring is
  level-based: the `waf.inkwall.dev/unwire` finalizer only makes a policy deleted while the
  operator is down wait for it ([§5](#5-uninstall-and-disable)).
- **IngressRoute.** `{name: inkwall-waf}` goes first in every route's `middlewares`, with the user's
  entries kept in order, and `waf.inkwall.dev/wired: inkwall-waf` is set. Unprotecting removes the
  entries that name it in the route's namespace (a same-named one elsewhere is the user's), and any
  list it leaves empty.
  - The reference has no namespace. Traefik resolves it in the IngressRoute's namespace, where the
    Middleware is, so it works with [`allowCrossNamespace`](https://doc.traefik.io/traefik/providers/kubernetes-crd/#allowcrossnamespace) off (the default).
  - To a merge patch, `spec.routes` is one list. So the patch carries the `resourceVersion`, and a
    conflict retries.
- **Only with an injected Traefik.** Routes are wired only while a Traefik pod that the webhook
  selects is running, with injection on. Otherwise new Traefik pods would get no engine to call, so
  everything is unwired (`SidecarMissing`, or `InjectionDisabled`, [§5](#5-uninstall-and-disable)).
  A Traefik scaled to 0 is wired again when its first injected pod is created, about a second later.
- **Without Traefik's CRDs** nothing is wired, and nothing crashes. The leader looks for the
  IngressRoute CRD every 30 s. Once it is installed, the bundle builder and the wiring watch
  IngressRoutes (`operator/internal/crdwatch`). The wiring's resync (1 min) notices a Middleware CRD
  installed later.
- **`Programmed=True`** when all the policy's Traefik Ingresses and IngressRoutes are wired and
  every running Traefik pod has the engine. Otherwise the reason is one of:
  - `ControllerUnsupported`: another controller or kind;
  - `WiringFailed`: no Traefik CRDs, a name clash, or an IngressRoute that can't be written;
  - `PendingRestart`: pods older than the webhook, listed;
  - `SidecarMissing`: no Traefik pod selected, or pods without the engine (the operator was down
    in detect mode, or they opted out), listed;
  - `NoTargets`;
  - `InjectionDisabled`.
- **Not yet:** `HTTPRoute` targets; matching engines to the pods that serve a policy's class (all
  engines count for `Enforced`); IngressRoutes nested with `parentRefs`. Whether Traefik attachment
  should default to something else is open ([§12](#12-open-questions)).

### 4.5 Resolver

The resolver turns policies and routes into `(host, pathMatch, method)` sets, which is all the
engine matches on. This is decision D6, the operator resolves routes
([0002 §11](0002-system-architecture.md#11-decisions-adr-log)). It:

- expands hosts × paths;
- for an `HTTPRoute`, wires the integration of every Gateway;
- lets the most specific target win ([0002 §4.2](0002-system-architecture.md#42-crds-wafinkwalldevv1alpha1));
- applies `WAFPolicyDefault`;
- resolves rule set and IP list references.

It runs again when a targeted route changes (routes are indexed by target).

**Built (v0.1.0)** (`operator/resolver`; Ingress, and IngressRoute and HTTPRoute since):

- **Conflicts:** the oldest policy wins (by creation time, then name), and the others get
  `Conflict`, as in [Gateway API](https://gateway-api.sigs.k8s.io/). Rejecting both would leave the route unprotected.
- **Precedence.** Identical routes (host, path and methods) from two targets go to the most
  specific one: an HTTPRoute rule (`sectionName`), then a whole HTTPRoute, then an Ingress or an
  IngressRoute. Between targets of the same kind, they go to the older policy. The other policy
  keeps its other routes, and its `Accepted` message lists the ones it lost.
- **Errors fall back.** A policy that can't be resolved keeps its version in the current bundle, so
  a bad edit never weakens protection. A policy that was never resolved is left out. A missing
  target is not an error.
- **ConfigMap rules** come only from ConfigMaps labelled `waf.inkwall.dev/rules=true`, which keeps
  the cache small.
- **Ingress paths.** [`ImplementationSpecific`](https://kubernetes.io/docs/concepts/services-networking/ingress/#path-types) paths are prefixes, as in Traefik and ingress-nginx.
  A default backend is covered only for an Ingress without rules.
- **IngressRoute routes** come from each route's [`match`](https://doc.traefik.io/traefik/routing/routers/#rule).
  - Supported: `Host`, `Path` (exact) and `PathPrefix`, one string each (`` `…` `` or `"…"`),
    joined by `&&`, in parentheses or not. No `Host` means any host; no path means `/`.
  - Anything else is `Accepted=False` (`TargetUnsupported`): `||`, `!`, `HostRegexp`, `Method`,
    `Header`, `Query`, `ClientIP`, two Hosts or two paths, or several values. The condition names
    the route (`spec.routes[1]`), its rule and what can't be read. The previous version stays in
    force.
  - Traefik's `PathPrefix` is a string prefix, but it is read element-wise. Other paths of a covered
    host get that host's most general policy in the engine, so none goes uninspected.
- **HTTPRoute routes** are its `hostnames` × each rule's `matches`.
  - `Exact` and `PathPrefix` paths, cleaned; a `method` is kept. No `hostnames` means any host (the
    listeners' hostnames aren't read); a rule without `matches`, or a match without a path, is
    `PathPrefix /`.
  - `sectionName` narrows the target to the rule of that `name`. A name no rule has is a missing
    target.
  - `RegularExpression` paths, `headers` and `queryParams` are `Accepted=False`
    (`TargetUnsupported`), naming the rule (`spec.rules[1].matches[0] (rule admin)`). The previous
    version stays in force. A rule the target doesn't select isn't read.
  - Read once the HTTPRoute CRD (`gateway.networking.k8s.io/v1`) is installed: the leader looks for
    it every 30 s, then the bundle builder watches HTTPRoutes (`operator/internal/crdwatch`).
    Without it nothing changes.
  - No proxy wires an HTTPRoute yet: such a policy is `Programmed=False`
    (`ControllerUnsupported`).
- **Cross-namespace `WAFRuleSet` references** are rejected until a grant mechanism exists. Use a
  `ClusterWAFRuleSet` instead.

### 4.6 Bundle builder (leader only)

1. Debounce for 1 s, so a 200-object [GitOps](https://opengitops.dev/) sync makes one bundle.
2. Build the `Bundle` [proto](https://protobuf.dev/) ([0002 §4.3](0002-system-architecture.md#43-bundle-format)). Builtin
   rules are referenced by name and version, not embedded.
3. If the content hash matches the current bundle's, stop.
4. Bump the monotonic version. It continues from the stored bundle across leader changes.
5. Sign with the cluster's [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) key.
6. Store it [gzipped](https://www.rfc-editor.org/rfc/rfc1952) in the Secret `inkwall-bundle`, which is also the engines' cold-start source.
   Split it into chunk Secrets if it doesn't fit in one.

**Built (v0.1.0)** (`operator/bundle`, `pkg/agent`):

- The Secret holds the `SignedBundle` and the public key. The key is generated on first use into
  `inkwall-bundle-signing-key`.
- The hash skips the version and creation time. The version continues from the Secret, or from the
  leader's memory if the Secret was deleted. The cluster ID is the [UID](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids) of the `kube-system`
  Namespace.
- **Engine cold start:** the engine uses its on-disk cache, or else reads the Secret
  (`--bundle-secret`). It reads it with a second projected token for the API server and
  `kube-root-ca.crt`, and verifies it like a streamed bundle.

**Chunks** (`pkg/bundlesecret`). Secrets are [capped at 1 MiB](https://kubernetes.io/docs/concepts/configuration/secret/#restriction-data-size).

- A bundle of up to 900 KiB compressed is stored as `bundle.pb.gz` in `inkwall-bundle`, as before,
  so older engines can read it.
- A larger one is split into Secrets of 900 KiB, named `inkwall-bundle-a-0`… or
  `inkwall-bundle-b-0`… and labelled `waf.inkwall.dev/bundle-chunk`. `inkwall-bundle` then holds a
  `manifest.json` instead: the [SHA-256](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) and size of the compressed bundle, and the chunk names.
- **Write order.** At every build, the chunks are written to the set (`a` or `b`) that the current
  manifest doesn't use, then the manifest. Chunks the manifest doesn't list are deleted after.
  A reader therefore never sees a manifest before its chunks. It also checks the hash: a reader that
  read the manifest just before the next bundle replaced its chunks fails and retries.
- **Limits.** At most 8 chunks (7.2 MiB) and 64 MiB decompressed. A bundle over that is not
  published, and the current one stays. The builder warns when it publishes a bundle over 75% of
  the limit. `inkwall_operator_bundle_compressed_bytes` is the size each replica serves.
- **Repair.** A chunk deleted or edited makes the builder publish the bundle again, as a new
  version. That new version has no previous version for an unresolvable policy to fall back on.
- **Access.** `inkwall-bundle-reader` grants `get` on every chunk name. So must the Role of an
  engine configured by hand with `--bundle-secret`.
- **Streaming.** The stream carries the bundle whole. Engines accept messages of up to 65 MiB
  (gRPC's default is 4 MiB).
- **Compatibility.**
  - An engine without chunk support finds no `bundle.pb.gz` in a chunked Secret. It keeps its
    cache, or waits for the operator; it never applies part of a bundle. Such engines also refuse a
    streamed bundle over 4 MiB decompressed, and keep their last one.
  - An operator without chunk support can't read a chunked Secret, and builds nothing. Before
    rolling back, delete `inkwall-bundle` and its chunks (`-l waf.inkwall.dev/bundle-chunk`).
    Engines accept bundles of the restarted version sequence, as they are newer.

**Built: signing key rotation** (`operator/bundle/keyring.go`, `pkg/agent`, `pkg/bundlekey`).

A rotation starts in one of two ways:

- on request, by a new value of the `waf.inkwall.dev/rotate-signing-key` annotation on the
  `InkwallConfig`. This is GitOps-friendly, sits next to the rest of the cluster's configuration,
  and needs no write access to the operator's Secrets;
- on schedule, when `spec.signingKey.rotationInterval` (≥ 1h) has passed.

The keys and the rotation's state live in `inkwall-bundle-signing-key`, so a new leader continues
a rotation. It has three phases:

1. **Publishing.** A new key is generated and added to `trusted-keys.pub`; the trust ConfigMaps
   follow. The old key still signs. Engines re-read their key file every 10 s, and report the IDs of
   the keys they trust in `Hello` and `Heartbeat`.
2. **Switch.** The operator switches once two things hold: at least a grace period has passed
   (`--signing-key-grace`, 1 min: the [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)'s ConfigMap update delay), and every connected engine
   reports the new key. A new leader first waits 30 s for the replicas' reports. The current content
   is then signed again with the new key, as a new version, so engines cache a bundle the new key
   signed. The old public key stays trusted.
3. **Retire.** Once the grace period has passed again and every connected engine runs a bundle
   signed with the new key, the old key is removed: `trusted-keys.pub` has one key.

Details:

- An engine that reports no keys (older than rotation) blocks the switch until it is replaced. The
  operator logs the engines it waits for.
- The phase is the Secret's `waf.inkwall.dev/rotation-phase` annotation (`Publishing`,
  `Retiring`). The bundle Secret's `waf.inkwall.dev/key-id` names the key that signed it.
- A deleted signing key Secret is recreated with the keys in the leader's memory.
- Tested at three levels. Unit tests cover multi-key verification, reloading and the state machine.
  [envtest](https://book.kubebuilder.io/reference/envtest) covers an engine that gets the key late: it holds the switch, and nothing is NACKed. On
  [kind](https://kind.sigs.k8s.io/), both Traefik's injected engine and a hand-configured one rotate with no NACK and no
  restart.

### 4.7 Distribution server (all replicas)

The distribution server serves gRPC `BundleService.Watch`
([0002 §5.2](0002-system-architecture.md#52-engine--operator-bundle-distribution)) through the
Service `inkwall-operator`. Every replica serves streams from the Secret; only building is
leader-only. Losing a replica just moves its engines to another.

**Built (v0.1.0)** (`operator/internal/distribution`):

- **Port and TLS.** Port 9445 (`--distribution-port`). TLS uses the webhook certificate, which also
  names the Service; engines verify it with the operator CA.
- **Authentication.** A [`TokenReview`](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) (audience `inkwall-operator`), then a [`SubjectAccessReview`](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access)
  that the engine's ServiceAccount may `get` the bundle Secret (the grant from
  [§4.3](#43-injection-controller)). Results are cached for 1 min.
- **Streams.** The first message must be `Hello`, with an `engine_id` of 1 to 253 bytes (the
  engine's pod name). Engines that are already current aren't sent the bundle again. Streams
  silent for 30 s are closed. At most 50 sends run at once. A stream waiting for a send slot, or
  sending, still reads its engine's heartbeats (#148).
- **What the operator accepts from engines** (#205). A `Hello` or `Heartbeat` over these limits is
  refused with `InvalidArgument`, which ends the stream. Engines send far less.
  - `node_name`: empty or a DNS subdomain (at most 253 bytes); `engine_version`: at most 128 bytes.
  - `trusted_key_ids`: at most 16, each 1 to 64 bytes (engines send 16 hex digits per key).
  - `pod_namespace` and `pod_name`: when the token is bound to a pod, its pod is used and the
    `Hello`'s isn't. Otherwise they must be empty, a DNS label and a DNS subdomain.
  - A `Nack`'s error is cut to 1 KiB, without splitting a character. It goes into the engine's
    record and the `Enforced` message.
- **Events.** Each event gets the stream's engine ID and pod, not its own. Events beyond 1,000 in
  one message are dropped and counted with the engine's own drops.
- **Aggregation through ConfigMaps.** Each replica writes its engines to `inkwall-engines-<pod>`
  (owned by its Pod) on change and every 10 s. The leader merges them every 2 s, drops reports
  older than 30 s, and counts an engine that moved between replicas once.
- **Report size.** An engine's record is at most about 3.5 KiB with the limits above, a few hundred
  bytes in practice. A report holds at most 900 KiB of engines, by engine ID, so the ConfigMap
  stays under 1 MiB. The engines left out are counted by `inkwall_operator_engines_left_out`.
  They don't count in `Enforced` or in key rotation.

### 4.8 Status aggregator

The status aggregator turns the results of the resolver, the wiring and the engines' ACKs into the
conditions of [§3.2](#32-status-contract). It writes only on change, at most once per object every
2 s.

**Built (v0.1.0):** `Enforced=True` when every connected engine runs a bundle whose version is at
least the policy's `status.bundleVersion`. Otherwise the reason is `NoEngines`, `EnginesBehind`
(`1/3 engines on bundle 42`), `EngineNack` (with the first error) or `NotInBundle`. It waits for
the bundle builder to report the policy's current generation (`status.observedGeneration`).

**Writes per bundle** (#149). The builder writes a policy's `bundleVersion` only when the bundle
changes what the policy enforces: its own entry, the rule sets it binds, or suspension
(`bundle.PolicyHashes`). It remembers the version per policy; a new leader keeps a policy's
reported version when the bundle didn't change it. So a one-policy edit writes one policy's status,
and the `Enforced` of the others, which name their own bundle, stays as it is.

Metrics: `inkwall_operator_bundle_version`, `inkwall_operator_engines{state}`,
`inkwall_operator_bundle_compressed_bytes` ([§4.6](#46-bundle-builder-leader-only)), and, from the
wiring, `inkwall_operator_wired_targets{integration}` and
`inkwall_operator_wiring_failures{integration}` (targets that are `WiringFailed`).

**Not yet:** an `integration` label on the engine counts (engines aren't matched to proxies yet),
reconcile duration, policy condition counts.

### 4.9 Upstream sync (leader only)

Upstream sync connects the operator to the control plane.

- In **GitOps** mode it pushes CRD snapshots and status to the control plane, and never writes
  CRDs.
- In **Managed** mode it writes the control plane's policies as CRDs labelled
  `inkwall.dev/source: saas`, and rejects other edits of them.

The contract is in [0002 §5.3](0002-system-architecture.md#53-operator--saas) and
[0002 §7.5](0002-system-architecture.md#75-cluster-enrollment-managed--gitops-mode).

**Built: enrollment and the primary stream** (`operator/internal/controlplane`). This runs on the
leader only, and is idle in Standalone mode (the default).

- **Enrollment.** The leader reads the enrollment token from
  `spec.controlPlane.enrollmentSecretRef`, key `token`; the Secret must be in the operator's
  namespace. It generates an [ECDSA P-256](https://csrc.nist.gov/pubs/fips/186-5/final) key and enrolls. A retry after a lost response reuses the
  key.
- **Identity.** The certificate and key go in the `inkwall-control-plane-identity` Secret (type
  [`kubernetes.io/tls`](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets), plus `cluster-id`).
- **Primary stream.** The leader then holds the primary stream (`Hello`, `Welcome`, heartbeats),
  and renews the certificate two thirds into its lifetime. `--control-plane-ca` trusts a private CA.
- **Condition.** `InkwallConfig` reports `ControlPlaneConnected`:
  - `Connected`;
  - `EnrollmentTokenMissing`, `EnrollmentTokenNotInOperatorNamespace`;
  - `EnrollmentTokenRejected` (waits for a new token);
  - `EnrollFailed`;
  - `CertificateRejected` and `CertificateExpired` (the identity is deleted; waits for a new token);
  - `ClusterDisabled` (waits for a configuration change);
  - `Unreachable`, `InvalidEndpoint`.
- **Chart values.** `controlPlane.caBundle` and `controlPlane.enrollmentToken` supply the CA and
  the token.

**Tested** on kind against a stub control plane (`operator/test/stubcontrolplane`, built on
`operator/test/fakecontrolplane`), never a real one:

- enroll, connect, heartbeats, state sync, events;
- a Managed round trip: a policy sent through the stub's `POST /snapshot` is written, blocks
  through Traefik, is acknowledged and comes back `Enforced`. `kubectl edit`, `patch`, label
  removal and delete are refused. A bad snapshot changes nothing; an empty one prunes;
- a used token, refused.

**Built: state sync and events.**

- The leader sends `ClusterState` after `Welcome`, on any change (checked every 5 s), on `Resync`,
  and every 5 min. It only reads the cluster to do so.
- The engines go last in `ClusterState`, by engine ID, as many as fit in the contract's 16 MiB.
  The engines left out are counted by `inkwall_operator_state_engines_left_out`.
- Every replica forwards its engines' security events on its own events stream, while the control
  plane accepts them. They go through a bounded disk buffer (`--events-dir`, an `emptyDir`). When it
  is full, the oldest events are dropped and counted.
- What wasn't acknowledged is sent again after a reconnect or a restart.
  `inkwall_operator_events_buffered` follows the buffer, outages included.
- Every replica also sums its engines' request counts per policy and sends them on that stream
  every 10 s, when the control plane accepts them, even if it doesn't accept events.
- The events stream reconnects with jittered backoff bounded at 10 s (the leader's primary stream:
  1 min), so the backlog drains soon after an outage.

**Built: Managed mode.** The leader applies each policy snapshot beside the stream, all or nothing.

1. **Refuse** (`PolicyNack`, nothing written):
   - a cluster not in Managed mode;
   - version 0, or a version older than the last applied;
   - any kind but `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet`;
   - a rule set with `configMapRef`;
   - an object without the namespace its kind needs, or listed twice;
   - an existing object the operator didn't write (no source label): it never takes one over.
2. **Dry run** every create, update and delete ([`dryRun: All`](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run), with [strict field validation](https://kubernetes.io/docs/reference/using-api/api-concepts/#field-validation), so the
   CRD schema and the validating webhook see each object, and an unknown field is refused rather
   than dropped). One refused object refuses the snapshot. A dry run that can't be done (the API
   server or the webhook is unreachable) isn't a refusal: the stream is dropped and the snapshot
   comes again.
3. **Write** the objects, rule sets first, labelled `inkwall.dev/source: saas`. The operator sets
   the label itself and ignores the snapshot's own value.
4. **Prune** the labelled objects the snapshot no longer has, policies first.
5. **Record** the version on the identity Secret (`waf.inkwall.dev/policy-version`, sent in
   `Hello`), and answer `PolicyAck`.

Retries and ordering:

- A write that fails after the dry run is retried for about 15 s. Then the stream is dropped, and
  the control plane sends the snapshot again on reconnect (`Hello` has the older version).
- The same version again is applied again (idempotent) and acknowledged.
- A snapshot still waiting when a newer one arrives is refused as superseded.

Nothing new feeds the engines. The bundle builder signs these CRDs with the cluster's key like any
other, and `ClusterState` reports their `Enforced` back.

**The validating webhook guards these objects.**

- In Managed mode, only the operator may create, change or delete an object labelled
  `inkwall.dev/source: saas`, or add or remove that label. The operator learns its own identity
  from a [`SelfSubjectReview`](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#self-subject-review) at start-up. The namespace controller may still delete the objects
  with their namespace.
- It fails closed, also when it can't read the mode.
- Deletes reach the webhook only for labelled objects (an `objectSelector`), so deleting anything
  else never needs the operator.
- Out of Managed mode, they are ordinary objects again: their owners can edit or delete them, and
  the operator no longer writes them. Whoever can edit the `InkwallConfig` can leave Managed mode.

## 5. Uninstall and disable

Removal must never leave a proxy failing closed on a missing engine.

**Built (v0.1.0):**

- **Suspend.** `InkwallConfig.spec.suspend: true` puts every engine in allow-all within seconds,
  and removes nothing.
- **Unprotected routes.** Ingresses and IngressRoutes that are no longer protected are unwired,
  level-based ([§4.4](#44-wiring-controller)).
- **`helm uninstall`** runs a [pre-delete hook](https://helm.sh/docs/topics/charts_hooks/), `inkwall-operator unwire`
  (`operator/manager/unwire.go`). It:
  1. scales the operator to 0 and waits for its pods (a draining replica still wires);
  2. sets the Pod webhook to `Ignore`;
  3. removes Inkwall's Middleware from every wired Ingress and IngressRoute, keeping the user's;
  4. deletes the Middlewares it created.

  `WAFPolicy` objects stay. Sidecars leave as proxy pods restart.
- Tested on kind: after the uninstall, a restarted Traefik serves the routes (an Ingress and an
  IngressRoute) without the engine.

**Built since, in milestone O5 (uninstall, suspend, chaos, scale; [§11](#11-milestones))**
(`operator/internal/wiring`):

- **Finalizer `waf.inkwall.dev/unwire`** on every `WAFPolicy`.
  - The wiring controller, on the leader, adds it before the policy's routes are wired. A policy it
    can't add it to yet is wired anyway (unwiring would drop its protection), and the add is
    retried.
  - A deleted policy is no longer wired. The finalizer is removed once none of its targets is still
    wired for it alone. This is read from the API server, since the cache may lag a wiring just
    done.
  - A route that can't be written holds the finalizer, retried, and keeps its namespace's
    Middleware. A target that doesn't exist, or whose CRD doesn't, holds nothing. A target another
    policy protects stays wired.
  - Deleted while the operator is down, the policy, its routes' wiring and enforcement stay until
    the operator is back.
  - Patches carry the `resourceVersion`, so another controller's finalizer is never dropped.
- **Injection off** (`--inject=false`, or the chart's `injection.enabled=false`, which removes the
  Pod webhook). The wiring controller still runs. It unwires every route it wired, deletes its
  Middlewares, removes the finalizer from every policy, and reports `Programmed=False`
  (`InjectionDisabled`).
  - The same happens when no Traefik pod is selected ([§4.4](#44-wiring-controller)): an
    `InkwallConfig` selector that doesn't match Traefik's pods, or an `InkwallConfig` deleted when
    the pods don't have the default labels.
  - Deleting an `InkwallConfig` doesn't unwire by itself. Without one, the operator uses the
    defaults, and keeps wiring the routes of the pods they still select.
- **Uninstall** runs the hook with injection off too. The hook also sets the `WAFPolicy` webhook to
  `Ignore` (no replica answers it, and it would refuse the update), and removes the finalizer from
  every policy. Deleting a policy, or its namespace, then never waits for an operator that is gone.
  Without the hook (`--no-hooks`, `uninstall.unwire=false`), the chart README says how to clean up.
- Tested on kind:
  - a policy deleted while the operator is scaled to 0 stays, wired, until the operator is back;
  - `helm upgrade --set injection.enabled=false` unwires, and Traefik serves the routes
    uninspected, also from a new pod;
  - an `InkwallConfig` selecting other pods unwires, and deleting it wires again.

## 6. Failure modes

| Failure | Traffic | Detection | Recovery |
|---|---|---|---|
| Operator down | None: engines keep their last bundle | Engines' `inkwall_operator_connected` is 0 | Restart; engines resync |
| Leader down | None | Leader election | A follower builds within ~15 s |
| Operator rollout | None: a stopping replica keeps serving for `--shutdown-delay` (5 s), not ready | — | Engines reconnect |
| Webhook down, proxy pod created | Detect mode: the pod starts uninspected. Block mode: the pod is refused; running pods serve | `SidecarMissing` | Restart the pod after recovery, or label it `waf.inkwall.dev/inject: "false"` to scale (uninspected) |
| Invalid rule | Rejected at admission | Error to `kubectl` / Argo CD | Fix the rule |
| Engine can't compile (version skew) | Engine keeps its previous bundle | `EngineNack` | Upgrade the engines or fix the rule |
| Bundle Secret deleted | None | Builder recreates it | Automatic |
| Bundle chunk deleted or edited | None; meanwhile new engines can't cold start from the Secret | Builder logs it | Automatic: published again |
| Bundle over 7.2 MiB compressed | None: the current bundle stays; changes are not published | Builder error; warning past 75%; `inkwall_operator_bundle_compressed_bytes` | Shrink the policies (fewer, or smaller rule sets) |
| Signing key rotated | None: the operator signs with the new key only once every connected engine trusts it | Secret's `rotation-phase`; operator logs the engines it waits for | Automatic ([§4.6](#46-bundle-builder-leader-only)); replace engines older than rotation |
| Unknown controller version | Wiring may break | `Programmed=False` | Update or pin the integration |
| API server down | None | — | Automatic |

Runbook: [When the operator is down](../../deploy/helm/inkwall/README.md#when-the-operator-is-down).

## 7. RBAC

Least privilege. The built rules are in [`role.yaml`](../../operator/config/rbac/role.yaml): a
`ClusterRole`, plus a `Role` in `inkwall-system`.

| Resources | Verbs | Why |
|---|---|---|
| `waf.inkwall.dev/*` | read; update status | Own CRDs |
| `wafpolicies` | update, patch | The `waf.inkwall.dev/unwire` finalizer ([§5](#5-uninstall-and-disable)) |
| `wafpolicies`, `wafrulesets`, `clusterwafrulesets` | create, update, delete | Managed mode ([§4.9](#49-upstream-sync-leader-only)); the webhook keeps others off them |
| `ingressclasses`, `ingresses`, `pods` | read | Resolution, injection checks, discovery |
| `gatewayclasses` (gateway.networking.k8s.io) | read | Discovery |
| `ingresses` | patch | Traefik annotation |
| `ingressroutes` (traefik.io) | read, patch | Traefik routes' `middlewares` |
| `httproutes`, `gateways`, `gatewayclasses` (gateway.networking.k8s.io) | read | HTTPRoute targets ([§4.5](#45-resolver)) |
| `middlewares` (traefik.io) | full | Traefik wiring |
| `configmaps` | full, cluster-wide | `inkwall-trust` per namespace, engine reports |
| `secrets` | in `inkwall-system` | Bundle, signing key, certificates |
| `roles`, `rolebindings` | in `inkwall-system` | Bundle Secret grant ([§4.3](#43-injection-controller)) |
| `tokenreviews`, `subjectaccessreviews` | create | Engine authentication ([§4.7](#47-distribution-server-all-replicas)) |
| webhook configurations | patch | `failurePolicy`, CA bundle |
| `namespaces/kube-system` | get | Cluster ID |
| `leases`, `events` | write | Leader election, events |

**Not yet:**

- one `ClusterRole` per controller, aggregated by the chart, with rules for absent proxies left out
  (`.Capabilities.APIVersions`). The markers are already grouped by integration; controller-gen
  merges them into one role;
- rules for writing Gateway API objects, Envoy Gateway, Istio and controller ConfigMaps;
- a `deployments` restart patch, only with `rollout: Automatic`.

## 8. Scale targets (v1)

| Dimension | Target |
|---|---|
| `WAFPolicy` objects | 5,000 |
| Routes resolved | 50,000 |
| Engines per cluster | 500 |
| Change → enforced everywhere (p95) | < 10 s |
| Operator memory | < 512 MiB |
| Bundle (compressed) | < 900 KiB in one Secret; up to 7.2 MiB in chunks |

**Measured** (#115) by `make scale-test SCALE=full` (`operator/test/scale`).

How the test runs:

- **Operator.** It runs with its production defaults (1 s debounce, 2 s engine reports, unthrottled
  client), in the test process. It talks to envtest's API server and [etcd](https://etcd.io/docs/) (Kubernetes 1.29), which
  are separate processes and not counted.
- **Objects.** Each policy targets its own route object: half Ingresses, half IngressRoutes. Each
  has 10 routes (2 hosts × 5 path prefixes).
- **Engines.** Fake engines (`operator/test/fakeengine`, 5 s heartbeats, one token each) run in a
  child process, also not counted. They verify and decode every bundle.
- **Timing.** First all objects are synced at once. Then 10 edits, of one policy each, with the
  operator idle between them, are timed until every engine ACKs the new bundle.
- **Memory** is the test process's: the Go heap ([`runtime.MemStats`](https://pkg.go.dev/runtime#MemStats), the peak sampled every 250 ms,
  garbage included) and peak RSS (`VmHWM`). The harness's share is small.
- **Reconcile** is the bundle reconciler's mean time during the edits (controller-runtime's
  histogram). **Resolve** is `resolver.Resolve` alone.
- **Machine.** One run per size, on a 12-thread i7-1255U with 16 GiB. The API server, the operator
  and the engines share it, so the times are pessimistic.

| Policies / routes | Engines | Peak RSS | Peak heap | Bundle gzip (raw) | Reconcile | Resolve | Initial sync | Change → all engines, p50 / max |
|---|---|---|---|---|---|---|---|---|
| 100 / 1,000 | 50 | 139 MiB | 116 MiB | 3 KiB (37 KiB) | 0.16 s | 1 ms | 1.0 s | 1.0 / 1.0 s |
| 100 / 1,000 | 500 | 198 MiB | 135 MiB | 3 KiB (37 KiB) | 0.32 s | 1 ms | 1.1 s | 1.1 / 1.1 s |
| 1,000 / 10,000 | 50 | 178 MiB | 146 MiB | 26 KiB (381 KiB) | 1.5 s | 12 ms | 0.6 s | 1.1 / 1.1 s |
| 1,000 / 10,000 | 500 | 193 MiB | 135 MiB | 26 KiB (381 KiB) | 3.4 s | 14 ms | 1.3 s | 1.6 / 7.9 s |
| 5,000 / 50,000 | 50 | 507 MiB | 432 MiB | 134 KiB (1.9 MiB) | 8.7 s | 41 ms | 21.6 s | 1.4 / 1.5 s |
| 5,000 / 50,000 | 500 | **518 MiB** | 369 MiB | 134 KiB (1.9 MiB) | 14 s | 52 ms | 16.1 s | 3.5 / 6.2 s |

Initial sync is the time from the last object created until every engine has all policies. With 10
edits, the p95 is the slowest edit.

Against the targets:

- **Bundle size: met.** It is 134 KiB compressed at 5,000 policies, far under 900 KiB.
  Uncompressed it is 1.9 MiB, nearly half of gRPC's default 4 MiB receive limit, which engines
  keep.
- **Change → every engine: met** since #149 (5.3 s at 5,000 × 500). Before, it was met up to
  5,000 policies × 50 engines (1.5 s), but not at 5,000 × 500: there it took 4 s typically, but one
  edit took 47 s.
  - Cause: waiting for one of the 50 send slots counted against a stream's 30 s idle timeout, and
    its heartbeats weren't read meanwhile. So engines were disconnected, and got the bundle again
    after reconnecting.
  - Fixed (#148): bundles are sent from a [goroutine](https://go.dev/tour/concurrency/1) of their own, so heartbeats are read meanwhile.
    Reruns at 5,000 × 500 since have no disconnects.
  - One edit in ten still took 11–28 s after it: the reconcile below. Since #149, the slowest of
    10 edits takes 5–6 s.
- **Operator memory: just over the target at 5,000 × 500** (518 MiB); met everywhere else.
  - Before: each stream marshalled the bundle itself. A stream's send returns once the message is
    queued on its connection, not once it is written. So the operator held engines × bundle bytes
    (1,004 MiB at 1,000 × 500, 2,038 MiB at 5,000 × 500).
  - Now (#147): each bundle is encoded once ([`grpc.PreparedMsg`](https://pkg.go.dev/google.golang.org/grpc#PreparedMsg), per send compressor), and every
    stream queues that one buffer. Memory no longer grows with the number of engines: 5,000 × 500
    is at 5,000 × 50's level, and the rest is the reconcile.
  - The live heap after a [GC](https://go.dev/doc/gc-guide) is under 110 MiB at every size.
  - The 1,000 × 500 and 5,000 × 500 rows are from after #147. Before it, on the same machine and
    harness: 988 MiB / 953 MiB heap at 1,000 × 500, and 2,007 MiB / 1,886 MiB at 5,000 × 500.
    Both runs shared the machine with a kind e2e test, so their times are noisier.
- **The reconcile and the initial sync** (#149). Each new bundle wrote the `status.bundleVersion`
  of every policy, then the Reporter rewrote every `Enforced`. So a reconcile took 9–19 s at 5,000
  policies, and changes during it waited.
  - Now a bundle writes the status of the policies it changes only
    ([§4.8](#48-status-aggregator)), and the first build after a sync writes up to 8 statuses at
    once.
  - Same machine and harness, before → after:

| Policies / engines | Reconcile | Initial sync | Change → all engines, p50 / p95 / max |
|---|---|---|---|
| 5,000 × 50 | 15.9 → 0.42 s | 25.0 → 3.2 s | 1.4 / 3.1 / 3.1 → 1.8 / 2.5 / 2.5 s |
| 5,000 × 500 | 12.1 → 0.37 s | 15.8 → 5.2 s | 3.8 / 10.8 / 10.8 → 3.9 / 5.3 / 5.3 s |

  The table above predates #149. With 10 edits, p95 and max are the same edit. Peak RSS at
  5,000 × 500 was 404 MiB before and 509 MiB after, in one run each: under the target, but close.

**Engine memory per policy.** A compiled Coraza WAF with the CRS keeps
about 2.1 MiB of heap, and takes 10–15 ms to compile.

- Policies with the same rule sets and CRS settings share one compiled WAF, whatever their
  exclusions (#42).
- Exclusions are applied to each request, not compiled into the rule set. They use the
  transaction-level `ctl:ruleRemoveById` / `ruleRemoveTargetById`, with paths decided on
  `REQUEST_FILENAME` as before.
- `BenchmarkCompile` (`pkg/policy`, in the CI bench gate) compiles a bundle of CRS policies that
  differ only in exclusions, from an empty cache (i7-1255U, medians):

| Policies | Before: time | Before: live heap | After: time | After: live heap |
|---|---|---|---|---|
| 1 | 10 ms | 2.1 MiB | 10 ms | 2.1 MiB |
| 100 | 0.89 s | 205 MiB | 11 ms | 2.2 MiB |
| 1,000 | 9.3 s | 2.0 GiB | 15 ms | 2.9 MiB |

**One exception: rule sets that negate `ARGS` targets.** If a rule set's own SecLang negates an
`ARGS` target (`!ARGS:q`), it takes no argument exclusion per request. Coraza 3.8.1 adds a
transaction's target exclusions to the rule's own negations in place, so concurrent requests could
get each other's.

- A policy with argument exclusions on such rules gets compiled rule sets of its own, with the
  exclusions compiled in (`SecRuleUpdateTargetById` after the user's rules).
- That is one rule set for requests on no path exclusion, plus at most one per path exclusion with
  an argument. A request's rule set is chosen by its path (`argsNegation` in `pkg/rules/coraza`).
- The CRS and Inkwall's own rules negate no `ARGS` targets (`TestCRSNegatesNoArgs`).

Applying exclusions per request changes three things from v0.1.0:

- An argument exclusion (`when.argument`, without a path) now also covers the rules chained to the
  excluded rule, as one with a path already did. With rule sets that negate `ARGS` targets
  themselves, it is compiled in and covers the rule only, as before.
- A rule ID that no rule has, in an argument exclusion without a path, is ignored, as in every
  other exclusion. Before, it failed the bundle: `SecRuleUpdateTargetById` rejected it, and the
  engine kept its previous set.
- A rule set whose own SecLang negates `ARGS` targets falls back to rule sets per policy, as above.

## 9. Testing

- **Unit tests:** the resolver, bundle hashing and versioning, conflicts.
- **Golden files** for `Render` per controller version. Not yet: there is no `Render`
  ([§4.2](#42-integration-interface)).
- **envtest** (`operator/test/testenv`): reconcilers, conditions, wiring that keeps the user's
  entries, and webhooks.
- **kind e2e test** (`make kind-e2e`): injection, then wiring, then an attack blocked, then
  `Ready`, and a clean uninstall. It installs the operator with shorter waits, so the same steps
  take less time: a 15 s `--signing-key-grace` (its kind cluster's kubelet updates ConfigMaps
  within 10 s) and a 2 s `--selector-restart-max-delay`.
- **Scale**, with fake engines in envtest (`make scale-test`, [§8](#8-scale-targets-v1)). CI runs
  100 policies × 50 engines.
- **Upgrade** from the last release on kind (`make kind-upgrade`, every PR): routes stay protected
  through Traefik, wired once.
- **Planned:** chaos tests (kill the leader, delete the Secret, take the webhook down).

## 10. Code layout

```
operator/
├── api/v1alpha1/       # CRD types, CEL rules
├── bundle/             # builder, signer, signing key rotation
├── integrations/       # known proxies (Traefik)
├── internal/
│   ├── controller/     # reconcilers
│   ├── controlplane/   # upstream sync (§4.9)
│   ├── crdwatch/       # watches added once a CRD is installed
│   ├── discovery/      # proxy controllers in InkwallConfig.status (§4.1)
│   ├── distribution/   # BundleService server, auth, status
│   ├── injection/
│   └── wiring/         # the controller, Integration, Traefik
├── manager/
├── resolver/
├── webhook/            # validating + mutating handlers, Managed-mode guard
├── config/             # kubebuilder kustomize bases
└── test/               # testenv, fakeengine, fakecontrolplane, stubcontrolplane, scale
```

`main` is in `cmd/operator`. Planned: one package per proxy under `integrations/`. The Helm chart `deploy/helm/inkwall` is the supported install; [kustomize](https://kubectl.docs.kubernetes.io/references/kustomize/) is for
development.

## 11. Milestones

| # | Milestone | Exit criteria | Status |
|---|---|---|---|
| O1 | Scaffold + CRDs + validation | CRDs with CEL, webhook compiles SecLang, envtest green | Done (v0.1.0) |
| O2 | Resolver + bundle + distribution | An engine on its own (not injected) gets signed bundles; `Enforced` works | Done (v0.1.0) |
| O3 | Envoy Gateway | kind: one `WAFPolicy`, attack blocked, `Ready=True` | Not yet (v0.3.0) |
| O4 | Pod webhook + ingress-nginx, Traefik, HAProxy | Same attack blocked via all four in one cluster | Pod webhook and Traefik done (v0.1.0); ingress-nginx, HAProxy not yet |
| O5 | Uninstall, suspend, chaos, scale | [§5](#5-uninstall-and-disable) and [§6](#6-failure-modes) verified in CI | Uninstall, suspend, scale done; chaos not yet ([§9](#9-testing)) |
| O6 | Upstream sync | Enroll with a control plane stub; policy round-trip | Done, against the stub ([§4.9](#49-upstream-sync-leader-only)) |

Shipped out of order: the Pod webhook and Traefik (part of O4) came first, in v0.1.0, before
Envoy Gateway (O3).

## 12. Open questions

1. Require Kubernetes ≥ 1.29 for native sidecars, or support older clusters with a regular sidecar
   and a documented startup race?
2. Traefik on a plain `Ingress`: an Ingress mutating webhook (today the operator patches the
   annotation), or an entry-point middleware as the default?
3. Manage standalone engine Deployments (an engine behind a Service) where injection is
   impossible, or leave that to Helm?
4. Replica aggregation: gRPC between replicas, or ConfigMaps (v0.1.0 uses ConfigMaps)?
