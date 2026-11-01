# Upgrading

This guide upgrades an Inkwall installation from 0.2.x (0.2.0 or 0.2.1) to 0.3.0, and from 0.1.x
(0.1.0 to 0.1.3) to 0.2.0, and lists what changes on the way. From 0.1.x, upgrade to 0.2.1 first,
then to 0.3.0: the upgrade test (`make kind-upgrade`) starts from the last release.

## Contents

- [From 0.2.x to 0.3.0](#from-02x-to-030)
  - [Before you upgrade](#before-you-upgrade)
  - [What's new in 0.3.0](#whats-new-in-030)
  - [What changes by itself in 0.3.0](#what-changes-by-itself-in-030)
  - [Upgrading the chart to 0.3.0](#upgrading-the-chart-to-030)
  - [Protecting HTTPRoutes](#protecting-httproutes)
  - [Checking 0.3.0 worked](#checking-030-worked)
  - [Rolling back to 0.2.x](#rolling-back-to-02x)
- [From 0.1.x to 0.2.0](#from-01x-to-020)
  - [Prerequisites](#prerequisites)
  - [What's new](#whats-new)
  - [What changes by itself](#what-changes-by-itself)
  - [Upgrading the chart](#upgrading-the-chart)
  - [Checking it worked](#checking-it-worked)
  - [Rolling back](#rolling-back)

## From 0.2.x to 0.3.0

0.3.0 protects [Gateway API](https://gateway-api.sigs.k8s.io/) [`HTTPRoute`](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) objects served by [Traefik's Gateway API
provider](https://doc.traefik.io/traefik/routing/providers/kubernetes-gateway/) or by [Envoy Gateway](https://gateway.envoyproxy.io/). `Ingress` and `IngressRoute` targets are wired as before.

### Before you upgrade

- Inkwall 0.2.x installed with the chart, the values you installed it with, and
  [Helm](https://helm.sh/docs/) 3.14 or later.
- [Kubernetes](https://kubernetes.io/docs/concepts/overview/) 1.29 or later, as before. CI now tests 0.3.0 on Kubernetes 1.34 (the upgrade
  test and [envtest](glossary.md#envtest)) and on kind's newest, 1.37. The Gateway API's v1.7 CRDs need
  Kubernetes 1.31 or later.
- **Check the policies that target an `HTTPRoute`.** 0.2.x accepted such targets but never
  enforced them: those policies were `Accepted=False` (`TargetUnsupported`). From 0.3.0, every
  `HTTPRoute` they target that Traefik or Envoy Gateway serves is wired and inspected, in the
  policy's mode. List them, and set `mode: Detect` on any you aren't sure of:

  ```sh
  kubectl get wafpolicy -A -o json |
    jq -r '.items[] | select(any(.spec.targetRefs[]; .kind == "HTTPRoute")) | "\(.metadata.namespace)/\(.metadata.name) \(.spec.mode // "Block")"'
  ```

- **Remove `spec.engine.socketDir` from your `InkwallConfig`**, if you set it. It never had an
  effect: Envoy Gateway's engine socket is in `/var/run/inkwall-socket`, and Traefik reaches the
  engine over loopback TCP. It is deprecated: setting or changing it draws a warning, and it will
  be removed from a later API version. An `InkwallConfig` that has it keeps working. One created
  before 0.3.0 may hold its old default, `/var/run/inkwall`; it is ignored, and keeping it as it
  is draws no warning.
- **Check how the chart grants the integrations' permissions.** The default,
  `rbac.integrations.*: true` (also with `--reuse-values`, which has no such values), grants every
  integration's role, as 0.2.x did, so a proxy installed after Inkwall is protected. If you opt
  into `auto`, the chart grants an integration's role only if its proxy's CRDs are installed when
  you run `helm upgrade`: run `helm upgrade` again once a proxy is installed, or its integration
  stays disabled (`IntegrationDisabled`). If Argo CD or Flux installs the chart, keep both values
  `true` or `false` in Git: Argo CD renders without asking the cluster, so `auto` grants every
  role, and Flux asks only when it upgrades the release ([GitOps](gitops.md)).
- Anything that parses the `Enforced` condition's message (alerts, scripts) needs the new text:
  see [below](#what-changes-by-itself-in-030).

### What's new in 0.3.0

The upgrade adds no new kinds, and changes the CRDs as follows:

| Object | Field | |
|---|---|---|
| `WAFPolicy` | `spec.targetRefs[*].kind: HTTPRoute` (`group: gateway.networking.k8s.io`), optional `sectionName` | Now resolved and wired: through Traefik's Gateway API provider (an `ExtensionRef` filter to the `inkwall-waf` Middleware), or through Envoy Gateway (an `EnvoyExtensionPolicy` calling the engine over [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)). `sectionName` protects one named rule of the route, and takes precedence over a policy on the whole route |
| `WAFPolicy` | `status.bundleVersion` | Now the first bundle that enforces the policy as it is now, not the newest bundle: a bundle that changes only other policies leaves it (#187) |
| `InkwallConfig` | `status.proxies` | The proxy controllers named by the cluster's IngressClasses and GatewayClasses, their integration, and how far Inkwall wires their routes: `Full`, `Partial` or `Unsupported`. Written into an existing `InkwallConfig` `default` only |
| `InkwallConfig` | `spec.engine.socketDir` | Deprecated and ignored ([above](#before-you-upgrade)); no default, no path rule |

The `ValidatingWebhookConfiguration` gets a webhook for `InkwallConfig`, with
`failurePolicy: Ignore`: it only warns, so the `InkwallConfig` stays editable while the operator
is down.

Each integration's permissions move into a `ClusterRole` of its own, `inkwall-operator-traefik`
and `inkwall-operator-envoy-gateway`; the base `inkwall-operator` role keeps what the resolver and
discovery read (routes, Gateways and classes). Traefik's role writes its Middlewares and the
references to them in Ingresses, IngressRoutes and now HTTPRoutes; Envoy Gateway's writes its
`EnvoyProxy`, `EnvoyExtensionPolicy`, `Backend` and `ClientTrafficPolicy` objects and patches
Gateways. The new chart values `rbac.integrations.traefik` and `rbac.integrations.envoyGateway`
choose which are granted ([integration permissions](../deploy/helm/inkwall/README.md#integration-permissions)):

| Value | Default | |
|---|---|---|
| `rbac.integrations.traefik`, `envoyGateway` | `true` | `true` always grants the role, `false` never. `auto` grants it when the cluster serves the proxy's API group (`traefik.io/v1alpha1`, `gateway.envoyproxy.io/v1alpha1`) at install or upgrade time; when Helm can't ask the cluster (`helm template`, `--dry-run=client`), every role. A value missing from your release (`--reuse-values`) means `true` |

The operator checks its permissions when it starts, and every minute. An integration it lacks some
of is disabled instead of stalling the others: a policy on its proxy's routes is `Programmed=False`
with the new reason `IntegrationDisabled`, naming the permissions missing, and
`InkwallConfig.status.proxies` lists the proxy as `Unsupported`. Without Traefik's role, the Pod
webhook selects no pod, so Traefik's pods start without an engine nothing would wire. When a role
is granted or revoked, each replica restarts after a random delay (`--selector-restart-max-delay`).

Besides `rbac.integrations`, no chart values change, and no operator flags are added.
The operator now sets the Go runtime's soft memory limit
([`GOMEMLIMIT`](https://go.dev/doc/gc-guide#Memory_limit)) to 90% of its container's memory limit
(`operator.resources.limits.memory`, 512Mi by default), so its garbage collector works harder near
the limit instead of letting the heap double. Without a memory limit, Kubernetes gives it the
node's allocatable memory, so the limit is then harmless. To change it, change
`operator.resources.limits.memory`.

New operator [metrics](https://prometheus.io/docs/concepts/data_model/):

| Metric | |
|---|---|
| `inkwall_operator_wired_targets{integration}` | Policy targets wired to the engine, by integration (`traefik`, `envoy-gateway`) |
| `inkwall_operator_wiring_failures{integration}` | Targets that couldn't be wired (`Programmed=False`, `WiringFailed`) |
| `inkwall_operator_engines_left_out` | Engines left out of a replica's engine report, over the ConfigMap's size limit; while any are, `Enforced` is `False` (`EnginesUnreported`) |
| `inkwall_operator_request_stats_dropped_total{reason}` | Policies' request counts dropped on their way to a control plane ([connecting to a control plane](control-plane.md)) |
| `inkwall_operator_state_engines_left_out` | Engines left out of the state sent to a control plane, over its message limit |

`inkwall-engine` gets the `ext-proc` command, Envoy's [external processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) over gRPC, which
the operator uses for Envoy Gateway ([running the engine without Kubernetes](standalone-proxy.md)).
`inkwallctl` gets `migrate ingress-nginx` ([migrating from ingress-nginx](migrating-from-ingress-nginx.md)), and
`inkwallctl test --ingress` reads Traefik `IngressRoute` and Gateway API `HTTPRoute` objects, as the
operator reads them, and checks their fields strictly: a misspelled field is an error
([testing policies](testing-policies.md)).

### What changes by itself in 0.3.0

Without any configuration on your part, the upgrade changes the following:

- **`HTTPRoute` targets are enforced**, as [above](#before-you-upgrade).
- **The `Enforced` condition's messages no longer count engines.** `Enforced=True` says
  `every engine runs bundle 42 or later`, and `EnginesBehind` says `some engines don't run bundle
  42 yet`, instead of `5/6 engines on bundle 42`. So engines that come and go (a proxy rollout)
  no longer rewrite every policy's status. `inkwall_operator_engines{state}` has the counts.
  `EngineNack` says `some engines rejected bundle 42 (first: shop/traefik-abc: error)`, naming
  the first engine that rejected it.
- **A new reason, `EnginesUnreported`**: `Enforced=False` while a replica's engine report leaves
  engines out (thousands of engines on one replica), and a key rotation waits meanwhile.
- **A policy's status is written only when it changes.** `status.bundleVersion` moves only when a
  bundle changes what the policy enforces (#187), and `Enforced` and `Ready` are written only when
  they change (#212). The `BUNDLE` column of `kubectl get wafpolicy` therefore differs between
  policies. Policies upgraded from 0.2.x keep their version until their next change.
- **`Programmed=False` after uninstall.** The `helm uninstall` hook now sets `Programmed=False`
  and `Ready=False`, reason `Unwired`, on every policy whose routes it unwired. In 0.2.x they kept
  `Programmed=True`.
- **Request counts.** Engines count, per policy, the requests they allow, deny and detect, with
  their latency, and the operator sends the totals to a connected control plane (GitOps or
  Managed mode, if the control plane asks for them). `Standalone` sends nothing.
- **Limits on what an engine sends.** The operator refuses an engine whose `Hello` or heartbeat
  carries oversized fields (an ID over 253 bytes, say), keeps the first 1,000 security events of
  a message and counts the rest as dropped, and cuts a rejection's error to 1 KiB. Engines from
  0.2.x stay well within these limits.
- **Less of the cluster in the operator's cache.** It caches proxy pods with one informer per
  integration selector. Before, custom `InkwallConfig` selectors that shared no label key with
  Envoy Gateway's made it cache and watch every pod in the cluster.
- **Your `ClientTrafficPolicy` wins.** When you add a `ClientTrafficPolicy` for a Gateway that has
  the operator's (`inkwall-waf-<gateway>`), the operator deletes its own, and your
  `connection.bufferLimit` then caps the bodies inspected ([client IP](client-ip.md#envoy-gateway)).

Traefik's pods keep their 0.2.x engine until they restart, so restart Traefik after the upgrade.
The 0.2.x engine keeps enforcing its rules, but misses what 0.3.0 changed in the engine: it sends
no request counts, and it matches an `HTTPRoute`'s wildcard hostname against a single DNS label,
not the several the Gateway API allows (`*.example.com` then doesn't cover `a.b.example.com`).
Envoy Gateway's pods need no restart: 0.2.x never put an engine in them. They get the 0.3.0
engine with a Gateway's first protected route, and Envoy Gateway rolls them itself whenever the
operator changes their `EnvoyProxy`, such as for a new engine image. An engine image set in
`InkwallConfig.spec.engine.image` stays as it is: change it to 0.3.0 yourself.

### Upgrading the chart to 0.3.0

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.3.0 \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   The chart upgrades the CRDs too (`crds.install`). If you install the CRDs yourself, apply the
   new ones first:

   ```sh
   helm template inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.3.0 \
     --show-only templates/crds.yaml | kubectl apply --server-side -f -
   ```

2. Wait for the operator:

   ```sh
   kubectl -n inkwall-system rollout status deployment/inkwall-operator
   ```

3. Restart Traefik, so its pods run the 0.3.0 engine ([above](#what-changes-by-itself-in-030)):

   ```sh
   kubectl -n <traefik namespace> rollout restart deployment/<traefik>
   ```

If Argo CD or Flux installs the chart, change the chart version in Git instead: see
[GitOps](gitops.md#installing-the-chart-with-a-gitops-tool). If they manage your `HTTPRoute`
objects or Envoy Gateway's `EnvoyProxy` objects, read [GitOps](gitops.md) for the fields the
operator now writes there.

### Protecting HTTPRoutes

To protect `HTTPRoute` objects, the proxy that serves them needs the Gateway API:

- **Traefik:** install the Gateway API CRDs (the [standard channel](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api)) and turn on
  Traefik's Gateway API provider (`providers.kubernetesGateway.enabled=true` in its chart). The
  operator wires the HTTPRoutes whose parent Gateway has a GatewayClass of controller
  `traefik.io/gateway-controller`.
- **Envoy Gateway** (v1.9; not with `mergeGateways`, nor Envoy as a DaemonSet): turn on its
  Backend API, which the engine's socket needs, with
  `--set config.envoyGateway.extensionApis.enableBackend=true` on its chart, as in the
  [README](../README.md#install). The operator puts the engine into the Envoy pods through each
  Gateway's `EnvoyProxy`, and Envoy Gateway rolls them: no restart on your part.

The operator looks for the Gateway API's and Envoy Gateway's CRDs every 30 s, so they can be
installed before or after the upgrade. Then target the routes, as in the
[README](../README.md#protect-a-route):

```yaml
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: web}
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api, sectionName: orders}
```

A route of another Gateway API controller is resolved into the bundle, but not wired: the policy
is `Programmed=False` (`ControllerUnsupported`). To see which controllers Inkwall wires, create
an `InkwallConfig` named `default` if you have none, and read its `status.proxies`.

### Checking 0.3.0 worked

```sh
helm -n inkwall-system list
kubectl get wafpolicy -A
kubectl get inkwallconfig default -o jsonpath='{range .status.proxies[*]}{.controllerName} {.support}{"\n"}{end}'
kubectl -n <traefik namespace> get pods -l app.kubernetes.io/name=traefik \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}'
```

It worked if the release shows chart version 0.3.0, the policies are `Ready`, the proxies you run
are `Full`, and Traefik's pods run the `inkwall-engine:0.3.0` image. Send an attack through a
protected route, as in the [README](../README.md#protect-a-route), to check it's blocked.

### Rolling back to 0.2.x

0.2.x neither wires nor unwires HTTPRoutes. Before `helm rollback`, unprotect them: remove the
`HTTPRoute` entries from every policy's `targetRefs`, or delete those policies. The operator then
removes its filters from the HTTPRoutes, takes the engine out of the `EnvoyProxy` objects, points
the Gateways it pointed at its own `EnvoyProxy` (`spec.infrastructure.parametersRef`) back at none,
and deletes its Envoy Gateway objects. Wait until the first command prints nothing (no HTTPRoute,
Gateway or `EnvoyProxy` still carries its mark) and the second finds no resources (none of its
`EnvoyExtensionPolicy`, `Backend`, `ClientTrafficPolicy` or `EnvoyProxy` objects is left):

```sh
kubectl get httproutes.gateway.networking.k8s.io,gateways.gateway.networking.k8s.io,envoyproxies.gateway.envoyproxy.io -A \
  -o jsonpath='{range .items[?(@.metadata.annotations.waf\.inkwall\.dev/wired)]}{.kind} {.metadata.namespace}/{.metadata.name}{"\n"}{end}'
kubectl get envoyextensionpolicies.gateway.envoyproxy.io,backends.gateway.envoyproxy.io,clienttrafficpolicies.gateway.envoyproxy.io,envoyproxies.gateway.envoyproxy.io \
  -A -l app.kubernetes.io/managed-by=inkwall-operator
```

Then roll back, and restart Traefik so its pods run the older engine again:

```sh
helm -n inkwall-system rollback inkwall
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```

0.2.x's CRD has no `status.proxies`, so the API server drops it.

## From 0.1.x to 0.2.0

### Prerequisites

- Inkwall 0.1.x installed with the chart, and the values you installed it with.
- [Helm](https://helm.sh/docs/) 3.14 or later, for
  [`--reset-then-reuse-values`](https://helm.sh/docs/helm/helm_upgrade/).

### What's new

From 0.1.1 or later, the upgrade changes no [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
and no chart values. The operator gets two flags, with the defaults it used before; set them with
`operator.extraArgs` if you need others:

| Flag | Default | |
|---|---|---|
| `--signing-key-grace` | `1m` | The least time each phase of a [signing key rotation](key-rotation.md) lasts |
| `--selector-restart-max-delay` | `30s` | When the `InkwallConfig`'s integration selectors change, or an integration's permissions are granted or revoked, each replica restarts after a random delay up to this |

From 0.1.0, the upgrade also adds fields to the existing CRDs, and makes some existing fields take
effect. It adds no new kinds.

| Object | Field | |
|---|---|---|
| `WAFPolicy` | `spec.targetRefs[*].kind: IngressRoute` (`group: traefik.io`) | Protect [Traefik](https://doc.traefik.io/traefik/) [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) objects |
| `InkwallConfig` | `spec.signingKey.rotationInterval` | Rotate the signing key on a schedule ([key rotation](key-rotation.md)) |
| `InkwallConfig` | [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) `waf.inkwall.dev/rotate-signing-key` | Rotate it now |
| `InkwallConfig` | `spec.mode: GitOps` or `Managed`, `spec.controlPlane` | Connect to a control plane ([control plane](control-plane.md)). In 0.1.0 they existed but did nothing |
| `InkwallConfig` | [condition](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties) `ControlPlaneConnected` | The connection's state |
| `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` | [label](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) `inkwall.dev/source: saas` | Objects written by the control plane in [Managed mode](glossary.md#cluster-mode) |

It adds these chart values, all off or idle by default:

| Value | Default | |
|---|---|---|
| `controlPlane.caBundle` | `""` | The control plane's CA, if private |
| `controlPlane.enrollmentToken` | `""` | Its one-time enrollment token |
| `controlPlane.eventsBufferMiB` | `64` | Each operator replica's buffer of security events while the control plane is unreachable |

Nothing connects to a control plane until you set `spec.mode` to `GitOps` or `Managed`:
`Standalone` stays the default. An `InkwallConfig` already set to `GitOps` or `Managed` under 0.1.0
starts connecting after the upgrade.

### What changes by itself

Without any configuration on your part, the upgrade from any 0.1.x changes the following:

- **Bundles split into chunks past 900 KiB.** A [bundle](glossary.md#bundle) of up to 900 KiB
  compressed stays in the [Secret](https://kubernetes.io/docs/concepts/configuration/secret/) `inkwall-bundle`, as before. A larger one, which 0.1.x
  couldn't publish, is split into Secrets named `inkwall-bundle-a-0`… or `inkwall-bundle-b-0`…,
  labelled `waf.inkwall.dev/bundle-chunk`, up to 7.2 MiB. The `inkwall-bundle-reader` Role, which
  lets Traefik's engines read the bundle, now also grants `get` on every chunk name. If you run an
  engine with `--bundle-secret` and a Role of your own, add the chunk names to it. Engines from
  0.1.x can't read a chunked Secret when they start, and refuse a streamed bundle over 4 MiB
  decompressed: they keep their last bundle, or wait for the operator.
- **The engine's answer to Traefik capped.** Each `inkwall-waf` ForwardAuth
  [Middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) gets
  `maxResponseBodySize: 65536`, except on Traefik before v3.7, whose CRD has no such field. Already
  set since 0.1.2.
- **The engine enforces its cached bundle from its first request.** A restarted engine container
  no longer answers before it applies its cached bundle
  ([GHSA-9x6c-5v2m-835r](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-9x6c-5v2m-835r),
  also fixed in 0.1.3). The fix is in the engine, so it takes effect when Traefik restarts.

From 0.1.0, the upgrade also changes the following:

- **A finalizer on every `WAFPolicy`.** The operator adds the
  [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)
  `waf.inkwall.dev/unwire`. A deleted policy then waits until the operator has unwired its
  routes. If you manage policies with [Argo CD](https://argo-cd.readthedocs.io/en/stable/) or [Flux](https://fluxcd.io/flux/), read [GitOps](gitops.md).
- **Unwiring when the engine can't be injected.** With `injection.enabled=false`, or when no
  running pod matches Traefik's selector, the operator unwires every route it wired and reports
  `Programmed=False` (reason `InjectionDisabled` or `SidecarMissing`), so the routes keep working,
  uninspected. 0.1.0 left them wired. The `helm uninstall` hook now also runs with injection off,
  and removes the finalizers.
- **Signing keys in a new format.** The Secret `inkwall-bundle-signing-key` and the `inkwall-trust`
  [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) get `trusted-keys.pub`, the list of keys engines accept. The key doesn't change.
  New engines read `trusted-keys.pub`; engines from 0.1.0 keep reading `ed25519.pub`, which
  stays.
- **New webhooks.** The [`ValidatingWebhookConfiguration`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) gets webhooks for deleting objects
  labelled `inkwall.dev/source: saas`. Unlabelled objects never reach them.
- **An events buffer** on each operator pod: an
  [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) of
  `controlPlane.eventsBufferMiB` + 16 MiB. It stays empty in Standalone.

Traefik pods keep their 0.1.x engine until they restart. That engine keeps working, but misses the
engine fixes made since, doesn't read chunks, and, from 0.1.0, holds up any signing key
rotation: restart Traefik after the upgrade. An engine image set in
`InkwallConfig.spec.engine.image` stays as it is: change it to 0.2.0 yourself.

### Upgrading the chart

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.2.0 \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   `--reset-then-reuse-values` takes the new chart's defaults, then your values. Passing your
   values file again (`-f values.yaml`) works too. Avoid `--reuse-values`, which keeps the old
   values without the new defaults. From 0.1.0, it failed on 0.1.1 with
   `nil pointer evaluating interface {}.caBundle`; the chart defaults those values since 0.1.2
   (#143).

   The chart upgrades the CRDs too (`crds.install`, on by default). If you install the CRDs
   yourself, apply the new ones first:

   ```sh
   helm template inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.2.0 \
     --show-only templates/crds.yaml | kubectl apply --server-side -f -
   ```

2. Wait for the operator:

   ```sh
   kubectl -n inkwall-system rollout status deployment/inkwall-operator
   ```

3. Restart Traefik, so its pods get the new engine:

   ```sh
   kubectl -n <traefik namespace> rollout restart deployment/<traefik>
   ```

If Argo CD or Flux
installs the chart, change the chart version in Git instead: see
[GitOps](gitops.md#installing-the-chart-with-a-gitops-tool).

### Checking it worked

```sh
helm -n inkwall-system list
kubectl get wafpolicy -A
kubectl get wafpolicy -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.metadata.finalizers}{"\n"}{end}'
kubectl -n <traefik namespace> get pods -l app.kubernetes.io/name=traefik \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}'
kubectl get middlewares.traefik.io -A --field-selector metadata.name=inkwall-waf \
  -o jsonpath='{range .items[*]}{.metadata.namespace} {.spec.forwardAuth.maxResponseBodySize}{"\n"}{end}'
```

It worked if the release shows chart version 0.2.0, the policies are `Ready` and carry
`waf.inkwall.dev/unwire`, Traefik's pods run the `inkwall-engine:0.2.0` image, and each
`inkwall-waf` Middleware has `maxResponseBodySize` 65536 (none on Traefik before v3.7). Send an
attack through a protected route, as in the [README](../README.md#protect-a-route), to check it's
blocked.

### Rolling back

0.1.x can't read a bundle split into chunks, and never publishes a bundle over 900 KiB. Before
`helm rollback`, check there are no chunks:

```sh
kubectl -n inkwall-system get secret -l waf.inkwall.dev/bundle-chunk
```

If there are, shrink the policies until the bundle fits again: 0.2.0 then stores it in
`inkwall-bundle` alone, and deletes the chunks. Otherwise the rolled-back operator can't read the
bundle and builds nothing. Then delete `inkwall-bundle` and its chunks, so it builds a new one, if
the policies fit:

```sh
kubectl -n inkwall-system delete secret inkwall-bundle
kubectl -n inkwall-system delete secret -l waf.inkwall.dev/bundle-chunk
```

Rolling back to 0.1.0 needs more: 0.1.0 doesn't know the finalizer, `IngressRoute` targets, Managed
mode or key rotation. Before `helm rollback`:

1. Switch to `Standalone` if you set another mode
   ([disconnecting](control-plane.md#disconnecting)), and wait for any signing key rotation to
   finish (the Secret's `waf.inkwall.dev/rotation-phase` is empty).
2. Delete the policies that target an `IngressRoute`.
3. Remove the finalizer from every policy, or none of them can be deleted under 0.1.0:

   ```sh
   kubectl get wafpolicy -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}' |
     while read -r ns name; do
       kubectl -n "$ns" patch wafpolicy "$name" --type merge -p '{"metadata":{"finalizers":null}}'
     done
   ```

Then roll back, and restart Traefik so its pods run the older engine again:

```sh
helm -n inkwall-system rollback inkwall
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```
