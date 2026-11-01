# Upgrading

This guide upgrades an Inkwall installation from 0.1.x (0.1.0 to 0.1.3) to 0.2.0, and lists what
changes on the way. Upgrading from 0.2.0 or 0.2.1 to 0.2.2 changes one thing:
[proxy pods only in the proxy namespaces](#what-changes-by-itself).

## Contents

- [Prerequisites](#prerequisites)
- [What's new](#whats-new)
- [What changes by itself](#what-changes-by-itself)
- [Upgrading the chart](#upgrading-the-chart)
- [Checking it worked](#checking-it-worked)
- [Rolling back](#rolling-back)

## Prerequisites

- Inkwall 0.1.x installed with the chart, and the values you installed it with.
- [Helm](https://helm.sh/docs/) 3.14 or later, for
  [`--reset-then-reuse-values`](https://helm.sh/docs/helm/helm_upgrade/).

## What's new

From 0.1.1 or later, the upgrade changes no [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).
From 0.2.2, it adds one chart value, `injection.proxyNamespaces` ([below](#what-changes-by-itself)),
with the operator flag `--proxy-namespaces`. The operator gets two more flags, with the defaults it used before; set them with
`operator.extraArgs` if you need others:

| Flag | Default | |
|---|---|---|
| `--signing-key-grace` | `1m` | The least time each phase of a [signing key rotation](key-rotation.md) lasts |
| `--selector-restart-max-delay` | `30s` | When the `InkwallConfig`'s integration selectors change, each replica restarts after a random delay up to this |

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

## What changes by itself

Without any configuration on your part, the upgrade from any 0.1.x changes the following:

- **Proxy pods only in the proxy namespaces** (from 0.2.2). The operator now looks for Traefik's
  pods only in the namespaces of the new value `injection.proxyNamespaces`: `traefik` and
  `kube-system` by default. Only pods there get the engine and read access to the bundle; a pod
  with Traefik's labels elsewhere is an ordinary pod. If Traefik runs in another namespace, list it when you upgrade ([step 1](#upgrading-the-chart)). Until then, its pods get no engine
  and its routes are not wired (served uninspected, `Programmed=False`, `SidecarMissing`); so
  when pods that run the engine are in a namespace the value doesn't list, `helm upgrade` stops
  with `pods with the Inkwall engine run in namespace(s) <namespaces>, which
  injection.proxyNamespaces doesn't list` and changes nothing. Add them, or set `{*}` to keep the
  old behaviour. Helm checks this only when it can reach the cluster: not with `helm template`,
  nor in Argo CD. See
  [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces). Also in 0.1.5.
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

## Upgrading the chart

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.2.0 \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   If Traefik runs in a namespace other than `traefik` or `kube-system`, add the
   [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces), e.g.
   `--set 'injection.proxyNamespaces={ingress}'`. Otherwise the upgrade stops with the message
   above, naming the namespaces to add.

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

## Checking it worked

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

## Rolling back

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
