# Upgrading

This guide upgrades an Inkwall installation from 0.1.0 to 0.1.1 or later, and lists what changes
on the way.

## Contents

- [Prerequisites](#prerequisites)
- [What's new](#whats-new)
- [What changes by itself](#what-changes-by-itself)
- [Upgrading the chart](#upgrading-the-chart)
- [Checking it worked](#checking-it-worked)
- [Rolling back](#rolling-back)

## Prerequisites

- Inkwall 0.1.0 installed with the chart, and the values you installed it with.
- [Helm](https://helm.sh/docs/) 3.14 or later, for
  [`--reset-then-reuse-values`](https://helm.sh/docs/helm/helm_upgrade/).

## What's new

The upgrade adds fields to the existing [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/),
and makes some existing fields take effect. It adds no new kinds.

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

Without any configuration on your part, the upgrade changes the following:

- **A finalizer on every `WAFPolicy`.** The operator adds the
  [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)
  `waf.inkwall.dev/unwire`. A deleted policy then waits until the operator has unwired its
  routes. If you manage policies with [Argo CD](https://argo-cd.readthedocs.io/en/stable/) or [Flux](https://fluxcd.io/flux/), read [GitOps](gitops.md).
- **Unwiring when the engine can't be injected.** With `injection.enabled=false`, or when no
  running pod matches Traefik's selector, the operator unwires every route it wired and reports
  `Programmed=False` (reason `InjectionDisabled` or `SidecarMissing`), so the routes keep working,
  uninspected. 0.1.0 left them wired. The `helm uninstall` hook now also runs with injection off,
  and removes the finalizers.
- **Signing keys in a new format.** The [Secret](https://kubernetes.io/docs/concepts/configuration/secret/) `inkwall-bundle-signing-key` and the `inkwall-trust`
  [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) get `trusted-keys.pub`, the list of keys engines accept. The key doesn't change.
  New engines read `trusted-keys.pub`; engines from 0.1.0 keep reading `ed25519.pub`, which
  stays.
- **New webhooks.** The [`ValidatingWebhookConfiguration`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) gets webhooks for deleting objects
  labelled `inkwall.dev/source: saas`. Unlabelled objects never reach them.
- **An events buffer** on each operator pod: an
  [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) of
  `controlPlane.eventsBufferMiB` + 16 MiB. It stays empty in Standalone.

Traefik pods keep their 0.1.0 engine until they restart. That engine keeps working, but holds up
any signing key rotation: restart Traefik after the upgrade.

## Upgrading the chart

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   `--reset-then-reuse-values` takes the new chart's defaults, then your values. Passing your
   values file again (`-f values.yaml`) works too. Avoid `--reuse-values`, which keeps the 0.1.0
   values without the new defaults: upgrading to 0.1.1 with it fails with
   `nil pointer evaluating interface {}.caBundle`. The 0.1.2 chart defaults those values (#143).

   The chart upgrades the CRDs too (`crds.install`, on by default). If you install the CRDs
   yourself, apply the new ones first:

   ```sh
   helm template inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
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
```

It worked if the release shows the new chart version, the policies are `Ready` and carry
`waf.inkwall.dev/unwire`, and Traefik's pods run the new engine image.

## Rolling back

0.1.0 doesn't know the finalizer, `IngressRoute` targets, Managed mode or key rotation. Before
`helm rollback`:

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

Then roll back, and restart Traefik so its pods run the 0.1.0 engine again:

```sh
helm -n inkwall-system rollback inkwall
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```
