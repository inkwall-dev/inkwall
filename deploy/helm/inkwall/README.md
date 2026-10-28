# inkwall Helm chart

Installs the Inkwall operator, its CRDs and its webhooks ([design](../../../docs/design/0004-operator.md)).
The operator validates policies and rule sets, builds them into a signed bundle, serves it to the
engines, injects the engine into Traefik pods and wires their Ingresses and IngressRoutes.
Kubernetes 1.29 or later.

```sh
helm install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
  --namespace inkwall-system --create-namespace
kubectl -n inkwall-system rollout status deployment/inkwall-operator
```

The chart is signed with cosign (see [CONTRIBUTING.md](../../../CONTRIBUTING.md#cutting-a-release)).
From a checkout, `make kind-operator` builds the images and installs `deploy/helm/inkwall` on the
kind cluster of `make kind-up`.

## What it installs

| Object | Notes |
|---|---|
| CRDs (`waf.inkwall.dev`) | Installed and upgraded with the chart, kept on uninstall (`crds.install`) |
| `Deployment` `inkwall-operator` | 2 replicas, leader election; non-root, read-only root filesystem, no capabilities |
| `PodDisruptionBudget` | When `operator.replicas` > 1 |
| `ServiceAccount`, `ClusterRole`, `Role` and bindings | Rules generated from the operator's code; the `Role` covers the release namespace only |
| `ValidatingWebhookConfiguration` `inkwall-operator-validating` | WAF kinds only, fails closed, 2 s timeout |
| Pre-delete hook (`Job`, `Role`, `RoleBinding` `<release>-inkwall-operator-unwire`) | Runs only on `helm uninstall`: unwires the routes (`uninstall.unwire`) |
| `ConfigMap` `inkwall-control-plane-ca`, `Secret` `inkwall-enrollment` | Only with `controlPlane.caBundle` / `controlPlane.enrollmentToken` (names for a release named `inkwall`) |
| `MutatingWebhookConfiguration` `inkwall-operator-mutating` | Traefik pods only, at creation; fails open, or closed while a policy is in block mode (`injection.enabled`) |
| `Service` `inkwall-operator-webhook` | |
| `Service` `inkwall-operator` | Bundle distribution to the engines, gRPC over TLS on port 9445 |
| Webhook certificate | `Secret` filled by the operator, or a cert-manager `Certificate` |

The CRDs, RBAC rules and webhooks are rendered from `files/`, which `make generate` copies from the
operator's generated manifests: don't edit `files/` by hand.

## Values

See [`values.yaml`](values.yaml) for all of them.

| Value | Default | |
|---|---|---|
| `operator.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-operator`, the chart's `appVersion`, `IfNotPresent` | |
| `operator.replicas` | `2` | One leads; all serve the webhooks |
| `operator.resources` | 100m CPU, 128Mi requested; 512Mi limit | |
| `operator.extraArgs` | `[]` | Extra `inkwall-operator` flags |
| `operator.podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | | Default affinity spreads replicas across nodes |
| `operator.podDisruptionBudget.enabled`, `minAvailable` | `true`, `1` | |
| `engine.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-engine`, the chart's `appVersion`, `IfNotPresent` | The engine injected into Traefik pods; `InkwallConfig.spec.engine.image` overrides it |
| `injection.enabled` | `true` | Inject the engine into Traefik pods when they are created |
| `controlPlane.caBundle` | `""` | The optional control plane's CA (PEM), when its certificate isn't from a public CA; e.g. `--set-file controlPlane.caBundle=ca.crt` |
| `controlPlane.enrollmentToken` | `""` | Its one-time enrollment token, stored in the Secret `inkwall-enrollment` (key `token`; `<release>-inkwall-enrollment` for a release not named `inkwall`); or create that Secret yourself |
| `controlPlane.eventsBufferMiB` | `64` | Each replica's buffer of security events while the control plane is unreachable (an `emptyDir`); when full, the oldest are dropped and counted |
| `uninstall.unwire` | `true` | On `helm uninstall`, unwire the routes first (a pre-delete hook), so they keep working |
| `serviceAccount.name`, `annotations` | the release's full name, `{}` | |
| `crds.install` | `true` | |
| `distribution.port` | `9445` | Port engines connect to |
| `webhook.port`, `timeoutSeconds` | `9443`, `2` | |
| `webhook.certs.mode` | `rotate` | `rotate`: the operator creates, renews and injects a self-signed certificate. `certManager`: cert-manager issues it |
| `webhook.certs.certManager.issuerRef` | a self-signed `Issuer` | |

## Connecting to a control plane

Optional: Standalone, the default, never connects. For GitOps or Managed mode, install with the
control plane's CA (if private) and the one-time enrollment token it gave you, then point the
cluster at it:

```sh
helm upgrade --install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
  --namespace inkwall-system --create-namespace \
  --set-file controlPlane.caBundle=ca.crt --set controlPlane.enrollmentToken=<token>
kubectl apply -f - <<'YAML'
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata: {name: default}
spec:
  mode: GitOps
  controlPlane:
    endpoint: grpcs://<host>:<port>
    enrollmentSecretRef: {name: inkwall-enrollment, namespace: inkwall-system}
YAML
kubectl get inkwallconfig default -o jsonpath='{.status.conditions}'
```

The token Secret must be in the release namespace (`inkwall-enrollment` above is its name for a
release named `inkwall`). The operator enrolls once, keeps the cluster's
certificate in `inkwall-control-plane-identity`, and reports `ControlPlaneConnected`. The
`InkwallConfig` isn't part of the chart: a release can't create a custom resource of a CRD it
installs itself.

### Managed mode

With `mode: Managed`, policies come from the control plane. The operator writes each policy
snapshot it sends as `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet` objects labelled
`inkwall.dev/source: saas`, all or nothing (a server-side dry run of every object first; one
refused object refuses the snapshot and nothing changes), deletes the labelled objects a snapshot no
longer has, and acknowledges it. They are enforced like any other policy, in bundles signed with the
cluster's own key, and their `Enforced` condition goes back to the control plane.

Change them in the control plane, not with `kubectl`: while the cluster is in Managed mode the
validating webhook refuses anyone but the operator creating, editing or deleting a labelled object,
or adding or removing the label. Your own, unlabelled objects stay yours, and the operator never
overwrites one with a policy of the same name (it refuses the snapshot instead). Rule sets from the
control plane carry their rules inline: `configMapRef` is refused. Switching back to `GitOps` or
`Standalone` leaves the labelled objects in place, as ordinary objects you can edit or delete.

## Rotating the signing key

The operator signs policy bundles with an ed25519 key it generates on first use, in the
`inkwall-bundle-signing-key` Secret. To rotate it, give the `InkwallConfig` a new value of the
`waf.inkwall.dev/rotate-signing-key` annotation (any value: each new one starts a rotation), or
rotate it on a schedule with `spec.signingKey.rotationInterval`:

```sh
kubectl annotate inkwallconfig default --overwrite waf.inkwall.dev/rotate-signing-key="$(date +%s)"
kubectl -n inkwall-system get secret inkwall-bundle-signing-key \
  -o jsonpath='{.metadata.annotations.waf\.inkwall\.dev/rotation-phase}'
```

```yaml
spec:
  signingKey:
    rotationInterval: 2160h # 90 days
```

Traffic is unaffected. The operator publishes the new key to every engine first (the `inkwall-trust`
ConfigMaps; engines reload them without restarting), keeps signing with the old key until every
connected engine reports the new one, then switches, and drops the old key once every engine runs a
bundle the new key signed. The phase reads `Publishing`, then `Retiring`, then nothing. Each phase
lasts at least a minute, the time the kubelet takes to update a mounted ConfigMap. The operator logs
the engines it waits for; an engine from before Inkwall supported rotation never reports the new key,
so restart its pod to give it the current image. An engine you configured yourself reads its keys
from `--bundle-key`: keep that file in sync with the Secret's `trusted-keys.pub` during a rotation.

## Uninstalling

`helm uninstall` keeps the CRDs (and so every WAF object) and the two Secrets the operator creates
in its namespace, `inkwall-bundle` and `inkwall-bundle-signing-key`. A reinstall continues with the
same signing keys (and a rotation in progress), so engines keep trusting them. Delete the namespace
to remove the Secrets.

Before anything is deleted, a pre-delete hook (`uninstall.unwire`, on by default) runs
`inkwall-operator unwire`: it stops the operator, sets the Pod webhook to `Ignore`, and removes
Inkwall's Middleware from every route it wired, keeping your own middlewares. The routes then keep
working, uninspected; Traefik pods drop the engine when they restart. If the hook fails, the
uninstall stops: fix the cause (`kubectl -n <namespace> logs job/<release>-inkwall-operator-unwire`)
and run it again, or skip the hook with `helm uninstall --no-hooks` and remove the
`inkwall-waf` entries from the Ingresses' `traefik.ingress.kubernetes.io/router.middlewares`
annotations and from the IngressRoutes' `spec.routes[*].middlewares` yourself (the objects Inkwall
wired are annotated `waf.inkwall.dev/wired`).

## When the operator is down

Traffic is unaffected: every engine keeps enforcing its last bundle, and a new engine pod reads the
bundle Secret. What depends on the operator is **creating proxy pods**:

- **No policy in block mode:** the Pod webhook fails open. New Traefik pods start without the engine,
  so their traffic is not inspected. Affected policies report `Programmed=False`
  (`SidecarMissing`) with the pods to restart once the operator is back.
- **A policy in block mode:** the Pod webhook fails closed. A Traefik pod can't be created without
  its engine, so Traefik can't scale up or replace pods (after a node drain or failure) until the
  operator is back. Pods already running keep serving.

If Traefik must start pods before the operator is back, in order of preference:

1. Bring the operator back: check its pods and events (`kubectl -n <namespace> get pods,events`).
   Replacement Traefik pods are then created with the engine.
2. Let Traefik start **uninspected**: label its pods to opt out, which the webhook doesn't even
   see, for example:

   ```sh
   kubectl -n <traefik namespace> patch deployment <traefik> --type merge \
     -p '{"spec":{"template":{"metadata":{"labels":{"waf.inkwall.dev/inject":"false"}}}}}'
   ```

   Remove the label once the operator is back (the pods restart and get the engine). Until then the
   policies report `SidecarMissing`.

Don't edit the `MutatingWebhookConfiguration` instead: the operator sets its `failurePolicy` back
when it returns, and a `helm upgrade` resets it.
