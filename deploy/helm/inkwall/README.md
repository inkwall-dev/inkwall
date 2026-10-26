# inkwall Helm chart

Installs the Inkwall operator, its CRDs and its webhooks ([design](../../../docs/design/0004-operator.md)).
The operator validates policies and rule sets, builds them into a signed bundle, serves it to the
engines, injects the engine into Traefik pods and wires their Ingresses. Kubernetes 1.29 or later.

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
| `serviceAccount.name`, `annotations` | the release's full name, `{}` | |
| `crds.install` | `true` | |
| `distribution.port` | `9445` | Port engines connect to |
| `webhook.port`, `timeoutSeconds` | `9443`, `2` | |
| `webhook.certs.mode` | `rotate` | `rotate`: the operator creates, renews and injects a self-signed certificate. `certManager`: cert-manager issues it |
| `webhook.certs.certManager.issuerRef` | a self-signed `Issuer` | |

## Uninstalling

`helm uninstall` keeps the CRDs (and so every WAF object) and the two Secrets the operator creates
in its namespace, `inkwall-bundle` and `inkwall-bundle-signing-key`. A reinstall continues with the
same signing key, so engines keep trusting it. Delete the namespace to remove the Secrets. Uninstall
does not yet unwire the proxies first (milestone O5, 0004 §5).

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
