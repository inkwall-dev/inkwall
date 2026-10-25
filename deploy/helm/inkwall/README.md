# inkwall Helm chart

Installs the Inkwall operator, its CRDs and its validating webhook
([design](../../../docs/design/0004-operator.md)). Kubernetes 1.29 or later.

```sh
helm install inkwall deploy/helm/inkwall --namespace inkwall-system --create-namespace
kubectl -n inkwall-system rollout status deployment/inkwall-operator
```

On the kind cluster of `make kind-up`, `make kind-operator` builds the operator image, installs
the chart with it and checks that the webhook is served.

The operator validates rule sets and policies when they are saved, builds them into a signed
bundle, and serves it to the engines. Injecting the engine into the proxies is the next step.

## What it installs

| Object | Notes |
|---|---|
| CRDs (`waf.inkwall.dev`) | Installed and upgraded with the chart, kept on uninstall (`crds.install`) |
| `Deployment` `inkwall-operator` | 2 replicas, leader election; non-root, read-only root filesystem, no capabilities |
| `PodDisruptionBudget` | When `operator.replicas` > 1 |
| `ServiceAccount`, `ClusterRole`, `Role` and bindings | Rules generated from the operator's code; the `Role` covers the release namespace only |
| `ValidatingWebhookConfiguration` `inkwall-operator-validating` | WAF kinds only, fails closed, 2 s timeout |
| `MutatingWebhookConfiguration` `inkwall-operator-mutating` | Traefik pods only, at creation, fails open (`injection.enabled`) |
| `Service` `inkwall-operator-webhook` | |
| `Service` `inkwall-operator` | Bundle distribution to the engines, gRPC over TLS on port 9445 |
| Webhook certificate | `Secret` filled by the operator, or a cert-manager `Certificate` |

**Uninstalling** keeps the CRDs (and so every WAF object), and the two Secrets the operator creates
in its namespace: `inkwall-bundle` and `inkwall-bundle-signing-key`. A reinstall continues with the
same signing key, so engines keep trusting it. Delete the namespace to remove them. A full uninstall
that first unwires the proxies is part of milestone O5 (0004 §5).

The CRDs, RBAC rules and webhooks are rendered from `files/`, which `make generate` copies from
the operator's generated manifests: don't edit `files/` by hand.

## Values

| Value | Default | |
|---|---|---|
| `operator.image.repository` | `ghcr.io/inkwall-dev/inkwall-operator` | |
| `operator.image.tag` | the chart's `appVersion` | |
| `operator.replicas` | `2` | One leads; all serve the webhook |
| `operator.resources` | 100m CPU, 128Mi requested; 512Mi limit | |
| `operator.extraArgs` | `[]` | Extra `inkwall-operator` flags |
| `operator.nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | | Default affinity spreads replicas across nodes |
| `operator.podDisruptionBudget.minAvailable` | `1` | |
| `serviceAccount.name`, `serviceAccount.annotations` | | |
| `crds.install` | `true` | |
| `webhook.certs.mode` | `rotate` | `rotate`: the operator creates, renews and injects a self-signed certificate. `certManager`: cert-manager issues it |
| `webhook.certs.certManager.issuerRef` | a self-signed `Issuer` | |
| `webhook.port`, `webhook.timeoutSeconds` | `9443`, `2` | |
| `distribution.port` | `9445` | Port engines connect to |
| `engine.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-engine`, the chart's `appVersion` | The engine injected into Traefik's pods; `InkwallConfig.spec.engine.image` overrides it |
| `injection.enabled` | `true` | Inject the engine into Traefik pods when they are created |
