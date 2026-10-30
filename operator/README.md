# inkwall-operator

The Inkwall [Kubernetes operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) ([design](../docs/design/0004-operator.md)). To install it, use the
[Helm chart](../deploy/helm/inkwall/README.md). This page says what the operator does and how to
develop it.

## Contents

- [What it does](#what-it-does)
- [Develop](#develop)
- [Layout](#layout)

## What it does

- **Validates** `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet` objects with a [webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/). [SecLang](https://coraza.io/docs/seclang/)
  rules (`seclang`) must compile with the engine's [Coraza](https://coraza.io/) version after the [Core Rule Set](https://coreruleset.org/), and
  only rule directives are allowed (0004 §3.1). The webhook fails closed, for the WAF kinds only,
  and always accepts updates that don't change the spec.
- **Builds** the policies and the routes they target into a [policy bundle](../docs/glossary.md#bundle), signed with the
  cluster's [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) key, in the `inkwall-bundle` [Secret](https://kubernetes.io/docs/concepts/configuration/secret/). Past 900 KiB compressed, the bundle is
  split into chunk Secrets. The [leader](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election) builds it a second after a change, and every 10 minutes,
  and reports `Accepted` on each policy. It rotates the signing key on request (the
  `waf.inkwall.dev/rotate-signing-key` [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) on the `InkwallConfig`) or on a schedule,
  without an engine ever rejecting a bundle.
- **Serves** the bundle to the engines over [gRPC](https://grpc.io/docs/) with [TLS](https://www.rfc-editor.org/rfc/rfc8446) on port 9445, and reports `Enforced`
  from their acknowledgements.
- **Injects** the engine as a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) into [Traefik](https://doc.traefik.io/traefik/) [pods](https://kubernetes.io/docs/concepts/workloads/pods/) when they are created. It selects
  them by `app.kubernetes.io/name=traefik`, or by `InkwallConfig.spec.integrations[].selector`,
  and gives them the `inkwall-trust` [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) and read access to the bundle. A pod labelled
  `waf.inkwall.dev/inject: "false"` is left alone. `--inject=false` turns injection off and
  unwires the routes.
- **Wires** each targeted [`Ingress`](https://kubernetes.io/docs/concepts/services-networking/ingress/) or [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) to an `inkwall-waf` [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) [Middleware](https://doc.traefik.io/traefik/middlewares/overview/),
  placed first in its middlewares, and reports `Programmed`. The `waf.inkwall.dev/unwire`
  [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/) keeps a deleted policy until its routes are unwired.
- **Connects** to the optional control plane in `GitOps` and `Managed` mode
  ([guide](../docs/control-plane.md)).

`kubectl get wafpolicy -A` shows `READY` once a policy is accepted, wired and enforced by every
engine; the condition messages say what is missing (e.g. `PendingRestart`). Rules read from a
ConfigMap need the label `waf.inkwall.dev/rules=true`. The operator creates and rotates a
self-signed webhook certificate, in the `inkwall-operator-webhook-tls` Secret; with [cert-manager](https://cert-manager.io/docs/),
run it with `--webhook-certs=external`.

## Develop

`make help` lists every target. The ones for the operator:

| Target | What it does |
|---|---|
| `make generate` | Regenerates the deepcopy code, [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/), [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) and webhook configuration, and copies them into the chart |
| `make test` | Unit tests, and operator tests against a local API server ([envtest](https://book.kubebuilder.io/reference/envtest)) at `ENVTEST_K8S_VERSION`, the oldest supported Kubernetes |
| `make scale-test` | Checks the scale targets (0004 §8) with fake engines, in envtest |
| `make helm-lint` | Lints and renders the chart |
| `make kind-operator` | Builds the images, installs the chart on the [kind](https://kind.sigs.k8s.io/) cluster of `make kind-up`, and checks the webhook |
| `make kind-e2e` | End to end on kind: a `WAFPolicy` enforced by an engine in bundle mode |

To change the API:

1. Edit the types in `api/v1alpha1/`: validation as [kubebuilder markers](https://book.kubebuilder.io/reference/markers/crd-validation), [CEL rules](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-rules) in
   `+kubebuilder:validation:XValidation`.
2. Run `make generate`, and commit the generated files.
3. Add cases to `api/v1alpha1/validation_test.go`.

The CRDs validate on their own, without the operator:

```sh
kubectl apply --server-side -f operator/config/crd/bases -f operator/config/samples
```

## Layout

| Path | What |
|---|---|
| `api/v1alpha1/` | `waf.inkwall.dev/v1alpha1` types: `InkwallConfig`, `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` |
| `config/` | Generated CRDs, RBAC and webhook configuration (don't edit by hand); `samples/` has one object of each kind |
| `manager/` | Assembles the [controllers](https://kubernetes.io/docs/concepts/architecture/controller/), webhooks and [probes](https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/) ([`../cmd/operator`](../cmd/operator) is the binary) |
| `webhook/` | Validating webhook and its certificate |
| `integrations/` | The proxies Inkwall knows (Traefik) and their pod selectors |
| `resolver/` | `WAFPolicy` + Ingresses and IngressRoutes + rule sets → bundle policies and `Accepted` (pure; `inkwallctl test --policy` uses it too) |
| `bundle/` | Content hash, versions, Ed25519 signing and key rotation, the bundle and signing key Secrets |
| `internal/controller/` | Bundle builder |
| `internal/distribution/` | `BundleService` server, engine authentication and reports, `Enforced` |
| `internal/injection/` | Engine sidecar, trust ConfigMap, RBAC grant |
| `internal/wiring/` | Traefik Middleware, route wiring, `Programmed` |
| `internal/controlplane/` | Connection to the optional control plane: enrollment, cluster state, events, Managed mode |
| `internal/crdwatch/` | Watches a kind whose CRD may be missing, such as Traefik's `IngressRoute` |
| `test/fakeengine/`, `test/testenv/` | Fake engine speaking the bundle protocol; envtest API server |
| `test/fakecontrolplane/`, `test/stubcontrolplane/` | Fake control plane for tests, and the server the kind end-to-end test runs it in |
| `test/scale/` | Scale test (`make scale-test`) |
