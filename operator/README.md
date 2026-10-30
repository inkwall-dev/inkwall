# inkwall-operator

The Inkwall Kubernetes operator ([design](../docs/design/0004-operator.md)). To install it, use the
[Helm chart](../deploy/helm/inkwall/README.md). This page says what the operator does and how to
develop it.

## Contents

- [What it does](#what-it-does)
- [Develop](#develop)
- [Layout](#layout)

## What it does

- **Validates** `WAFPolicy`, `WAFRuleSet` and `ClusterWAFRuleSet` objects with a webhook. SecLang
  rules (`seclang`) must compile with the engine's Coraza version after the Core Rule Set, and
  only rule directives are allowed (0004 §3.1). The webhook fails closed, for the WAF kinds only,
  and always accepts updates that don't change the spec.
- **Builds** the policies and the routes they target into a policy bundle, signed with the
  cluster's Ed25519 key, in the `inkwall-bundle` Secret. Past 900 KiB compressed, the bundle is
  split into chunk Secrets. The leader builds it a second after a change, and every 10 minutes,
  and reports `Accepted` on each policy. It rotates the signing key on request (the
  `waf.inkwall.dev/rotate-signing-key` annotation on the `InkwallConfig`) or on a schedule,
  without an engine ever rejecting a bundle.
- **Serves** the bundle to the engines over gRPC with TLS on port 9445, and reports `Enforced`
  from their acknowledgements.
- **Injects** the engine as a native sidecar into Traefik pods when they are created. It selects
  them by `app.kubernetes.io/name=traefik`, or by `InkwallConfig.spec.integrations[].selector`,
  and gives them the `inkwall-trust` ConfigMap and read access to the bundle. A pod labelled
  `waf.inkwall.dev/inject: "false"` is left alone. `--inject=false` turns injection off and
  unwires the routes.
- **Wires** each targeted `Ingress` or `IngressRoute` to an `inkwall-waf` ForwardAuth Middleware,
  placed first in its middlewares, and reports `Programmed`. The `waf.inkwall.dev/unwire`
  finalizer keeps a deleted policy until its routes are unwired.
- **Connects** to the optional control plane in `GitOps` and `Managed` mode
  ([guide](../docs/control-plane.md)).

`kubectl get wafpolicy -A` shows `READY` once a policy is accepted, wired and enforced by every
engine; the condition messages say what is missing (e.g. `PendingRestart`). Rules read from a
ConfigMap need the label `waf.inkwall.dev/rules=true`. The operator creates and rotates a
self-signed webhook certificate, in the `inkwall-operator-webhook-tls` Secret; with cert-manager,
run it with `--webhook-certs=external`.

## Develop

`make help` lists every target. The ones for the operator:

| Target | What it does |
|---|---|
| `make generate` | Regenerates the deepcopy code, CRDs, RBAC and webhook configuration, and copies them into the chart |
| `make test` | Unit tests, and operator tests against a local API server (envtest) at `ENVTEST_K8S_VERSION`, the oldest supported Kubernetes |
| `make scale-test` | Checks the scale targets (0004 §8) with fake engines, in envtest |
| `make helm-lint` | Lints and renders the chart |
| `make kind-operator` | Builds the images, installs the chart on the kind cluster of `make kind-up`, and checks the webhook |
| `make kind-e2e` | End to end on kind: a `WAFPolicy` enforced by an engine in bundle mode |

To change the API:

1. Edit the types in `api/v1alpha1/`: validation as kubebuilder markers, CEL rules in
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
| `manager/` | Assembles the controllers, webhooks and probes ([`../cmd/operator`](../cmd/operator) is the binary) |
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
