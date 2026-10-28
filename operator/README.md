# inkwall-operator

The Kubernetes operator ([design](../docs/design/0004-operator.md)). It:

- **validates** `WAFPolicy` and rule set objects with a webhook: `seclang` rules must compile with
  the engine's Coraza version after the Core Rule Set, and only rule directives are allowed
  (0004 §3.1). It fails closed for the WAF kinds only; updates that don't change the spec are
  always accepted;
- **builds** the policies and the Ingresses they target into a bundle, signed with the cluster's
  ed25519 key, in the `inkwall-bundle` Secret (leader only; a second after a change, and every
  10 minutes), and reports `Accepted` on each policy. It rotates the key on request (the
  `waf.inkwall.dev/rotate-signing-key` annotation on the `InkwallConfig`) or on a schedule, without
  an engine ever rejecting a bundle;
- **serves** the bundle to the engines over gRPC/TLS on port 9445 and reports `Enforced` from their
  acknowledgements;
- **injects** the engine as a native sidecar into Traefik pods at creation (selected by
  `app.kubernetes.io/name=traefik`, or `InkwallConfig.spec.integrations[].selector`), with the
  `inkwall-trust` ConfigMap and read access to the bundle. Opt a pod out with the label
  `waf.inkwall.dev/inject: "false"`; `--inject=false` turns injection off;
- **wires** each targeted Ingress to an `inkwall-waf` ForwardAuth Middleware (prepended to
  `traefik.ingress.kubernetes.io/router.middlewares`) and reports `Programmed`.

`kubectl get wafpolicy -A` shows `READY` once a policy is accepted, wired and enforced by every
engine; the condition messages say what's missing (e.g. `PendingRestart`). Rules read from a
ConfigMap need the label `waf.inkwall.dev/rules=true`. The webhook certificate is self-signed and
rotated by the operator, in the `inkwall-operator-webhook-tls` Secret; with cert-manager, run with
`--webhook-certs=external`.

Install it with the [Helm chart](../deploy/helm/inkwall).

## Develop

`make help` lists every target. The ones for the operator:

| Target | What |
|---|---|
| `make generate` | Regenerate deepcopy code, CRDs, RBAC and webhook configuration, and copy them into the chart |
| `make test` | Unit tests, operator tests against a local API server (envtest) at `ENVTEST_K8S_VERSION`, the oldest supported Kubernetes |
| `make helm-lint` | Lint and render the chart |
| `make kind-operator` | Build the images, install the chart on the kind cluster of `make kind-up`, check the webhook |
| `make kind-e2e` | End to end on kind: a `WAFPolicy` enforced by an engine in bundle mode |

To change the API: edit the types in `api/v1alpha1/` (validation as kubebuilder markers, CEL in
`+kubebuilder:validation:XValidation`), run `make generate` and commit the generated files, and add
cases to `api/v1alpha1/validation_test.go`.

The CRDs validate on their own, without the operator:

```sh
kubectl apply --server-side -f operator/config/crd/bases -f operator/config/samples
```

## Layout

| Path | What |
|---|---|
| `api/v1alpha1/` | `waf.inkwall.dev/v1alpha1` types: `InkwallConfig`, `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` |
| `config/` | Generated CRDs, RBAC and webhook configuration (don't edit by hand); `samples/` has one of each kind |
| `manager/` | Assembles controllers, webhooks and probes ([`../cmd/operator`](../cmd/operator) is the binary) |
| `webhook/` | Validating webhook and its certificate |
| `integrations/` | The proxies Inkwall knows (Traefik) and their pod selectors |
| `resolver/` | `WAFPolicy` + Ingresses and IngressRoutes + rule sets → bundle policies and `Accepted` (pure; `inkwallctl test --policy` uses it too) |
| `bundle/` | Content hash, versions, ed25519 signing and key rotation, bundle and signing key Secrets |
| `internal/controller/` | Bundle builder |
| `internal/distribution/` | `BundleService` server, engine authentication and reports, `Enforced` |
| `internal/injection/` | Engine sidecar, trust ConfigMap, RBAC grant |
| `internal/wiring/` | Traefik Middleware, Ingress annotation, `Programmed` |
| `test/fakeengine/`, `test/testenv/` | Fake engine speaking the bundle protocol; envtest API server |
