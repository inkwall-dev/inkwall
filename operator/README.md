# inkwall-operator

The Kubernetes operator ([design](../docs/design/0004-operator.md)). It is being built in the
milestones of 0004 §11; today it has the API, the validating webhook, and the manager the
controllers will run in.

| Path | What |
|---|---|
| `api/v1alpha1/` | The `waf.inkwall.dev/v1alpha1` types: `InkwallConfig`, `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` |
| `config/crd/bases/` | The CRDs generated from the types (`make generate`); don't edit them by hand |
| `config/rbac/`, `config/webhook/` | The operator's RBAC and webhook configuration, generated from markers |
| `config/samples/` | One example of each kind |
| `webhook/` | The validating webhook and its certificate |
| `test/testenv/` | Starts a local API server (envtest) for tests |
| [`../cmd/operator`](../cmd/operator) | The `inkwall-operator` binary |

## Trying the API

The CRDs validate objects on their own, without the operator running:

```sh
kubectl apply --server-side -f operator/config/crd/bases
kubectl apply --server-side -f operator/config/samples
kubectl get inkwall -A
```

## Validating webhook

The CRD schemas catch malformed objects. The webhook checks what they can't (0004 §3.1):

- **Rule sets** (`seclang`) must compile with the engine's Coraza version, loaded after the Core
  Rule Set as the engine loads them, so exclusions of CRS rules are checked too. Errors name the
  line. Only rule directives are allowed (`SecRule`, `SecAction`, `SecMarker`, `SecRuleRemoveBy*`,
  `SecRuleUpdate*`): settings that change the engine as a whole or write files are rejected.
  Rules read from a ConfigMap are checked when the bundle is built; the webhook warns about that.
- **Policies**: skip and exclusion paths must be clean, as the engine's router requires.

Updates that don't change the spec are always accepted, so an object stays editable and
deletable. The webhook fails closed for the WAF kinds only (`failurePolicy: Fail`, 2 s timeout).

Its certificate is self-signed and rotated by the operator ([cert-controller](https://github.com/open-policy-agent/cert-controller)):
the CA and serving certificate live in the `inkwall-operator-webhook-tls` Secret, the CA is
injected into the webhook configuration, and each replica copies the certificate to its webhook
server, so no volume mount is needed. With cert-manager instead, run with `--webhook-certs=external`.

## Changing the API

1. Edit the types in `api/v1alpha1/`. Validation is written as kubebuilder markers: OpenAPI
   constraints and CEL rules (`+kubebuilder:validation:XValidation`).
2. Run `make generate` to regenerate the deepcopy code and the CRDs, and commit both.
3. Add cases to `api/v1alpha1/validation_test.go`. `make test` runs them against a real API server
   at the oldest supported Kubernetes version (`ENVTEST_K8S_VERSION`).
