# inkwall-operator

The Kubernetes operator ([design](../docs/design/0004-operator.md)). It is being built in the
milestones of 0004 §11; today it has the API and the manager the controllers will run in.

| Path | What |
|---|---|
| `api/v1alpha1/` | The `waf.inkwall.dev/v1alpha1` types: `InkwallConfig`, `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` |
| `config/crd/bases/` | The CRDs generated from the types (`make generate`); don't edit them by hand |
| `config/samples/` | One example of each kind |
| `test/testenv/` | Starts a local API server (envtest) for tests |
| [`../cmd/operator`](../cmd/operator) | The `inkwall-operator` binary |

## Trying the API

The CRDs validate objects on their own, without the operator running:

```sh
kubectl apply --server-side -f operator/config/crd/bases
kubectl apply --server-side -f operator/config/samples
kubectl get inkwall -A
```

## Changing the API

1. Edit the types in `api/v1alpha1/`. Validation is written as kubebuilder markers: OpenAPI
   constraints and CEL rules (`+kubebuilder:validation:XValidation`).
2. Run `make generate` to regenerate the deepcopy code and the CRDs, and commit both.
3. Add cases to `api/v1alpha1/validation_test.go`. `make test` runs them against a real API server
   at the oldest supported Kubernetes version (`ENVTEST_K8S_VERSION`).
