# inkwall Helm chart

This [chart](https://helm.sh/docs/topics/charts/) installs the Inkwall [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/), its [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) and its [webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
([design](../../../docs/design/0004-operator.md)). The operator validates policies and rule sets,
builds them into a signed [bundle](../../../docs/glossary.md#bundle), serves the bundle to the engines, injects the engine into [Traefik](https://doc.traefik.io/traefik/)
[pods](https://kubernetes.io/docs/concepts/workloads/pods/) and, through [Envoy Gateway](https://gateway.envoyproxy.io/)'s `EnvoyProxy`, into Envoy pods, and wires the [`Ingress`](https://kubernetes.io/docs/concepts/services-networking/ingress/),
[`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) and [`HTTPRoute`](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) objects your policies target.

## Contents

- [Install](#install)
- [What it installs](#what-it-installs)
- [Values](#values)
- [Connecting to a control plane](#connecting-to-a-control-plane)
- [Rotating the signing key](#rotating-the-signing-key)
- [Uninstalling](#uninstalling)
  - [Turning injection off](#turning-injection-off)
  - [Deleting a policy](#deleting-a-policy)
- [When the operator is down](#when-the-operator-is-down)
- [When the engine is down](#when-the-engine-is-down)

## Install

You need [Kubernetes](https://kubernetes.io/docs/concepts/overview/) 1.29 or later and [Helm](https://helm.sh/docs/) 3. CI
tests on Kubernetes 1.34 and on kind's newest (1.37).

```sh
helm install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
  --namespace inkwall-system --create-namespace
kubectl -n inkwall-system rollout status deployment/inkwall-operator
```

The rollout finishing means the operator is running. Traefik pods created from then on get the
engine; restart the ones already running. Envoy Gateway rolls a Gateway's Envoy pods itself when
it gets its first protected route. To upgrade, see [upgrading](../../../docs/upgrading.md).

The chart is signed with [cosign](https://docs.sigstore.dev/cosign/signing/overview/) v3: see [CONTRIBUTING.md](../../../CONTRIBUTING.md#cutting-a-release)
for how to verify it. From a checkout, `make kind-operator` builds the images and installs
`deploy/helm/inkwall` on the [kind](https://kind.sigs.k8s.io/) cluster of `make kind-up`.

## What it installs

The names below are for a release named `inkwall`.

| Object | Notes |
|---|---|
| CRDs (`waf.inkwall.dev`) | Installed and upgraded with the chart, kept on uninstall (`crds.install`) |
| [`Deployment`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) `inkwall-operator` | 2 replicas with [leader election](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election); non-root, read-only root filesystem, no capabilities |
| [`PodDisruptionBudget`](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#pod-disruption-budgets) | When `operator.replicas` is more than 1 |
| [`ServiceAccount`](https://kubernetes.io/docs/concepts/security/service-accounts/), [`ClusterRole`, `Role` and bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) | Rules generated from the operator's code; the `Role` covers the release namespace only. They include writing Envoy Gateway's `EnvoyProxy`, `EnvoyExtensionPolicy`, `Backend` and `ClientTrafficPolicy` objects and patching Gateways, whether Envoy Gateway is installed or not |
| `ValidatingWebhookConfiguration` `inkwall-operator-validating` | WAF kinds only; fails closed, 2 s timeout |
| `MutatingWebhookConfiguration` `inkwall-operator-mutating` | Traefik pods only, at creation; fails open, or closed while a policy is in block mode (`injection.enabled`) |
| [`Service`](https://kubernetes.io/docs/concepts/services-networking/service/) `inkwall-operator-webhook` | The webhooks |
| `Service` `inkwall-operator` | Bundle distribution to the engines: [gRPC](https://grpc.io/docs/) over [TLS](https://www.rfc-editor.org/rfc/rfc8446) on port 9445 |
| Webhook certificate | A [`Secret`](https://kubernetes.io/docs/concepts/configuration/secret/) the operator fills, or a [cert-manager](https://cert-manager.io/docs/) [`Certificate`](https://cert-manager.io/docs/usage/certificate/) |
| [`ConfigMap`](https://kubernetes.io/docs/concepts/configuration/configmap/) `inkwall-control-plane-ca`, `Secret` `inkwall-enrollment` | Only with `controlPlane.caBundle` or `controlPlane.enrollmentToken` |
| [Pre-delete hook](https://helm.sh/docs/topics/charts_hooks/): [`Job`](https://kubernetes.io/docs/concepts/workloads/controllers/job/), `Role` and `RoleBinding` `inkwall-operator-unwire` | Runs only on `helm uninstall`: unwires the routes and releases the `WAFPolicy` objects (`uninstall.unwire`) |

The chart renders the CRDs, [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) rules and webhooks from `files/`, which `make generate` copies
from the operator's generated manifests. Don't edit `files/` by hand.

## Values

[`values.yaml`](values.yaml) has every value, with comments.

| Value | Default | |
|---|---|---|
| `operator.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-operator`, the chart's `appVersion`, `IfNotPresent` | |
| `operator.replicas` | `2` | One leads; all serve the webhooks |
| `operator.resources` | 100m CPU and 128Mi requested; 512Mi limit | |
| `operator.extraArgs` | `[]` | Extra `inkwall-operator` flags |
| `operator.podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | | The default [affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/) spreads the replicas across nodes |
| `operator.podDisruptionBudget.enabled`, `minAvailable` | `true`, `1` | |
| `engine.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-engine`, the chart's `appVersion`, `IfNotPresent` | The engine injected into Traefik pods and put into Envoy Gateway's Envoy pods; `InkwallConfig.spec.engine.image` overrides it |
| `injection.enabled` | `true` | Inject the engine into Traefik pods when they are created. `false`: see [turning injection off](#turning-injection-off) |
| `controlPlane.caBundle` | `""` | The optional control plane's CA (PEM), when its certificate isn't from a public CA, e.g. `--set-file controlPlane.caBundle=ca.crt` |
| `controlPlane.enrollmentToken` | `""` | The control plane's one-time enrollment token, stored in the Secret `inkwall-enrollment` (key `token`); or leave it empty and create that Secret yourself |
| `controlPlane.eventsBufferMiB` | `64` | Each replica's buffer of security events while the control plane is unreachable (an [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)); when it is full, the oldest events are dropped and counted |
| `uninstall.unwire` | `true` | On `helm uninstall`, unwire the routes first (a pre-delete hook), so they keep working, and remove the operator's [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/) from the `WAFPolicy` objects |
| `serviceAccount.name`, `annotations` | the operator's name (`inkwall-operator`), `{}` | |
| `crds.install` | `true` | |
| `distribution.port` | `9445` | The port engines connect to |
| `webhook.port`, `timeoutSeconds` | `9443`, `2` | |
| `webhook.certs.mode` | `rotate` | `rotate`: the operator creates, renews and injects a self-signed certificate. `certManager`: cert-manager issues it |
| `webhook.certs.certManager.issuerRef` | a self-signed `Issuer` | |

The chart names its namespaced objects after the release's full name: `inkwall` for a release
whose name contains `inkwall`, else `<release>-inkwall`. For a release named `waf`, for example,
the token Secret is `waf-inkwall-enrollment`. The webhook configurations keep the names in the
table above.

## Connecting to a control plane

The operator can connect to an optional control plane; `Standalone`, the default, never connects.
To connect, install the chart with the control plane's CA (if private) and its one-time
enrollment token, then point the cluster at it with an `InkwallConfig`:

```sh
helm upgrade --install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
  --namespace inkwall-system --create-namespace \
  --set-file controlPlane.caBundle=ca.crt --set controlPlane.enrollmentToken=<token>
```

The `InkwallConfig` isn't part of the chart, because a release can't create a custom resource of a
CRD it installs itself. [Connecting to a control plane](../../../docs/control-plane.md) shows how to
create it, check the connection, use Managed mode and disconnect.

## Rotating the signing key

The operator signs policy bundles with an [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) key it generates on first use, in the Secret
`inkwall-bundle-signing-key`. To rotate it now, change the `waf.inkwall.dev/rotate-signing-key`
[annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) on the `InkwallConfig`:

```sh
kubectl annotate inkwallconfig default --overwrite waf.inkwall.dev/rotate-signing-key="$(date +%s)"
```

To rotate it on a schedule, set `spec.signingKey.rotationInterval`. Traffic is unaffected.
[Rotating the bundle signing key](../../../docs/key-rotation.md) explains the phases, how to check
them and what a rotation waits for.

## Uninstalling

```sh
helm -n inkwall-system uninstall inkwall
```

Before anything is deleted, a pre-delete hook (`uninstall.unwire`, on by default) runs
`inkwall-operator unwire`. It stops the operator and sets the Pod and `WAFPolicy` webhooks to
`Ignore`. It removes Inkwall's Middleware from every route it wired, keeping your own
Middlewares. For Envoy Gateway, it deletes its `EnvoyExtensionPolicy`, `Backend` and
`ClientTrafficPolicy` objects, takes the engine out of your `EnvoyProxy` objects, and points the
Gateways it pointed at its own `EnvoyProxy` back at none. Every `WAFPolicy` then reports
`Programmed=False` and `Ready=False` (reason `Unwired`), and loses the `waf.inkwall.dev/unwire`
finalizer. The routes then keep working, uninspected; Traefik pods drop the engine when they
restart, and Envoy Gateway rolls its Envoy pods without it; deleting a policy, or its namespace, no
longer waits for the operator.

`helm uninstall` keeps:

- the CRDs, and so every WAF object;
- the Secrets the operator creates in its namespace: `inkwall-bundle`,
  `inkwall-bundle-signing-key` and, for a bundle too large for one Secret, its chunks (labelled
  `waf.inkwall.dev/bundle-chunk`).

A reinstall continues with the same signing keys, and any rotation in progress, so engines keep
trusting them. To remove the Secrets, delete the namespace.

If the hook fails, the uninstall stops. Find the cause in the hook's logs and run the uninstall
again:

```sh
kubectl -n inkwall-system logs job/inkwall-operator-unwire
```

Or skip the hook, with `helm uninstall --no-hooks` (or `uninstall.unwire=false`), and undo the
wiring yourself:

1. Remove the `inkwall-waf` entries from the Ingresses' `traefik.ingress.kubernetes.io/router.middlewares`
   annotations, from the IngressRoutes' `spec.routes[*].middlewares`, and the `ExtensionRef`
   filters to `inkwall-waf` from the HTTPRoutes' `spec.rules[*].filters`. The objects Inkwall
   wired are annotated `waf.inkwall.dev/wired`.
2. For Envoy Gateway, delete the objects labelled `app.kubernetes.io/managed-by: inkwall-operator`
   of the kinds `envoyextensionpolicies`, `backends` and `clienttrafficpolicies`
   (`gateway.envoyproxy.io`). In each `EnvoyProxy` annotated `waf.inkwall.dev/wired`, remove the
   init container `inkwall-engine`, the volumes `inkwall-*` and the mount `inkwall-socket`, and the
   annotations `waf.inkwall.dev/wired` and `waf.inkwall.dev/hash`. In each Gateway annotated
   `waf.inkwall.dev/wired`, remove `spec.infrastructure.parametersRef` (it names the operator's
   `EnvoyProxy`) and the annotation, then delete the operator's `EnvoyProxy` objects.
3. Remove the finalizer from the policies, or they can't be deleted:

   ```sh
   kubectl get wafpolicy -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}' |
     while read -r ns name; do
       kubectl -n "$ns" patch wafpolicy "$name" --type merge -p '{"metadata":{"finalizers":null}}'
     done
   ```

### Turning injection off

`--set injection.enabled=false` removes the Pod webhook: Traefik pods started from then on have no
engine. The operator keeps running, unwires every route it wired, deletes its Middlewares and
releases the policies (`Programmed=False`, reason `InjectionDisabled`). Traefik serves the routes
uninspected. It also undoes its Envoy Gateway wiring, as on uninstall.

The same happens when no running pod matches the integration's selector any more, because new pods
wouldn't get the engine (reason `SidecarMissing`). That is the case with an `InkwallConfig`
selector that doesn't match Traefik's pods, or after deleting that selector when Traefik's pods
don't have the default labels.

Turn injection on again and the routes are wired again at once. Restart Traefik to inject the
engine (reason `PendingRestart` until then).

### Deleting a policy

The operator holds each `WAFPolicy` with the `waf.inkwall.dev/unwire` finalizer until it has
unwired the policy's routes. A policy deleted while the operator is down, and its namespace, wait
for the operator; the routes stay wired and enforced meanwhile. Before going back to a version
without the finalizer (0.1.0), remove it from the policies [as above](#uninstalling), or they
can't be deleted.

## When the operator is down

Traffic is unaffected: every engine keeps enforcing its last bundle, and a new engine pod reads the
bundle Secret. What depends on the operator is **creating Traefik pods** (Envoy Gateway's Envoy
pods don't depend on it: their engine comes from the `EnvoyProxy`, not from the Pod webhook):

- **No policy in block mode:** the Pod webhook fails open. New Traefik pods start without the
  engine, so their traffic is not inspected. The affected policies report `Programmed=False`
  (reason `SidecarMissing`), with the pods to restart once the operator is back.
- **A policy in block mode:** the Pod webhook fails closed. A Traefik pod can't be created without
  its engine, so Traefik can't scale up or replace pods (after a [node drain](https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/) or failure) until the
  operator is back. Pods already running keep serving.

If Traefik must start pods before the operator is back, in order of preference:

1. Bring the operator back. Check its pods and events
   (`kubectl -n inkwall-system get pods,events`). Replacement Traefik pods are then created with the
   engine.
2. Let Traefik start **uninspected**: label its pods to opt out, so the webhook never sees them:

   ```sh
   kubectl -n <traefik namespace> patch deployment <traefik> --type merge \
     -p '{"spec":{"template":{"metadata":{"labels":{"waf.inkwall.dev/inject":"false"}}}}}'
   ```

   Remove the label once the operator is back; the pods restart and get the engine. Until then, the
   policies report `SidecarMissing`.

Don't edit the `MutatingWebhookConfiguration` instead: the operator sets its [`failurePolicy`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy) back
when it returns, and a `helm upgrade` resets it.

## When the engine is down

The policy's mode and failure mode are applied by the engine, so they hold only while it answers.
When Traefik can't reach the engine in its pod, Traefik answers **500** and doesn't forward the
request, **in detect mode as in block mode**: Traefik's [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) has no setting to let requests
through, or to change its timeout ([traefik/traefik#9857](https://github.com/traefik/traefik/issues/9857)).

| The engine | What Traefik's clients get |
|---|---|
| Crashed or restarting (connection refused) | 500 at once |
| Hung (no answer) | 500 after 30 s, Traefik's fixed timeout |
| Slower than the policy's `timeout` | The policy's failure mode: 503 in block mode, allowed in detect mode |

What keeps an outage short:

- Traefik starts only once its engine is ready (the engine is a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) with a startup
  probe).
- The kubelet restarts a crashed engine at once, then with a back-off, and a hung one once its
  liveness probe fails (about 30 s).
- While the engine isn't ready, neither is Traefik's pod, so its Service sends it no new
  connections. Run several Traefik replicas: an engine down in one pod then costs only the
  connections that pod already has.

To find an engine outage: `kubectl -n <traefik namespace> get pods` shows the restarts, and Traefik
logs `Error calling http://127.0.0.1:9001/v1/forward-auth` for each request it answered 500.

Through Envoy Gateway, Envoy answers 500 when it can't reach the engine, unless every policy on
the route fails open (`failureMode: Open`, or detect mode without one): the route's
`EnvoyExtensionPolicy` then has `failOpen: true`, and Envoy lets the request through uninspected.
When those policies are all in detect mode, it also has `shadowMode: true`: Envoy doesn't wait for
the engine at all, so a slow or hung engine delays nothing. Otherwise
Envoy waits for the engine 500 ms longer than the policy's `timeout`. A request the engine can't
inspect within the policy's `timeout` gets the policy's failure mode from the engine: 503 in block
mode. Large bodies take longer: CRS takes about 200 ms on a 48 KB form field on a fast machine, so
raise `timeout` (up to 1s) for routes that take large bodies.
