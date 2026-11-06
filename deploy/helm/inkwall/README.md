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
- [Proxy namespaces](#proxy-namespaces)
- [Integration permissions](#integration-permissions)
- [Connecting to a control plane](#connecting-to-a-control-plane)
- [Rotating the signing key](#rotating-the-signing-key)
- [Suspending inspection](#suspending-inspection)
- [Redacting security events](#redacting-security-events)
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
engine; restart the ones already running. Envoy Gateway and Istio roll a Gateway's pods themselves
when it gets its first protected route ([Istio](../../../docs/istio.md)). To upgrade, see [upgrading](../../../docs/upgrading.md).

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
| [`ServiceAccount`](https://kubernetes.io/docs/concepts/security/service-accounts/), [`ClusterRole`, `Role` and bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) | Rules generated from the operator's code; the `Role` covers the release namespace only. Each integration has a `ClusterRole` of its own, `inkwall-operator-traefik`, `inkwall-operator-envoy-gateway`, `inkwall-operator-istio`, `inkwall-operator-istio-ingress` and `inkwall-operator-haproxy`, granted unless `rbac.integrations` leaves it out: see [integration permissions](#integration-permissions) |
| `ValidatingWebhookConfiguration` `inkwall-operator-validating` | WAF kinds only; fails closed, 2 s timeout |
| `MutatingWebhookConfiguration` `inkwall-operator-mutating` | Three Pod webhooks: Traefik pods, the HAProxy Kubernetes Ingress Controller's and Istio ingress gateway pods (`istio: ingressgateway`) in the [proxy namespaces](#proxy-namespaces) only, at creation; fail open, or closed while a policy is in block mode (`injection.enabled`) |
| [`Service`](https://kubernetes.io/docs/concepts/services-networking/service/) `inkwall-operator-webhook` | The webhooks |
| `Service` `inkwall-operator` | Bundle distribution to the engines: [gRPC](https://grpc.io/docs/) over [TLS](https://www.rfc-editor.org/rfc/rfc8446) on port 9445 |
| Webhook certificate | A [`Secret`](https://kubernetes.io/docs/concepts/configuration/secret/) the operator fills, or a [cert-manager](https://cert-manager.io/docs/) [`Certificate`](https://cert-manager.io/docs/usage/certificate/) |
| [`ConfigMap`](https://kubernetes.io/docs/concepts/configuration/configmap/) `inkwall-control-plane-ca`, `Secret` `inkwall-enrollment` | Only with `controlPlane.caBundle` or `controlPlane.enrollmentToken` |
| [Pre-delete hook](https://helm.sh/docs/topics/charts_hooks/): [`Job`](https://kubernetes.io/docs/concepts/workloads/controllers/job/), `Role` and `RoleBinding` `inkwall-operator-unwire` | Runs only on `helm uninstall`: unwires the routes, releases the `WAFPolicy` objects and deletes the operator's trust ConfigMaps, bundle grant and leader Lease (`uninstall.unwire`) |

The chart renders the CRDs, [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) rules and webhooks from `files/`, which `make generate` copies
from the operator's generated manifests. Don't edit `files/` by hand.

## Values

[`values.yaml`](values.yaml) has every value, with comments.

| Value | Default | |
|---|---|---|
| `operator.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-operator`, the chart's `appVersion`, `IfNotPresent` | |
| `operator.replicas` | `2` | One leads; all serve the webhooks |
| `operator.resources` | 100m CPU and 128Mi requested; 512Mi limit | The operator sets `GOMEMLIMIT` to 90% of the memory limit, unless `GOMEMLIMIT` is set |
| `operator.extraArgs` | `[]` | Extra `inkwall-operator` flags |
| `operator.podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | | The default [affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/) spreads the replicas across nodes |
| `operator.podDisruptionBudget.enabled`, `minAvailable` | `true`, `1` | |
| `engine.image.repository`, `tag`, `pullPolicy` | `ghcr.io/inkwall-dev/inkwall-engine`, the chart's `appVersion`, `IfNotPresent` | The engine injected into Traefik pods and put into Envoy Gateway's Envoy pods and Istio's Gateway pods; `InkwallConfig.spec.engine.image` overrides it |
| `injection.enabled` | `true` | Inject the engine into proxy pods: Traefik's, the HAProxy Kubernetes Ingress Controller's and Istio ingress gateways' when they are created, Envoy Gateway's and Istio Gateways' through their configuration. `false`: see [turning injection off](#turning-injection-off) |
| `injection.proxyNamespaces` | `[traefik, kube-system, envoy-gateway-system, istio-ingress, istio-system, haproxy-controller]` | The namespaces the proxies' pods run in; only pods there get the engine and the policy bundle. See [proxy namespaces](#proxy-namespaces) |
| `controlPlane.caBundle` | `""` | The optional control plane's CA (PEM), when its certificate isn't from a public CA, e.g. `--set-file controlPlane.caBundle=ca.crt` |
| `controlPlane.enrollmentToken` | `""` | The control plane's one-time enrollment token, stored in the Secret `inkwall-enrollment` (key `token`); or leave it empty and create that Secret yourself |
| `controlPlane.eventsBufferMiB` | `64` | Each replica's buffer of security events while the control plane is unreachable (an [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)); when it is full, the oldest events are dropped and counted |
| `rbac.integrations.traefik`, `envoyGateway`, `istio`, `istioIngress`, `haproxy` | `true`, `true`, `true`, `true`, `true` | Grant each integration's `ClusterRole`: `true`, `auto` (when the cluster serves the proxy's API group) or `false`. See [integration permissions](#integration-permissions) |
| `uninstall.unwire` | `true` | On `helm uninstall`, unwire the routes first (a pre-delete hook), so they keep working, and remove the operator's [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/) from the `WAFPolicy` objects |
| `serviceAccount.name`, `annotations` | the operator's name (`inkwall-operator`), `{}` | |
| `crds.install` | `true` | |
| `distribution.port` | `9445` | The port engines connect to |
| `webhook.port`, `timeoutSeconds` | `9443`, `2` | |
| `webhook.certs.mode` | `rotate` | `rotate`: the operator creates, renews and injects a self-signed certificate. `certManager`: cert-manager issues it |
| `webhook.certs.certManager.issuerRef` | a self-signed `Issuer` | |

The chart names its namespaced objects after the release's full name: `inkwall` for a release
whose name contains `inkwall`, else `<release>-inkwall`. For a release named `waf`, for example,
the token Secret is `waf-inkwall-enrollment`. Names are cut to 63 characters: the operator's
other objects keep their suffix (`-webhook`, `-traefik`, ...), cutting the name before it. The webhook configurations keep the names in the
table above.

## Proxy namespaces

The operator recognises a proxy's pods by their labels: Traefik's `app.kubernetes.io/name: traefik`,
Envoy Gateway's `app.kubernetes.io/name: envoy` and `app.kubernetes.io/managed-by: envoy-gateway`,
Istio's `gateway.istio.io/managed: istio.io-gateway-controller` (Gateway API) and `istio: ingressgateway`
(its ingress gateways), the HAProxy Kubernetes Ingress Controller's
`app.kubernetes.io/name: kubernetes-ingress`, or the `InkwallConfig`'s selectors. A proxy pod gets the engine, and its ServiceAccount gets
read access to the policy bundle, which holds every namespace's policies and rules; with that
access, its engine connects to the operator and reports which bundle it enforces.

Anyone who may create a pod may give it those labels ([GHSA-r5cq-6vq5-q8qg](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-r5cq-6vq5-q8qg)). So the operator only looks for proxy pods in
the namespaces listed in `injection.proxyNamespaces`: `traefik`, `kube-system` (where k3s and RKE2
run Traefik), `envoy-gateway-system` (where Envoy Gateway runs the Envoy pods), and `istio-ingress`
and `istio-system` (where Istio's docs put Gateways: Istio runs a Gateway's pods in the Gateway's
namespace), and `haproxy-controller` (where the HAProxy Kubernetes Ingress Controller's docs install
it) by default. A pod
with a proxy's labels anywhere else is an ordinary pod: no engine, no access to the bundle. List
only namespaces whose pods you trust as much as the proxy itself: those where only the people who
run the proxy create pods.

If your proxy runs in another namespace, list it, with the defaults you still need:

```sh
helm upgrade --install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
  --namespace inkwall-system --create-namespace --reset-then-reuse-values \
  --set 'injection.proxyNamespaces={ingress,envoy-gateway-system}'
```

Until it is listed, the proxy's pods don't get the engine, its routes are not wired (they are
served uninspected), and policies on them report `Programmed=False` with reason `SidecarMissing`. `helm upgrade`
refuses to leave a proxy so: when pods that already run the engine are in a namespace the value
doesn't list, it stops with an error naming them (when Helm can reach the cluster; `helm template`
and Argo CD can't check).
Envoy Gateway runs the Envoy pods in its own namespace, unless its deployment mode puts them in each
Gateway's namespace: then list those namespaces, as for Istio Gateways in other namespaces. `{*}` makes every namespace a proxy namespace, as
before 0.3.0, 0.2.2 and 0.1.5: only for clusters where everyone who may create a pod may also read
every policy. Changing the value restarts the operator.

An engine configured by hand, with a Role of your own that grants `get` on the bundle Secret,
is not affected: the operator accepts any engine whose ServiceAccount may read the bundle.

## Integration permissions

Each integration's permissions are in a `ClusterRole` of its own: Traefik's writes its
Middlewares, and the references to them in Ingresses, IngressRoutes and HTTPRoutes; Envoy Gateway's writes its `EnvoyProxy`,
`EnvoyExtensionPolicy`, `Backend` and `ClientTrafficPolicy` objects and patches Gateways; Istio's
(`inkwall-operator-istio`) writes its `EnvoyFilter` objects and the ConfigMaps Gateways name in
their `parametersRef`, and patches Gateways; the HAProxy Kubernetes Ingress Controller's
(`inkwall-operator-haproxy`) writes the backend snippet annotations of its Ingresses (and reads its
`Backend` kind, so that the role is its own: Traefik's grants the same Ingress access). Without
it, the controller's pods don't get the engine. Istio ingress's (`inkwall-operator-istio-ingress`)
reads VirtualServices and Istio's own Gateways and writes its `EnvoyFilter` objects.
`rbac.integrations.<integration>` (`traefik`, `envoyGateway`, `istio`, `istioIngress`, `haproxy`) is one of:

- `true`, the default (also when the value is missing, as in `helm upgrade --reuse-values` from
  0.2): always granted, so a proxy installed after Inkwall is protected. On a cluster without the
  proxy, the role names kinds the cluster doesn't serve, which grants nothing usable;
- `auto`: the role is granted when the cluster serves the proxy's API group
  (`traefik.io/v1alpha1`, `gateway.envoyproxy.io/v1alpha1`, `networking.istio.io/v1alpha3`,
  `networking.istio.io/v1`, `ingress.v3.haproxy.org/v3`) at
  install or upgrade time, so a
  cluster without Envoy Gateway doesn't grant the operator its kinds. Install the proxy first, or
  run `helm upgrade` once it is installed. `helm template` and `--dry-run=client` can't ask the
  cluster, so they render every role;
- `false`: never granted.

```sh
helm upgrade --install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
  --namespace inkwall-system --create-namespace --set rbac.integrations.envoyGateway=false
```

The operator checks its permissions when it starts, and disables an integration it lacks some of
instead of failing. The other integrations work. A policy on a route of the disabled
integration's proxy reports `Programmed=False` with reason `IntegrationDisabled`, naming the
permissions missing and the `rbac.integrations` value that grants them, and
`InkwallConfig.status.proxies` lists that proxy as `Unsupported`, with the same message (when there
is an `InkwallConfig`):

```sh
kubectl get inkwallconfig default -o jsonpath='{.status.proxies}'
```

Without Traefik's role, its Pod webhook selects no pod: Traefik's pods start without the engine,
which nothing would wire. The same goes for Istio's ingress gateway pods without the
`istio-ingress` role.

Changing `rbac.integrations` restarts the operator, which then checks again. A role granted or
revoked outside the chart is picked up within about a minute: each replica restarts, after a
random delay, with the integration enabled or disabled. Routes the integration wired before it was
disabled stay wired: unprotect them (or uninstall) before leaving its role out.

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

If there is no `InkwallConfig` yet, create an empty one first, as
[the prerequisites](../../../docs/key-rotation.md#prerequisites) show.

To rotate it on a schedule, set `spec.signingKey.rotationInterval`. Traffic is unaffected.
[Rotating the bundle signing key](../../../docs/key-rotation.md) explains the phases, how to check
them and what a rotation waits for.

## Suspending inspection

The emergency switch: every engine allows every request, within seconds, and nothing is removed.
It sets `spec.suspend` on the `InkwallConfig` named `default`. That object is optional: a fresh
install has none and runs with the defaults, so the first command creates an empty one if it's
missing (an empty spec keeps every default), and the second sets `spec.suspend` and changes
nothing else.

<!-- e2e: suspend (hack/kind/e2e.sh runs this block) -->
```sh
kubectl get inkwallconfig default -o name 2>/dev/null || kubectl create -f - <<'YAML'
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
YAML
kubectl patch inkwallconfig default --type merge -p '{"spec":{"suspend":true}}'
```

Don't set it with `kubectl apply --server-side` and a manifest of only `spec.suspend`: on an
`InkwallConfig` created with a plain `kubectl apply`, kubectl's move to server-side apply then
removes every field the manifest leaves out. If the `InkwallConfig` lives in Git, change it there
instead, or your [GitOps](https://opengitops.dev/) tool may undo the switch.

While inspection is suspended, every `WAFPolicy` reports it: `Enforced=False` and `Ready=False`,
reason `Suspended`, with the message `InkwallConfig default suspends inspection (spec.suspend): every engine
allows every request`. The `InkwallConfig` has a `Suspended` condition, `True` while the bundle the
engines get suspends inspection:

<!-- e2e: suspended (hack/kind/e2e.sh runs this block) -->
```sh
kubectl get inkwallconfig default -o jsonpath='{.status.conditions[?(@.type=="Suspended")]}'
```

Resume:

<!-- e2e: resume (hack/kind/e2e.sh runs this block) -->
```sh
kubectl patch inkwallconfig default --type merge -p '{"spec":{"suspend":false}}'
```

Each policy is `Enforced` again once every engine runs the bundle that resumes inspection.

The switch works even when policy changes don't fit the bundle (policies `Accepted=False`, reason
`BundleTooLarge`): the bundle the engines run is published again, suspended, and once resumed, they
run it as before.

## Redacting security events

Each security event an engine sends to the operator (and on to the control plane, when one is
connected) names the rules that matched, the variable each matched (`ARGS:q`) and a snippet: at
most 64 bytes of what it matched. The engine never sends a snippet of:

- cookies, response bodies, and the `Authorization`, `Cookie`, `Set-Cookie` and
  `Proxy-Authorization` headers;
- an argument or a header whose name looks like a credential: it contains, in any case and
  ignoring `-`, `_` and `.`, `pass`, `pwd`, `secret`, `token`, `apikey`, `auth`, `session`,
  `sessid`, `jwt`, `bearer`, `credential`, `privatekey`, `card`, `ccnum`, `cvv`, `cvc`, or `ssn`
  as a word.
  `ARGS:password`, `ARGS_POST:token`, `ARGS_POST:json.user.Password` and `X-Api-Key` leave none,
  `ARGS:q` keeps its snippet. Some harmless names match (`author`): a missing snippet is the safe
  mistake;
- a whole query string or body (`QUERY_STRING`, `REQUEST_URI`, `REQUEST_BODY`) whose snippet
  contains one of those names.

`spec.events.redact` on the `InkwallConfig` adds to that:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  events:
    redact:
      headers: [X-Tenant-Secret]   # header names, any case
      arguments: [email, phone]    # argument-name parts, any case: user_email too
      snippets: false              # or send no snippets at all
```

The engines get it with the next bundle, within seconds; events already sent keep their snippets.
Engine logs never carry snippets, whatever this says.

## Uninstalling

```sh
helm -n inkwall-system uninstall inkwall
```

Before anything is deleted, a pre-delete hook (`uninstall.unwire`, on by default) runs
`inkwall-operator unwire`. It stops the operator and sets the Pod and `WAFPolicy` webhooks to
`Ignore`. It removes Inkwall's Middleware from every route it wired, keeping your own
Middlewares. For Envoy Gateway, it deletes its `EnvoyExtensionPolicy`, `Backend` and
`ClientTrafficPolicy` objects, takes the engine out of your `EnvoyProxy` objects, and points the
Gateways it pointed at its own `EnvoyProxy` back at none. For Istio, it deletes its `EnvoyFilter`
objects, takes the engine out of your Gateways' ConfigMaps (putting back the `deployment` overlay
as it was), and points the Gateways it pointed at its own ConfigMap back at none; for Istio's
ingress gateways, it deletes its `EnvoyFilter` objects. Every `WAFPolicy` then reports
`Programmed=False` and `Ready=False` (reason `Unwired`), and loses the `waf.inkwall.dev/unwire`
finalizer. The routes then keep working, uninspected; Traefik pods drop the engine when they
restart, as do Istio's ingress gateway pods, and Envoy Gateway and Istio's Gateway API roll their
pods without it; deleting a policy, or its namespace, no
longer waits for the operator. Last, the hook deletes what the operator created outside the chart
for itself and the engines: the `inkwall-trust` ConfigMaps in the proxy namespaces (labelled
`app.kubernetes.io/managed-by: inkwall-operator`; an unlabelled one of your own is kept), the
`inkwall-bundle-reader` Role and RoleBinding and the engine reports (`inkwall-engines-*`
ConfigMaps) in its namespace, and its leader Lease `inkwall-operator.waf.inkwall.dev`. Engines
still running keep their last bundle until their pod restarts.

`helm uninstall` keeps:

- the CRDs, and so every WAF object;
- the Secrets the operator creates in its namespace: `inkwall-bundle`,
  `inkwall-bundle-signing-key`, for a bundle too large for one Secret, its chunks (labelled
  `waf.inkwall.dev/bundle-chunk`), and, with a control plane, `inkwall-control-plane-identity`.

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
   For Istio, delete the `envoyfilters` (`networking.istio.io`) labelled
   `app.kubernetes.io/managed-by: inkwall-operator`. In each ConfigMap labelled
   `waf.inkwall.dev/sidecar: "true"`, put the annotation `waf.inkwall.dev/original-deployment` back
   as the `deployment` key (or remove the engine's entries) and remove that label and annotation;
   in each Gateway annotated `waf.inkwall.dev/configmap`, remove `spec.infrastructure.parametersRef`
   and the annotation, then delete the operator's ConfigMaps (`inkwall-waf-<gateway>`). That
   label also covers the `inkwall-istio-ingress` and `inkwall-istio-ingress-<00 to 31>`
   `EnvoyFilter` objects of Istio's ingress gateways.
3. Remove the finalizer from the policies, or they can't be deleted:

   ```sh
   kubectl get wafpolicy -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}' |
     while read -r ns name; do
       kubectl -n "$ns" patch wafpolicy "$name" --type merge -p '{"metadata":{"finalizers":null}}'
     done
   ```
4. Delete what the operator created besides: the trust ConfigMaps and engine reports, the bundle
   grant and the leader Lease.

   ```sh
   kubectl delete configmap -A -l app.kubernetes.io/managed-by=inkwall-operator
   kubectl -n inkwall-system delete role,rolebinding inkwall-bundle-reader --ignore-not-found
   kubectl -n inkwall-system delete lease inkwall-operator.waf.inkwall.dev --ignore-not-found
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
bundle Secret. What depends on the operator is **creating Traefik pods**, and Istio's ingress
gateway pods, which get the engine the same way (Envoy Gateway's Envoy pods and Istio's Gateway
API pods don't depend on it: their engine comes from their pod template, not from the Pod
webhook):

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

Through Istio, the route's ext_proc filter has the same settings (`failure_mode_allow` for
`failOpen`, `observability_mode` for `shadowMode`), and Envoy answers 503 when it can't reach the
engine (`status_on_error`) and 504 when the engine doesn't answer in time, unless every policy on
the route fails open. See [Istio](../../../docs/istio.md#when-the-engine-is-down).
