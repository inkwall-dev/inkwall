# Protecting routes served by Istio

This guide protects the `HTTPRoute` routes that [Istio](https://istio.io/latest/docs/)'s Gateways serve: Istio's
implementation of the [Gateway API](https://gateway-api.sigs.k8s.io/), whose GatewayClass controller is
`istio.io/gateway-controller`. The operator adds the engine to the pods Istio runs for each Gateway,
and an [`EnvoyFilter`](glossary.md#envoyfilter) that sends the protected routes' requests to it through
Envoy's [ext_proc filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter). You write the same `WAFPolicy` as for any other proxy.

## Contents

- [Prerequisites](#prerequisites)
- [How it works](#how-it-works)
- [Protect a route](#protect-a-route)
- [The policy's status](#the-policys-status)
- [Settings](#settings)
  - [Block mode and detect mode](#block-mode-and-detect-mode)
  - [Bodies](#bodies)
  - [Rule names](#rule-names)
- [When the engine is down](#when-the-engine-is-down)
- [Your Gateway's ConfigMap](#your-gateways-configmap)
- [Limits](#limits)
- [Undoing it](#undoing-it)

## Prerequisites

- Istio 1.28 or later, with its Gateway API implementation (on by default) and the
  [Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api). Tested with Istio 1.31.3 (its `base` and `istiod` Helm
  charts, no mesh) and the Gateway API's standard CRDs v1.7.0. Istio's Envoy must be 1.36 or later:
  older ones reject the filter's settings, so the operator refuses to wire an older Istio (it reads
  the version from the `istio-proxy` image tag).
- Inkwall installed with `rbac.integrations.istio` not `false` (the default is `true`), and the
  namespace of each Gateway listed in `injection.proxyNamespaces`. Istio runs a Gateway's pods in
  the Gateway's namespace: `istio-ingress` and `istio-system` are listed by default; list your
  other Gateways' namespaces ([proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces)).
- Kubernetes 1.29 or later: the engine joins the Gateway's pods as a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/).

Install Istio first or after Inkwall, in either order. With `rbac.integrations.istio=auto`, the
role is granted only if the cluster serves `networking.istio.io/v1alpha3` at install time: run
`helm upgrade` once Istio is installed.

## How it works

For each Gateway that serves a protected HTTPRoute:

1. **The engine joins the Gateway's pods.** Istio renders a Gateway's Deployment and overlays it
   with the `deployment` key of the ConfigMap the Gateway names in
   `spec.infrastructure.parametersRef` ([Istio's Gateway API docs](https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/)). The operator adds
   the engine there: into your ConfigMap, if the Gateway names one, keeping your entries; or into
   a ConfigMap of its own, `inkwall-waf-<gateway>`, which it names in the Gateway. Istio rolls the
   Gateway's pods. The engine serves ext_proc on a Unix socket,
   `/var/run/inkwall-socket/extproc.sock`, in an [`emptyDir`](glossary.md#emptydir) also mounted in
   the `istio-proxy` container.
2. **Once every running pod of the Gateway has the engine**, the operator writes an `EnvoyFilter`,
   `inkwall-waf-<gateway>`, in the Gateway's namespace, for that Gateway's pods only. It adds a
   cluster for the engine's socket and, per protected HTTPRoute, an ext_proc filter that is off by
   default and on for the Envoy routes of the protected rules. Unprotected routes don't call the
   engine.
3. **The engine inspects each request** with the policy and answers: continue, or 403 for an
   attack (413 for an oversized body, 503 when it can't inspect the request in time).

Istio has no ext_proc extension provider of its own (its `extensionProviders` have ext_authz,
with no detect mode that lets a request through without waiting), so the operator writes the
filter itself. [Design 0002 §6.1](design/0002-system-architecture.md#61-envoy-raw-envoy-envoy-gateway-istio-contour)
records the decision.

## Protect a route

An HTTPRoute attached to an Istio Gateway:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: istio-ingress
spec:
  gatewayClassName: istio
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
  namespace: shop
spec:
  parentRefs: [{name: edge, namespace: istio-ingress}]
  hostnames: [shop.example.com]
  rules:
    - name: api
      matches: [{path: {type: PathPrefix, value: /api}}]
      backendRefs: [{name: api, port: 8080}]
    - backendRefs: [{name: web, port: 8080}]
```

A policy that targets it, or one rule of it (`sectionName`):

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
  namespace: shop
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: web}
  mode: Block
```

Then wait for the policy to be `Ready`, and send an attack through the Gateway:

```console
$ kubectl -n shop get wafpolicy web
NAME   MODE    READY   BUNDLE   AGE
web    Block   True    3        40s
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' "http://$GATEWAY/?id=1%27%20OR%20%271%27%3D%271"
403
```

`$GATEWAY` is the Gateway's address (`kubectl -n istio-ingress get gateway edge`). The operator's
objects:

```sh
kubectl -n istio-ingress get envoyfilter inkwall-waf-edge
kubectl -n istio-ingress get gateway edge -o jsonpath='{.spec.infrastructure.parametersRef}'
kubectl -n istio-ingress get pods -l gateway.networking.k8s.io/gateway-name=edge \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.initContainers[*].name}{"\n"}{end}'
```

## The policy's status

`Programmed` is `True` only when the route's requests reach the engine:

| `Programmed` reason | Meaning |
|---|---|
| `Programmed` | Every running pod of each of the route's Gateways has the engine, the `EnvoyFilter` has the route, and Istio has accepted the route on each Gateway (its parent status, `Accepted=True`) |
| `PendingRestart` | Istio is rolling a Gateway's pods; some don't have the engine yet |
| `SidecarMissing` | A Gateway has no running pod, or its namespace isn't a proxy namespace |
| `Pending` | Waiting for Istio to accept the route, or for another of its Gateways |
| `WiringFailed` | Istio's `EnvoyFilter` CRD isn't installed; Istio is older than 1.28; a rule name is shared ([rule names](#rule-names)); the Gateway's ConfigMap doesn't exist or its `deployment` key isn't YAML; or an `EnvoyFilter` named `inkwall-waf-<gateway>` isn't the operator's |
| `IntegrationDisabled` | The operator lacks the `inkwall-operator-istio` ClusterRole (`rbac.integrations.istio`) |

Istio reports nothing on an `EnvoyFilter`, so `Programmed` rests on the pods and the route's
status. While a route waits for one of its Gateways, it stays wired on its other Gateways whose
pods have the engine. `Ready` follows `Programmed`, so a policy is never `Ready` while its traffic
goes uninspected. A route also attached to a Gateway of a proxy Inkwall doesn't wire is
`Programmed`, with a message naming it: its traffic there isn't inspected.

`kubectl get inkwallconfig default -o jsonpath='{.status.proxies}'` lists `istio.io/gateway-controller`
as `Full` (or `Unsupported`, with the reason, when the integration is disabled).

## Settings

Each protected route's filter has the settings of its policies, as through Envoy Gateway. When
several policies target the same route, the strictest wins.

| Policy | ext_proc |
|---|---|
| Headers | Sent, with `request.protocol` |
| A policy inspects bodies | `request_body_mode: BUFFERED_PARTIAL` (Envoy holds the request until the engine answers) |
| `timeout` (250 ms by default) | `message_timeout`: the longest timeout plus 500 ms, so the engine decides first |
| `failureMode: Open` on every policy (or detect mode without one) | `failure_mode_allow: true` |
| Otherwise | `failure_mode_allow: false`, `status_on_error: 503` |
| Responses | Not sent |

### Block mode and detect mode

In block mode, Envoy waits for the engine's verdict. When every policy on the route is in
`Detect` mode (and fails open), the filter has `observability_mode: true`: Envoy sends the engine
a copy of the request, body streamed, and forwards it without waiting. The engine logs what it
would have blocked.

### Bodies

Envoy hands ext_proc at most its per-connection buffer of a body. When a route's body is held for
the engine, the `EnvoyFilter` raises the Gateway's listeners' `per_connection_buffer_limit_bytes`
to 10 MiB, the largest `body.maxBytes`. A body cut there is handled as an oversized one
(`body.onOversize`).

### Rule names

Istio names the Envoy route of an HTTPRoute rule after the rule's `name`, or
`<namespace>.<route>.<index>` for an unnamed rule, without the route's name. The filter is turned on
by those names, so a protected rule named like a rule of another HTTPRoute on the same Gateway
would turn it on for that route too. The operator refuses that (`WiringFailed`, naming both):
rename one of the rules.

## When the engine is down

| The engine | What clients get, in block mode |
|---|---|
| Unreachable (crashed, restarting) | 503 (`status_on_error`) |
| Hung (no answer) | 504, after the policy's `timeout` plus 500 ms |
| Slower than the policy's `timeout` | The policy's failure mode, from the engine: 503 |

When every policy on the route fails open, Envoy lets the request through uninspected instead; in
detect mode it doesn't wait at all. The kubelet restarts a crashed engine, and a hung one once its
liveness probe fails (about 30 s). Run several Gateway replicas.

## Your Gateway's ConfigMap

If your Gateway already names a ConfigMap in `spec.infrastructure.parametersRef`, the operator
edits only its `deployment` key: it adds the init container `inkwall-engine` first, the volumes
`inkwall-*` and the `inkwall-socket` mount of the `istio-proxy` container after yours, and keeps
your entries and fields. It labels the ConfigMap `waf.inkwall.dev/sidecar: "true"` and keeps your
`deployment` overlay, as it was, in the annotation `waf.inkwall.dev/original-deployment`. When the
engine leaves, your overlay is put back as it was, comments included, unless you changed it
meanwhile: then only the operator's entries are removed. An overlay that isn't valid YAML is
reported (`WiringFailed`), not overwritten. A ConfigMap the Gateway names that doesn't exist is
`WiringFailed` too.

The operator doesn't watch ConfigMaps: if you remove the engine from yours, it is added back when
Istio rolls the pods.

## Limits

- **HTTPRoute targets only.** `VirtualService` targets, for Istio's own `Gateway` API, are planned
  ([#281](https://github.com/inkwall-dev/inkwall/issues/281)). Mesh sidecars aren't wired: the
  `EnvoyFilter` selects Gateway pods only.
- **Gateways Istio deploys.** A Gateway bound to an existing deployment
  (`networking.istio.io/gateway-name`, or a manual `spec.addresses`) isn't: the operator can't put
  the engine into pods Istio doesn't render.
- **Responses aren't inspected** through Istio yet: the filter sends Envoy's request phases only
  (response inspection runs through raw Envoy today).
- **gRPC and WebSocket** are as through Envoy Gateway: see [gRPC](grpc.md) and
  [WebSocket](websocket.md).

## Undoing it

Delete the policy, or remove the route from its `targetRefs`: the operator removes the route from
the `EnvoyFilter` first (deleting it with the Gateway's last protected route), then takes the
engine out of the Gateway's ConfigMap, points the Gateway back at no ConfigMap if it set one, and
deletes its own. Istio rolls the pods without the engine. `helm uninstall` does the same for every
Gateway: see [uninstalling](../deploy/helm/inkwall/README.md#uninstalling).
