# Protecting routes served by Istio

This guide protects the routes [Istio](https://istio.io/latest/docs/)'s gateways serve, through either of its APIs:

- the `HTTPRoute` routes of Istio's implementation of the [Gateway API](https://gateway-api.sigs.k8s.io/), whose GatewayClass
  controller is `istio.io/gateway-controller`: the operator adds the engine to the pods Istio runs
  for each Gateway (the `istio` integration);
- the [`VirtualService`](glossary.md#virtualservice) routes bound to Istio's own `Gateway` objects
  (`networking.istio.io`), served by an ingress gateway deployed with Istio's `gateway` Helm chart:
  the Pod webhook adds the engine to its pods when they start (the `istio-ingress` integration).
  See [VirtualServices](#virtualservices).

Either way, an [`EnvoyFilter`](glossary.md#envoyfilter) sends the protected routes' requests to the engine through Envoy's
[ext_proc filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter). You write the same `WAFPolicy` as for any other proxy.

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
- [VirtualServices](#virtualservices)
  - [Engine placement](#engine-placement)
  - [Protect a VirtualService](#protect-a-virtualservice)
  - [What a VirtualService may match](#what-a-virtualservice-may-match)
  - [Route names](#route-names)
  - [Status](#status)
- [The operator's probe](#the-operators-probe)
- [Limits](#limits)
- [Undoing it](#undoing-it)

## Prerequisites

<!-- versions: ISTIO_VERSION GATEWAY_API_VERSION -->
- Istio 1.28 or later; for HTTPRoutes, its Gateway API implementation (on by default) and the
  [Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api); for VirtualServices, an ingress gateway from its
  `gateway` Helm chart. Tested with Istio 1.31.3 (its `base` and `istiod` Helm
  charts, no mesh) and the Gateway API's standard CRDs v1.7.0. Istio's Envoy must be 1.36 or later:
  older ones reject the filter's settings, so the operator refuses to wire an older Istio (it reads
  the version from the `istio-proxy` image tag).
- Inkwall installed with `rbac.integrations.istio` (HTTPRoutes) or `rbac.integrations.istioIngress`
  (VirtualServices) not `false` (the default is `true`), and the
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
NAME   MODE    READY   REASON   BUNDLE   AGE
web    Block   True    Ready    3        40s
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
| `Programmed` | Every running pod of each of the route's Gateways has the engine, the `EnvoyFilter` has the route, Istio has accepted the route on each Gateway (its parent status, `Accepted=True`), and [the operator's probe](#the-operators-probe) has reached the engine through every pod, on every listener the route is attached to |
| `Unverified` | Wired, but the probe hasn't reached the engine yet, or got another answer (the filter isn't on the route: its traffic isn't inspected there); also every route in `Detect` mode, whose answer Envoy discards |
| `NotProbeable` | Wired, but the probe can't make a request the route serves: each match of one of its protected rules is a regular expression (path, header or query parameter) |
| `PendingRestart` | Istio is rolling a Gateway's pods; some don't have the engine yet |
| `SidecarMissing` | A Gateway has no running pod, or its namespace isn't a proxy namespace |
| `Pending` | Waiting for Istio to accept the route, or for another of its Gateways |
| `WiringFailed` | Istio's `EnvoyFilter` CRD isn't installed; Istio is older than 1.28; a rule name is shared ([rule names](#rule-names)); the Gateway's ConfigMap doesn't exist or its `deployment` key isn't YAML; or an `EnvoyFilter` named `inkwall-waf-<gateway>` isn't the operator's |
| `IntegrationDisabled` | The operator lacks the `inkwall-operator-istio` ClusterRole (`rbac.integrations.istio`) |

Istio reports nothing on an `EnvoyFilter`, and accepts one whose patches match no Envoy route, so
`Programmed` rests on the pods, the route's status and the probe. While a route waits for one of its Gateways, it stays wired on its other Gateways whose
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

## VirtualServices

Istio's own API routes with a `Gateway` (`networking.istio.io`), which selects ingress gateway pods
by label, and `VirtualService` objects bound to it (`spec.gateways`). The operator protects a
VirtualService a `WAFPolicy` targets with `{group: networking.istio.io, kind: VirtualService, name:
…}`, through the `istio-ingress` integration and its ClusterRole, `inkwall-operator-istio-ingress`
(`rbac.integrations.istioIngress`).

### Engine placement

An ingress gateway from Istio's `gateway` Helm chart is your own Deployment: Istio has no API to
add a container to it. So, as for Traefik, a Pod webhook (`istio-ingress.pods.waf.inkwall.dev`)
adds the engine to its pods when they are created, and mounts the engine's socket directory in
their `istio-proxy` container. It selects pods labelled `istio: ingressgateway` (the chart's label
for a release named `istio-ingressgateway`; set another in the `InkwallConfig`'s
`spec.integrations`, `controller: istio-ingress`) in the proxy namespaces. Pods that ran before
Inkwall get the engine when restarted:

```sh
kubectl -n istio-ingress rollout restart deployment/istio-ingressgateway
```

The `InkwallConfig`'s selector for `istio-ingress` must be plain labels (`matchLabels`): it is also
the `EnvoyFilter`'s `workloadSelector`.

### Protect a VirtualService

```yaml
apiVersion: networking.istio.io/v1
kind: Gateway
metadata: {name: edge, namespace: istio-ingress}
spec:
  selector: {istio: ingressgateway}
  servers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: ["*"]}]
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata: {name: web, namespace: shop}
spec:
  hosts: [shop.example.com]
  gateways: [istio-ingress/edge]
  http:
    - name: api                      # every http route needs a name
      match: [{uri: {prefix: /api/}}]
      route: [{destination: {host: api}}]
    - name: web
      route: [{destination: {host: web}}]
---
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: web, namespace: shop}
spec:
  targetRefs:
    - {group: networking.istio.io, kind: VirtualService, name: web}
  mode: Block
```

Once every running pod the VirtualService's Gateways select has the engine, the namespace of those
pods gets `EnvoyFilter` objects for its gateway pods (`workloadSelector` `istio: ingressgateway`):
`inkwall-istio-ingress`, with the engine's cluster, and shards `inkwall-istio-ingress-00` to `-31`
with, per protected VirtualService, an ext_proc filter, off by default and on for the Envoy routes
of its http routes, with the [settings](#settings) of its policies. A VirtualService always lands in
the same shard (a hash of its namespace and name), so thousands of them stay under etcd's size
limit for one object. Each shard lists the VirtualServices it wires in the annotation
`waf.inkwall.dev/virtualservices`.

### What a VirtualService may match

The engine routes requests by host, path and method, so a VirtualService's routes are each of its
`hosts` (`*`: any host; `*.example.com`: subdomains at any depth) with each of its http routes'
matches:

| Match | Protected as |
|---|---|
| no `match`, or a match without `uri` | every path |
| `uri: {exact: /login}` | that path |
| `uri: {prefix: /api/}` or `{prefix: /api}` | `/api` and the paths under it. Istio's prefix is a string prefix, so `/api` also routes `/apiv2`; the engine's routes are whole path segments, and gives such a path the host's most general policy, as any path of a protected host its routes miss |
| `method: {exact: GET}` | that method |

A `uri` `regex`, `ignoreUriCase`, `headers`, `queryParams`, `withoutHeaders`, `authority`,
`scheme`, `port`, `sourceLabels`, `sourceNamespace` or `gateways` match, a `method` other than
`exact`, a `delegate` route, a short host name (a mesh service, such as `reviews`) or a
VirtualService without http routes is refused: the policy is `Accepted=False`
(`TargetUnsupported`), naming the field, and keeps the version in force, if any. `inkwallctl
test --ingress` reads VirtualServices too.

### Route names

Istio names a VirtualService's Envoy routes after its http routes (`name`, then `.` and the match's
`name` for a named match), and the filter is turned on by those names. So:

- every http route of a protected VirtualService needs a `name`, or the policy reports
  `WiringFailed` naming it;
- a name that another VirtualService on the same gateway pods also uses would turn the filter on for
  that VirtualService too: refused (`WiringFailed`, naming both); rename one.

### Status

| `Programmed` reason | Meaning |
|---|---|
| `Programmed` | Every running pod the VirtualService's Gateways select has the engine and the socket mount, the `EnvoyFilter` has the VirtualService, and [the operator's probe](#the-operators-probe) has reached the engine through every pod, on every Gateway server that serves its hosts |
| `Unverified` | Wired, but not proven by the probe yet, or the probe got another answer; also every VirtualService in `Detect` mode |
| `NotProbeable` | Wired, but the probe can't make a request it serves: one of its http routes has only regular expression matches, or a server serving it uses mutual TLS or passthrough |
| `PendingRestart` | Some of those pods started before Inkwall: restart them |
| `SidecarMissing` | No such pod is running, or one opted out (`waf.inkwall.dev/inject: "false"`) |
| `Pending` | Its Gateway doesn't exist yet; or, with Istio's status on (`PILOT_ENABLE_STATUS`), Istio hasn't reconciled the VirtualService |
| `WiringFailed` | Its Gateways select pods the Pod webhook doesn't inject (outside the proxy namespaces, or without the `istio-ingress` labels), which would serve it uninspected; an http route without a name, or a shared name; Istio older than 1.28; Istio's `VirtualService`, `Gateway` or `EnvoyFilter` CRD missing |
| `IntegrationDisabled` | The operator lacks the `inkwall-operator-istio-ingress` ClusterRole |
| `ControllerUnsupported` | It is bound to no Gateway (only the `mesh`) |

Istio reports nothing on an `EnvoyFilter` or, by default, a VirtualService, so `Programmed` rests on
the pods and the objects. Istio's ingress gateways have no class, so they aren't listed in the
`InkwallConfig`'s `status.proxies`.

## The operator's probe

The `EnvoyFilter`'s patches select Envoy's routes by the names Istio gives them, and Istio accepts a
patch that matches nothing: the route would then be served uninspected. So the operator proves
each wired route (0002 §6.1, as for [HAProxy](haproxy.md#the-probe-and-programmed)): a request to
each gateway pod, on each listener (HTTPRoute) or server (VirtualService) the route is served on,
with the route's host and a path its rule matches, and a header `X-Inkwall-Probe` carrying a MAC
under the bundle's probe key. The engine behind the route's filter answers it itself (200 and its
own MAC): the request never reaches your app. A route is `Programmed` only once every pod answered
on every listener; it is probed again every 5 minutes, and every 20 seconds until it answers.

- **The request** follows the route's first match the probe can make: an exact or prefix path
  (under a prefix, the reserved path `.well-known/inkwall-probe/<nonce>`), exact headers, query
  parameters and the method. A wildcard host is made concrete (`*.example.com`:
  `inkwall-probe.example.com`). Over TLS for an HTTPS listener or a `SIMPLE` TLS server, without
  checking the certificate (the MAC is the proof).
- **Not probeable:** a rule (http route) whose every match is a regular expression, and a server
  with mutual TLS or passthrough: `NotProbeable`, with the reason.
- **Detect mode:** Envoy's observability mode discards the engine's answer, so a route whose
  policies are all in `Detect` mode stays `Unverified`.
- The probe reaches the pods on their listener's port (the pod address and the Gateway listener's
  or server's port number): a Gateway whose pods listen on another port than the server's (a
  `targetPort` mapping) stays `Unverified`.

## Limits

- **Gateways only.** Mesh sidecars aren't wired: the `EnvoyFilter` selects gateway pods only, and
  a VirtualService also bound to the `mesh` is `Programmed` with a message saying its mesh traffic
  isn't inspected.
- **Gateway API Gateways Istio deploys.** A Gateway API Gateway bound to an existing deployment
  (`networking.istio.io/gateway-name`, or a manual `spec.addresses`) isn't: the operator can't put
  the engine into pods Istio doesn't render.
- **Responses aren't inspected** through Istio yet: the filter sends Envoy's request phases only, and
  a policy that inspects responses reports `ResponsesNotInspected` on Istio's routes (they are
  inspected through Envoy Gateway and raw Envoy).
- **gRPC and WebSocket** are as through Envoy Gateway: see [gRPC](grpc.md) and
  [WebSocket](websocket.md).

## Undoing it

Delete the policy, or remove the route from its `targetRefs`: the operator removes the route from
the `EnvoyFilter` first (deleting it with the Gateway's last protected route), then takes the
engine out of the Gateway's ConfigMap, points the Gateway back at no ConfigMap if it set one, and
deletes its own. Istio rolls the pods without the engine. For a VirtualService, the operator
removes it from its namespace's `EnvoyFilter`; the ingress gateway's pods keep the engine until
they restart, as Traefik's do. `helm uninstall` does the same for every Gateway and
VirtualService: see [uninstalling](../deploy/helm/inkwall/README.md#uninstalling).
