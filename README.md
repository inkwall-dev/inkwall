# Inkwall

**A Kubernetes-native [web application firewall](https://owasp.org/www-community/Web_Application_Firewall).** You install one [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/); it injects an
inspection engine next to your [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/) and enforces the `WAFPolicy` objects you attach
to your routes. The engine runs OWASP [Coraza](https://coraza.io/) with the
[Core Rule Set](https://coreruleset.org/) (CRS).

> **Status: v0.3.0, early.** Inkwall works with [**Traefik**](https://doc.traefik.io/traefik/) and its [`Ingress`](https://kubernetes.io/docs/concepts/services-networking/ingress/),
> [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) and [Gateway API](https://gateway-api.sigs.k8s.io/) `HTTPRoute` routes, with [**Envoy Gateway**](https://gateway.envoyproxy.io/) and its
> `HTTPRoute` routes, and as a standalone reverse proxy in front of anything else. The API is
> `v1alpha1` and will change. See [Limits](#limits) and the [roadmap](#roadmap).

The [docs index](docs/README.md) lists every guide, reference and design doc.

## Contents

- [How it works](#how-it-works)
- [Install](#install)
- [Protect a route](#protect-a-route)
- [Without Kubernetes](#without-kubernetes)
- [Limits](#limits)
- [Roadmap](#roadmap)
- [Development](#development)
- [Contributing, security, license](#contributing-security-license)

## How it works

![Inkwall architecture: the proxy asks the inkwall-engine sidecar for a verdict before forwarding; the operator watches WAFPolicy and route objects and pushes signed policy bundles to every engine](docs/diagrams/system-overview.svg)

1. The operator, **`inkwall-operator`**, injects the engine, **`inkwall-engine`**, into Traefik's
   [pods](https://kubernetes.io/docs/concepts/workloads/pods/) as a [sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/). It attaches a [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) [Middleware](https://doc.traefik.io/traefik/middlewares/overview/) to every `Ingress`, `IngressRoute`
   or Traefik-served `HTTPRoute` a policy targets. With [Envoy Gateway](https://gateway.envoyproxy.io/), it adds the engine to the Envoy pods through the
   Gateway's [`EnvoyProxy`](docs/glossary.md#envoyproxy), and gives every `HTTPRoute` a policy targets an
   [`EnvoyExtensionPolicy`](docs/glossary.md#envoyextensionpolicy) whose [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) filter calls the engine. It sends signed
   [policy bundles](docs/glossary.md#bundle) to every engine.
2. The engine inspects each request with the CRS and answers allow or deny. When the operator is
   down, it keeps enforcing its last bundle.
3. Each policy's status shows how far it got: `Accepted`, then `Programmed` (its routes are wired),
   then `Enforced` (every engine runs it), then `Ready`. The `InkwallConfig` named `default`, if
   you create one, lists in `status.proxies` the proxy controllers of the cluster's IngressClasses
   and GatewayClasses, and whether Inkwall wires their routes (`Full`, `Partial` or
   `Unsupported`).

## Install

You need [Kubernetes](https://kubernetes.io/docs/concepts/overview/) 1.29 or later and [Helm](https://helm.sh/docs/) 3. CI
tests on Kubernetes 1.34 and on kind's newest (1.37).

```sh
helm install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.3.0 \
  --namespace inkwall-system --create-namespace
kubectl -n inkwall-system rollout status deployment/inkwall-operator
```

Then install Traefik, or restart it: only pods created after the operator get the engine.

```sh
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```

For `HTTPRoute` targets served by Traefik, install the [Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api) and turn on
Traefik's [Gateway API provider](https://doc.traefik.io/traefik/routing/providers/kubernetes-gateway/) (`providers.kubernetesGateway.enabled=true` in its chart).

Envoy Gateway needs no restart: Envoy Gateway rolls the Envoy pods of a Gateway when it gets its
first protected route. Turn on its Backend API, which the engine's socket needs:

```sh
helm upgrade --install eg oci://docker.io/envoyproxy/gateway-helm --version v1.9.3 \
  --namespace envoy-gateway-system --create-namespace \
  --set config.envoyGateway.extensionApis.enableBackend=true
```

The [chart README](deploy/helm/inkwall/README.md) lists the chart's values and shows how to
uninstall. The guides cover [upgrading](docs/upgrading.md),
[GitOps with Argo CD and Flux](docs/gitops.md), [rotating the signing key](docs/key-rotation.md),
[connecting to a control plane](docs/control-plane.md) and
[the client IP behind a load balancer](docs/client-ip.md).

The images, the chart and the checksums are signed keyless with [cosign](https://docs.sigstore.dev/cosign/signing/overview/) v3: verify them
with cosign v3, as cosign v2 reports "no signatures found". To verify an image:

```sh
cosign verify ghcr.io/inkwall-dev/inkwall-engine:0.3.0 \
  --certificate-identity-regexp '^https://github.com/inkwall-dev/inkwall/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The binaries (`inkwall-engine`, `inkwall-operator`, `inkwallctl`) are on the
[releases page](https://github.com/inkwall-dev/inkwall/releases).

## Protect a route

To protect a route, create a `WAFPolicy` that targets it:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
  namespace: shop
spec:
  targetRefs: [{kind: Ingress, name: web}]   # an Ingress Traefik serves
  mode: Block                                # the default, Detect, logs but never blocks
```

For an `HTTPRoute`, served by Envoy Gateway or Traefik, target it with its group, and optionally one
rule: `{group: gateway.networking.k8s.io, kind: HTTPRoute, name: web, sectionName: api}`. One policy
can target routes of both proxies. Traefik wires an HTTPRoute only when every Gateway it is attached
to is Traefik's: another proxy fails the rules that refer to Traefik's Middleware, so a route also
attached to one is `WiringFailed`. Give each proxy its own HTTPRoute.

Once the policy is `Ready`, every engine enforces it. Send an attack to check:

```console
$ kubectl get wafpolicy -n shop
NAME   MODE    READY   BUNDLE   AGE
web    Block   True    2        3s
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' "http://$TRAEFIK/?id=1%27%20OR%20%271%27%3D%271"
403
```

Start in `Detect` mode, tune [false positives](https://coreruleset.org/docs/concepts/false_positives_tuning/) on the policy (`exclusions`, `skip` paths,
[`ruleSets[].paranoiaLevel`](https://coreruleset.org/docs/concepts/paranoia_levels/)), then switch to `Block`. Extra rules come from `WAFRuleSet` and
`ClusterWAFRuleSet` objects: built-in, [SecLang](https://coraza.io/docs/seclang/) or a [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/).
[`operator/config/samples`](operator/config/samples) has one object of each kind. To test
policies before they reach the cluster, see [testing policies offline](docs/testing-policies.md).
Coming from ingress-nginx with ModSecurity? `inkwallctl migrate ingress-nginx` converts its
annotations into policies: see [migrating from ingress-nginx](docs/migrating-from-ingress-nginx.md).

To stop protecting the route, delete the policy or remove the route from its `targetRefs`: the
operator removes its Middleware from the route, and Traefik serves it uninspected. For an
HTTPRoute, it deletes the route's `EnvoyExtensionPolicy`, and takes the engine out of a Gateway
with no protected route left, leaving its `EnvoyProxy` as it was.

**Safe by default.** In block mode, a request that can't be inspected in time is rejected (503),
so padding a request past the deadline doesn't get an attack through; detect mode never blocks.
If Traefik can't reach the engine at all (crashed, restarting or hung), Traefik answers 500 in
both modes: see [when the engine is down](deploy/helm/inkwall/README.md#when-the-engine-is-down).
Envoy, through Envoy Gateway, answers 500 too, unless every policy on the route fails open: then
it lets the request through. On a route whose policies are all in detect mode (and fail open),
Envoy doesn't wait for the engine at all: it sends it a copy of the request and forwards it.
Every engine verifies the signature of each bundle. While a policy blocks, Traefik pods can't start
without the engine: see
[when the operator is down](deploy/helm/inkwall/README.md#when-the-operator-is-down).

## Without Kubernetes

The engine also runs as a standalone reverse proxy in front of any HTTP service:

```console
$ inkwall-engine proxy --upstream http://localhost:3000 --mode block
$ curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8480/?id=1%27%20OR%20%271%27%3D%271'
403
```

See [running the engine without Kubernetes](docs/standalone-proxy.md) for its flags and other
modes, and [testing policies offline](docs/testing-policies.md) for `inkwallctl test`.

## Limits

- Proxies: **Traefik** and **Envoy Gateway** (v1.9; not with `mergeGateways` or Envoy as a
  DaemonSet), plus the standalone proxy. Raw [Envoy](https://www.envoyproxy.io/docs/envoy/latest/), [HAProxy](https://docs.haproxy.org/), [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) and [Caddy](https://caddyserver.com/docs/)
  are designed, not built.
- Targets: **`Ingress`** and Traefik **`IngressRoute`** (match rules that join `Host`, `Path` and
  `PathPrefix` with `&&`) through Traefik; [Gateway API](https://gateway-api.sigs.k8s.io/) **[`HTTPRoute`](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/)** through Envoy Gateway or
  [Traefik's Gateway API provider](https://doc.traefik.io/traefik/routing/providers/kubernetes-gateway/) (`Exact` and `PathPrefix` paths, methods; no header or
  query matches). Other Gateway API controllers' HTTPRoutes are resolved into the bundle, but not
  wired.
- One cluster per operator. The operator can connect to an optional control plane, which isn't in
  this repository: in `GitOps` mode it sends it a read-only copy of your policies, in `Managed`
  mode it writes the policies the control plane sends, and in both it forwards the engines'
  security events. `Standalone`, the default, connects to nothing. See
  [connecting to a control plane](docs/control-plane.md).
- A cluster's policies must fit in a bundle of 7.2 MiB compressed. Past 900 KiB, the bundle is
  split over several [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/).
- Behind a load balancer, the engine sees the client's IP only with the [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) on Traefik's
  [entry points](https://doc.traefik.io/traefik/routing/entrypoints/) or with [`externalTrafficPolicy: Local`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip): see [client IP](docs/client-ip.md).

## Roadmap

Tracked on the [project board](https://github.com/orgs/inkwall-dev/projects/1) and in
[milestones](https://github.com/inkwall-dev/inkwall/milestones):

- **v0.2.0** (shipped): signing key rotation, offline tests of `WAFPolicy` objects, `IngressRoute`
  targets, unwiring with a finalizer and the operator side of the optional control plane, first
  shipped in 0.1.1; bundles split into chunk Secrets, operator memory that no longer grows with
  engines, the ForwardAuth answer capped, user guides, and fuzzing, scale and upgrade tests.
- **v0.3.0** (shipped): Gateway API `HTTPRoute` targets with Traefik and [Envoy Gateway](https://gateway.envoyproxy.io/) (through
  [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)), proxy discovery, per-policy request counts sent to the control plane, policy
  statuses written only when they change, and `inkwallctl migrate ingress-nginx`, which turns
  ingress-nginx [ModSecurity](https://kubernetes.github.io/ingress-nginx/user-guide/third-party-addons/modsecurity/) annotations into policies.
- **v1.0.0** (next): a stable API (out of `v1alpha1`) with an upgrade path.
- Then more proxies: HAProxy, ingress-nginx, Caddy.

## Development

```sh
make check        # lint, tests, vulnerability scan, docs checks
make crs-test     # OWASP CRS regression suite through the proxy
make kind-up      # kind cluster with a demo behind the engine and Traefik
make kind-e2e     # operator end to end on kind (what CI runs)
```

`make help` lists every target. The design docs are in [`docs/design`](docs/design/README.md);
start with the [component map](docs/design/0005-component-map.md).

## Contributing, security, license

Read [CONTRIBUTING.md](CONTRIBUTING.md) (commit format, branches, releases) and follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately, as
[SECURITY.md](SECURITY.md) describes. Inkwall is licensed under the [Apache License 2.0](LICENSE).
