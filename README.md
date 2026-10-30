# Inkwall

**A Kubernetes-native web application firewall.** Install one operator; it injects an inspection
engine (OWASP [Coraza](https://coraza.io/) with the [Core Rule Set](https://coreruleset.org/)) next
to your ingress controller and enforces the `WAFPolicy` objects you attach to your routes.

**Docs:** the [docs index](docs/README.md) lists every guide, reference and design doc.

> **Status: v0.1.2, early; v0.2.0 is next.** Works today with **Traefik** and **`Ingress`** or
> **`IngressRoute`** routes, plus a standalone reverse proxy for anything else. The API is
> `v1alpha1` and will change. See [Limits](#limits) and the [roadmap](#roadmap).

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

1. **`inkwall-operator`** injects `inkwall-engine` into Traefik's pods as a sidecar, attaches a
   ForwardAuth Middleware to every `Ingress` or `IngressRoute` a policy targets, and pushes signed
   policy bundles to every engine.
2. **`inkwall-engine`** inspects each request with CRS and answers allow or deny. It keeps
   enforcing its last bundle when the operator is down.
3. **Status** on each policy shows how far it got: `Accepted` → `Programmed` (wired) →
   `Enforced` (every engine runs it) → `Ready`.

## Install

Needs Kubernetes 1.29+ and Helm 3.

```sh
helm install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.1.2 \
  --namespace inkwall-system --create-namespace
```

Then install or restart Traefik: pods started after the operator get the engine. Chart options are in
the [chart README](deploy/helm/inkwall/README.md).

Guides: [upgrading](docs/upgrading.md), [GitOps with Argo CD and Flux](docs/gitops.md),
[rotating the signing key](docs/key-rotation.md), [connecting to a control plane](docs/control-plane.md),
[client IP behind a load balancer](docs/client-ip.md).

Images, chart and checksums are signed keyless with cosign. To verify:

```sh
cosign verify ghcr.io/inkwall-dev/inkwall-engine:0.1.2 \
  --certificate-identity-regexp '^https://github.com/inkwall-dev/inkwall/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Binaries (`inkwall-engine`, `inkwall-operator`, `inkwallctl`) are on the
[releases page](https://github.com/inkwall-dev/inkwall/releases).

## Protect a route

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: web
  namespace: shop
spec:
  targetRefs: [{kind: Ingress, name: web}]   # an Ingress Traefik serves
  mode: Block                                # default Detect: log, never block
```

```console
$ kubectl get wafpolicy -n shop
NAME   MODE    READY   BUNDLE   AGE
web    Block   True    2        3s
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' "http://$TRAEFIK/?id=1%27%20OR%20%271%27%3D%271"
403
```

Start in `Detect`, tune false positives on the policy (`exclusions`, `skip` paths, the rule set's
`paranoiaLevel`), then switch to `Block`. Extra rules come from `WAFRuleSet` and `ClusterWAFRuleSet`
objects (built-in, SecLang or a ConfigMap). Samples are in
[`operator/config/samples`](operator/config/samples).

**Safe by default.** In block mode, a request that can't be inspected in time is rejected (503), so
padding a request past the deadline doesn't get an attack through; detect mode never blocks. Bundles
are signed and verified by every engine. While a policy blocks, Traefik pods can't start without
the engine; see [when the operator is down](deploy/helm/inkwall/README.md#when-the-operator-is-down).

## Without Kubernetes

The engine also runs as a standalone reverse proxy in front of any HTTP service:

```console
$ inkwall-engine proxy --upstream http://localhost:3000 --mode block
$ curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8480/?id=1%27%20OR%20%271%27%3D%271'
403
```

Main flags (`inkwall-engine proxy -h` for all):

| Flag | Default | Purpose |
|---|---|---|
| `--mode` | `detect` | `block` to enforce |
| `--paranoia-level` | `1` | CRS paranoia level, 1-4 |
| `--rules` / `--rules-before-crs` | | SecLang rules and exclusions, after / before CRS |
| `--skip-paths`, `--skip-body-paths` | | Routes not inspected, or without body inspection |
| `--disable-rule-groups` | | CRS families the app can't be vulnerable to, e.g. `php,java` |
| `--max-body-bytes` | `65536` | Body bytes inspected; `--oversize-body` decides the rest |
| `--failure-mode` | `auto` | Uninspectable requests: closed in block mode, open in detect |
| `--trusted-proxies` | | CIDRs whose `X-Forwarded-For` is trusted |

Other modes: `inkwall-engine forward-auth` (Traefik ForwardAuth, `127.0.0.1:9001`) and
`inkwall-engine check` (the `POST /v1/check` API, [`api/engine/v1`](api/engine/v1/engine.proto)).
Each blocked or detected request logs one JSON line with the rule IDs; metrics are on
`:9480/metrics`. Inspection costs about 0.5 ms per request
([baseline](docs/design/0001-performance-first-architecture.md#31-measured-baseline-2026-10-03)).

**Test rules offline** with `inkwallctl test`: a URL, a raw request (`--request`) or a browser HAR
(`--har`), with the same flags; `--expect allow|deny` makes it a CI check.

```console
$ inkwallctl test 'http://shop.example.com/?id=1%27%20OR%20%271%27%3D%271'
deny  403  GET /?id=1%27%20OR%20%271%27%3D%271  reason=rule  rules=942100,949110  interrupting=949110  847µs
```

**Test `WAFPolicy` objects** before they reach the cluster: `--policy` with the rule sets, ConfigMaps
and Ingresses they use resolves them as the operator does (each request goes to the policy of its
host and path, `policy=` names it) and compiles them as the engine does. Files (or directories
of them) may hold several YAML documents of any of these kinds, or `kubectl get -o yaml` output. Without `--ingress`, a single
policy applies to every request. Objects the operator would reject (a missing rule set, rules that
don't compile) are errors. Inspection deadlines are raised to 10 s, so a slow CI runner can't turn a
verdict into a timeout.

```console
$ inkwallctl test --policy wafpolicy.yaml --rule-set wafruleset.yaml --configmap configmap.yaml \
    --ingress ingress.yaml --request requests.http
allow      GET /products/42  policy=shop/storefront  580µs
deny  403  GET /?id=1%27%20OR%20%271%27%3D%271  policy=shop/storefront  reason=rule  rules=942100,949110  interrupting=949110  623µs
log        GET /api/orders?debug=true  policy=shop/api  reason=rule  rules=100100  interrupting=100100  20µs
allow      GET /?id=1%27%20OR%20%271%27%3D%271  reason=no_policy  0s
```

Or test the bundle the cluster enforces, its signature checked with the cluster's key:

```sh
kubectl -n inkwall-system get secret inkwall-bundle -o yaml > bundle.yaml
kubectl -n inkwall-system get secret inkwall-bundle -o jsonpath='{.data.ed25519\.pub}' > bundle.pub
inkwallctl test --bundle bundle.yaml --bundle-key bundle.pub --har traffic.har
```

A bundle too large for one Secret is split into chunks: `inkwallctl` then prints the `kubectl get
secret` command that saves the Secret with them.

In CI, with attacks and legitimate traffic kept next to the policies (exit 1 on a wrong verdict, 2
on an error):

```yaml
- run: |
    inkwallctl test --policy k8s/waf/ --expect deny --request test/waf/attacks.http
    inkwallctl test --policy k8s/waf/ --expect allow --har test/waf/legitimate.har
```

## Limits

- Proxies: **Traefik** only (and the standalone proxy). Envoy, HAProxy, ingress-nginx and Caddy are
  designed, not built.
- Targets: **`Ingress`** and Traefik **`IngressRoute`** (rules of `Host`, `Path` and `PathPrefix`
  joined by `&&`); not Gateway API `HTTPRoute` yet.
- One cluster per operator. The operator can connect to an optional control plane, which isn't in
  this repository: in `GitOps` mode it sends it a read-only copy of your policies, in `Managed` mode
  it writes the policies the control plane sends, and in both it forwards the engines' security
  events. `Standalone`, the default, connects nothing. See [control plane](docs/control-plane.md).
- A cluster's policies fit in a bundle of up to 7.2 MiB compressed, split over several Secrets past
  900 KiB.
- Behind a load balancer the engine sees the client's IP only with the PROXY protocol on Traefik's
  entry points or `externalTrafficPolicy: Local`: see [client IP](docs/client-ip.md).

## Roadmap

Tracked on the [project board](https://github.com/orgs/inkwall-dev/projects/1) and in
[milestones](https://github.com/inkwall-dev/inkwall/milestones):

- **v0.2.0** (next): signing key rotation, offline tests of `WAFPolicy` objects, `IngressRoute`
  targets and the operator side of the optional control plane, all shipped in 0.1.1; bundle chunks
  and memory at scale, on `main`.
- **v0.3.0**: Gateway API `HTTPRoute` targets with Traefik and Envoy Gateway, proxy discovery,
  engine request metrics to the control plane, migrating ingress-nginx ModSecurity annotations.
- **v1.0.0**: a stable API (out of `v1alpha1`) with an upgrade path.
- Then more proxies: HAProxy, ingress-nginx, Caddy.

## Development

```sh
make check        # lint, tests, vulnerability scan
make crs-test     # OWASP CRS regression suite through the proxy
make kind-up      # kind cluster with a demo behind the engine and Traefik
make kind-e2e     # operator end to end on kind (what CI runs)
```

`make help` lists every target. Design docs are in [`docs/design`](docs/design/README.md); start with
the [component map](docs/design/0005-component-map.md).

## Contributing, security, license

Read [CONTRIBUTING.md](CONTRIBUTING.md) (commit format, branches, releases) and follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Inkwall is licensed under the [Apache License 2.0](LICENSE).
