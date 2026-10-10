# Inkwall

**A Kubernetes-native web application firewall. Install one operator, and every ingress and gateway
in your cluster is protected by the same policy.**

> **Status: early development.** No release exists yet. The inspection engine works as a standalone
> reverse proxy and behind Traefik's ForwardAuth (see [Try it](#try-it)); the other proxy
> integrations and the Kubernetes operator are not built yet. The architecture is written up in [`docs/design`](docs/design/README.md). Sections other than
> "Try it" describe the target, not shipped features.

---

## Why Inkwall

Running a WAF in Kubernetes today means picking one per proxy: ModSecurity for ingress-nginx, a
plugin for Traefik, a WASM filter for Envoy, an SPOA agent for HAProxy, each with its own config,
rules, and failure modes. Change your ingress, and you rebuild your WAF.

Inkwall makes the WAF a Kubernetes primitive, the way cert-manager did for TLS:

- **One policy, every proxy.** Write a `WAFPolicy` against an `Ingress` or `HTTPRoute`. The
  operator discovers which controller serves it and wires the engine in using that proxy's native
  hook.
- **Standard rules.** Built on [OWASP Coraza](https://coraza.io/) and the
  [OWASP Core Rule Set](https://coreruleset.org/). Existing ModSecurity rules and exclusions keep
  working.
- **Fast by design.** The engine runs as a sidecar next to the proxy over a Unix socket (or
  in-process for Caddy), with tiered checks so most requests never touch a regex. Latency budgets are
  part of the design, and CI will fail on regressions.
- **Safe by default.** New routes start in detect mode (no added latency, no false-positive
  outages). In block mode nothing is forwarded uninspected; detect mode never blocks. Policies are
  signed.
- **GitOps first, SaaS optional.** CRDs in Git are the source of truth. Everything enforces fully
  offline; an optional control plane adds fleet management and attack analytics.
- **A way off ingress-nginx.** Protect ingress-nginx today, move routes to a Gateway API
  implementation tomorrow, and keep the same policies.

## How it works

```mermaid
flowchart LR
    U([clients]) --> P
    subgraph POD["ingress controller pod"]
        P["proxy<br/>Envoy · HAProxy · nginx · Traefik"]
        E["inkwall-engine<br/>sidecar"]
        P <-->|"Unix socket<br/>check / verdict"| E
    end
    P --> A["your services"]
    OP["inkwall-operator"] -->|"signed policy bundles"| E
    K["WAFPolicy · HTTPRoute · Ingress"] --> OP
```

1. **`inkwall-operator`** watches your routes and `WAFPolicy` objects, injects the engine into your
   ingress controller pods, wires the proxy, and pushes signed policy bundles to every engine.
2. **`inkwall-engine`** answers each proxy's native protocol (Envoy `ext_proc`/`ext_authz`, HAProxy
   SPOE, forward-auth, a Lua plugin for ingress-nginx) and returns allow / deny in microseconds.
3. **Status** on each policy tells you how far it got: `Accepted` → `Programmed` → `Enforced`
   on every engine.

## Example

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: shop
  namespace: shop
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: shop-api
  mode: Detect            # switch to Block once false positives are tuned
  ruleSets:
  - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
    paranoiaLevel: 1
  rateLimits:
  - name: login
    match: {path: /api/login, methods: [POST]}
    key: ClientIP
    limit: 10
    window: 1m
```

```console
$ kubectl get wafpolicy -n shop
NAME   MODE     READY   ENGINES   AGE
shop   Detect   True    3/3       2m
```

(Illustrative. The API is `v1alpha1` and will change.)

## Try it

The engine runs today as a standalone reverse proxy in front of any HTTP service. It inspects requests
with the OWASP Core Rule Set, which is embedded in the binary.

```console
$ make build
$ ./bin/inkwall-engine proxy --upstream http://localhost:3000 --mode block
$ curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8480/?id=1%27%20OR%20%271%27%3D%271'
403
```

Each blocked or detected request produces one JSON log line with the matching rule IDs. Metrics are on
`:9480/metrics`, health on `:9480/healthz` and `:9480/readyz`.

Defaults are deliberately safe. The engine starts in **detect mode**: it logs what it would block
and never blocks. In **block mode**, a request that cannot be fully inspected (inspection timed out,
failed, or the engine is overloaded) is **rejected with 503**, so padding a request until inspection
times out cannot get an attack through; in detect mode such requests are allowed and logged. Use
`--failure-mode open` to prefer availability in block mode. Useful flags:

| Flag | Default | Purpose |
|---|---|---|
| `--mode` | `detect` | `block` to enforce |
| `--paranoia-level` | `1` | CRS paranoia level, 1-4 |
| `--max-body-bytes` | `65536` | Body bytes to inspect |
| `--oversize-body` | `auto` | Bodies over the limit: `deny` (413), `allow` (forwarded uninspected, logged), `auto` = deny in block mode |
| `--max-args` | `1000` | Maximum arguments per source; more is rejected with 400 |
| `--rules` | | SecLang rules and configure-time exclusions, loaded after CRS |
| `--rules-before-crs` | | Runtime exclusions (`ctl:ruleRemoveById` …) and settings, loaded before CRS |
| `--trusted-proxies` | | CIDRs whose `X-Forwarded-For` is trusted |
| `--skip-paths` | | Paths never inspected, e.g. `/healthz,/static/*` |
| `--skip-body-paths` | | Paths whose body is not inspected, e.g. `/upload/*` |
| `--disable-rule-groups` | | CRS families the app can't be vulnerable to, e.g. `php,java` (~13-15% faster) |
| `--failure-mode` | `auto` | `auto` = closed in block mode, open in detect; or `open` / `closed` |
| `--timeout` | `250ms` | Inspection deadline per request (a safety cap, not typical latency) |

Run `./bin/inkwall-engine proxy -h` for all flags. Inspection currently costs about 0.5 ms per
request plus roughly 0.15 ms per request argument, so skipping static and trusted routes matters; see
the
[performance baseline](docs/design/0001-performance-first-architecture.md#31-measured-baseline-2026-10-03).

**Behind Traefik**, `inkwall-engine forward-auth` answers Traefik's ForwardAuth middleware on
`127.0.0.1:9001/v1/forward-auth`, with the same flags minus `--upstream`. Run it as a sidecar in
Traefik's pod with `--trusted-proxies=127.0.0.1/32`, and configure the middleware with
`trustForwardHeader: false` (otherwise clients can make the engine inspect a URI of their choice) and
`forwardBody: true` (otherwise bodies are not inspected). See
[`hack/kind/traefik-demo.yaml`](hack/kind/traefik-demo.yaml) and the
[design notes](docs/design/0002-system-architecture.md#63-traefik).

**The check API.** `inkwall-engine check` serves the engine's own API, `POST /v1/check`
([`api/engine/v1`](api/engine/v1/engine.proto)), for proxies without a native protocol: the proxy
describes one request as a `CheckRequest`, in protobuf (`application/x-protobuf`) or JSON
(`application/json`), and gets the verdict back. It listens on `127.0.0.1:9002` by default. It trusts
the caller's `client_ip`, so expose it only to the proxy, for example on a Unix socket:

```console
$ ./bin/inkwall-engine check --listen unix:/run/inkwall/engine.sock --mode block
$ curl -s --unix-socket /run/inkwall/engine.sock -H 'Content-Type: application/json' \
    -d '{"method":"GET","raw_uri":"/?id=1%27%20OR%20%271%27%3D%271","authority":"shop.example.com"}' \
    http://engine/v1/check
{"action":"ACTION_DENY","status":403,"rule_ids":[942100,949110],"reason":"REASON_RULE",...}
```

To run it in Kubernetes, `make kind-up` creates a [kind](https://kind.sigs.k8s.io/) cluster with a
demo app published twice: behind the engine's reverse proxy (`127.0.0.1:30480`) and through Traefik
with the engine as a forward-auth sidecar (`127.0.0.1:30080`), both in block mode. `make kind-test`
sends benign and attack requests through both and checks the verdicts. `make kind-down` deletes the
cluster. The setup is in [`hack/kind`](hack/kind).

Development checks: `make check` (lint, tests, vulnerability scan) and `make crs-test` (the OWASP CRS
regression suite, about 4,500 tests, through the proxy).

## Planned integrations

| Proxy / controller | Hook | Body inspection |
|---|---|---|
| Envoy, Envoy Gateway, Istio, Contour | `ext_proc` (or `ext_authz`) | streamed |
| HAProxy (both Kubernetes ingress controllers) | SPOE | yes |
| ingress-nginx | Lua plugin (or global auth URL) | yes (plugin) |
| Traefik | ForwardAuth (works today), later a plugin | yes, with `forwardBody` (buffered) |
| Caddy | native module, in-process | yes |
| Anything else | standalone reverse proxy | yes |

## Roadmap

1. **Engine:** Coraza + CRS, tiered pipeline, standalone reverse-proxy mode, benchmark harness.
2. **Envoy integration** end to end on kind.
3. **HAProxy, ingress-nginx, Traefik, Caddy** integrations.
4. **Operator + Helm chart:** discovery, injection, wiring, signed bundles, status.
5. **Optional control plane:** multi-cluster policy management and attack analytics.

## Documentation

| Doc | What it covers |
|---|---|
| [Component map](docs/design/0005-component-map.md) | Start here: diagrams of every component, where it runs, why Coraza |
| [Performance-first architecture](docs/design/0001-performance-first-architecture.md) | Latency budgets, tiered pipeline, failure behaviour |
| [System architecture](docs/design/0002-system-architecture.md) | Engine, CRDs, protocols, per-proxy integration |
| [Kubernetes operator](docs/design/0004-operator.md) | Discovery, injection, wiring, bundles, status, uninstall |
| [Adapter protocols](docs/design/0006-adapter-protocols.md) | ext_authz, ext_proc, forward-auth, SPOE explained |

## Contributing

Contributions and design feedback are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for commit
conventions, branching, and releases. Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in public
issues.

## License

Inkwall is licensed under the [Apache License 2.0](LICENSE).
