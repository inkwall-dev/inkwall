# 0005 — Component Map and Rule Engine Choice

- Status: Draft
- Date: 2026-09-27
- Updated: 2026-10-31
- Owner: noureldin
- Depends on: [0002 — System Architecture](0002-system-architecture.md),
  [0004 — Kubernetes Operator](0004-operator.md)

This document lists every Inkwall component, where it runs, where its code lives, and whether it
is built. It then traces two key flows: a request in block mode and a policy change. Last, it
explains why the engine evaluates rules with [Coraza](https://coraza.io/) today.

[Terms](../glossary.md) used here:

- **Engine:** `inkwall-engine`, the process that inspects requests and returns verdicts.
- **Proxy:** the [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)'s data-plane process ([Traefik](https://doc.traefik.io/traefik/), [Envoy](https://www.envoyproxy.io/docs/envoy/latest/), ...), which asks the
  engine about each request.
- **Adapter:** an engine listener that speaks one proxy's protocol, plus the proxy-side
  configuration or plugin that calls it ([0006](0006-adapter-protocols.md)).
- **Operator:** `inkwall-operator`, which injects the engine into proxy [pods](https://kubernetes.io/docs/concepts/workloads/pods/), wires the proxy to
  it and distributes policy.
- **Wiring:** configuring the proxy to call the engine on protected routes.
- **Bundle:** the policy bundle, an immutable, versioned, signed snapshot of all of a cluster's
  policies, built by the operator and enforced by every engine.
- **Control plane:** the optional hosted service that manages clusters. It is a separate product,
  not in this repository.
- **Coraza:** the [Go](https://go.dev/) [WAF](https://owasp.org/www-community/Web_Application_Firewall) library that evaluates rules today. **CRS:** the [OWASP Core Rule Set](https://coreruleset.org/) (CRS).

## Contents

- [1. Component overview](#1-component-overview)
- [2. Where each component runs and when it is built](#2-where-each-component-runs-and-when-it-is-built)
- [3. Engine internals](#3-engine-internals)
- [4. Operator internals](#4-operator-internals)
- [5. Key flows](#5-key-flows)
  - [5.1 Request in block mode](#51-request-in-block-mode)
  - [5.2 Policy change (GitOps mode)](#52-policy-change-gitops-mode)
- [6. Why Coraza](#6-why-coraza)
  - [6.1 What a WAF rule engine must do](#61-what-a-waf-rule-engine-must-do)
  - [6.2 Why Coraza fits](#62-why-coraza-fits)
  - [6.3 Alternatives considered](#63-alternatives-considered)
  - [6.4 Risks and mitigations](#64-risks-and-mitigations)
  - [6.5 Where Coraza is used, and where it is not](#65-where-coraza-is-used-and-where-it-is-not)

## 1. Component overview

![Inkwall architecture: the proxy asks the inkwall-engine sidecar for a verdict before forwarding; the operator watches WAFPolicy and route objects and pushes signed policy bundles to every engine](../diagrams/system-overview.svg)

- **Request path:** the client sends a request to the proxy. The proxy asks the engine [sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) for
  a verdict, over a [Unix socket](https://man7.org/linux/man-pages/man7/unix.7.html) or localhost, then forwards the request to the app.
- **Control path:** policies come from Git or [`kubectl`](https://kubernetes.io/docs/reference/kubectl/) and reach the [kube-apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/). The operator
  validates them in its [webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/), stores a signed bundle in a [Secret](https://kubernetes.io/docs/concepts/configuration/secret/) and streams it to the engines.
  Status goes back onto the [custom resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).
- **Planned:** [Caddy](https://caddyserver.com/docs/), with the engine compiled in.
- **Optional:** a control plane, connected over one primary [mTLS](https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2) stream per cluster, plus an
  events stream per operator replica. The operator's side is built
  ([0004 §4.9](0004-operator.md#49-upstream-sync-leader-only)).

## 2. Where each component runs and when it is built

All components are licensed [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). Everything in the cluster works without the control plane,
which only adds management, analytics and threat intelligence.

| Component | Runs in | Code | Status |
|---|---|---|---|
| **inkwall-engine** | Sidecar in ingress controller pods, or standalone | `cmd/engine`, `pkg/` | Built |
| **Engine adapters** | Engine process | `pkg/adapters/*` | Built: `forwardauth`, `httpcheck` (`/v1/check`), `proxy`, `extproc` ([ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)). Not yet: [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter), [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt) |
| **Proxy-side glue** | Proxy configuration | `operator/integrations`, `operator/internal/wiring` | Built: Traefik [Middleware](https://doc.traefik.io/traefik/middlewares/overview/). Not yet: nginx [Lua](https://github.com/openresty/lua-nginx-module), SPOE, Envoy configuration |
| **Caddy module** | Compiled into Caddy | `adapters/caddy` (own [`go.mod`](https://go.dev/ref/mod#go-mod-file)) | Not yet |
| **Traefik plugin** (thin client) | Traefik ([Yaegi](https://github.com/traefik/yaegi)) | `adapters/traefik-plugin` (own `go.mod`) | Not yet |
| **inkwall-operator** | `inkwall-system`, 2 replicas | `cmd/operator`, `operator/` | Built |
| **Admission webhooks** | Operator process | `operator/webhook` | Built (validate, inject) |
| **[CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)** | kube-apiserver | `operator/api/v1alpha1`, `operator/config/crd` | Built: WAFPolicy, WAFRuleSet, ClusterWAFRuleSet, InkwallConfig |
| **[Helm](https://helm.sh/docs/) chart** | User install | `deploy/helm/inkwall` | Built |
| **OLM bundle** ([Operator Lifecycle Manager](https://olm.operatorframework.io/) package) | [OperatorHub](https://operatorhub.io/) | [operator-sdk](https://sdk.operatorframework.io/) | Not yet |
| **inkwallctl** | Developer machine, CI | `cmd/inkwallctl` | Built: `test` (flags, `--policy`, `--bundle`), `bench`, `migrate ingress-nginx` |
| **[Protobuf](https://protobuf.dev/) APIs** (engine, agent, bundle, events, controlplane) | Engine, operator, control plane | `api/` | Built |
| **Control plane** | Hosted by Inkwall | Separate product | Not in this repository; the operator's side is built (`operator/internal/controlplane`) |

## 3. Engine internals

![inkwall-engine internals as built today: the reverse-proxy, forward-auth and check-API adapters turn their input into a request.Request and call pipeline.Check, which consults the route table, runs the Coraza evaluator with the OWASP CRS and reports every verdict to telemetry](../diagrams/engine-internals.svg)

**Built (v0.1.0):** everything in the diagram; each component in it links to its source. Also:

- `pkg/policy`: one pipeline per policy in the bundle, swapped atomically;
- `pkg/agent`: the stream from the operator, bundle verification and the disk cache;
- `pkg/clientip`: the client IP.

**Built since:**

- `pkg/events`: redacted security events in a bounded [ring buffer](https://en.wikipedia.org/wiki/Circular_buffer), sent to the operator in batches
  on the agent stream;
- `pkg/bundlekey`: the trusted signing keys;
- `pkg/bundlesecret`: the bundle Secret's format, chunks included;
- `pkg/adapters/extproc`: Envoy's external processing over [gRPC](https://grpc.io/docs/) ([0006 §2](0006-adapter-protocols.md#2-ext_proc-envoy-external-processing)).

**Not yet:**

- The adapters `extauthz` (gRPC) and `spoe` (SPOP).
- Tier T1, IP lists and rate limits (`pkg/iplist`, `pkg/ratelimit`), between the route table and
  the rules ([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first)).
- Traces in telemetry.
- Inkwall's own rule engine ([0007](0007-inkwall-engine.md)) as a second `pkg/rules` evaluator.

## 4. Operator internals

| Part | Does | Code | Status |
|---|---|---|---|
| Discovery and integration registry | Find the ingress controller's pods; list the proxy controllers of the [IngressClasses](https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class) and [GatewayClasses](https://gateway-api.sigs.k8s.io/reference/api-types/gatewayclass/) in `InkwallConfig.status.proxies` | `operator/integrations`, `operator/internal/discovery` | Built: Traefik, its pods by [label selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors); discovery. Not yet: envoygateway, istio, ingressnginx, haproxy, caddy |
| Injection | Add the engine as a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) through the Pod webhook | `operator/internal/injection` | Built |
| Wiring | Render proxy configuration; [merge-patch](https://www.rfc-editor.org/rfc/rfc7386) user-owned routes; one `Integration` per proxy | `operator/internal/wiring` | Built (Traefik) |
| Resolver | Turn policy targets into host, path and method | `operator/resolver` | Built |
| Bundle builder | Leader only: debounce changes (1 s), build, sign, version, write the Secret | `operator/bundle`, `operator/internal/controller` | Built |
| Distribution server | Every replica, over gRPC; ACK, NACK, heartbeat | `operator/internal/distribution` | Built |
| Status | The `Enforced` condition (engines on the current bundle) | `operator/internal/distribution` | Built |
| Validating webhook | Compile rule sets as the engine does; check paths; in Managed mode, let only the operator write the control plane's objects | `operator/webhook` | Built |
| Upstream sync | Leader only, mTLS to the control plane: enrollment, state sync, events (from every replica), Managed mode | `operator/internal/controlplane` | Built (tested against a stub) |
| WAFIPList CRD | IP lists | — | Not yet |

The leader is the operator replica that holds the [leader-election lease](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election). Managed mode is the
cluster mode in which the control plane owns the policies and the operator writes them as custom
resources ([0002 §4.1](0002-system-architecture.md#41-sources-of-truth)).

## 5. Key flows

### 5.1 Request in block mode

1. The proxy terminates [TLS](https://www.rfc-editor.org/rfc/rfc8446), matches the route and asks the engine.
2. The engine runs its tiers: T0 maps the route to a policy; T1 checks IP lists and rate limits
   (not built yet); T2 and T3 run the CRS rules on headers, URI and body.
3. If the [anomaly score](https://coreruleset.org/docs/concepts/anomaly_scoring/) stays below the threshold, the engine answers "continue" and the proxy
   forwards the request. If the score reaches the threshold, the engine answers 403 and emits an
   event.
4. If the engine is slow or down:
   - **Engine too slow** (built): the engine's own deadline passes, and it applies the failure
     mode itself. It answers 503 in block mode and allows the request in detect mode.
   - **Engine unreachable, by design** (Envoy and the other planned proxies): the proxy's timeout,
     set just above the engine's deadline, expires, and the proxy applies the failure mode: 503 in
     block mode, forward in detect mode.
   - **Engine unreachable, with Traefik** (built): Traefik's [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) has no timeout or
     failure setting, so Inkwall's failure mode does not apply: Traefik answers 500 and doesn't
     forward the request, in both modes. A refused connection gets it at once, a hung engine
     after Traefik's fixed 30 s timeout ([0002 §7.3](0002-system-architecture.md#73-engine-unavailable)).

### 5.2 Policy change (GitOps mode)

GitOps mode is the cluster mode in which policies are custom resources applied from Git, and
mirrored to the control plane if one is connected.

1. Git (through [Argo CD](https://argo-cd.readthedocs.io/en/stable/), for example) applies a WAFPolicy. The validating webhook compiles its
   rules.
2. The leader resolves the policy's targets, waits 1 s for more changes, then writes a signed,
   versioned bundle Secret.
3. Every replica pushes the bundle to its engines. Each engine compiles it in the background, swaps
   it in atomically and acknowledges it (ACK).
4. The leader sets `Enforced=True` once every engine runs the policy's bundle.

## 6. Why Coraza

### 6.1 What a WAF rule engine must do

A WAF rule engine needs:

- a rule language: variables, operators, transformations, actions, chaining, phases;
- transformations that defeat evasion;
- body processors for forms, multipart, JSON and XML;
- anomaly scoring, collections and audit logs;
- a maintained rule set with regression tests.

Writing all of that from scratch is a large job, and every parsing difference is a potential
bypass.

### 6.2 Why Coraza fits

| Need | Coraza |
|---|---|
| Mature rules | Runs [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)'s rule language ([SecLang](https://coraza.io/docs/seclang/)) and the **OWASP CRS**, with the CRS regression tests |
| Go-native | Pure Go, no [cgo](https://pkg.go.dev/cmd/cgo): static binaries, easy cross-compiles, can run in-process |
| Compatibility | Existing ModSecurity rules and CRS exclusions work, so there is a migration path from [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) with ModSecurity |
| License | Apache-2.0, like Inkwall and CRS |
| Community | An OWASP project; proven in [`coraza-caddy`](https://github.com/corazawaf/coraza-caddy), [`coraza-spoa`](https://github.com/corazawaf/coraza-spoa) and [`coraza-proxy-wasm`](https://github.com/corazawaf/coraza-proxy-wasm) |
| Extension points | A plugin API for operators and transformations (multiphase evaluation and [`coraza-wasilibs`](https://github.com/corazawaf/coraza-wasilibs) were rejected: [0001 §3.1](0001-performance-first-architecture.md#31-measured-baseline-2026-10-03)) |
| Reuse | The same library runs in the engine, the validating webhook and `inkwallctl test`, so all three agree |

### 6.3 Alternatives considered

| Alternative | Why not (for now) |
|---|---|
| **Write our own engine** | A large effort, and a high bypass risk as a starting point. Later chosen for performance: it runs the CRS, with Coraza as the reference (oracle) and fallback ([0007](0007-inkwall-engine.md)) |
| **[libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity) v3 through cgo** | cgo overhead on every request, harder builds, and C memory bugs inside our process. Trustwave handed it to OWASP in 2024 |
| **[libinjection](https://github.com/libinjection/libinjection) only** | Detects only [SQL injection](https://owasp.org/www-community/attacks/SQL_Injection) and [XSS](https://owasp.org/www-community/attacks/xss/); no rule language, no CRS |
| **Machine-learning detection** | No training data or feedback loop yet, and its verdicts are hard to explain. Possible later as another `Evaluator` |
| **Our own rule language** | Lock-in, and no existing rules to start from |

### 6.4 Risks and mitigations

| Risk | Mitigation |
|---|---|
| CRS is regex-heavy and slow | Tiered pipeline, argument and body limits, admission control, fail-closed block mode, CI benchmarks ([0001](0001-performance-first-architecture.md)); Inkwall's own engine in the long term ([0007](0007-inkwall-engine.md)) |
| Dependence on the community | Coraza sits behind `pkg/rules.Evaluator` and is pinned; [go-ftw](https://github.com/coreruleset/go-ftw) tests run on every upgrade; fixes go upstream; forking is the last resort |
| An upgrade changes detection | Coraza and CRS are pinned per release ([0002 §8.6](0002-system-architecture.md#86-versioning-and-compatibility)) and exposed as a named built-in rule set |
| [Garbage-collection](https://go.dev/doc/gc-guide) pauses | Transaction pooling, [`GOMEMLIMIT`](https://go.dev/doc/gc-guide#Memory_limit), allocs/op gated in CI |

### 6.5 Where Coraza is used, and where it is not

| Component | Uses Coraza? | For |
|---|---|---|
| inkwall-engine (`pkg/rules/coraza`) | Yes | Tier T2, T3 and T4 rules (headers and URI, body, response) |
| Operator's validating webhook | Yes | Compiling rules at admission |
| inkwallctl (`test`, with flags, `--policy` or `--bundle`) | Yes | Local and CI validation |
| Caddy module (not yet) | Yes (embeds the engine) | In-process evaluation |
| Adapters, router, IP lists, rate limiter | No | Inkwall's own code; runs before the rules |
| Traefik Yaegi plugin, nginx Lua plugin (not yet) | No | Thin clients that call the engine |
| Control plane (not yet) | For validation | Rejecting bad rules before they reach clusters |
