# 0005 — Component Map and Rule Engine Choice

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin
- Depends on: [0002](0002-system-architecture.md), [0004](0004-operator.md)

Every Inkwall component, where it runs, and why the engine is built on Coraza.

## 1. Component overview

![Inkwall architecture: the proxy asks the inkwall-engine sidecar for a verdict before forwarding; the operator watches WAFPolicy and route objects and pushes signed policy bundles to every engine](../diagrams/system-overview.svg)

- Request path: client → proxy → engine sidecar (verdict over UDS or localhost) → app.
- Control path: Git / `kubectl` → kube-apiserver → operator (webhooks, bundle Secret) → signed
  bundle stream to engines → status back on the CRDs.
- Planned: Caddy with an in-process engine, and an optional SaaS control plane connected over one
  mTLS stream per cluster.

## 2. Where each component runs and when it is built

All Apache-2.0. Everything in the cluster works without the SaaS, which only adds management,
analytics and threat intel.

| Component | Runs in | Code | v0.1.0 |
|---|---|---|---|
| **inkwall-engine** | Sidecar in ingress controller pods, or standalone | `cmd/engine`, `pkg/` | Built |
| **Engine adapters** | Engine process | `pkg/adapters/*` | Built: `forwardauth`, `httpcheck` (`/v1/check`), `proxy`. Not yet: ext_authz, ext_proc, SPOE |
| **Proxy-side glue** | Proxy config | `operator/integrations`, `operator/internal/wiring` | Built: Traefik Middleware. Not yet: nginx Lua, SPOE, Envoy config |
| **Caddy module** | Compiled into Caddy | `adapters/caddy` (own go.mod) | Not yet |
| **Traefik plugin** (thin client) | Traefik (Yaegi) | `adapters/traefik-plugin` (own go.mod) | Not yet |
| **inkwall-operator** | `inkwall-system`, 2 replicas | `cmd/operator`, `operator/` | Built |
| **Admission webhooks** | Operator process | `operator/webhook` | Built (validate, inject) |
| **CRDs** | kube-apiserver | `operator/api/v1alpha1`, `operator/config/crd` | Built: WAFPolicy, WAFRuleSet, ClusterWAFRuleSet, InkwallConfig |
| **Helm chart** | User install | `deploy/helm/inkwall` | Built |
| **OLM bundle** | OperatorHub | operator-sdk | Not yet (Stage 6) |
| **inkwallctl** | Developer machine, CI | `cmd/inkwallctl` | Built: `test` (flags, `--policy`, `--bundle`), `bench`. Not yet: `migrate` |
| **Protobuf APIs** (engine, agent, bundle) | Engine, operator, control plane | `api/` | Built |
| **Control plane** (SaaS) | Inkwall-hosted | separate product | Not yet (Stage 5) |

## 3. Engine internals

![inkwall-engine internals as built today: the reverse-proxy, forward-auth and check-API adapters turn their input into a request.Request and call pipeline.Check, which consults the route table, runs the Coraza evaluator with the OWASP CRS and reports every verdict to telemetry](../diagrams/engine-internals.svg)

**Built (v0.1.0):** as in the diagram; each component links to its source. Also `pkg/policy` (one
pipeline per bundle policy, swapped atomically), `pkg/agent` (operator stream, bundle verify,
disk cache) and `pkg/clientip`.

**Not yet:**

- Adapters `extauthz` (gRPC), `extproc` (gRPC stream), `spoe` (SPOP).
- T1 tier: `pkg/iplist`, `pkg/ratelimit`, between the route table and rules.
- `pkg/events`: verdicts through a ring buffer and batch shipper; traces in telemetry.
- The native engine (0007) as a second `pkg/rules` evaluator.

## 4. Operator internals

| Part | Does | Code | v0.1.0 |
|---|---|---|---|
| Discovery + integration registry | Find controller pods (design: also IngressClass, GatewayClass) | `operator/integrations` | Built: Traefik, by selectors. Not yet: envoygateway, istio, ingressnginx, haproxy, caddy |
| Injection | Native sidecar via Pod webhook | `operator/internal/injection` | Built |
| Wiring | Render proxy config, server-side apply | `operator/internal/wiring` | Built (Traefik) |
| Resolver | Policy targets → host/path/method | `operator/resolver` | Built |
| Bundle builder | Leader only: debounce changes (1 s), build, sign, version, write Secret | `operator/bundle`, `operator/internal/controller` | Built |
| Distribution server | All replicas, gRPC; ACK/NACK/heartbeat | `operator/internal/distribution` | Built |
| Status | `Enforced` condition (engines on current bundle) | `operator/internal/distribution` | Built |
| Validating webhook | Compile rule sets as the engine does; check paths | `operator/webhook` | Built |
| Upstream sync | Leader only, mTLS to the control plane | — | Not yet |
| WAFIPList CRD | IP lists | — | Not yet |

## 5. Key flows

### 5.1 Request in block mode

1. Proxy terminates TLS, matches the route, asks the engine.
2. Engine: T0 route → policy, T1 IP/rate (not yet), T2/T3 CRS rules.
3. Below threshold: continue, proxy forwards. Score ≥ threshold: 403 and an event.
4. Engine down or slow: proxy timeout → 503 in block mode, forward in detect mode.

### 5.2 Policy change (GitOps mode)


1. Git / Argo CD applies a WAFPolicy; the validating webhook compiles its rules.
2. Leader resolves targets, debounces 1 s, writes a signed, versioned bundle Secret.
3. Every replica pushes the bundle to its engines; engines compile in the background, swap
   atomically and ACK.
4. Leader sets `Enforced=True` with the engine count (e.g. 6/6).

## 6. Why Coraza

### 6.1 What a WAF rule engine must do

A rule language (variables, operators, transformations, actions, chaining, phases); anti-evasion
transformations; body processors for forms, multipart, JSON and XML; anomaly scoring, collections,
audit logs; and a maintained rule set with regression tests. Writing it from scratch is large, and
every parsing difference is a potential bypass.

### 6.2 Why Coraza fits

| Need | Coraza |
|---|---|
| Mature rules | Runs ModSecurity SecLang and **OWASP CRS** with its regression tests |
| Go-native | Pure Go, no cgo: static binaries, easy cross-compiles, can run in-process |
| Compatibility | Existing ModSecurity rules and CRS exclusions work: a migration path from ingress-nginx + ModSecurity |
| License | Apache-2.0, as are Inkwall and CRS |
| Community | OWASP project; proven in `coraza-caddy`, `coraza-spoa`, `coraza-proxy-wasm` |
| Extension points | Plugin API for operators and transformations (multiphase and `coraza-wasilibs` rejected, 0001 §3.1) |
| Reuse | Same library in the engine, the validating webhook and `inkwallctl test`, so all three agree |

### 6.3 Alternatives considered

| Alternative | Why not (for now) |
|---|---|
| **Write our own engine** | Large effort, high bypass risk as a start. Later chosen for performance, running CRS, with Coraza as oracle and fallback ([0007](0007-inkwall-engine.md)) |
| **libmodsecurity v3 via cgo** | cgo overhead per request, harder builds, C memory bugs in-process; Trustwave handed it to OWASP in 2024 |
| **libinjection only** | SQLi/XSS only; no rule language or CRS |
| **ML detection** | No training data or feedback loop yet; verdicts hard to explain. Possible later `Evaluator` |
| **Proprietary rule DSL** | Lock-in, no rules to start from |

### 6.4 Risks and mitigations

| Risk | Mitigation |
|---|---|
| CRS is regex-heavy and slow | Tiered pipeline, argument and body limits, admission control, fail-closed block, CI benchmarks (0001); own engine long term (0007) |
| Community dependency | Behind `pkg/rules.Evaluator`; pinned; go-ftw tests on upgrade; fixes upstream; fork last |
| Upgrade changes detection | Coraza and CRS pinned per release (0002 §8.6), exposed as a named builtin rule set |
| GC pauses | Transaction pooling, `GOMEMLIMIT`, allocs/op gated in CI |

### 6.5 Where Coraza is used, and where it is not

| Component | Uses Coraza? | For |
|---|---|---|
| inkwall-engine (`pkg/rules/coraza`) | Yes | T2 / T3 / T4 rules |
| Operator validating webhook | Yes | Compiling rules at admission |
| inkwallctl (`test`, with flags, `--policy` or `--bundle`) | Yes | Local and CI validation |
| Caddy module (not yet) | Yes (embeds the engine) | In-process evaluation |
| Adapters, router, IP lists, rate limiter | No | Inkwall code; runs before rules |
| Traefik Yaegi plugin, nginx Lua plugin (not yet) | No | Thin clients calling the engine |
| Control plane (not yet) | For validation | Rejecting bad rules before clusters |
