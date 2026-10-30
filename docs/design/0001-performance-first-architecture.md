# 0001 — Performance-First Architecture

- Status: Draft
- Date: 2026-09-27
- Updated: 2026-10-30
- Owner: noureldin

Inkwall is a web application firewall (WAF) that sits in the request path, so every request pays
for it in latency. This document sets the performance rules every component follows: the latency
budgets, the order in which a request is checked, how the engine is built, where it runs, and
what happens when it fails. It also records what has been measured so far: the budgets are not met
yet.

Terms used here:

- **Engine:** `inkwall-engine`, the process that inspects requests and returns verdicts.
- **Proxy:** the ingress controller's data-plane process (Traefik, Envoy, ...), which asks the
  engine about each request.
- **Verdict:** the engine's answer: allow, deny, or log (in detect mode), plus metadata.
- **Policy:** a `WAFPolicy`: the mode, rule sets, limits and exclusions for a set of routes.
- **Bundle:** the policy bundle, an immutable, signed snapshot of all of a cluster's policies,
  which the operator builds and every engine enforces.
- **CRS:** the OWASP Core Rule Set (CRS). **Coraza:** the Go WAF library that evaluates it today.

## Contents

- [1. Goal](#1-goal)
- [2. Where latency comes from (and how we kill each source)](#2-where-latency-comes-from-and-how-we-kill-each-source)
- [3. Latency budgets](#3-latency-budgets)
  - [3.1 Measured baseline (2026-10-03)](#31-measured-baseline-2026-10-03)
- [4. Request pipeline: tiered, cheapest first](#4-request-pipeline-tiered-cheapest-first)
  - [Enforcement modes (per route)](#enforcement-modes-per-route)
- [5. Engine internals](#5-engine-internals)
  - [5.1 Process model](#51-process-model)
  - [5.2 Rule evaluation](#52-rule-evaluation)
  - [5.3 State (rate limits, reputation)](#53-state-rate-limits-reputation)
  - [5.4 Telemetry](#54-telemetry)
  - [5.5 Wire format](#55-wire-format)
- [6. Deployment topology](#6-deployment-topology)
- [7. Failure behaviour](#7-failure-behaviour)
- [8. Proving it: the performance test harness](#8-proving-it-the-performance-test-harness)
- [9. Open questions](#9-open-questions)

## 1. Goal

1. A request that passes inspection gains less latency than normal network jitter.
2. When Inkwall fails or is overloaded, traffic keeps flowing, unless the policy says to fail
   closed.
3. Performance is tested: every pull request is benchmarked, and a regression fails CI.

Blocking a request inline always costs time. So we set **budgets** ([§3](#3-latency-budgets)),
and new routes start in detect mode, which adds no latency.

## 2. Where latency comes from (and how we kill each source)

| Source | Typical cost | Mitigation |
|---|---|---|
| Hop from the proxy to an engine on another node | 0.3–2 ms, bad tails | Run in-process, or as a sidecar over a Unix socket |
| Connection setup per request | 0.1–1 ms | Persistent HTTP/2 streams, keepalive pools, SPOE pipelining |
| Body buffering | Grows with the body | Headers only by default; bodies only where needed, with a size cap |
| CRS regex evaluation | 50 µs to several ms | Prefilter ([§5.2](#52-rule-evaluation)), precompiled rules, early exit |
| Allocation and garbage collection | p99 spikes | Pooling, a zero-allocation hot path, `GOMEMLIMIT`, allocs/op gated in CI |
| Lock contention | p99 spikes | Lock-free policy reads (`atomic.Pointer`), sharded counters |
| Logging and telemetry | Blocking I/O | Ring buffer and a background shipper; drop events, never apply backpressure |
| Control plane down | Unbounded | The hot path never calls it; the last known good policy is local |

## 3. Latency budgets

These are the initial targets. The measurements in [§3.1](#31-measured-baseline-2026-10-03) check
them.

A budget is the latency Inkwall **adds**, compared with the same proxy without Inkwall, with the
engine at 70% CPU.

| Integration mode | Header-only p50 | Header-only p99 | Body (per 8 KB) p99 |
|---|---|---|---|
| In-process (Caddy module, Envoy Go filter) | ≤ 50 µs | ≤ 300 µs | ≤ 300 µs |
| Sidecar over a Unix socket (Envoy, HAProxy, nginx) | ≤ 150 µs | ≤ 1 ms | ≤ 500 µs |
| Sidecar over localhost TCP (Traefik ForwardAuth) | ≤ 250 µs | ≤ 1.5 ms | n/a |
| Detect mode (asynchronous or mirrored) | ~0 | ~0 | ~0 |

- **Per-request deadline:** 250 ms by default, set per policy. It is a safety cap. When it
  passes, the failure mode applies and the engine emits an event.
- **Failure mode** (what happens to a request the engine could not inspect): by default, the engine **fails
  closed in block mode and fails open in detect mode**. Failing open in block mode can be bypassed:
  an attacker pads the request until inspection passes the deadline (about 5 KiB was enough with a
  20 ms deadline).

### 3.1 Measured baseline (2026-10-03)

Engine only (`BenchmarkEvaluate`, `BenchmarkEvaluateArgs`): Coraza 3.8.1, CRS 4.25 at paranoia
level 1 (PL1), on one core of an i7-1255U.

| Request | Time | Budget it maps to |
|---|---|---|
| Benign GET, no body | ~0.51 ms | Header-only p50 ≤ 0.15 ms (sidecar) |
| Benign form POST, 2 fields | ~0.74 ms | |
| Form POST, 10 / 50 / 150 fields | 1.4 / 5.8 / 18.8 ms | Body p99 ≤ 0.5 ms per 8 KB |
| JSON POST, 10 / 50 / 150 fields | 2.3 / 9.6 / 29.3 ms | |
| JSON POST, 8 KB, ~450 fields | ~100 ms | |

- **Header-only requests are about 3× over budget.** There is no single hotspot: regex takes about
  22% of the time, garbage collection about 14%.
- **Body cost grows linearly with the number of arguments:** about 0.13 ms per form field and
  0.2 ms per JSON field, because CRS runs most rules once per argument. By rule family: SQL
  injection 26%, XSS 23%, remote command execution 12%, PHP 9%.
- **An attacker can pad a request past any fixed deadline.** This is contained, not solved:
  - the engine fails closed on a timeout;
  - `--max-args` (default 1000) rejects a request before CRS runs;
  - oversized bodies are denied in block mode;
  - `MaxConcurrent` admission control bounds the CPU spent.
- **Under load** (2026-10-10, `inkwallctl bench`, in-process, 12 threads): about 780 requests/s per
  worker on a header-only GET (p50 0.73 ms), and about 3,700 requests/s at most. At `--rate 2600`
  the request mix has p50 1.9 ms and p99 19.5 ms, from queueing behind requests with bodies. These
  are laptop numbers: compare them only on the same machine.

Measured, but not adopted:

- Coraza's `SecRxPreFilter`: 10–25% faster, but it **misses attacks** in `test/crs` (CRS tests
  942220-2 and 932311-7).
- `coraza-wasilibs` crashes on Go 1.26. Coraza's multiphase evaluation is 7% slower.
  `no_regex_multiline` gains 3% but changes behaviour. `GOGC=400` gains about 7%; it is left as a
  deployment setting.

Next levers, by expected gain:

1. **Skip routes and bodies per route** (tier T0, [§4](#4-request-pipeline-tiered-cheapest-first)).
   **Built** in the engine (`pkg/router`): the flags `--skip-paths` and `--skip-body-paths` when the
   engine is configured by flags, and a `WAFPolicy`'s `skip` per policy, carried in the bundle
   (`skip_paths`, `skip_body_paths`). **Not yet:** skipping in the proxy, so skipped requests still
   reach the engine.
2. Cut Coraza's overhead per rule and per argument, ideally upstream, together with a prefilter
   fix.
3. A single-pass prefilter ([§5.2](#52-rule-evaluation)). It must pass the CRS test suite first.

**The budgets are not met yet.**

## 4. Request pipeline: tiered, cheapest first

The engine checks a request in tiers. Each tier runs only if the previous ones reached no decision.

| Tier | Does | Built (v0.1.0) |
|---|---|---|
| T0 | Route match and skip list (static files, health checks) | Yes (`pkg/router`) |
| T1 | IP allow and deny lists, rate limits (~1 µs); answers 403 or 429 | No |
| T2 | CRS rules on headers and URI, with early exit; answers 403 | Yes |
| T3 | Body rules, only if the policy and the content type need them, with a size cap | Yes |
| T4 | Response inspection, off by default | No |

- By design, T0 skips run **in the proxy** where possible
  ([0004 §4.4](0004-operator.md#44-wiring-controller)), so skipped requests never reach the
  engine. Not built yet: see [§3.1](#31-measured-baseline-2026-10-03).
- Moving T1 into the proxies' own features comes later, not in v1.

### Enforcement modes (per route)

- **Detect mode** (the default): by design, the proxy forwards the request at once, and the
  engine inspects a copy asynchronously, adding no latency. **Built today:** every built adapter
  still waits for the verdict; in detect mode the engine inspects inline, logs what it would have
  denied, and always allows (`pkg/pipeline`).
- **Block mode:** the proxy waits for an inline verdict, within the budget.
- **Block-high-confidence mode** (not built yet): inline verdicts for tiers T0–T2; bodies are
  inspected asynchronously and feed IP reputation.

The intended workflow: onboard a route in detect mode, tune out the false positives, then promote
it to block mode.

## 5. Engine internals

### 5.1 Process model

- One binary, `inkwall-engine`. All its listeners share one core. **Built:** the forward-auth
  listener, `/v1/check` and the reverse proxy. **Not yet:** ext_authz, ext_proc and SPOE. (Each
  protocol is described in [0006](0006-adapter-protocols.md).)
- Policies are compiled once into an immutable set and swapped through an `atomic.Pointer`, so
  reads take no lock. **Built** (`pkg/policy`).
- **Not yet:** `sync.Pool` buffers, automaxprocs, `GOMEMLIMIT` at 90% of the memory limit, a tuned
  `GOGC`.

### 5.2 Rule evaluation

1. **Start with Coraza and the OWASP CRS. Built.** Coraza's own prefilter, multiphase evaluation
   and `coraza-wasilibs` were rejected ([§3.1](#31-measured-baseline-2026-10-03)).
2. **Single-pass prefilter (not built yet).** Put the required literals of every rule into one
   Aho-Corasick automaton (Hyperscan optional). One pass over a value then picks the rules that can
   match it.

   **Feasibility measured (2026-10-04,** `test/perf/prefilter`**):**

   | | Paranoia level 1 | Paranoia level 4 |
   |---|---|---|
   | CRS rules that run per argument | 104 | 196 |
   | Of those, filterable by required literals | 100 | 181 |
   | Benign rule-value evaluations skippable | 90.5% | 86.2% |
   | Operator time skippable (weighted by measured cost) | 72% (÷3.6) | 69% (÷3.2) |
   | Soundness violations (regex matched but filter said skip) | 0 of ~2.1M checks | 0 of ~3.9M checks |

   - Checked on the benign corpus, 9,747 CRS payloads and 13,314 Unicode case-fold variants.
   - Literals must match under Unicode case folding. Plain lowercasing was unsound: it missed
     `;BAſE64` (rule 932260) and `@@VERſION` (rule 942480); see
     [0007 §4.3](0007-inkwall-engine.md#43-prefilter-and-normalization-views).
   - A non-literal regex node (such as `.`) breaks a literal. Coraza gets this wrong.
   - Gain: about 30% if the filter runs after transformations, and 3–5× if it runs before them,
     which needs a sound decoded form of each value.
   - It ships only after the CRS test suite and differential fuzzing pass.
   - **Decision:** build it into Inkwall's own rule engine, which owns the rule loop
     ([0007](0007-inkwall-engine.md)).
3. Rules sit behind the `pkg/rules.Evaluator` interface
   ([0002 §3.1](0002-system-architecture.md#31-inkwall-engine-data-plane)), so another rule engine
   can replace Coraza without touching the adapters. **Built.**

### 5.3 State (rate limits, reputation)

**Not built yet.** Each CPU keeps local token buckets. Cluster-wide limits sync asynchronously,
about every 100 ms. The hot path never waits on the network, and we accept a little
over-admission.

### 5.4 Telemetry

- Design: events go to a lock-free ring buffer and are shipped in batches. Audit logs cover only
  matched or sampled requests. When the buffer overflows, events are dropped and counted.
- **Built:** Prometheus metrics, `/healthz` and `/readyz` (`pkg/telemetry`), and pprof
  (`--pprof`). Security events go to a bounded ring buffer and are shipped to the operator in
  batches (`pkg/events`); that buffer uses a mutex, not a lock-free design. **Not yet:** a
  lock-free buffer, audit logs.

### 5.5 Wire format

- Design: protobuf with `vtprotobuf` marshalers, and gRPC over long-lived HTTP/2 streams.
  **Built:** protobuf and the gRPC streams. **Not yet:** `vtprotobuf`.
- Adapters send only the fields the policy reads.

## 6. Deployment topology

**By default, the engine runs as a sidecar in the ingress controller's pod and is reached over a
Unix socket.** There is no hop to another node, no Service and no TLS.

| Proxy | Integration | Transport |
|---|---|---|
| Caddy | Native module (in-process) | Function call |
| Envoy / Envoy Gateway / Istio | ext_proc; optional Envoy Go filter | gRPC over a Unix socket |
| HAProxy | SPOE agent | Unix socket |
| ingress-nginx | Lua plugin (auth-url as a fallback) | Unix socket |
| Traefik | ForwardAuth; a plugin later | HTTP keepalive over localhost |

- The engine is injected through the ingress controller's extension point or a Pod webhook, never
  by patching the controller's Deployment ([0004 §4.3](0004-operator.md#43-injection-controller)).
- Its resources are sized from the policy: a CPU-throttled engine means a bad p99.
- A standalone engine Deployment behind a Service is supported, but slower.
- **Built (v0.1.0):** Traefik, with the engine injected by the Pod webhook; the standalone reverse
  proxy. **Not yet:** the other proxies.

## 7. Failure behaviour

![How a request gets its verdict: route skip lists, body size, an evaluation slot and evaluation under the deadline lead to allow, deny or log; overload, timeout and evaluator errors lead to "not inspected", which fails closed with 503 in block mode and open in detect mode](../diagrams/verdict-lifecycle.svg)

- **Detect mode denies nothing.** Requests that block mode would deny are logged. Oversized bodies
  are forwarded after the header and URI checks.
- **Failure mode:** the engine fails closed in block mode and fails open in detect mode. Set per policy, or with
  `--failure-mode` and `--oversize-body` when the engine is configured by flags.
- **Proxy timeouts:** by design always set, just above the engine's deadline. Not yet for Traefik:
  the operator's ForwardAuth Middleware sets no timeout.
- **Overload:** admission control sheds inspection, not traffic, and emits a metric.
- **Control plane down:** the engine enforces the last known good policy, indefinitely.

## 8. Proving it: the performance test harness

| Layer | What | State |
|---|---|---|
| Micro | `make bench-compare` and the CI job `bench`. Packages whose test binary is unchanged are skipped; the rest run base and head interleaved, 8 times. `hack/benchgate` flags a significant change (p < 0.05) of more than 5% in `sec/op`, `B/op` or `allocs/op`. The gate fails only if a re-run of the flagged benchmarks shows the change again | Built |
| Engine | `inkwallctl bench`: a fixed corpus (`cmd/inkwallctl/corpus.go`), closed-loop or at a fixed `--rate`, latency measured from the scheduled time. Any wrong verdict, timeout or overload fails the run | Built |
| End-to-end on kind | k6 against each proxy, with and without Inkwall; the difference is what [§3](#3-latency-budgets) budgets | Not yet |
| Profiling | `--pprof` on the admin listener; flame graphs in CI; Pyroscope | Endpoints built |
| Soak and chaos | A 24 h soak; kill the engine under load and check the failure mode | Not yet |

## 9. Open questions

1. Hyperscan (cgo) as an optional build, or pure Go only?
2. Envoy Go filter: supported or experimental?
3. Default body cap: 8 KB, 64 KB, or per content type?
4. Detect mode by default: is it acceptable to customers who expect blocking on day one?
