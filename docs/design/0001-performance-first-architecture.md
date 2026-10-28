# 0001 — Performance-First Architecture

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin

## 1. Goal

1. Added latency for a passing request stays below network jitter.
2. Inkwall failing or overloaded never blocks traffic unless the policy says fail-closed.
3. Performance is tested: every PR is benchmarked; regressions fail CI.

Inline blocking always costs time, so we set **budgets** (§3) and default new routes to detect mode.

## 2. Where latency comes from (and how we kill each source)

| Source | Typical cost | Mitigation |
|---|---|---|
| Cross-node hop proxy → engine | 0.3–2 ms, bad tails | In-process or sidecar over a Unix socket |
| Connection setup per request | 0.1–1 ms | Persistent HTTP/2 streams, keepalive pools, SPOE pipelining |
| Body buffering | Grows with body | Headers-only by default; bodies only where needed, size-capped |
| CRS regex evaluation | 50 µs–several ms | Prefilter (§5.2), precompiled rules, early exit |
| Allocation / GC | p99 spikes | Pooling, zero-alloc hot path, `GOMEMLIMIT`, allocs/op gated in CI |
| Lock contention | p99 spikes | Lock-free policy reads (`atomic.Pointer`), sharded counters |
| Logging / telemetry | Blocking I/O | Ring buffer + background shipper; drop, never backpressure |
| Control plane down | Unbounded | Hot path never calls it; last-known-good policy is local |

## 3. Latency budgets (initial targets, validated in Stage 1)

**Added** latency vs the same proxy without Inkwall, at 70% engine CPU.

| Integration mode | Header-only p50 | Header-only p99 | Body (per 8 KB) p99 |
|---|---|---|---|
| In-process (Caddy module, Envoy Go filter) | ≤ 50 µs | ≤ 300 µs | ≤ 300 µs |
| Sidecar over Unix socket (Envoy, HAProxy, nginx) | ≤ 150 µs | ≤ 1 ms | ≤ 500 µs |
| Sidecar over localhost TCP (Traefik ForwardAuth) | ≤ 250 µs | ≤ 1.5 ms | n/a |
| Detect mode (async / mirrored) | ~0 | ~0 | ~0 |

- Per-request deadline: default 250 ms, per policy; a safety cap. On timeout the failure mode
  applies and an event is emitted.
- Failure mode defaults to **closed in block, open in detect**: fail-open block is bypassable by
  padding a request past the deadline (~5 KiB sufficed at 20 ms).

### 3.1 Measured baseline (2026-10-03)

Engine only (`BenchmarkEvaluate`, `BenchmarkEvaluateArgs`): Coraza 3.8.1, CRS 4.25, PL1, one core
of an i7-1255U.

| Request | Time | Budget it maps to |
|---|---|---|
| Benign GET, no body | ~0.51 ms | Header-only p50 ≤ 0.15 ms (sidecar) |
| Benign form POST, 2 fields | ~0.74 ms | |
| Form POST, 10 / 50 / 150 fields | 1.4 / 5.8 / 18.8 ms | Body p99 ≤ 0.5 ms per 8 KB |
| JSON POST, 10 / 50 / 150 fields | 2.3 / 9.6 / 29.3 ms | |
| JSON POST, 8 KB, ~450 fields | ~100 ms | |

- **Header-only is ~3× over budget**, with no single hotspot (regex ~22%, GC ~14%).
- **Body cost is linear in argument count** (~0.13 ms/form field, ~0.2 ms/JSON field); CRS runs most
  rules per argument. SQLi 26%, XSS 23%, RCE 12%, PHP 9%.
- **A fixed deadline is reachable by padding.** Contained, not solved: fail-closed on timeout,
  `--max-args` (default 1000) rejects before CRS, oversized bodies denied in block mode,
  `MaxConcurrent` admission control bounds CPU.
- Under load (2026-10-10, `inkwallctl bench`, in-process, 12 threads): ~780 req/s per worker on a
  header-only GET (p50 0.73 ms); max ~3,700 req/s; at `--rate 2600` the mix has p50 1.9 ms,
  p99 19.5 ms (queueing behind bodies). Laptop numbers; compare on one machine.

Measured, not adopted:

- Coraza `SecRxPreFilter`: 10–25% faster but **misses attacks** in `test/crs` (942220-2, 932311-7).
- `coraza-wasilibs` (crashes on Go 1.26), multiphase (7% slower), `no_regex_multiline` (3%, behaviour
  change). `GOGC=400` (~7%) left as a deployment setting.

Next levers, by expected gain:

1. Per-route skip of routes and bodies (§4, T0). **Built** for standalone mode (`--skip-paths`,
   `--skip-body-paths`, `pkg/router`); **not yet** set per route by the operator.
2. Less Coraza per-rule, per-argument overhead, ideally upstream, with a prefilter fix.
3. Single-pass prefilter (§5.2); must pass the CRS suite first.

**The budgets are not met yet.**

## 4. Request pipeline: tiered, cheapest first

Each tier runs only if the previous one did not decide.

| Tier | Does | Built (v0.1.0) |
|---|---|---|
| T0 | Route match, skip list (static, health checks) | Yes (`pkg/router`) |
| T1 | IP allow/deny, rate limit (~1 µs) → 403/429 | No |
| T2 | Header/URI CRS rules, early exit → 403 | Yes |
| T3 | Body rules, only if policy and content type need it, capped | Yes |
| T4 | Response inspection, off by default | No |

- T0 skips run **in the proxy** where possible (0004 §4.4), so skipped requests never reach the engine.
- Pushing T1 into proxy-native features: later, not v1.

### Enforcement modes (per route)

- **detect** (default): proxy forwards at once; engine inspects a copy async. Zero added latency.
- **block**: inline verdict within budget.
- **block-high-confidence** (not yet): inline for T0–T2; bodies async, feeding IP reputation.

Workflow: onboard in detect, tune false positives, promote to block.

## 5. Engine internals

### 5.1 Process model

- One binary `inkwall-engine`; listeners share one core. **Built:** forward-auth, `/v1/check`,
  reverse proxy. **Not yet:** ext_authz, ext_proc, SPOE.
- Policy compiled once into an immutable set, swapped via `atomic.Pointer`; no lock on read.
  **Built** (`pkg/policy`).
- **Not yet:** `sync.Pool` buffers, automaxprocs, `GOMEMLIMIT` at 90% of the limit, tuned `GOGC`.

### 5.2 Rule evaluation

1. **Start:** Coraza + OWASP CRS. **Built.** Coraza's prefilter, multiphase and `coraza-wasilibs`
   rejected (§3.1).
2. **Single-pass prefilter (Stage 6, not yet):** required literals of every rule in one
   Aho-Corasick automaton (Hyperscan optional); one pass picks the rules that can match.

   **Feasibility measured (2026-10-04,** `test/perf/prefilter`**):**

   | | Paranoia level 1 | Paranoia level 4 |
   |---|---|---|
   | CRS rules that run per argument | 104 | 196 |
   | Of those, filterable by required literals | 100 | 181 |
   | Benign rule-value evaluations skippable | 90.5% | 86.2% |
   | Operator time skippable (weighted by measured cost) | 72% (÷3.6) | 69% (÷3.2) |
   | Soundness violations (regex matched but filter said skip) | 0 of ~2.1M checks | 0 of ~3.9M checks |

   - Checked on the benign corpus, 9,747 CRS payloads and 13,314 Unicode fold variants.
   - Match under Unicode case folding: lowercasing was unsound (`;BAſE64` 932260, `@@VERſION`
     942480) (0007 §4.3). Non-literal nodes (e.g. `.`) break a literal, which Coraza gets wrong.
   - Gain: ~30% after transformations; 3–5× before them (needs a sound decoded form).
   - Ships only after the CRS suite and differential fuzzing pass.
   - **Decision:** build it into Inkwall's own engine, which owns the rule loop
     ([0007](0007-inkwall-engine.md)).
3. Rules sit behind `pkg/rules.Evaluator` (0002 §3.1) so an engine can replace Coraza without
   touching adapters. **Built.**

### 5.3 State (rate limits, reputation)

**Not yet.** Local per-CPU token buckets; cluster limits synced async (~100 ms). Hot path never
waits on the network; small over-admission accepted.

### 5.4 Telemetry

- Events to a lock-free ring buffer, shipped in batches; audit logs only for matched or sampled
  requests; overflow drops and counts.
- **Built:** Prometheus metrics, `/healthz`, `/readyz` (`pkg/telemetry`), pprof (`--pprof`).
  **Not yet:** ring buffer, shipper, audit logs.

### 5.5 Wire format

- Protobuf with `vtprotobuf` marshalers, gRPC over long-lived HTTP/2 streams.
- Adapters send only fields the policy reads.

## 6. Deployment topology

**Default: sidecar in the ingress controller pod over a Unix socket**: no node, Service or TLS hop.

| Proxy | Integration | Transport |
|---|---|---|
| Caddy | Native module (in-process) | function call |
| Envoy / Envoy Gateway / Istio | ext_proc; optional Envoy Go filter | UDS gRPC |
| HAProxy | SPOE agent | UDS |
| ingress-nginx | Lua plugin (auth-url fallback) | UDS |
| Traefik | ForwardAuth, plugin later | localhost HTTP keepalive |

- Inject via the controller's extension point or a Pod webhook, never by patching its Deployment
  (0004 §4.3); size from policy, since a throttled engine means bad p99.
- Standalone Deployment behind a Service: supported, slower.
- **Built (v0.1.0):** Traefik via Pod-webhook injection; standalone reverse proxy.
  **Not yet:** other proxies.

## 7. Failure behaviour

![How a request gets its verdict: route skip lists, body size, an evaluation slot and evaluation under the deadline lead to allow, deny or log; overload, timeout and evaluator errors lead to "not inspected", which fails closed with 503 in block mode and open in detect mode](../diagrams/verdict-lifecycle.svg)

- Detect denies nothing: would-be blocks are logged; oversized bodies forwarded after header/URI checks.
- Failure mode: **closed in block, open in detect**; per policy or `--failure-mode`, `--oversize-body`.
- Proxy timeouts always set, just above the engine deadline.
- Overload: admission control sheds inspection, not traffic, and emits a metric.
- Control plane down: last-known-good policy enforced indefinitely.

## 8. Proving it: the performance test harness (built in Stage 1)

| Layer | What | State |
|---|---|---|
| Micro | `make bench-compare`, CI job `bench`: packages whose test binary is unchanged are skipped, the rest run base and head interleaved 8×; `hack/benchgate` flags a significant (p < 0.05) change > 5% in `sec/op`, `B/op`, `allocs/op`, and the gate fails only if a re-run of the flagged benchmarks shows it again | Built |
| Engine | `inkwallctl bench`: fixed corpus (`cmd/inkwallctl/corpus.go`), closed-loop or `--rate`, latency from scheduled time; any wrong verdict, timeout or overload fails | Built |
| End-to-end on kind | k6 per proxy with and without Inkwall; the delta is what §3 means | Not yet |
| Profiling | `--pprof` on the admin listener; flamegraphs in CI, Pyroscope | Endpoints built |
| Soak / chaos | 24 h soak; kill the engine mid-load, check the failure mode | Not yet |

## 9. Open questions

1. Hyperscan (cgo) as an optional build, or pure Go only?
2. Envoy Go filter: supported or experimental?
3. Default body cap: 8 KB, 64 KB, or per content type?
4. Detect by default: acceptable for customers expecting blocking on day one?
