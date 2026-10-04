# 0001 — Performance-First Architecture

- Status: Draft
- Date: 2026-09-27
- Owner: noureldin

## 1. Goal

Inkwall must never be the reason a request is slow. Concretely:

1. A request that passes inspection sees added latency below normal network jitter.
2. Inkwall failing or overloaded never blocks traffic unless a policy explicitly says fail-closed.
3. Performance is a tested contract: every PR is benchmarked and regressions fail CI.

"Zero overhead" cannot be achieved while blocking inline (inspecting takes time), so we commit to
**budgets** (section 3) and make the zero-overhead path (detect mode) the default for new routes.

## 2. Where latency comes from (and how we kill each source)

| Source | Typical cost | Mitigation |
|---|---|---|
| Network hop proxy → engine (cross-node) | 0.3–2 ms, bad tails | Never cross nodes. Engine runs in-process or as a sidecar in the proxy pod over a Unix socket |
| Connection setup per request | 0.1–1 ms | Persistent HTTP/2 (gRPC) streams, keepalive pools, SPOE pipelining |
| Body buffering | Grows with body size, holds the request | Headers-only by default; bodies only for routes/content types that need them, streamed, size-capped |
| Regex-heavy rule evaluation (CRS) | 50 µs–several ms | Prefilter + fast operators (section 5.2), precompiled rules, early exit |
| Allocation / GC pauses | p99 spikes | Pooled transactions, zero-alloc hot path, `GOMEMLIMIT`, allocs/op gated in CI |
| Lock contention (policy, counters) | p99 spikes under load | Lock-free policy reads (`atomic.Pointer`), per-core sharded counters |
| Logging / telemetry | Blocking I/O | Ring buffer + background batch shipper; drop under pressure, never backpressure |
| Control plane unavailable | Unbounded | Hot path never calls the control plane; last-known-good policy is local |

## 3. Latency budgets (initial targets, validated in Stage 1)

Measured as **added** latency vs the same proxy with Inkwall disabled, at 70% CPU on the engine.

| Integration mode | Header-only p50 | Header-only p99 | Body (per 8 KB) p99 |
|---|---|---|---|
| In-process (Caddy module, Envoy Go filter) | ≤ 50 µs | ≤ 300 µs | ≤ 300 µs |
| Sidecar over Unix socket (Envoy, HAProxy, nginx) | ≤ 150 µs | ≤ 1 ms | ≤ 500 µs |
| Sidecar over localhost TCP (Traefik ForwardAuth) | ≤ 250 µs | ≤ 1.5 ms | n/a |
| Detect mode (async / mirrored) | ~0 | ~0 | ~0 |

Hard per-request deadline (default 20 ms, configurable per policy): when it is exceeded the request
follows the policy's failure mode (default **fail-open**) and an event is emitted.

### 3.1 Measured baseline (2026-10-03)

First measurement of the engine alone (`BenchmarkEvaluate`, `BenchmarkEvaluateArgs`): Coraza 3.8.1,
CRS 4.25, paranoia level 1, single core of an i7-1255U. This is rule evaluation only, without any
proxy hop.

| Request | Time | Budget it maps to |
|---|---|---|
| Benign GET, no body | ~0.51 ms | Header-only p50 ≤ 0.15 ms (sidecar) |
| Benign form POST, 2 fields | ~0.74 ms | |
| Form POST, 10 / 50 / 150 fields | 1.4 / 5.8 / 18.8 ms | Body p99 ≤ 0.5 ms per 8 KB |
| JSON POST, 10 / 50 / 150 fields | 2.3 / 9.6 / 29.3 ms | |
| JSON POST, 8 KB, ~450 fields | ~100 ms | |

Findings:

- **The header-only path is about 3× over budget.** Cost is spread across Coraza evaluating all CRS
  rules (regex ~22%, rule evaluation and collection lookups, GC ~14%); there is no single hotspot.
- **Body cost is linear in the number of arguments,** about 0.13 ms per form field and 0.2 ms per
  JSON field, because CRS runs most rules once per argument. No CRS family dominates: SQLi 26%,
  XSS 23%, RCE 12%, PHP 9%, the rest small.
- **The 20 ms deadline is reached at ~100 JSON fields.** With fail-open, bodies beyond that are
  effectively uninspected. This is the most important gap. Admission control (`MaxConcurrent`)
  keeps abandoned evaluations from exhausting the CPU, and `--oversize-body deny` plus
  `--max-args` stop padding from hiding payloads, but neither makes inspection faster.

Measured and not adopted:

- **Coraza's regex prefilter (`SecRxPreFilter`)**: 10–25% faster, but the CRS regression suite
  (`test/crs`) showed it **misses attacks** (CRS tests 942220-2 and 932311-7). Left off until the
  suite passes with it on.
- `coraza-wasilibs` (crashes on Go 1.26), multiphase evaluation (7% slower), `no_regex_multiline`
  (3% faster, not worth the behaviour change). `GOGC=400` gives ~7% and is left as a deployment
  setting.

Next levers, in order of expected gain:

1. Per-route policy so static and low-risk routes skip inspection, and bodies are inspected only for
   routes that need them (§4, T0). **Done for standalone mode** (`--skip-paths`,
   `--skip-body-paths`, `pkg/router`); the operator will set these per route.
2. Reducing Coraza's per-rule, per-argument overhead (transformation cache hashing, allocations),
   preferably as upstream contributions, together with a fix for the prefilter's false negatives.
3. A single-pass prefilter across all rules (§5.2), which needs changes inside Coraza. Any
   prefilter must pass the CRS regression suite before it is enabled.

The budgets above stay as targets; they are not met yet.

## 4. Request pipeline: tiered, cheapest first

Most requests must exit in the earliest tiers.

```
request ─▶ T0 route match & skip list  ── skip (static assets, health checks) ─▶ upstream
            (precompiled, O(1)/trie)
          ─▶ T1 IP allow/deny + rate limit ─ deny ─▶ 403/429
            (CIDR trie, sharded token buckets, ~1 µs)
          ─▶ T2 header/URI inspection ─ deny ─▶ 403
            (prefiltered CRS phase 1–2, early exit)
          ─▶ T3 body inspection (only if policy + content-type require it)
            (streamed, capped at N KB, JSON/form parsers are zero-copy)
          ─▶ T4 response inspection (off by default)
```

Each tier runs only if the previous one did not decide. The T0 skip decision for unprotected routes
runs **inside the proxy** where possible (per-route attachment or a local route set, 0004 §4.4), so
those requests never reach the engine at all. Pushing T1 (IP lists, rate limits) into proxy-native
features is a later optimization, not part of v1.

### Enforcement modes (per route)

- **detect** (default for new routes): the proxy forwards immediately; the engine analyses a copy
  asynchronously (Envoy ext_proc `observability_mode`, nginx `mirror`, HAProxy SPOE async
  groups). Zero added latency.
- **block**: inline verdict within the budget.
- **block-high-confidence**: inline only for T0–T2; body analysis runs async and feeds IP
  reputation / auto-ban for subsequent requests.

Workflow: onboard a route in detect mode, tune false positives in the UI, then promote it to block.

## 5. Engine internals

### 5.1 Process model

- A single Go binary `inkwall-engine` with pluggable listeners: gRPC (ext_authz / ext_proc), HTTP
  forward-auth, SPOE, reverse-proxy. The same core handles all of them.
- Policies are compiled once when loaded into an immutable `Snapshot` and swapped atomically
  (`atomic.Pointer[Snapshot]`, RCU-style). Requests never take a lock to read policy.
- Coraza transactions, header maps and body buffers come from `sync.Pool`, which keeps allocations
  near zero.
- `GOMAXPROCS` matches the CPU limit (automaxprocs), `GOMEMLIMIT` sits at 90% of the memory
  limit, and `GOGC` is tuned from profiles.

### 5.2 Rule evaluation

1. **Start:** Coraza + OWASP CRS. Coraza's per-rule regex prefilter, multiphase evaluation and
   `coraza-wasilibs` were planned here but were measured as unsafe, slower or broken (§3.1).
2. **Single-pass prefilter (Stage 6):** extract required literals from every rule and compile them into a single
   multi-pattern automaton (Aho-Corasick in pure Go; Hyperscan via cgo as an optional build).
   One pass over the request tells us which rules can possibly match; the rest are skipped. Most
   benign requests match no literals, so they skip regex evaluation entirely.

   **Feasibility measured (2026-10-04,** `test/perf/prefilter`**):**

   | | Paranoia level 1 | Paranoia level 4 |
   |---|---|---|
   | CRS rules that run per argument | 104 | 196 |
   | Of those, filterable by required literals | 100 | 181 |
   | Benign rule-value evaluations skippable | 90.5% | 86.2% |
   | Operator time skippable (weighted by measured cost) | 72% (÷3.5) | 69% (÷3.2) |
   | Soundness violations (regex matched but filter said skip) | 0 of 890k checks | 0 of 1.67M checks |

   The soundness check includes all 9,747 CRS regression-test payloads. The extraction treats any
   non-literal node (for example an unescaped `.`) as breaking a literal, which is where Coraza's own
   prefilter goes wrong. What cannot be filtered is mostly the two libinjection rules (941100,
   942100), which are cheap per value.

   The end-to-end gain depends on where the filter runs. Inside Coraza's rule loop, after
   transformations, it saves only operator time (about 36–45% of the total), so roughly 30%
   overall. Before transformations it also skips transformation and per-rule overhead, where 3–5×
   is realistic; that needs a sound "maximally decoded" form of each value to match literals
   against. Either way it needs a hook inside Coraza (upstream API or fork), and it ships only after
   passing the CRS suite and differential fuzzing.
3. Rule evaluation stays behind the `pkg/rules.Evaluator` interface (0002 §3.1) so a custom
   engine can replace Coraza without touching adapters.

### 5.3 State (rate limits, reputation)

- Local first: sharded token buckets (per-CPU shards, no global mutex).
- Cluster-wide limits are synced asynchronously (gossip or Redis batch every ~100 ms). The hot path
  never waits on the network, and small over-admission is accepted.

### 5.4 Telemetry

- Events go to a lock-free ring buffer; a background goroutine batches and ships them
  (OTLP / to the SaaS).
- Full audit logs are kept only for matched or sampled requests.
- If the buffer overflows we drop and count; the request is never delayed.

### 5.5 Wire format

- Protobuf with `vtprotobuf` generated marshalers (no reflection), gRPC over HTTP/2 with long-lived
  streams.
- Adapters send only the fields the active policy needs (the operator configures the proxy to
  omit bodies/headers that no rule reads).

## 6. Deployment topology

**Default: sidecar in the ingress controller pod, over a Unix domain socket.** No node hop, no
Service/kube-proxy hop, no TLS between proxy and engine.

| Proxy | Integration | Transport |
|---|---|---|
| Caddy | Native Caddy module (in-process) | function call |
| Envoy / Envoy Gateway / Istio | ext_proc (headers-only processing mode unless body is needed); optional in-process Envoy Go filter for custom builds | UDS gRPC |
| HAProxy | SPOE agent (pipelined, async for detect mode) | UDS |
| ingress-nginx | Lua plugin using cosocket keepalive pool (auth-url as a simpler fallback) | UDS |
| Traefik | ForwardAuth first, Go/WASM plugin later | localhost HTTP keepalive |

The operator injects the sidecar through the controller's native extension point or a Pod
mutating webhook, never by patching the controller's Deployment (0004 §4.3), and sizes it from
policy (CPU requests matter: a throttled engine means p99 latency).

A standalone `Deployment` behind a Service is also supported for small clusters, but it is
documented as the slower mode.

## 7. Failure behaviour

- Proxy-side timeouts are always set (ext_authz/ext_proc `timeout`, SPOE `timeout processing`,
  nginx `proxy_read_timeout`) and set just above the engine deadline.
- Default is **fail-open** (`failure_mode_allow: true` etc.); fail-closed is per policy.
- Engine overload: admission control sheds inspection (not traffic) once queue depth crosses a
  threshold, and emits a metric.
- Control plane down: the engine keeps enforcing the last-known-good policy indefinitely.

## 8. Proving it: the performance test harness (built in Stage 1)

1. **Micro:** `go test -bench -benchmem` for every hot-path function; `allocs/op` and `ns/op`
   compared with `benchstat` against `main` in CI, and a regression above 5% fails the PR.
2. **Engine:** a fixed corpus (benign traffic mix + CRS attack payloads) replayed against the
   engine directly, reporting p50/p99/p999 and RPS per core.
3. **End-to-end on kind:** for each proxy, k6 runs the same scenario **with and without Inkwall**
   and the reported number is the delta. This is the number the budgets in section 3 refer to.
4. **Profiling:** pprof endpoints behind a flag, flamegraphs attached to benchmark CI runs,
   optional continuous profiling (Pyroscope).
5. **Soak / chaos:** 24 h soak for GC and memory; kill the engine mid-load and verify fail-open
   with no request errors.

## 9. Open questions

1. Ship Hyperscan (cgo, fastest) as an optional build, or stay pure Go (portable, easier releases)?
2. Should the Envoy Go filter (in-process, needs Envoy contrib build) be a supported mode or experimental?
3. Default body inspection cap: 8 KB, 64 KB, or per content type?
4. Detect-by-default for new routes: acceptable for customers who expect blocking on day one?
