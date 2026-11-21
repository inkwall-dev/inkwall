# 0009 — Rate Limits

- Status: Draft
- Date: 2026-11-20
- Updated: 2026-11-20
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md),
  [0002 — System Architecture](0002-system-architecture.md),
  [0004 — Kubernetes Operator](0004-operator.md)

Rate limits are the second half of tier T1
([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first)): the
engine counts a client's requests to a policy's routes and answers 429 with `Retry-After` past the
limit, before the rules run. This document decides the scope for v0.7.0, the `WAFPolicy` API, the
answer through each proxy, the engine's data structure and its memory bound, what shows in
metrics, events and status, and how it is tested. It answers the open question of
[0002 §12](0002-system-architecture.md#12-open-questions) on distributed rate limiting for now:
each engine limits on its own, and cluster-wide limits come later. **Nothing here is built yet**
(#705).

[Terms](../glossary.md) used here:

- **Engine:** `inkwall-engine`, the process that inspects requests and returns verdicts.
- **Proxy:** the ingress controller's data-plane process (Traefik, Envoy, HAProxy, ...), which
  asks the engine about each request.
- **Policy:** a `WAFPolicy`. **Bundle:** the signed snapshot of all policies that every engine
  enforces.
- **Limit:** one entry of a policy's `rateLimits`: a rate, a burst and a key.
- **Key:** what a limit counts by: the client IP, or the value of a request header.
- **Bucket:** the state the engine keeps for one key of one limit.

## Contents

- [1. Goals and scope](#1-goals-and-scope)
- [2. Per-engine limits first](#2-per-engine-limits-first)
  - [2.1 What a limit means with several engines](#21-what-a-limit-means-with-several-engines)
  - [2.2 Cluster-wide limits, deferred](#22-cluster-wide-limits-deferred)
- [3. API](#3-api)
  - [3.1 Fields](#31-fields)
  - [3.2 Token bucket semantics](#32-token-bucket-semantics)
  - [3.3 Keys](#33-keys)
  - [3.4 Modes, IP lists, skips and exclusions](#34-modes-ip-lists-skips-and-exclusions)
  - [3.5 Validation](#35-validation)
  - [3.6 Older engines](#36-older-engines)
- [4. The answer: 429 and Retry-After](#4-the-answer-429-and-retry-after)
- [5. Engine design](#5-engine-design)
  - [5.1 Where in the pipeline](#51-where-in-the-pipeline)
  - [5.2 Data structure](#52-data-structure)
  - [5.3 Memory bound and eviction](#53-memory-bound-and-eviction)
  - [5.4 Clock, bundle swaps and restarts](#54-clock-bundle-swaps-and-restarts)
  - [5.5 Bundle and API changes](#55-bundle-and-api-changes)
- [6. Observability](#6-observability)
- [7. Client IP](#7-client-ip)
- [8. Testing](#8-testing)
- [9. Decisions](#9-decisions)
- [10. Open questions](#10-open-questions)

## 1. Goals and scope

Rate limits answer two needs a WAF is expected to cover:

- **Abuse of one endpoint:** credential stuffing on `/login`, scraping of a search, a client that
  retries in a tight loop.
- **CPU protection:** a limited request is refused for about a microsecond, before its body is
  read and before it takes an evaluation slot and costs the CRS its 0.5 ms or more
  ([0001 §3.1](0001-performance-first-architecture.md#31-measured-baseline-2026-10-03)).

**In v0.7.0:**

- `WAFPolicy.spec.rateLimits`: per policy, keyed by client IP or by a request header, optionally
  narrowed to paths and methods of the policy's routes ([§3](#3-api)).
- Each engine enforces each limit on its own, in memory, never waiting on the network
  ([§2](#2-per-engine-limits-first)).
- 429 with `Retry-After` through every adapter: forward-auth, ext_proc, SPOE, `/v1/check` and the
  standalone proxy ([§4](#4-the-answer-429-and-retry-after)).
- A hard memory bound per engine ([§5.3](#53-memory-bound-and-eviction)).
- Metrics, sampled security events with the reason `rate-limit`, `inkwallctl explain`
  ([§6](#6-observability)).

**Later, not in v0.7.0:**

- Cluster-wide limits ([§2.2](#22-cluster-wide-limits-deferred)).
- Limits outside a policy: engine-wide, or for routes no policy covers.
- Limits in the standalone engine configured by flags: v0.7.0 limits come from the bundle only.
- Keys made of several parts (IP and header), cookies, JWT claims.
- Moving limits into the proxies' own features (Envoy's local rate limit, HAProxy's stick tables),
  as [0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first)
  already defers.
- The `RateLimit` and `RateLimit-Policy` response headers: still an IETF draft
  ([draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)).

## 2. Per-engine limits first

**Decision:** in v0.7.0, a limit is enforced by each engine on its own. The documented meaning is
plain: *each engine allows `requests` per `period` per key*. The hot path never waits on the
network ([0001 §5.3](0001-performance-first-architecture.md#53-state-rate-limits-reputation)).

### 2.1 What a limit means with several engines

Usually the engine is a sidecar of each proxy pod
([0001 §6](0001-performance-first-architecture.md#6-deployment-topology)), so a route served by N
proxy pods is limited by N engines. With a standalone engine Deployment behind a Service, also
supported by 0001 §6, N is the number of engine replicas. For one key:

| How the client's requests spread | Requests it gets through, per `period` |
|---|---|
| One connection, or connections that land on one pod | `requests` (plus `burst`) |
| Over k of the N pods | up to k × `requests` |
| Over all N pods (many connections) | up to N × `requests` |
| Behind an L7 load balancer or CDN, which spreads requests, not connections, over the proxy pods | up to N × `requests`, for every client |
| Forward-auth to a standalone engine Deployment: the proxy's calls spread per request over the engine replicas | up to N × `requests`, for every client |

A Kubernetes Service balances connections, not requests, and HTTP keep-alive and HTTP/2 keep a
client on one connection. So a client that reaches the proxies directly meets the limit as written,
and one that opens many connections at once can get up to N times it. Behind an L7 load balancer
or a CDN, the common setup of [§7](#7-client-ip), the load balancer pools clients onto its own
connections and spreads their requests over the pods, so every client can get up to N times the
limit. Either way it stays bounded: with 3 proxy replicas, `requests: 10` and `burst: 20`, a
brute-forcer gets at most 30 tries a minute in steady state, plus each engine's burst once (90 in
the first minute, and one more burst per engine restart), instead of thousands. That is the job of a per-IP limit in front of a
login, and it is what v0.7.0 promises. The docs say to pick a limit as "what one engine allows",
and `inkwallctl explain policy` prints the ceiling ([§6](#6-observability)).

**Rejected: dividing the limit by the number of engines.** The operator knows the engines (the
`Enforced` condition counts them, `operator/internal/distribution/status.go`), so the bundle could
carry `requests / N`. Rejected because:

- A client on one connection would get `requests / N`: three replicas would turn a limit of 10 into
  3 for exactly the ordinary client.
- The engine count changes with every scale-up, rollout and crash. The bundle is cluster-wide,
  signed and debounced ([0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)); rebuilding it
  for each pod event would churn every engine.
- A policy's routes may be served by several proxies with different replica counts; one number
  doesn't fit them.

### 2.2 Cluster-wide limits, deferred

Three ways to share counts were considered. All are deferred, for the same reasons: each adds a
network path the engine doesn't have today, the per-engine limit already bounds abuse to N times
the limit, and none should be designed before v0.7.0 shows how limits are used.

| Option | For | Against |
|---|---|---|
| [Redis](https://redis.io/docs/latest/) (or another shared store) | Exact counts; a known pattern (Envoy's global rate limit service) | A stateful dependency in or beside the request path; another thing to secure, scale and fail over; each check either waits on it (forbidden by [0001 §5.3](0001-performance-first-architecture.md#53-state-rate-limits-reputation)) or syncs asynchronously anyway |
| Gossip between engines | No new component | Engines today talk only to the operator: gossip needs membership, a port, NetworkPolicy rules, an mTLS identity per engine; traffic grows with engines × hot keys |
| Relayed by the operator | Reuses the engines' existing stream to the operator ([0002 §5.2](0002-system-architecture.md#52-engine--operator-bundle-distribution)); no new dependency | Seconds, not 100 ms, of lag; the operator becomes part of enforcement; bounded to hot keys only |

The likely first step, when it comes: each engine reports its few hottest over-limit keys per limit
on the stream it already has, and the operator sends back the sum, which engines add to their local
buckets asynchronously. It over-admits for a few seconds and never blocks a request. The engine
side is ready for it: a bucket can take a debt from elsewhere ([§5.2](#52-data-structure)). This
stays [open question 1](#10-open-questions).

## 3. API

```yaml
spec:
  mode: Block
  rateLimits:
    - name: login                  # unique in the policy; in events, logs and explain
      requests: 10                 # tokens added per period
      period: 1m                   # 1s to 1h
      burst: 20                    # bucket size; default: requests
      key: {clientIP: {}}          # or {header: {name: X-Api-Key}}
      match:                       # optional: default, every request of the policy
        paths: ["/login", "/api/session/*"]
        methods: [POST]
    - name: api
      requests: 600
      period: 1m
      key: {clientIP: {ipv6PrefixLength: 64}}
      mode: Detect                 # optional: log only, on a Block policy
```

### 3.1 Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | DNS label, ≤ 63 | required | Names the limit in events, logs and `explain`; unique in the policy |
| `requests` | 1–1,000,000 | required | Requests allowed per `period`, per key, per engine |
| `period` | duration, 1s–1h | required | The period of `requests` |
| `burst` | 1–1,000,000 | `requests` | Requests a key may send at once after being idle |
| `key.clientIP.ipv6PrefixLength` | 32–128 | 56 | IPv6 clients are counted by this prefix; IPv4 by the address |
| `key.header.name` | header name, ≤ 128 | — | Count by this header's value instead ([§3.3](#33-keys)) |
| `match.paths` | `PathPattern` list, ≤ 16 | all | Exact paths or prefixes ending in `*`, the type of `skip.paths` (`operator/api/v1alpha1/wafpolicy_types.go`) |
| `match.methods` | method list, ≤ 9 | all | Only these methods count |
| `mode` | `Detect` | the policy's | `Detect` logs instead of denying, on a `Block` policy ([§3.4](#34-modes-ip-lists-skips-and-exclusions)) |

The limits live in the policy, not in a separate CRD: they protect the policy's routes, change with
them in the same review, and reach engines in the same bundle. A separate `WAFRateLimit` kind,
shared by policies like `WAFIPList`, was rejected for v0.7.0: an IP list is data many policies
share; a limit is tied to one application's endpoints.

`match.paths` narrows within the policy's routes; it cannot reach other routes, since the engine
consults a policy only for requests on its routes (`pkg/policy`). Paths use the patterns of
`skip.paths`, on the path `router.UnambiguousPath` returns (`pkg/router`), with two differences,
both toward counting:

- **A path that can't be read one way** (percent-encoding, `;`, `//`, dot segments) counts against
  every path-scoped limit of the policy. For a skip such a path is inspected, the safe side; for a
  limit the safe side is counting. Otherwise `POST /%6Cogin`, `/login;x` or `//login` would never
  touch a `/login` limit, though the application may read them as `/login`.
- **Case and one trailing slash are ignored.** `UnambiguousPath` accepts `/Login` and `/login/` as
  they are, and `skip.paths` compares exactly (`matchAny`), so they would escape an exact `/login`
  limit. Many frameworks route both to `/login`. A limit compares both sides in ASCII lower case,
  with one trailing slash removed (`/login/` matches `/login`; a prefix `/api/*` is unchanged).
  This can only count more requests, never fewer.

### 3.2 Token bucket semantics

A limit is a [token bucket](https://en.wikipedia.org/wiki/Token_bucket) per key: it holds at most
`burst` tokens, gains `requests` tokens per `period` evenly (one every `period / requests`), and
each counted request takes one. A request that finds no token is over the limit. A new key starts
full.

The engine stores it as the [generic cell rate
algorithm](https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm) (GCRA), which is the same
bucket written as one number: the time at which the bucket will be full again (the *theoretical
arrival time*, TAT). With `T = period / requests`:

1. `tat = max(TAT, now)`.
2. If `tat + T − now > burst × T`, the request is over the limit, and `Retry-After` is
   `tat + T − now − burst × T`, rounded up to whole seconds, at least 1.
3. Otherwise `TAT = tat + T`, and the request passes.

One `int64` per key, no floating point, and an exact `Retry-After`. A bucket whose TAT is in the
past is full, the same as no bucket, which is what makes eviction safe ([§5.3](#53-memory-bound-and-eviction)).

**One limit** is checked and charged in one step, under its bucket's shard lock: steps 1–3 run
without releasing it. Two requests racing on one key can't both take its last token.

**Several limits** on one request. The `Block` limits that match it are charged in order, each
atomically as above. If one refuses, the ones already charged are refunded (`TAT −= T`, under their
locks), the request is over, and `Retry-After` is the largest of the refusing limit's and of those
the request would have exceeded. So a refused request spends no token of another limit, and no
limit ever admits more than its rate. The cost of not holding every lock at once: between a charge
and its refund, a concurrent request of the same key can find that bucket a token short and be
refused. That needs the key to be at its limit on another limit at the same instant, and errs
toward refusing, which the client retries after `Retry-After`.

**`Detect` limits never gate the others.** Each is checked and charged on its own, after the
`Block` limits, and only logs. Otherwise a client over a loose `Detect` limit would leave the
`Block` limits uncharged and never denied.

Rejected: a fixed or sliding window counter. A fixed window lets 2 × `requests` through across a
window boundary; a sliding window needs two counters and a timestamp per key for the same
guarantee the bucket gives with one number, and has no natural burst.

### 3.3 Keys

- **`clientIP`** (the default use): the resolved client address, `request.Request.ClientIP`, set
  by the adapters through `pkg/clientip` (the proxy's resolved address, then `X-Forwarded-For`
  through the trusted proxies, then the peer: [0002 §8.2](0002-system-architecture.md#82-client-ip-correctness)).
  `/v1/check` is the exception: it takes the caller's `client_ip`, then `peer_ip`
  (`pkg/adapters/httpcheck`). Key derivation unmaps IPv4-mapped IPv6 addresses itself, so they
  count as IPv4 whichever adapter set them. A request with no valid address (a `/v1/check` call
  with neither field) is not limited by an IP key: one shared bucket would let one caller deny
  every such request. It is counted in `inkwall_rate_limit_skipped_total{reason="no_key"}`, and
  the `/v1/check` docs say to send `client_ip`. IPv6 clients count by their `/56` by default. One
  subscriber holds at least a `/64`, so per address an attacker would have 2^64 keys and would
  flush the table ([§5.3](#53-memory-bound-and-eviction)); providers often hand out a `/56` or a
  `/48`, which a `/64` key would split into 256 or 65,536 keys. `/56` bounds a `/48` holder to 256
  keys, and a policy can choose `/64` or finer.
- **`header`**: the value of a request header (its first value), for fairness between
  authenticated clients: an API key, a tenant ID. The engine keeps a 64-bit keyed hash of the
  value ([`hash/maphash`](https://pkg.go.dev/hash/maphash), with a seed chosen at engine start),
  never the value, so neither memory nor events hold credentials. A request **without the header**
  is counted by its client IP under the same limit, so leaving the header out is no way around it.
  The key carries a one-byte tag (address or header hash), so a header hash never collides with an
  IP fallback key of the same limit.
  The docs say plainly that a client chooses its header's value: a header key shares a limit
  between honest clients; it doesn't stop an attacker, who can send a new value each time. Use a
  `clientIP` limit for that.

`X-Forwarded-For` and `Forwarded` are refused as header keys ([§3.5](#35-validation)): the client
IP is the right key for those, resolved through the trusted proxies.

### 3.4 Modes, IP lists, skips and exclusions

| Situation | What happens |
|---|---|
| Policy in `Block` mode | Over the limit: denied with 429 and `Retry-After`, before the rules |
| Policy in `Detect` mode, or a limit with `mode: Detect` | Over the limit: counted, and the request goes on to the rules. If no rule decides, the verdict is `log` with reason `rate-limit`; if a rule matched, its reason wins and the limit still shows in the metric `inkwall_rate_limit_exceeded_total` ([§6](#6-observability)) |
| Client in the policy's IP deny list | Denied with `ip-deny` before any limit: not counted |
| Client in the policy's IP allow list (and not in a deny list) | Let through uninspected, as today (`ip-allow`): **not counted, never limited** |
| Path in `skip.paths` | Not counted: skipped requests are meant to never reach the engine once skips move into the proxy ([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first)), and health checks shouldn't spend a client's tokens |
| Path in `skip.bodyPaths` | Counted: only the body isn't inspected |
| `exclusions` | No effect: exclusions turn off rules by ID ([0002 §4.2](0002-system-architecture.md#42-crds-wafinkwalldevv1alpha1)); a limit is not a rule and has no ID. To exempt a path, narrow `match.paths`; to exempt a client, use the IP allow list |
| Inspection suspended (`InkwallConfig.spec.suspend`) | No limits: the engine allows every request before any policy (`pkg/policy`, `Set.Check`) |
| The engine unreachable or failing, and the policy's `failureMode` is `Open` | No limits: the proxy lets the request through uninspected, as for the rules |
| A request several policies inspect (`policiesFor`) | Each policy is checked in `Set.Check`'s order, and its limits charged, until one denies: `Set.Check` stops there, so later policies' limits aren't charged for that request. The strictest verdict wins, as for the rules |
| WebSocket | The handshake counts once; messages don't |
| gRPC | A call counts once, whatever its messages |

**Allow lists skip limits**, deliberately. The allow list exists for clients the operator trusts
not to need inspection (health checkers, its own scanner), and those are the clients most likely to
send many requests. A client that should be inspected but not limited is better served by a limit
whose `match` leaves its paths out.

`mode: Detect` on a single limit exists so that a new limit can be tried on a policy already in
`Block` without moving the whole policy back to `Detect`, the same onboarding as the rules
([0001 §4](0001-performance-first-architecture.md#enforcement-modes-per-route)). A limit can't be
stricter than its policy: `mode: Block` on a `Detect` policy is refused ([§3.5](#35-validation)).

### 3.5 Validation

Everything a limit needs is checked by the schema and CEL, the first and cheapest step of
[0004 §3.1](0004-operator.md#31-validation):

- `rateLimits`: at most 8 per policy (like `ruleSets`); names unique
  (`self.all(a, self.exists_one(b, b.name == a.name))`, the pattern of `targetRefs`).
- `requests` and `burst`: 1 to 1,000,000. `period`: `duration(self) >= duration('1s') &&
  duration(self) <= duration('1h')`, the pattern of `timeout`.
- `key`: exactly one of `clientIP` and `header`.
- `header.name`: an HTTP token, at most 128 characters (so never a pseudo-header such as
  `:authority`), not `X-Forwarded-For`, `Forwarded` or `Host`, compared case-insensitively.
- `ipv6PrefixLength`: 32 to 128.
- `match.paths`: the `PathPattern` type's pattern, at most 16; `match.methods`: an enum of the
  standard methods, a set.
- `mode`: only `Detect`. A limit that merely repeats the policy's mode needs no field, and a
  `Block` limit on a `Detect` policy would be the stricter one, which the policy mode exists to
  prevent.

The validating webhook adds nothing new: limits reference no other object and compile to nothing.
The resolver has nothing to resolve. The bundle builder copies the limits into the policy
([§5.5](#55-bundle-and-api-changes)). Size: a limit adds about 60 bytes to the bundle before
compression without `match.paths`, and up to about 400 bytes with 16 paths; 8 limits on each of
5,000 policies ([0004 §8](0004-operator.md#8-scale-targets-v1)) add about 2.4 MB raw, and about
16 MB in the worst case, which compresses with the rest under the 7,200 KiB ceiling (repeated
paths compress well; the scale test of [§8](#8-testing) checks the worst case).

### 3.6 Older engines

An engine before 0.7.0 ignores the new field and limits nothing. The operator already handles that
case for every new field: `requirement` in `operator/internal/distribution/status.go` names the
field that needs the newest engine, and `enforcedConditions` sets `Enforced=False` with reason
`EnginesOutdated` while any engine running the bundle is older. `spec.rateLimits` joins that list
with version 0.7.0, so a policy with limits reads, for example: "some engines are too old to
enforce spec.rateLimits, which they ignore (first: … runs 0.6.1; it needs 0.7.0 or later)". The
upgrade guide says: upgrade the chart first (the CRD field), then the engines. It also says that
rolling the operator back below 0.7.0 drops limits without a word: the older operator doesn't
know the field, so neither the bundle nor the `requirement` check carries it.

## 4. The answer: 429 and Retry-After

Today a deny carries only a status: `Verdict.Status` (`pkg/pipeline/verdict.go`), and the shared
denial (`pkg/adapters/internal/httpadapter/denial.go`) adds `X-Request-Id` and a short text or JSON
body. Rate limits add one field to the verdict, `RetryAfter` (whole seconds), and every adapter
adds a `Retry-After` header to a 429. The body stays the shared one (`Too Many Requests`, or
`{"error":"too_many_requests",...}` with `--json-denials`), except through SPOE, where HAProxy
writes its own denials (`--json-denials` doesn't apply there, `cmd/engine/main.go`).

| Adapter | How a deny is answered today | With a rate limit |
|---|---|---|
| forward-auth (Traefik) | The engine answers the status (`pkg/adapters/forwardauth/forwardauth.go`); Traefik returns a non-2xx answer to the client with its headers and body (Traefik's `pkg/middlewares/auth/forward.go`, [0006 §3](0006-adapter-protocols.md#3-forward-auth-traefik-forwardauth-nginx-auth_request)) | 429 with `Retry-After` from the engine; Traefik passes both on. The e2e checks the header reaches the client. nginx's `auth_request` accepts only 2xx, 401 and 403 and turns any other answer into 500: the docs give the `error_page 500 = @ratelimited` mapping, or say to use another adapter |
| ext_proc (Envoy Gateway, Istio, raw Envoy) | `ImmediateResponse` with the status, headers and body (`deny` in `pkg/adapters/extproc/extproc.go`) | One more header in `ImmediateResponse.headers`. A route in `Detect` runs ext_proc in observability mode and answers nothing, as today |
| SPOE (HAProxy) | Variables `action`, `status`, `request_id`; HAProxy's rules deny with `deny_status` (`pkg/adapters/spoe/spoe.go`, `operator/internal/wiring/haproxy.go`) | A new variable `retry_after`, and a rule `http-request deny deny_status 429 hdr retry-after "%[var(txn.inkwall.retry_after)]" ...` before the catch-all 403. The operator renders it for the HAProxy Ingress Controller; a hand-written `haproxy.cfg` must add it and `retry_after` to `register-var-names` (`examples/haproxy`), or the client gets 403 |
| `/v1/check` | `CheckResponse.status` and `response_headers` (`pkg/adapters/httpcheck/httpcheck.go`) | Status 429, `Retry-After` in `response_headers`, the new reason |
| Standalone proxy | `httpadapter.WriteDenial` (`pkg/adapters/proxy/proxy.go`) | The same, plus the header |

**gRPC.** A denied gRPC call is answered with a gRPC status (`httpadapter.GRPCCode`,
[0006 §7](0006-adapter-protocols.md#7-denying-grpc-calls)). Today 429 maps to `UNAVAILABLE`, gRPC's
own mapping of HTTP statuses (`pkg/adapters/internal/httpadapter/grpc.go`). `GRPCCode` maps by
status alone, so 429 itself moves to `RESOURCE_EXHAUSTED`, as an oversized body's 413 already
does: `UNAVAILABLE` tells gRPC clients the call is safe to retry at once, which is the opposite of
what a limit means. Only limits answer 429 by default; a SecLang rule that denies with
`status:429` changes too, and the upgrade notes say so. `grpc_test.go`'s table changes with it.
`Retry-After` is sent too, where the adapter can; gRPC clients don't read it.

The status is fixed at 429. A configurable status was rejected: 429 is the one every client and
CDN understands, and a 403 would hide from the client that waiting helps.

## 5. Engine design

### 5.1 Where in the pipeline

The route→policy match happens before a policy's pipeline runs: `pkg/policy`'s `Set.Check` picks
the policies of the request's route, then calls each one's `Pipeline.Check`. Limits are a policy's,
so they run inside `Pipeline.check` (`pkg/pipeline/pipeline.go`). Its order today and with limits:

1. IP lists (`ipListed`): deny → 403 `ip-deny`; allow → let through, `ip-allow`.
2. T0 skip list (`routes.Decide`): `SkipAll` → let through, `skipped`.
3. **Rate limits (new).** Over a limit: in `Block`, 429 `rate-limit` and stop; in `Detect`,
   remember it and go on.
4. WebSocket handshake rules, `body.grpc: Deny`.
5. The rules (`inspect` → `evaluate`), which take an evaluation slot (`Admission`).

Limits run after the IP lists and the skip list (the cheapest checks, and the decisions of
[§3.4](#34-modes-ip-lists-skips-and-exclusions)), and before anything takes an evaluation slot, so
a flood over its limit costs no CRS time and can't push other requests into `overload`.

Rejected: limits before the route→policy match, engine-wide. Then no policy would own them, and
their configuration would have no home in the API; an engine-wide limit is a later feature
([§1](#1-goals-and-scope)).

Limits are decided once, in `BodyLimit`, which adapters call before reading a body
(`pkg/pipeline/pipeline.go`), when the adapter calls it, and otherwise at step 3:

- **Per policy, in `Check`'s order.** `Set.BodyLimit` asks every policy of the request
  (`policiesFor`, no early stop: `pkg/policy/policy.go`), while `Set.Check` stops at the first
  deny. So `Set.BodyLimit` decides limits in `Check`'s order and stops charging after the first
  policy whose limits deny, as `Check` would. Each policy's decision is kept: a request has up to 4
  policies (`policiesFor`'s buffer).
- **Tagged with the set's version.** The decisions ride on the `Request`, with `Set.Version()`.
  A bundle swap between `BodyLimit` and `Check` gives `Check` a set whose limits may differ, so on
  a mismatch `Check` decides again (charging again: the rare cost of a swap mid-request).
- **A denied request gets a body limit of 0**, so a flood over its limit isn't even read.

Deciding in both places on every request was rejected: the key might gain a token between them,
and the request would then be inspected without its body.

### 5.2 Data structure

New package `pkg/ratelimit`. One engine-wide `Store` holds the buckets of every limit of every
policy, like the shared `Admission` and `Evaluators` (`pkg/policy/policy.go`); each compiled limit
holds its ID in it.

- **Sharded table.** A fixed number of shards (a power of two, 4 × `GOMAXPROCS` rounded up, at
  least 64), each a mutex and a fixed-size, open-addressed array of entries. The shard and the slot
  come from one `maphash` of (limit ID, key). The mutex is held for the lookup and the GCRA
  update: tens of nanoseconds.
- **Entry:** a one-byte tag (IPv4, IPv6 or header hash), the key (16 bytes: the masked address, or
  the 8-byte header hash), the limit ID (4), the TAT (8, nanoseconds on the engine's monotonic
  clock), and, for event sampling, the time of the last event and the requests limited since
  (4 + 4). 37 bytes, padded to 40, with no pointers, so the garbage collector never scans the
  table, and nothing is allocated per request.
- **Probing:** a key's neighbourhood is the 8 slots from its hashed slot (320 bytes, five cache
  lines); lookup, insert and eviction look only there.
- **Limit IDs, in the engine.** The `Store` interns each limit's identity, (policy namespace/name, limit name,
  key spec), to a `uint32` ID of its own, and never reuses one while the engine runs. The bundle
  carries no ID: it would depend on operator state (a deleted bundle Secret restarts the
  operator's counters, [0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)), and the
  engine's own table outlives bundles anyway. Changing `requests`, `period` or `burst` keeps the
  ID and its buckets: GCRA reads `T` and `burst` from the limit at each request, so the new rate
  applies at once to the TAT already there. Changing the name or the key spec is a new limit,
  which starts full. The policy is named as the bundle names it, namespace/name: a policy deleted and
  recreated under the same name keeps its buckets. Each compiled set holds its live IDs; an entry whose ID isn't live counts as
  free.
- **Cost target:** ≤ 1 µs per request with limits, 0 allocations, measured by the benchmarks of
  [§8](#8-testing) (the T1 budget of [0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first);
  for scale, `pkg/iplist` takes about 60 ns, the policy lookup about 440 ns).
- **Remote debt (later):** a bucket's TAT can be pushed forward by a number of requests seen
  elsewhere, which is all a cluster-wide sync ([§2.2](#22-cluster-wide-limits-deferred)) needs.
  Header hashes use a per-engine seed, so they can't be compared across engines: a sync would
  need a seed shared through the bundle, or only IP keys.

Rejected:

- **Per-CPU buckets**, as [0001 §5.3](0001-performance-first-architecture.md#53-state-rate-limits-reputation)
  first sketched. Go gives a goroutine no stable CPU number without the runtime's internals, and a
  key's bucket split over CPUs splits its burst, the problem of [§2.1](#21-what-a-limit-means-with-several-engines)
  inside one engine. Striped locks over one bucket per key keep the limit exact per engine.
- **[`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) per key, in a map.**
  A heap object with a mutex and floats per key: an allocation per new key, pointers for the GC to
  scan, and no eviction.
- **`sync.Map`.** Allocates per entry, and is unbounded.
- **The event log limiter's design** (`pkg/events/loglimit.go`: a map cleared entirely past 4,096
  keys). Fine for log lines; for limits, an attacker rotating keys would reset every client's
  bucket, its own included.

### 5.3 Memory bound and eviction

The table has a fixed capacity, allocated when the first bundle with limits arrives and never
grown: **`--rate-limit-keys`**, default 262,144 entries per engine (10 MiB of entries, held at a
load factor of at most 0.85, so about 12 MiB of table), set for injected engines by
`InkwallConfig.spec.engine.rateLimitKeys`. The flag is read at start: a change reaches injected
engines when their pods are recreated (a rollout, or `spec.engine.rollout: Automatic`). The
engine's default memory limit is 512 MiB, with `GOMEMLIMIT` at 90% of it
(`operator/internal/injection/sidecar.go`, `internal/memlimit`). The engine caps the table at a
quarter of `GOMEMLIMIT` and logs when it does, so a large setting can't starve the rules. With no
`GOMEMLIMIT` (a standalone engine without a memory limit) the cap is 64 MiB. The capacity is shared by all limits: most keys are
idle at any time, and a per-limit split would waste it.

When a key is new and its slot's neighbourhood is full, the engine evicts, in this order:

1. **A free entry**: a full bucket (TAT in the past), or one of a limit no longer in the bundle.
   A full bucket is exactly an absent one, so nothing is lost. Most evictions are these: a key idle
   for `burst × period / requests` is full.
2. **The bucket closest to full** among the neighbourhood (the earliest TAT): a sampled
   approximation of least-recently-limited, as Redis approximates LRU. This forgets some state:
   that client gets a fresh bucket.

The second kind is counted (`inkwall_rate_limit_evictions_total{kind="active"}`), with an alert:
it means the table is too small for the clients being limited, or an attacker is cycling keys
([§6](#6-observability)). Forgetting state errs toward letting requests through, never toward
denying a client that stayed within its limit. The alternative, refusing to track new keys when
the table is full, was rejected: either new clients would go unlimited (an attacker fills the table
first, then everything passes) or they would share one overflow bucket (one attacker gets everyone
new denied).

The `/56` default for IPv6 ([§3.3](#33-keys)) keeps one subscriber from filling the table alone:
a holder of a `/48`, the most a provider usually assigns, has 256 keys.

### 5.4 Clock, bundle swaps and restarts

- **Clock.** `Pipeline.checkRequest` already reads `time.Now()` once per request (for
  `Verdict.Duration`); limits use that reading's monotonic part, so they add no clock read and
  aren't moved by wall-clock steps. Today `check` doesn't get it, so it is passed down, and
  `BodyLimit` reads the clock when it decides ([§5.1](#51-where-in-the-pipeline)).
- **Bundle swaps.** Every bundle compiles new pipelines (`policy.Compile`), but the `Store`
  outlives them, as `Evaluators` does. A limit keeps its ID, and so its buckets, while its policy,
  `name` and key spec are unchanged, whatever its rate and burst; a new name or key spec gets a new
  ID and starts full, and the old ID's entries are free at once, counted as `idle` when reused
  ([§5.2](#52-data-structure)). So an unrelated policy change never resets limits, and an edit
  never looks like an attack in the `active` count.
- **Restarts.** State is in memory only. A restarted engine starts every bucket full: a client gets
  one extra burst per restart. Accepted, as [0001 §5.3](0001-performance-first-architecture.md#53-state-rate-limits-reputation)
  accepts a little over-admission; persisting buckets to the disk cache was rejected for the I/O it
  adds and the little it saves.

### 5.5 Bundle and API changes

- **`api/bundle/v1/bundle.proto`:** `Policy` gains `repeated RateLimit rate_limits = 15`. A new
  message `RateLimit`: `name`, `requests`, `period` (`google.protobuf.Duration`), `burst`, a
  `RateLimitKey` (`oneof`: `ClientIPKey { ipv6_prefix_length }`, `HeaderKey { name }`),
  `repeated string paths` (the router's syntax, as `skip_paths`), `repeated string methods`, and
  `bool detect`. No ID: the engine assigns its own ([§5.2](#52-data-structure)). Engines before
  0.7.0 skip the unknown field ([§3.6](#36-older-engines)).
- **`api/engine/v1/engine.proto`:** `REASON_RATE_LIMIT = 15` in `Reason` (the next number after
  `REASON_GRPC`); `pkg/pipeline` gains `ReasonRateLimit`, written `rate-limit` like `ip-deny`.
- **`api/events/v1/events.proto`:** `SecurityEvent` gains `string rate_limit = 23`, the limit's
  name, and `uint32 sampled_count = 24`, how many events this one stands for: for a limit, the
  requests limited since the key's last event ([§6](#6-observability)). It is generic, so other
  sampled events (geo blocking, design 0011) reuse it; 0 or 1 means the event stands for
  itself. Operators before 0.7.0 ignore both.
- **`pkg/pipeline.Verdict`:** `RetryAfter`, the limit's name, an `Event` flag (whether this
  verdict becomes a security event) and its sampled count, the requests it stands for. Adapters
  decide events through `httpadapter.IsEvent`, which reads the flag for a `rate-limit` verdict.
- **`pkg/request.Request`:** the per-policy limit decisions of `BodyLimit`, with the set's version
  ([§5.1](#51-where-in-the-pipeline)).
- **Capacity:** the engine flag `--rate-limit-keys`, set on injected engines from
  `InkwallConfig.spec.engine.rateLimitKeys` (`operator/internal/injection/sidecar.go` adds the
  flag when the field is set).

## 6. Observability

**Metrics** (engine; names in the style of `docs/monitoring.md`; every label bounded):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inkwall_requests_total` | counter | (existing) | New reason value `rate-limit` |
| `inkwall_policy_requests_total` | counter | (existing, opt-in) | The same reason, per policy |
| `inkwall_rate_limit_exceeded_total` | counter | `adapter`, `action` | Requests over a limit: `deny`, or `log` in `Detect`, also when a rule's reason won the verdict |
| `inkwall_rate_limit_keys` | gauge | | Buckets held now (full ones included until evicted) |
| `inkwall_rate_limit_key_capacity` | gauge | | The table's capacity after the memory cap |
| `inkwall_rate_limit_evictions_total` | counter | `kind` | `idle` (a free entry, harmless) or `active` (state forgotten) |
| `inkwall_rate_limit_skipped_total` | counter | `reason` | Requests a limit couldn't count: `no_key` (no valid client address) |
| `inkwall_rate_limit_events_dropped_total` | counter | | Limit events past the per-limit or the engine-wide event cap |

No metric is labelled by limit or key: 5,000 policies × 8 limits would be 40,000 series per engine,
and keys are unbounded. Per-policy counts come from the opt-in `inkwall_policy_requests_total`; the
limit's name is in events and logs. A new alert, `InkwallRateLimitStateEvicted`, fires when
`active` evictions continue for 15 minutes, with a runbook: raise `rateLimitKeys`, or look for an
attacker cycling addresses.

**Security events.** A limited request is a security event (`httpadapter.IsEvent`: every verdict
that isn't `allow`). But a flood would fill the bounded event buffer (`pkg/events`), which drops
the oldest events, and push out the attacks that matter. So limit events are **sampled per key**:
the first limited request of a key, then at most one event per key per minute, carrying the
number of requests limited since the last one in `sampled_count`. The sampling state is in the
bucket entry, so it
costs nothing more. Per key isn't enough when many keys are limited at once (100,000 bot
addresses would still send 100,000 events a minute), so each (policy, limit) also has an event
cap: a token bucket of 100 events per second, in the style of the log limiter
(`pkg/events/loglimit.go`). And all limits together have an engine-wide cap of 10 events per
second: the ring holds 10,000 events (`pkg/events/buffer.go`, `DefaultCapacity`), and at 100 per
second one flooded limit would fill it in 100 s while the operator is away, pushing out the
attacks that matter. The rest are counted in `inkwall_rate_limit_events_dropped_total`. The log lines go through the existing log limiter
(`--event-log-rate`), unchanged. Every limited request is still counted in the metrics.

**`inkwallctl explain`** ([0008](0008-assistants.md)):

- `explain request <id>` on a `rate-limit` event: the policy, the limit's name, rate, burst and key
  kind, the requests limited since the last event (`sampled_count`), and the cause and fix from
  the reasons registry
  (`operator/reasons/reasons.go` gains the `SecurityEvent` reason `rate-limit`: raise the limit,
  check the client IP the engine resolved, or narrow `match`). Since events are sampled, some 429s
  have no event; their `X-Request-Id` then isn't found, and the troubleshooting guide says so.
- `explain policy` lists the limits and their ceiling: "each of the engines serving this policy
  allows 10 per minute per client IP; a client spread over all of them gets up to N × 10"
  ([§2.1](#21-what-a-limit-means-with-several-engines)).
- `inkwallctl status` doesn't change. `inkwallctl test --policy` checks one request at a time and
  keeps no state, so it ignores limits and says so when a policy has any.

**Status.** No new condition. Limits can't be honoured in two cases, both already visible:

- an engine before 0.7.0 runs the bundle: `Enforced=False`, `EnginesOutdated` ([§3.6](#36-older-engines));
- a hand-written HAProxy configuration without the 429 rule answers 403: not detectable by the
  operator; the upgrade guide and `docs/haproxy.md` say what to add.

A wrong client IP (every client behind one load balancer address) can't be detected by the
operator either: [§7](#7-client-ip).

## 7. Client IP

A limit keyed on the client IP is only as right as the client IP. Behind a load balancer that hides
the client, every request comes from the load balancer's address, and one limit throttles
everyone: worse than no limit ([0002 §8.2](0002-system-architecture.md#82-client-ip-correctness)).
The docs of rate limits say this first, and link to [Client IP behind a load
balancer](../client-ip.md), which already says the planned limits will key on the address. The
user-facing guide tells users to check the `client_ip` of a few security events (or `inkwallctl
explain request`) before turning a limit to `Block`, and recommends `mode: Detect` for that first
step. The guide `docs/client-ip.md` changes "the planned rate limits" to the built ones.

## 8. Testing

| Layer | What | Where |
|---|---|---|
| Unit | GCRA with a fake clock: burst from idle, steady rate, refill, `Retry-After` rounding, a period of 1 h with `requests: 1`, the clock reading the same twice, a changed rate applied to an existing TAT; charging several limits with a refund when a later one refuses, never more than the rate per limit under concurrent requests; key derivation: IPv4, IPv4-mapped (unmapped by the key), IPv6 masked at each prefix length, no valid address (`no_key`), header missing (falls back to the IP, a different tag), first value of a repeated header; eviction order (free entries first, then the earliest TAT) and the `active` count; the memory cap from `GOMEMLIMIT` and without it; the per-limit and engine-wide event caps; concurrent use under `-race` | `pkg/ratelimit` |
| Unit | The pipeline order of [§5.1](#51-where-in-the-pipeline): `ip-deny` before limits, `ip-allow` and `SkipAll` not counted, `SkipBody` counted, `Detect` runs the rules and a rule's reason wins, `mode: Detect` on a `Block` policy, several limits (none left charged when one is over, the largest `Retry-After`), a `Detect` limit over its rate not stopping a `Block` limit, several policies (later ones not charged after a deny, in `BodyLimit` as in `Check`), the decisions made in `BodyLimit` used by `Check` and charged once, a bundle swap between them, a body limit of 0 when denied | `pkg/pipeline`, `pkg/policy` |
| Unit | Bundle swaps keep a limit's buckets when only its rate or burst changed, and reset it when its name or key spec changed; a renamed limit's old entries reused as `idle`, never `active` | `pkg/policy` |
| Unit | Each adapter's denial: 429, `Retry-After`, `X-Request-Id`, JSON body; gRPC `RESOURCE_EXHAUSTED` for 429 (`GRPCCode`'s table); SPOE's `retry_after` variable | each adapter's `denial_test.go`, `pkg/adapters/internal/httpadapter/grpc_test.go`, `pkg/adapters/spoe` |
| Unit | CRD validation (each CEL rule, accepted and refused), `requirement` returns 0.7.0 for `spec.rateLimits`, the bundle builder's output, the HAProxy snippet's 429 rule before the 403 one | `operator/api/v1alpha1/validation_test.go`, `operator/internal/distribution`, `operator/bundle`, `operator/internal/wiring` |
| Fuzz | Random sequences of (key, time step) against a reference token bucket in floating point: never more than `burst + requests × elapsed / period` admitted per key, never a refusal when the model has a token (within rounding), `Retry-After` ≥ 1 and correct; with the table forced tiny, eviction never admits more than a fresh bucket would | `pkg/ratelimit` |
| Fuzz | The existing adapter fuzzers run with a policy that has limits | `pkg/adapters/*` |
| Fuzz | Paths: any request path that `router.UnambiguousPath` refuses counts against every path-scoped limit; an accepted path that differs from a limited path only in ASCII case or one trailing slash counts against it; no path counts against fewer limits than its lower-cased, slash-trimmed form | `pkg/pipeline` |
| Benchmark | `BenchmarkAllow` over one hot key from every CPU (worst contention), 1M distinct keys (cache misses), and a full table (eviction path); `BenchmarkCheck` with and without limits. Target ≤ 1 µs and 0 allocs/op; gated by `make bench-compare` (`hack/benchgate`) like every benchmark, with the under-1 µs threshold of [0001 §8](0001-performance-first-architecture.md#8-proving-it-the-performance-test-harness) | `pkg/ratelimit`, `pkg/pipeline` |
| e2e on kind | Per proxy: Traefik (`hack/kind/e2e.sh`), Envoy Gateway, Istio, raw Envoy and HAProxy (their `*-e2e.sh`). From one client pod, `burst` requests pass and the next gets 429 with `Retry-After`; after it, one passes again; a second client pod is not affected; a policy in `Detect` passes everything and logs a `rate-limit` event; an engine before 0.7.0 makes the policy `EnginesOutdated` (`hack/kind/upgrade.sh`) | `hack/kind` |
| Soak | `hack/kind/soak.sh` gains a limited policy, a few steady clients over their limit, and a client cycling through new header values and IPv6 `/56`s at 2,000 keys per second for the soak's duration: engine memory stays flat under its limit, the steady clients stay limited throughout (their state is kept while the cycling client's keys are evicted), clean traffic is never limited, and p99 doesn't move | `hack/kind/soak.sh` |

## 9. Decisions

| # | Decision | Rejected |
|---|---|---|
| 1 | Per-engine limits in v0.7.0, stated as "per engine" | Dividing by the engine count; cluster-wide sync now |
| 2 | Cluster-wide limits deferred; operator-relayed sync is the first option to evaluate | Redis; gossip ([§2.2](#22-cluster-wide-limits-deferred)) |
| 3 | `WAFPolicy.spec.rateLimits`, up to 8, per policy | A separate CRD |
| 4 | Token bucket stored as GCRA (one `int64` per key) | Fixed and sliding windows |
| 5 | Keys: client IP (IPv6 by `/56`), or a header's hashed value falling back to the IP | Raw header values; per-address IPv6 |
| 6 | After IP lists and the skip list, before WebSocket, gRPC and the rules; decided once, in `BodyLimit` when the adapter calls it, per policy in `Check`'s order, tagged with the set's version | Before the policy match; deciding in both `BodyLimit` and `Check` |
| 7 | Allow-listed clients and skipped paths are never limited; exclusions don't apply | Limits over the allow list |
| 8 | 429 and `Retry-After` from every adapter; 429 maps to gRPC `RESOURCE_EXHAUSTED` | A configurable status; `RateLimit-*` headers; a reason-aware gRPC mapping |
| 9 | `Detect` counts and logs, the rules still run; `mode: Detect` per limit | A per-limit `Block` on a `Detect` policy |
| 10 | Sharded, fixed-capacity, pointer-free table; striped mutexes | Per-CPU buckets; `x/time/rate` per key; `sync.Map` |
| 11 | Fixed capacity (`--rate-limit-keys`, at most a quarter of `GOMEMLIMIT`, 64 MiB without one); evict free entries, then the closest to full | Growing tables; refusing new keys; clearing all |
| 12 | Limit IDs interned by the engine from (policy namespace/name, name, key spec); buckets survive bundle swaps, and rate or burst changes, not restarts | IDs assigned by the operator; persisting buckets |
| 13 | Old engines: `Enforced=False`, `EnginesOutdated` | A new condition |
| 14 | Sampled limit events (one per key per minute, with a count, capped at 100 per second per limit and 10 per second per engine); no per-limit metric labels | An event per limited request |
| 15 | Several `Block` limits: charged atomically each, in order, refunded when a later one refuses; `Detect` limits judged on their own | Check-then-charge without atomicity; `Detect` limits gating the others |
| 16 | Limit paths: an ambiguous path counts against every path-scoped limit; case and one trailing slash ignored | Skipping ambiguous paths; exact, case-sensitive matching |

## 10. Open questions

1. **Cluster-wide limits.** Operator-relayed, gossip or Redis ([§2.2](#22-cluster-wide-limits-deferred))?
   To decide with data from v0.7.0: how many keys are over a limit at once, and how far apart a
   client's requests spread over engines in practice.
2. **Limits beyond a policy.** An engine-wide limit, or one in `InkwallConfig`, for routes no
   policy covers?
3. **Richer keys.** IP and header together, a cookie, a JWT claim (which needs the token verified
   first)?
4. **Limits in the proxy.** Envoy's local rate limit and HAProxy's stick tables would refuse a
   request before it reaches the engine. Worth it once skips move into the proxy
   ([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first))?
