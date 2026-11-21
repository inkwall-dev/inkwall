# Rate limits

A policy's `rateLimits` limit how many requests a client may send to its routes: over a limit, a
request is denied with `429 Too Many Requests` and a `Retry-After` header, before the rules run.
They stop credential stuffing on a login form, a scraper walking a catalog, and a client that
floods an expensive endpoint. They need engines 0.7.0 or later.

Each engine counts on its own. Read [What a limit means](#what-a-limit-means) before setting the
numbers, and check the [client IP](#first-the-client-ip) before turning a limit to `Block`.

## Contents

- [A first limit](#a-first-limit)
- [What a limit means](#what-a-limit-means)
- [First, the client IP](#first-the-client-ip)
- [Fields](#fields)
- [Keys](#keys)
- [Which requests count](#which-requests-count)
- [What the client gets](#what-the-client-gets)
- [Detect first](#detect-first)
- [Memory](#memory)
- [Metrics and events](#metrics-and-events)
- [Upgrading and rolling back](#upgrading-and-rolling-back)

## A first limit

Ten login attempts a minute per client, in bursts of up to twenty, on a policy already in `Block`
mode, logging only while you watch it:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: shop, namespace: shop}
spec:
  targetRefs: [{kind: Ingress, name: shop}]
  mode: Block
  rateLimits:
    - name: login
      requests: 10
      period: 1m
      burst: 20
      match:
        paths: ["/login", "/api/session/*"]
        methods: [POST]
      mode: Detect        # log first; remove to deny
```

A limit is a token bucket per client: it holds at most `burst` tokens, gains `requests` tokens per
`period` evenly (here one every 6 seconds), and each counted request takes one. A client idle long
enough is full again. A request that finds no token is over the limit.

## What a limit means

Each engine keeps its own buckets, so a limit holds per client **per engine**. How many engines
a client reaches depends on the proxy in front:

| In front of the engines | A client's requests | What a client gets |
|---|---|---|
| One proxy pod | All reach one engine | The limit |
| N proxy pods behind a TCP load balancer (a `LoadBalancer` Service, an NLB) | One connection reaches one pod; a client with many connections spreads them | The limit per connection's pod: up to N × the limit |
| N proxy pods behind an L7 load balancer or a CDN | Spread per request, and many clients share connections | Up to N × the limit, for every client |
| A standalone engine Deployment behind forward-auth | Spread per request over its replicas | Up to replicas × the limit |

For a brute-force or a scraping limit the order of magnitude is what matters, and N × is fine. Set
the numbers as what one engine should allow, and keep N in mind. Restarting an engine starts its buckets full: a client gets one more burst.

## First, the client IP

A limit keyed on the client IP is only as right as the client IP. Behind a load balancer that hides
the client, every request comes from the load balancer's address, and one limit throttles
everyone: worse than no limit. Before turning a limit to `Block`, check the `client_ip` of a few
security events, or `inkwallctl explain request <id>`, and set up [Client IP behind a load
balancer](client-ip.md) if they show the load balancer.

## Fields

| Field | Default | Meaning |
|---|---|---|
| `name` | required | A DNS label, unique in the policy: in events, logs and `explain`. Renaming a limit starts its buckets full |
| `requests` | required | Requests per `period`, per key, per engine: 1 to 1,000,000 |
| `period` | required | 1s to 1h |
| `burst` | `requests` | The most a key may send at once after being idle: 1 to 1,000,000 |
| `key` | the client IP | [Keys](#keys) |
| `match.paths` | every path | Up to 16 exact paths (`/login`) or prefixes ending in `*` (`/api/*`) |
| `match.methods` | every method | `GET`, `POST`, ... |
| `mode` | the policy's | `Detect` logs instead of denying, on a `Block` policy. A limit can't be stricter than its policy |

At most 8 limits per policy. Changing `requests`, `period` or `burst` keeps the buckets: the new
rate applies at once.

## Keys

- **`key: {clientIP: {}}`** (the default): the client address the engine resolved. IPv4 counts by
  address, IPv6 by its `/56` (`ipv6PrefixLength`, 32 to 128): one subscriber holds at least a
  `/64`, often a `/56` or a `/48`, so counting by address would give one person billions of keys.
- **`key: {header: {name: X-Api-Key}}`**: the header's first value, for fairness between
  authenticated clients (an API key, a tenant ID). The engine keeps only a hash of the value. A
  request without the header counts by its client IP. A client chooses its header's value, so a
  header key shares a limit between honest clients; it doesn't stop an attacker, who sends a new
  value each time: use a client IP limit for that. `X-Forwarded-For`, `Forwarded` and `Host` are
  refused: count by the client IP instead.

A request with no valid client address (a [`/v1/check`](testing-policies.md) call without
`client_ip` or `peer_ip`) isn't limited by a client IP key, and is counted in
`inkwall_rate_limit_skipped_total{reason="no_key"}`.

## Which requests count

| Request | Counted |
|---|---|
| From a client in the policy's IP deny list | No: denied first (`ip-deny`) |
| From a client in its IP allow list | No: never limited |
| On a `skip.paths` path | No |
| On a `skip.bodyPaths` path | Yes |
| A path `match.paths` names, in another case (`/Login`) or with a trailing slash (`/login/`) | Yes: paths compare in lower case, one trailing slash ignored |
| A path that can be read more than one way (`/%6Cogin`, `/login;x`, `//login`, `/a/../login`) | Yes, by every limit with `match.paths`: the application may read it as one of them |
| A request several policies inspect | By each, in order, until one denies it |
| A WebSocket handshake, a gRPC call | Once; their messages don't count |
| With inspection suspended, or the engine unreachable and `failureMode: Open` | No |

When several of a policy's limits match a request, it takes a token from each or from none: a
request one limit refuses spends nothing of the others, and gets the longest `Retry-After`. A
`Detect` limit never stops another from counting.

## What the client gets

Over a limit in `Block` mode, `429 Too Many Requests` with `Retry-After` (whole seconds until a
token comes) and the `X-Request-Id` of every denial. The body is the usual denial's
(`Too Many Requests`, or JSON with `spec.engine.jsonDenials`). The body of a limited request isn't
read, except through HAProxy, which sends it with the request.

| Proxy | Notes |
|---|---|
| Traefik (ForwardAuth) | Passes the 429 and `Retry-After` to the client |
| Envoy Gateway, Istio, raw Envoy (ext_proc) | The engine's answer, as for any denial |
| HAProxy | The operator renders the 429 rule. A hand-written `haproxy.cfg` needs it, and `retry_after` in `register-var-names` ([HAProxy](haproxy.md)); without it the client gets 403 |
| nginx `auth_request` | Accepts only 2xx, 401 and 403 from the engine, and turns a 429 into 500: map it with `error_page 500 = @ratelimited`, or use another adapter |
| `/v1/check` | `status: 429`, and `Retry-After` in `response_headers` |

A denied gRPC call gets `RESOURCE_EXHAUSTED`, not `UNAVAILABLE`: the latter tells gRPC clients to
retry at once.

## Detect first

`mode: Detect` on a limit logs the requests over it and lets them through, on a policy already in
`Block`: the rules still run, and if a rule matches, its reason wins. Watch
`inkwall_rate_limit_exceeded_total{action="log"}` and the `rate-limit` events for a few days: real clients
should stay under the limit, and the events' `client_ip` should be real clients. Then remove
`mode`.

## Memory

Each engine holds at most `spec.engine.rateLimitKeys` buckets (`--rate-limit-keys`, default
262,144, about 12 MiB), allocated with the first bundle that has limits, shared by every limit of
every policy, and capped at a quarter of the engine's memory limit (64 MiB without one). The
setting reaches engines when their pods are recreated.

A bucket that is full again is free, so most keys cost nothing once their clients go quiet. A key can
use 8 slots near its hash; when they all hold buckets in use, the one closest to full is
forgotten: that client gets a fresh bucket, so this errs toward letting requests through. A few
happen before the table is full; `inkwall_rate_limit_evictions_total{kind="active"}` counts them,
and the alert `InkwallRateLimitStateEvicted` fires past 6 a minute for 15 minutes: raise
`rateLimitKeys`, or look for a client cycling addresses.

## Metrics and events

| Metric | Meaning |
|---|---|
| `inkwall_requests_total{reason="rate-limit"}` | Requests a limit decided (`action` `deny`, or `log` in `Detect`) |
| `inkwall_rate_limit_exceeded_total{action}` | Requests over a limit, also when a rule decided the request (`deny`, `log`) |
| `inkwall_rate_limit_keys`, `inkwall_rate_limit_key_capacity` | Buckets held, and the table's size |
| `inkwall_rate_limit_evictions_total{kind}` | `idle` (harmless) and `active` (state forgotten) |
| `inkwall_rate_limit_skipped_total{reason="no_key"}` | Requests without a valid client address |
| `inkwall_rate_limit_events_dropped_total` | Limit events left out by the caps below |

A limited request is a security event with reason `rate-limit` and the limit's name in
`rate_limit`. A flood would push other events out of the engine's buffer, so they are sampled: a
client's first limited request, then one a minute, with `sampled_count` saying how many requests
it stands for; at most 100 a second per limit and 10 a second per engine. Every limited request is
still counted in the metrics. So a 429's `X-Request-Id` may have no event: look up the client's
earlier one.

`inkwallctl test` compiles a policy's limits, so a wrong one is an error there too, but doesn't
apply them: it checks one request at a time and keeps no state, and says so on stderr.

## Upgrading and rolling back

Upgrade the chart first (the CRD field and the operator), then the engines. While an engine before
0.7.0 runs a policy with limits, the policy is `Enforced=False` with reason `EnginesOutdated`
naming `spec.rateLimits`: that engine limits nothing.

Rolling the operator back below 0.7.0 drops the limits without a word: the older operator doesn't
know the field, so neither its bundle nor its status carries it.

A SecLang rule that denies with `status:429` now answers gRPC calls with `RESOURCE_EXHAUSTED`
instead of `UNAVAILABLE`.
