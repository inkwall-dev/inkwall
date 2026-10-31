# 0006 — Adapter Protocols Primer

- Status: Draft
- Date: 2026-09-28
- Updated: 2026-10-31
- Owner: noureldin
- Depends on: [0002 §3.2](0002-system-architecture.md#32-adapters) and
  [0002 §6](0002-system-architecture.md#6-proxy-integrations)

Every proxy has its own way to ask an outside service "should I let this request through?". This
primer describes each of those protocols and the [adapter](../glossary.md#adapter) that answers it. [Forward-auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/),
`/v1/check`, the reverse proxy and [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) are built; [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) and [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt) are not yet.

An **adapter** is a thin listener in the engine (`inkwall-engine`), in `pkg/adapters/<name>`. It
converts the protocol's message into a `request.Request`, and the engine's `Verdict` back into the
protocol's answer. Detection is therefore identical whichever proxy asked. The **proxy** is the
[ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)'s data-plane process ([Traefik](https://doc.traefik.io/traefik/), [Envoy](https://www.envoyproxy.io/docs/envoy/latest/), ...). How each proxy is configured to call
its adapter is in [0002 §6](0002-system-architecture.md#6-proxy-integrations).

**Built (v0.1.0):** forward-auth ([§3](#3-forward-auth-traefik-forwardauth-nginx-auth_request)),
`/v1/check` over HTTP ([§5](#5-v1check-inkwalls-own-api)) and the reverse proxy
([§6](#6-reverse-proxy-standalone-mode)). **Built since:** ext_proc
([§2](#2-ext_proc-envoy-external-processing)), with the operator's Envoy Gateway configuration. **Not yet:** ext_authz
([§1](#1-ext_authz-envoy-external-authorization)) and SPOE
([§4](#4-spoe-haproxy-stream-processing-offload-engine)).

## Contents

- [1. ext_authz (Envoy external authorization)](#1-ext_authz-envoy-external-authorization)
- [2. ext_proc (Envoy external processing)](#2-ext_proc-envoy-external-processing)
- [3. forward-auth (Traefik `ForwardAuth`, nginx `auth_request`)](#3-forward-auth-traefik-forwardauth-nginx-auth_request)
- [4. SPOE (HAProxy Stream Processing Offload Engine)](#4-spoe-haproxy-stream-processing-offload-engine)
- [5. `/v1/check` (Inkwall's own API)](#5-v1check-inkwalls-own-api)
- [6. Reverse proxy (standalone mode)](#6-reverse-proxy-standalone-mode)
- [7. Comparison](#7-comparison)

---

## 1. ext_authz (Envoy external authorization)

- Envoy makes one [gRPC](https://grpc.io/docs/) call per request (`envoy.service.auth.v3.Authorization/Check`) with the
  headers, plus the body if `with_request_body` is set.
- The adapter replies **OK** or **Denied**, with our status code.
- It gives no view of the response. Every Envoy-based product supports it, so it is the fallback
  for Envoy. Envoy Gateway uses ext_proc instead ([§2](#2-ext_proc-envoy-external-processing)).

## 2. ext_proc (Envoy external processing)

- Envoy opens a bidirectional gRPC stream per request. It sends the request headers, the body
  chunks, and the response headers and body.
- The adapter answers each message with **continue**, **modify** or **immediate response** (which
  blocks the request).
- `processing_mode` asks for headers only, and for the body stages only on routes whose policy
  needs them.
- `observability_mode: true` doesn't wait for the answers. That gives detect mode at about zero
  latency ([0001 §4](0001-performance-first-architecture.md#enforcement-modes-per-route)).
- It is the most capable protocol, so it is the first choice for Envoy, [Envoy Gateway](https://gateway.envoyproxy.io/),
  [Istio](https://istio.io/latest/docs/) and [Contour](https://projectcontour.io/docs/).

**Built:** `pkg/adapters/extproc`, run as `inkwall-engine ext-proc` (gRPC, on `127.0.0.1:9003` or
a Unix socket). It answers the stream of one request as follows:

- **Headers:** it rebuilds the request from `:method`, `:path`, `:authority` and `:scheme`, and
  inspects the other headers. A `:path` not in origin form or with a fragment, an invalid
  `:authority`, a bad `:method` or a repeated pseudo-header gets an immediate **400**: such a
  request is never let through, as with forward-auth.
- **Body:** when the policy inspects bodies and Envoy sends the body in one message
  (`request_body_mode: BUFFERED` or `BUFFERED_PARTIAL`), the verdict waits for it. Envoy holds the
  headers meanwhile. A body Envoy sends otherwise (`NONE`, `STREAMED`), or cuts at its buffer
  limit (`BUFFERED_PARTIAL` without `end_of_stream`), goes uninspected and is handled like an
  oversized one (`body.onOversize`). The engine reads the mode from `protocol_config`, which Envoy
  sends from 1.33.
- **Allow:** CONTINUE. If the engine generated the request ID, it sets `x-request-id` on the
  request Envoy forwards; Envoy usually sets one itself.
- **Deny:** an immediate response with the verdict's status (403, 413, 503, ...), the same
  plain-text body as the other adapters, and `x-request-id`.
- **Later stages** (response headers or body, trailers), if the filter sends them: CONTINUE.
- **`observability_mode`:** the request is inspected and logged, and nothing is answered.
- **Client IP:** from `X-Forwarded-For`, which Envoy's connection manager sets before the filter
  runs, walked through `--trusted-proxies` ([client IP](../client-ip.md)). A Unix-socket peer
  counts as loopback, `127.0.0.1`.

Route lookup, `no-policy` pass-through, security events and metrics (`adapter="extproc"`) are those
of every adapter. `BenchmarkAdapters` (`pkg/adapters/extproc`) times it against forward-auth on
the same rules, each over a Unix socket.

**Envoy Gateway uses ext_proc, not ext_authz** (decided for v0.3.0). Both can deny with our
status and see a buffered body, and ext_authz is the simpler one: one call, no stream. ext_proc
wins on what comes next:

- It can see responses. Response inspection, a bot challenge and the block page rewritten by the
  engine need it ([0002 §12](0002-system-architecture.md#12-open-questions)).
- `observability_mode` gives detect mode without adding latency; ext_authz always waits.
- Envoy Gateway attaches it per route with an `EnvoyExtensionPolicy`, which takes the processing
  mode, so only routes whose policy inspects bodies buffer them ([0004 §4.4](0004-operator.md#44-wiring-controller)).
  ext_authz goes in a `SecurityPolicy`, and a route takes one, which may already carry the user's
  own authentication.
- The cost: Envoy keeps a stream per request, and the body is buffered, not streamed. The
  benchmark shows the difference to forward-auth on the same rules.

**Built: the operator's configuration** for Envoy Gateway ([0004 §4.4](0004-operator.md#44-wiring-controller)), one
`EnvoyExtensionPolicy` per protected HTTPRoute: `request_body_mode: BUFFERED_PARTIAL` on routes
whose policy inspects bodies (headers only otherwise), response stages `SKIP`, a message timeout
100 ms above the engine's deadline, `failOpen` only when every policy on the route fails open, and
an Envoy buffer limit (a `ClientTrafficPolicy` on the Gateway) of 10 MiB, the largest
`body.maxBytes`. On kind, a body attack is blocked before the app sees the request: Envoy holds
the headers until the engine answers the body. **Not yet:** `observability_mode` for detect mode.

## 3. forward-auth (Traefik `ForwardAuth`, nginx `auth_request`)

- The proxy sends an HTTP subrequest with the client's headers to `/v1/forward-auth`. The original
  request's method, URI, host, scheme and port come in `X-Forwarded-Method`, `-Uri`, `-Host`,
  `-Proto` and `-Port`. The adapter rebuilds the request from them, and strips them before
  inspection.
- **Allow:** the adapter answers **200** with `X-Request-Id`.
- **Deny:** it answers with the verdict's status (403, 413, 503, ...), which the proxy returns to
  the client.
- A missing or malformed `X-Forwarded-Method` or `X-Forwarded-Uri` gets **400**: such a request is
  never let through.
- It gives no view of the response, and sees the body only if the proxy forwards it.
  [ingress-nginx](https://kubernetes.github.io/ingress-nginx/)'s [`global-auth-url`](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#global-auth-url) uses the same mechanism.

![Traefik forward-auth sequence: for a benign request Traefik sends a subrequest to the engine, gets 200 with X-Request-Id and forwards to the app; for an attack the engine answers 403 and Traefik returns it to the client](../diagrams/forward-auth.svg)

The Traefik middleware must set:

- `trustForwardHeader: false`. Otherwise the engine inspects an `X-Forwarded-Uri` the client
  supplied. Behind a load balancer, the client IP then comes from the [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) on Traefik's
  [entry point](https://doc.traefik.io/traefik/routing/entrypoints/), not from the load balancer's [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For) ([client IP](../client-ip.md)).
- `forwardBody: true`, with `maxBodySize` above `--max-body-bytes`. Otherwise bodies pass
  uninspected.
- `authResponseHeaders: X-Request-Id`, to pass the request ID on to the app.

**Built:** `pkg/adapters/forwardauth`, run as `inkwall-engine forward-auth`.

## 4. SPOE (HAProxy Stream Processing Offload Engine)

- [HAProxy](https://docs.haproxy.org/) speaks its binary protocol, SPOP, pipelined over a few connections. The engine is the
  agent (an SPOA).
- The engine sets variables, such as `txn.inkwall.action=deny`, and HAProxy's rules act on them.
- On a timeout or an error, no variable is set. Failing closed therefore needs an extra rule that
  denies the request when the variable is missing.
- Asynchronous groups allow detect mode without waiting.

## 5. `/v1/check` (Inkwall's own API)

- The client sends `POST /v1/check` with a `CheckRequest` (`api/engine/v1`; schema in
  [0002 §5.1](0002-system-architecture.md#51-engine-check-api-for-lua-generic-http-clients-and-tests)),
  as [protobuf](https://protobuf.dev/) (`application/x-protobuf`) or JSON (`application/json`).
- The `CheckResponse` comes back in the same encoding: action, status, headers, matched rule IDs,
  and, in bundle mode, the policy that decided. (In bundle mode the engine gets its policies from
  the operator's bundles rather than from flags.)
- It is for clients with no native protocol, and we control what they send.
- Every well-formed check gets **200**, with the verdict in the body. Errors: 405 (not a POST), 415
  (content type), 413 (too large), 400 (can't be decoded, or invalid).
- The engine takes `client_ip` as given. So it must listen only where the proxy alone can reach
  it: a [Unix socket](https://man7.org/linux/man-pages/man7/unix.7.html) or localhost.

![POST /v1/check sequence: the caller sends a CheckRequest and the engine always answers 200 with a CheckResponse; ACTION_ALLOW lets the caller forward with X-Request-Id, ACTION_DENY with status 403 makes the caller return 403](../diagrams/check-api.svg)

**Built:** `pkg/adapters/httpcheck`, run as `inkwall-engine check`. `inkwallctl test`,
`inkwallctl bench --engine` and the tests use it.
**Not yet:** the gRPC `CheckService/Check` (defined in `api/engine/v1`, not served), the
ingress-nginx Lua plugin and the Traefik plugin.

## 6. Reverse proxy (standalone mode)

- The engine is the proxy. It inspects each request and forwards the allowed ones to `--upstream`.
- It sees the full body, at the cost of an extra network hop.
- It serves VMs and unsupported proxies. It is also the **reference** in tests: every adapter must
  give the same verdict as the reverse proxy for the same request
  ([0002 §10](0002-system-architecture.md#10-testing-architecture)).

![Reverse proxy sequence: a benign request is inspected and forwarded to the app with X-Request-Id and X-Forwarded headers; an attack gets 403 without reaching the app; an inspection timeout in block mode gets 503](../diagrams/reverse-proxy.svg)

**Built:** `pkg/adapters/proxy`, run as `inkwall-engine proxy`. It forwards only what it
inspected: an origin-form request target (`/path?query`) and a valid Host header. Anything else,
such as `GET http://host/path`, gets 400, because Go's HTTP client would forward a different Host.

"Standalone" in this heading means the engine runs on its own, without an ingress proxy. It is not
the cluster's [Standalone mode](../glossary.md#standalone) (no control plane).

---

## 7. Comparison

| | Transport | Body | Response | Proxy waits? | For | Status |
|---|---|---|---|---|---|---|
| ext_authz | gRPC call | Buffered, optional | No | Yes | Envoy fallback | Not yet |
| ext_proc | gRPC stream | Buffered (streaming possible) | Yes (not used yet) | Yes, or no (observability mode) | Envoy Gateway, Envoy, Istio, Contour | Built (Envoy Gateway) |
| forward-auth | HTTP subrequest | If forwarded | No | Yes | Traefik, ingress-nginx | Built |
| SPOE | SPOP | Yes | Possible | Yes, or no (asynchronous) | HAProxy | Not yet |
| `/v1/check` | HTTP (gRPC planned) | Yes | No | Yes | CLI, tests; Lua and Traefik plugins planned | Built |
| Reverse proxy | HTTP proxying | Yes | Yes | It is the path | VMs, test reference | Built |

[Caddy](https://caddyserver.com/docs/) needs no protocol: the planned module compiles the engine into Caddy
([0002 §6.5](0002-system-architecture.md#65-caddy)).
