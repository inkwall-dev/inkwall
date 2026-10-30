# 0006 — Adapter Protocols Primer

- Status: Draft
- Date: 2026-09-28
- Updated: 2026-10-30
- Owner: noureldin
- Depends on: [0002 §3.2](0002-system-architecture.md#32-adapters) and
  [0002 §6](0002-system-architecture.md#6-proxy-integrations)

Every proxy has its own way to ask an outside service "should I let this request through?". This
primer describes each of those protocols and the adapter that answers it. Forward-auth,
`/v1/check` and the reverse proxy are built; ext_authz, ext_proc and SPOE are not yet.

An **adapter** is a thin listener in the engine (`inkwall-engine`), in `pkg/adapters/<name>`. It
converts the protocol's message into a `request.Request`, and the engine's `Verdict` back into the
protocol's answer. Detection is therefore identical whichever proxy asked. The **proxy** is the
ingress controller's data-plane process (Traefik, Envoy, ...). How each proxy is configured to call
its adapter is in [0002 §6](0002-system-architecture.md#6-proxy-integrations).

**Built (v0.1.0):** forward-auth ([§3](#3-forward-auth-traefik-forwardauth-nginx-auth_request)),
`/v1/check` over HTTP ([§5](#5-v1check-inkwalls-own-api)) and the reverse proxy
([§6](#6-reverse-proxy-standalone-mode)). **Not yet:** ext_authz
([§1](#1-ext_authz-envoy-external-authorization)), ext_proc
([§2](#2-ext_proc-envoy-external-processing)) and SPOE
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

- Envoy makes one gRPC call per request (`envoy.service.auth.v3.Authorization/Check`) with the
  headers, plus the body if `with_request_body` is set.
- The adapter replies **OK** or **Denied**, with our status code.
- It gives no view of the response. Every Envoy-based product supports it, so it is the fallback
  for Envoy.

## 2. ext_proc (Envoy external processing)

- Envoy opens a bidirectional gRPC stream per request. It sends the request headers, the body
  chunks, and the response headers and body.
- The adapter answers each message with **continue**, **modify** or **immediate response** (which
  blocks the request).
- `processing_mode` asks for headers only, and for the body stages only on routes whose policy
  needs them.
- `observability_mode: true` doesn't wait for the answers. That gives detect mode at about zero
  latency ([0001 §4](0001-performance-first-architecture.md#enforcement-modes-per-route)).
- It is the most capable protocol, so it is the planned first choice for Envoy, Envoy Gateway,
  Istio and Contour.

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
  ingress-nginx's `global-auth-url` uses the same mechanism.

![Traefik forward-auth sequence: for a benign request Traefik sends a subrequest to the engine, gets 200 with X-Request-Id and forwards to the app; for an attack the engine answers 403 and Traefik returns it to the client](../diagrams/forward-auth.svg)

The Traefik middleware must set:

- `trustForwardHeader: false`. Otherwise the engine inspects an `X-Forwarded-Uri` the client
  supplied. Behind a load balancer, the client IP then comes from the PROXY protocol on Traefik's
  entry point, not from the load balancer's `X-Forwarded-For` ([client IP](../client-ip.md)).
- `forwardBody: true`, with `maxBodySize` above `--max-body-bytes`. Otherwise bodies pass
  uninspected.
- `authResponseHeaders: X-Request-Id`, to pass the request ID on to the app.

**Built:** `pkg/adapters/forwardauth`, run as `inkwall-engine forward-auth`.

## 4. SPOE (HAProxy Stream Processing Offload Engine)

- HAProxy speaks its binary protocol, SPOP, pipelined over a few connections. The engine is the
  agent (an SPOA).
- The engine sets variables, such as `txn.inkwall.action=deny`, and HAProxy's rules act on them.
- On a timeout or an error, no variable is set. Failing closed therefore needs an extra rule that
  denies the request when the variable is missing.
- Asynchronous groups allow detect mode without waiting.

## 5. `/v1/check` (Inkwall's own API)

- The client sends `POST /v1/check` with a `CheckRequest` (`api/engine/v1`; schema in
  [0002 §5.1](0002-system-architecture.md#51-engine-check-api-for-lua-generic-http-clients-and-tests)),
  as protobuf (`application/x-protobuf`) or JSON (`application/json`).
- The `CheckResponse` comes back in the same encoding: action, status, headers, matched rule IDs,
  and, in bundle mode, the policy that decided. (In bundle mode the engine gets its policies from
  the operator's bundles rather than from flags.)
- It is for clients with no native protocol, and we control what they send.
- Every well-formed check gets **200**, with the verdict in the body. Errors: 405 (not a POST), 415
  (content type), 413 (too large), 400 (can't be decoded, or invalid).
- The engine takes `client_ip` as given. So it must listen only where the proxy alone can reach
  it: a Unix socket or localhost.

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
the cluster's Standalone mode (no control plane).

---

## 7. Comparison

| | Transport | Body | Response | Proxy waits? | For | Status |
|---|---|---|---|---|---|---|
| ext_authz | gRPC call | Buffered, optional | No | Yes | Envoy fallback | Not yet |
| ext_proc | gRPC stream | Streamed | Yes | Yes, or no (observability mode) | Envoy, Istio, Contour | Not yet |
| forward-auth | HTTP subrequest | If forwarded | No | Yes | Traefik, ingress-nginx | Built |
| SPOE | SPOP | Yes | Possible | Yes, or no (asynchronous) | HAProxy | Not yet |
| `/v1/check` | HTTP (gRPC planned) | Yes | No | Yes | CLI, tests; Lua and Traefik plugins planned | Built |
| Reverse proxy | HTTP proxying | Yes | Yes | It is the path | VMs, test reference | Built |

Caddy needs no protocol: the planned module compiles the engine into Caddy
([0002 §6.5](0002-system-architecture.md#65-caddy)).
