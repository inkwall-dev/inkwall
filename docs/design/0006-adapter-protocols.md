# 0006 — Adapter Protocols Primer

- Status: Draft
- Date: 2026-09-28
- Owner: noureldin
- Depends on: [0002](0002-system-architecture.md) §3.2 and §6

Each adapter answers the proxy's question "should I let this request through?". Adapters are thin
listeners in `pkg/adapters/<name>` that convert the protocol's message to `request.Request` and the
`Verdict` back, so detection is identical whichever proxy asked. Proxy configuration: 0002 §6.

**Built (v0.1.0):** forward-auth (§3), `/v1/check` over HTTP (§5), reverse proxy (§6).
**Not yet:** ext_authz (§1), ext_proc (§2), SPOE (§4).

---

## 1. ext_authz (Envoy external authorization)

- One gRPC call per request (`envoy.service.auth.v3.Authorization/Check`) with headers, plus the
  body if `with_request_body` is set. Reply **OK** or **Denied** (with our status).
- No response visibility; supported by every Envoy-based product, so it is the Envoy fallback.

## 2. ext_proc (Envoy external processing)

- A bidirectional gRPC stream per request: request headers, body chunks, response headers and body,
  each answered with **continue**, **modify** or **immediate response** (block).
- `processing_mode` asks for headers only, body stages only for routes whose policy needs them.
- `observability_mode: true` doesn't wait for answers: detect mode at ~0 latency (0001 §4).
- Most capable, so the planned first choice for Envoy, Envoy Gateway, Istio and Contour.

## 3. forward-auth (Traefik `ForwardAuth`, nginx `auth_request`)

- The proxy sends an HTTP subrequest to `/v1/forward-auth` with the client's headers; the original
  request comes in `X-Forwarded-Method`, `-Uri`, `-Host`, `-Proto`, `-Port`, which the adapter
  rebuilds the request from and strips before inspection.
- **200** + `X-Request-Id` → allow. Deny → the verdict's status (403, 413, 503, ...), returned by the
  proxy to the client. Missing or malformed `X-Forwarded-Method`/`-Uri` → 400 (never let through).
- No response visibility; body only if the proxy forwards it. ingress-nginx `global-auth-url` uses
  the same mechanism.

![Traefik forward-auth sequence: for a benign request Traefik sends a subrequest to the engine, gets 200 with X-Request-Id and forwards to the app; for an attack the engine answers 403 and Traefik returns it to the client](../diagrams/forward-auth.svg)

Traefik middleware must set:

- `trustForwardHeader: false`, else the engine inspects a client-supplied `X-Forwarded-Uri`.
- `forwardBody: true` with `maxBodySize` above `--max-body-bytes`, else bodies pass uninspected.
- `authResponseHeaders: X-Request-Id` to pass the request ID upstream.

**Built:** `pkg/adapters/forwardauth`, `inkwall-engine forward-auth`.

## 4. SPOE (HAProxy Stream Processing Offload Engine)

- HAProxy's binary SPOP, pipelined over a few connections; the engine is the agent (SPOA).
- The engine sets variables (`txn.inkwall.action=deny`); HAProxy rules act on them. On timeout or
  error none is set, so fail-closed needs an extra rule denying when the variable is missing.
- Async groups allow detect mode without waiting.

## 5. `/v1/check` (Inkwall's own API)

- `POST /v1/check` with a `CheckRequest` (`api/engine/v1`, schema 0002 §5.1) as protobuf
  (`application/x-protobuf`) or JSON (`application/json`); `CheckResponse` (action, status, headers,
  matched rule IDs, the deciding policy in bundle mode) comes back in the same encoding.
- For clients with no native protocol; we control what is sent.
- Every well-formed check gets **200**, verdict in the body. Errors: 405 (not POST), 415 (content
  type), 413 (too large), 400 (undecodable or invalid).
- `client_ip` is taken as given: listen only where the proxy alone can reach it (Unix socket or
  localhost).

![POST /v1/check sequence: the caller sends a CheckRequest and the engine always answers 200 with a CheckResponse; ACTION_ALLOW lets the caller forward with X-Request-Id, ACTION_DENY with status 403 makes the caller return 403](../diagrams/check-api.svg)

**Built:** `pkg/adapters/httpcheck`, `inkwall-engine check`; used by `inkwallctl test`,
`inkwallctl bench --engine` and tests.
**Not yet:** gRPC `CheckService/Check` (defined in `api/engine/v1`, not served), the ingress-nginx
Lua plugin and the Traefik plugin.

## 6. Reverse proxy (standalone mode)

- The engine is the proxy: inspects each request, forwards allowed ones to `--upstream`. Sees the
  full body, at the cost of an extra hop.
- For VMs and unsupported proxies, and the **reference** in tests: every adapter must give the same
  verdict for the same request (0002 §10).

![Reverse proxy sequence: a benign request is inspected and forwarded to the app with X-Request-Id and X-Forwarded headers; an attack gets 403 without reaching the app; an inspection timeout in block mode gets 503](../diagrams/reverse-proxy.svg)

**Built:** `pkg/adapters/proxy`, `inkwall-engine proxy`.

---

## 7. Comparison

| | Transport | Body | Response | Waits? | For | Status |
|---|---|---|---|---|---|---|
| ext_authz | gRPC call | buffered, optional | no | yes | Envoy fallback | not yet |
| ext_proc | gRPC stream | streamed | yes | yes, or no (observability) | Envoy, Istio, Contour | not yet |
| forward-auth | HTTP subrequest | if forwarded | no | yes | Traefik, ingress-nginx | built |
| SPOE | SPOP | yes | possible | yes, or no (async) | HAProxy | not yet |
| `/v1/check` | HTTP (gRPC planned) | yes | no | yes | CLI, tests; Lua/Traefik plugins planned | built |
| reverse proxy | HTTP proxying | yes | yes | is the path | VMs, test reference | built |

Caddy needs no protocol: the planned module compiles the engine into Caddy (0002 §6.5).
