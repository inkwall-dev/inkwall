# 0006 — Adapter Protocols Primer

- Status: Draft
- Date: 2026-09-28
- Updated: 2026-11-03
- Owner: noureldin
- Depends on: [0002 §3.2](0002-system-architecture.md#32-adapters) and
  [0002 §6](0002-system-architecture.md#6-proxy-integrations)

Every proxy has its own way to ask an outside service "should I let this request through?". This
primer describes each of those protocols and the [adapter](../glossary.md#adapter) that answers it. [Forward-auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/),
`/v1/check`, the reverse proxy, [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) and [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt) are built; [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) is not yet.

An **adapter** is a thin listener in the engine (`inkwall-engine`), in `pkg/adapters/<name>`. It
converts the protocol's message into a `request.Request`, and the engine's `Verdict` back into the
protocol's answer. Detection is therefore identical whichever proxy asked. The **proxy** is the
[ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)'s data-plane process ([Traefik](https://doc.traefik.io/traefik/), [Envoy](https://www.envoyproxy.io/docs/envoy/latest/), ...). How each proxy is configured to call
its adapter is in [0002 §6](0002-system-architecture.md#6-proxy-integrations).

**Built (v0.1.0):** forward-auth ([§3](#3-forward-auth-traefik-forwardauth-nginx-auth_request)),
`/v1/check` over HTTP ([§5](#5-v1check-inkwalls-own-api)) and the reverse proxy
([§6](#6-reverse-proxy-standalone-mode)). **Built since:** ext_proc
([§2](#2-ext_proc-envoy-external-processing)), with the operator's Envoy Gateway and Istio configuration and for raw Envoy, and the SPOE agent
([§4](#4-spoe-haproxy-stream-processing-offload-engine)), configured by hand ([protecting HAProxy](../haproxy.md)) or by the operator for the HAProxy Kubernetes Ingress Controller. **Not yet:** ext_authz
([§1](#1-ext_authz-envoy-external-authorization)).

## Contents

- [1. ext_authz (Envoy external authorization)](#1-ext_authz-envoy-external-authorization)
- [2. ext_proc (Envoy external processing)](#2-ext_proc-envoy-external-processing)
- [3. forward-auth (Traefik `ForwardAuth`, nginx `auth_request`)](#3-forward-auth-traefik-forwardauth-nginx-auth_request)
- [4. SPOE (HAProxy Stream Processing Offload Engine)](#4-spoe-haproxy-stream-processing-offload-engine)
- [5. `/v1/check` (Inkwall's own API)](#5-v1check-inkwalls-own-api)
- [6. Reverse proxy (standalone mode)](#6-reverse-proxy-standalone-mode)
- [7. Denying gRPC calls](#7-denying-grpc-calls)
- [8. Comparison](#8-comparison)

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
  headers meanwhile. A body Envoy sends otherwise (`NONE`, `STREAMED` outside observability mode),
  or cuts at its buffer limit, goes uninspected and is handled like an oversized one
  (`body.onOversize`). The engine reads the mode from `protocol_config`, which Envoy sends from 1.33.
- **Cut or trailers:** Envoy sends a body without `end_of_stream` when it cut it at its buffer
  limit, but also when trailers follow (HTTP/2), whatever the body's size. It then sends no
  trailers message: Envoy Gateway can't ask for them (`request_trailer_mode` stays `SKIP`), and
  even then it would come after the verdict. So the engine takes such a body as complete, and
  inspects it, only when it is under the policy's limit and as long as its `Content-Length`. A
  body without `Content-Length` (HTTP/2 or chunked) may have been cut at a buffer smaller than
  the limit, which the engine doesn't know (the user's own `ClientTrafficPolicy`), so it is
  handled as oversized: with trailers and no `Content-Length`, a request gets `body.onOversize`.
  Bodies a client sends whole get no less inspection: under `Allow`, padding a body past the
  limit skips it as well. The operator reports a user's buffer below a policy's limit
  ([0004 §4.4](0004-operator.md#44-wiring-controller)).
- **Protocol:** the client's protocol (`HTTP/1.0`, `HTTP/1.1`, `HTTP/2`, `HTTP/3`) is Envoy's
  `request.protocol` [attribute](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes),
  when the filter sends it (`request_attributes`); `HTTP/1.1` otherwise.
- **Upgrade (WebSocket handshake):** Envoy sends an upgrade's headers without `end_of_stream`,
  whatever the body mode: what follows them is the upgraded connection's data, which the client
  sends only after the `101`. So a `GET` with an `Upgrade` header that declares no body (no
  `Transfer-Encoding`, no `Content-Length` but `0`) is decided on its headers, and an allow is
  `CONTINUE_AND_REPLACE` without a body mutation: Envoy sends nothing more of the stream, and the
  WebSocket's data goes to the upstream untouched. An upgrade that declares a body waits for it, as
  any request: the upgrade isn't a way around body inspection. Before #276, the engine waited for a
  body: Envoy held the handshake (`BUFFERED_PARTIAL`) or, in observability mode, streamed the
  WebSocket's frames as one until the connection closed ([WebSocket](../websocket.md)).
- **Allow:** CONTINUE. If the engine generated the request ID, it sets `x-request-id` on the
  request Envoy forwards; Envoy usually sets one itself.
- **Deny:** an immediate response with the verdict's status (403, 413, 503, ...), the same
  plain-text body as the other adapters, and `x-request-id`. A gRPC call gets a gRPC status
  instead ([§7](#7-denying-grpc-calls)).
- **Later stages** (response headers or body, trailers), if the filter sends them: CONTINUE, unless
  the request's policy inspects responses ([response inspection](#response-inspection-v040)).
- **`observability_mode`:** the request is inspected and logged, and nothing is answered. Envoy
  sends the body in chunks there (`STREAMED`, the only body mode it allows, whatever
  `protocol_config` says): the engine gathers them up to the policy's limit, decides at the end of the body or past the limit (`body.onOversize`), and then closes the
  stream, so Envoy sends no more. A stream that ends with no last chunk, as when trailers follow,
  is decided on what came, as a body without `end_of_stream` above.
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
`EnvoyExtensionPolicy` per protected HTTPRoute: the `request.protocol` attribute,
`request_body_mode: BUFFERED_PARTIAL` on routes whose policy inspects bodies (headers only
otherwise), response stages `SKIP`, a message timeout
500 ms above the engine's deadline (the engine decides, with the policy's failure mode; Envoy's timeout is for a hung engine), `failOpen` only when every policy on the route fails open, and
an Envoy buffer limit (a `ClientTrafficPolicy` on the Gateway) of 10 MiB, the largest
`body.maxBytes`. On kind, a body attack is blocked before the app sees the request: Envoy holds
the headers until the engine answers the body. A route whose policies are all in detect mode and
fail open (the engine never rejects its requests) gets `observability_mode` (Envoy Gateway's
`shadowMode`) and a `STREAMED` body instead, and no buffer limit: Envoy forwards the request
without waiting for the engine.

**The operator's probe** (#372, bundle mode): as the SPOE agent does ([§4](#4-spoe-haproxy-stream-processing-offload-engine)), the ext_proc adapter
answers a request whose `X-Inkwall-Probe` header carries a valid MAC of its host and URI under
the bundle's probe key (`pkg/haproxyprobe`) itself, uninspected, before anything else: an
immediate response, 200 with the answer's MAC in `X-Inkwall-Probe`, so the request never reaches
the upstream. Envoy's local replies take a defined HTTP status only, so not HAProxy's 299; the
MAC is the proof. A request with a wrong MAC, or before the engine has a key, is an ordinary
request. In observability mode Envoy ignores the reply and forwards the request, so there
(since v0.6.0, #475) the adapter doesn't answer: it keeps a receipt of the probe, which the agent
reports to the operator with its heartbeats, and inspects the request as any other, so a probe's
header carries nothing past the engine's log (0002 §6.1, proof by receipt). The operator probes
each gateway pod for Istio's routes before `Programmed` (#372).

### Response inspection (v0.4.0)

Decided for v0.4.0 ([#274](https://github.com/inkwall-dev/inkwall/issues/274)). Responses are
inspected for data leaks: SQL errors, stack traces, directory listings, source code, and whatever
the user's own rules look for (a secret, a leaked system prompt).

**Policy API.** `WAFPolicy.spec.responses`, off unless set, so nothing changes for existing
policies (`maxBytes` and `onOversize` without `inspect: true` are refused):

```yaml
responses:
  inspect: true        # default false
  maxBytes: 65536      # body bytes inspected; default 64 KiB, at most 10 MiB
  onOversize: Allow    # Allow | Deny; unset: Deny in Block mode, Allow in Detect mode
```

The bundle carries it as `Policy.responses` (`ResponseConfig`). Engines before 0.4.0 ignore the
field, so a policy that sets it isn't `Enforced` (`EnginesOutdated`) while one runs it, as for
`webSocket`.

**Rules.** The request's Coraza transaction is kept open for its response, and the response runs
phases 3 (status and headers) and 4 (body): the response rules see what the request rules set
(paranoia level, anomaly scores, the user's variables). With the CRS that is `RESPONSE-950` to
`956` (data leakage: generic, SQL, Java, PHP, IIS, web shells, Ruby), scored into the outbound
anomaly score and blocked by `RESPONSE-959` at `tx.outbound_anomaly_score_threshold` (4 by
default: one critical match). The user's `WAFRuleSet` rules on `RESPONSE_*` variables run too. The
response's verdict lists only what matched the response. In Block mode a request the rules
interrupt keeps no transaction: it was denied, and there is no response. In Detect mode (#360) the
request is let through, so its response reaches the client, and it is the one most worth
inspecting (an SQL injection's SQL error): the transaction runs DetectionOnly (a first phase 1
rule, 7700010, sets `ctl:ruleEngine=DetectionOnly` when the engine sets `TX:inkwall_detect`), the
request's event reports the interruption the rules would have made, and the response is inspected
as any other, with its own event. In DetectionOnly the rules go on after that interruption, so the
request's event may list more matches than in Block mode. The response's would-be interruption is
its first matched rule with a disruptive action (`deny`, `drop`, `redirect`: the CRS's 959100),
since Coraza records only the transaction's first.

**What is read.** The status and headers always. The body only when its media type is one the
rules read (`text/plain`, `text/html`, `text/xml`, `application/json`, `application/xml`,
`application/problem+json`; Coraza's `SecResponseBodyMimeType` is set to the same list): an
image, a download, Server-Sent Events or a gRPC stream passes without its body inspected, and
isn't oversized. A body over `maxBytes` has its prefix inspected (unlike a request body, a prefix
is meaningful to data leakage rules: no parser needs the whole), and then gets `onOversize`. A
`gzip` or `deflate` body is decoded, up to `maxBytes`, before the rules see it (the CRS skips
encoded bodies); another encoding (`br`, `zstd`) goes uninspected and gets `onOversize`. To keep
upstream bodies readable, the engine removes `Accept-Encoding` from requests on routes whose
response bodies it inspects (when Envoy waits for it; not in observability mode).

**Detect and block.** Detect mode logs the event (`phase: response`) and changes nothing. Block
mode replaces the response with the fixed plain-text error the request denials use and the
rule's status (403 for the CRS), with `x-request-id`; an oversized or undecodable body under
`onOversize: Deny` is replaced with **502**. Events carry `phase` (`PHASE_RESPONSE`), and never a
snippet of the response body: what a leak rule matched there is the leaked data.

**Failure mode and limits.** The response is evaluated under the policy's timeout, the engine's
admission limit and its failure mode, as a request is: a timeout or overload replaces the response
with 503 when the policy fails closed (Block mode's default), and lets it through when it fails
open. Each response is evaluated once.

**ext_proc.** Envoy sends the response headers, and the body with `response_body_mode:
BUFFERED_PARTIAL`; it holds the response headers until the body is answered, so the engine can
still replace the response with an immediate response. A body the rules don't read is decided at
the headers, whose answer sets `mode_override` (`response_body_mode: NONE`) so Envoy neither
buffers nor sends it; this needs the filter's `allow_mode_override`, and without it the body is
sent and continued. So is a response that isn't inspected at all, though Envoy sends it (another
policy on the route inspects responses, or Envoy's configuration asks for them). A body Envoy cut (no `end_of_stream`, and not its full `Content-Length`) is
handled as oversized; a body Envoy doesn't send in one piece (`NONE`, `STREAMED` outside
observability mode) goes uninspected, as oversized. In observability mode the body comes in chunks,
gathered up to the limit as for requests, and the stream is closed once the response is decided. There
Envoy doesn't hold the request, so the upstream may answer before the client has sent all of its
body: the response's messages are queued (up to 10 MiB of body) until the request is decided on
its whole body, then handled.
The kept transaction is released when the response is decided or the stream ends. A WebSocket handshake allowed on its headers (CONTINUE_AND_REPLACE) keeps
it too: a 101 releases it and is continued, and the upgraded stream's data is never inspected; any
other answer (an upstream that ignores `Upgrade`) is inspected as a response.

**Envoy Gateway (operator).** Only routes whose policies inspect responses get
`processingMode.response` (`body: BufferedPartial`, `Streamed` in shadow mode) and
`processingMode.allowModeOverride: true` in their `EnvoyExtensionPolicy`; other routes keep the
response stages off. Envoy holds a response body in the same per-connection buffer as a request
body, so a Gateway with a route whose responses Envoy holds (not in shadow mode) gets the
operator's `ClientTrafficPolicy` (10 MiB) even when no policy inspects request bodies; a user's
own `bufferLimit` below the route's largest `responses.maxBytes` is `WiringFailed`, as for
`body.maxBytes`.

**Traefik.** ForwardAuth never sees the response, so Traefik can't inspect responses (a Traefik
middleware plugin or the engine's reverse proxy in front of the app are the options for later). A
policy with `responses.inspect` on a route Traefik serves is not silently half-enforced: it is
`Programmed=False`, reason `ResponsesNotInspected`, naming the routes (and so not `Ready`), though
Traefik's routes are wired and their requests inspected. A separate condition was considered, with
`Programmed` true for the requests: rejected, because `Ready` would then claim the whole policy is
enforced. When such a policy is applied, the admission webhook warns that the responses of its
`Ingress`, `IngressRoute` and `HTTPRoute` targets may not be inspected, depending on the proxy that
serves them: it doesn't resolve the proxy (an `Ingress` may be Traefik's or HAProxy's, an
`HTTPRoute` Envoy Gateway's, Traefik's or Istio's), so it names none as the target's and leaves
that to `Programmed` (#380). The same holds for any integration whose `Result` doesn't set
`Responses`: Traefik's and HAProxy's. Envoy Gateway's and, since 0.5.0, both Istio integrations'
do (#374): Istio's `EnvoyFilter` gives a route whose policies inspect responses
`response_header_mode: SEND` and `response_body_mode: BUFFERED_PARTIAL` (`STREAMED` in detect
mode), with `allow_mode_override`, as Envoy Gateway's `EnvoyExtensionPolicy`, and raises the
listeners' buffer limit for them; other routes keep `SKIP`. VirtualServices, always Istio's, get
no warning.

**Latency and memory.** A route that inspects responses adds one evaluation per response
(phases 3 and 4; the CRS response rules are a few dozen, mostly `@pmFromFile` and `@rx` on the
body) and, in Block mode, Envoy holds the response until the engine answers: time to first byte
grows by the body's buffering and its evaluation. `BenchmarkEvaluateExchange` (a request and its
response) against `BenchmarkEvaluate/benign_get` (the request alone), on one loaded 12-thread
machine (2026-11-03): headers only (204) about 1× (noise), an 8 KB JSON body 5.5×, a 15 KB HTML page 8.5×, a
256 KB one 160× (220 ms there; the request alone took 1.4 ms). The cost grows with the body:
0.85 ms per KiB of HTML there, roughly 0.3 ms on an unloaded machine (scaled by
[0001](0001-performance-first-architecture.md#31-measured-baseline-2026-10-03)'s 0.5 ms request
baseline). So the default limit is 64 KiB, as for
request bodies, not Coraza's 512 KiB, which would take most of the default 250 ms deadline: a
policy that raises `maxBytes` should raise `timeout` with it, or large responses get the failure
mode (503 in Block mode). A body the rules don't read (an image) costs what headers do. Memory per in-flight request on such a route is
the kept Coraza transaction (with its request body buffer, up to `body.maxBytes`) plus the
response prefix (up to `responses.maxBytes`), in the engine, and Envoy's buffered response. The
evaluation holds an admission slot only while it runs, not while the upstream answers. Response
verdicts are counted apart: `inkwall_responses_total{action,reason}` and
`inkwall_response_check_duration_seconds`.

**Measured under load (#344).** Same 12-thread i7-1255U, 2026-11-04, shared with other jobs:

- **Through Envoy Gateway** (`make kind-response-load`): one Envoy pod with the engine, one
  `WAFPolicy` in Block mode on an HTTPRoute to nginx, 8 closed-loop clients for 20 s per run
  (`hack/loadgen`, from the host to the Envoy Service's NodePort), every response a 200. Envoy,
  the engine, nginx and the clients share the machine, so the throughput is the machine's, not a
  claim; the comparison is the point.

| Page (text/html) | `responses.inspect` | Requests/s | p50 | p99 | Engine response check (mean) | Engine peak RSS |
|---|---|---|---|---|---|---|
| 0.85 KB | off | 5,249 | 1.4 ms | 3.1 ms | none | 99 MiB |
| 0.85 KB | on | 2,591 | 3.0 ms | 5.7 ms | 0.86 ms | 104 MiB |
| 15.3 KB | off | 4,218 | 1.8 ms | 3.8 ms | none | 101 MiB |
| 15.3 KB | on | 527 | 16.5 ms | 21.3 ms | 13.0 ms | 107 MiB |

  The response check of the 15.3 KB page, 13 ms (from `inkwall_response_check_duration_seconds`),
  is 0.85 ms per KiB, as `BenchmarkEvaluateExchange` measured on this machine; p50 grows by about
  as much, and p99 stays within 5 ms of p50. Each check holds an admission slot, so a route of
  large HTML pages with responses inspected is CPU-bound in the engine: throughput fell 8× here
  with 8 clients. The engine's memory grows by about 6 MiB. Every budget holds: at the default
  64 KiB, a check is about 55 ms on this machine, within the default 250 ms deadline.
- **At scale** (`make scale-test SCALE=full SCALE_RESPONSES=1`, [0004 §8](0004-operator.md#8-scale-targets-v1)):
  every other policy inspecting responses (2,500 of 5,000) changes neither the time from a change
  to every engine nor the operator's peak RSS, at any size; the bundle grows by 2 KiB compressed.
  Compiled once as an engine does, the 5,000-policy bundle takes 0.08–0.09 s and 10–26 MiB of live
  heap (measured when response inspection compiled a rule set of its own; since #353, policies
  share one whatever their response settings), and a leaked SQL error through one of its policies is flagged in 0.3–0.6 ms.

**Flags.** Without the operator, `inkwall-engine ext-proc` takes `--inspect-responses`,
`--max-response-bytes` (64 KiB by default) and `--oversize-response` (`auto`, `allow`, `deny`), the
policy's `responses` fields. Only `ext-proc` defines them: the other adapters never see a response,
so none can be told to inspect one. With `--operator` they are refused, as the other policy flags.

**Built (engine):** the bundle field, the Coraza response phases, the pipeline's `Exchange`
(`CheckExchange`, `CheckResponse`), decoding, events and metrics, the ext_proc response stages
(with `FuzzExtProcResponse`), and the flags, so raw Envoy can inspect responses with the policy
from flags (`make raw-envoy-e2e` checks a leaked SQL error is replaced in block mode and logged in
detect mode). **Built (operator):** the CRD field and its validation, the bundle field from it,
Envoy Gateway's response processing mode and buffer limit, `ResponsesNotInspected` for the
other proxies, the webhook's warning; envtest, and the kind e2e through Envoy Gateway (a leaked
SQL error replaced in Block mode, logged in Detect mode, and the policy not `Programmed` for its
Traefik Ingress). **Not yet:** streamed responses (Server-Sent Events, gRPC streams) inspected
per chunk or message; responses through Traefik; the reverse proxy adapter's responses.

## 3. forward-auth (Traefik `ForwardAuth`, nginx `auth_request`)

- The proxy sends an HTTP subrequest with the client's headers to `/v1/forward-auth`. The original
  request's method, URI, host, scheme and port come in `X-Forwarded-Method`, `-Uri`, `-Host`,
  `-Proto` and `-Port`. The adapter rebuilds the request from them, and strips them before
  inspection.
- **Allow:** the adapter answers **200** with `X-Request-Id`.
- **Deny:** it answers with the verdict's status (403, 413, 503, ...), which the proxy returns to
  the client. A gRPC call gets its gRPC status in the headers too
  ([§7](#7-denying-grpc-calls)).
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

Traefik asks before it upgrades a WebSocket handshake, so a denial reaches the client instead of a
`101`. It drops the hop-by-hop `Upgrade` and `Connection` headers from the subrequest: the engine
tells a handshake by `Sec-WebSocket-Key` or `Sec-WebSocket-Version` too (#276). It never sees the
messages after the upgrade.

## 4. SPOE (HAProxy Stream Processing Offload Engine)

Decided for v0.4.0 ([#282](https://github.com/inkwall-dev/inkwall/issues/282)); the configuration is in [protecting HAProxy](../haproxy.md).

- [HAProxy](https://docs.haproxy.org/) speaks its binary protocol, SPOP 2.0 (HAProxy 3.1 or later, through a `mode spop`
  backend), over a few connections, TCP or a Unix socket. The engine is the agent (an SPOA):
  `inkwall-engine spoe`, on `127.0.0.1:9004` by default. Our own implementation, from HAProxy's
  `doc/SPOE.txt`; no agent library is vendored.
- **Frames.** Each connection starts with a HELLO handshake: the version (2.0), the maximum frame
  size (HAProxy's, at most the engine's body limit plus 1 MiB for the rest), and `pipelining`
  when HAProxy offers it. A HELLO marked `healthcheck` (`option spop-check`) is answered, and the
  connection closed. HAProxy then sends a **NOTIFY** frame per request; the engine answers each
  with an **ACK** of `set-var` actions, in any order with pipelining (at most 256 in flight per
  connection). Fragmented frames are refused (SPOP 2.0 has none), aborted ones skipped.
  **DISCONNECT** frames end a connection, with a status code; on shutdown the engine answers the
  NOTIFY frames in flight, then sends one.
- **The message** is `inkwall-request`, with the arguments `method` (`method`), `path` (`pathq`:
  path and query, the origin form even for HTTP/2), `version` (`req.ver`), `headers`
  (`req.hdrs_bin`), `body` (`req.body`), `ip` (`src`) and `https` (`ssl_fc`).
- **The verdict:** `txn.inkwall.action` is `allow` or `deny`, `txn.inkwall.status` the status
  to deny with (400, 403, 413, 503), `txn.inkwall.request_id` the request ID, which HAProxy sets
  as `X-Request-Id`. A denied gRPC call also gets `grpc_status`, `grpc_message` and
  `grpc_content_type` ([§7](#7-denying-grpc-calls)). The engine sets `action` on every answer, so an
  unset `action` means HAProxy got none. `deny_status` takes a fixed status, hence a rule per
  status the engine denies with.
- **Failure mode:** on a timeout (`timeout processing`), an agent that is down or an error,
  HAProxy sets no variable and goes on. Failing closed therefore needs a rule that denies with 503
  when `action` is unset, first among the rules; failing open leaves it out. The documented
  configuration fails closed, as the engine does in block mode by default. `option spop-check`
  marks a stopped engine down within a second, so requests aren't held for `timeout processing`.
  The engine's own failures (its `--timeout`, overload) are decided by its failure mode, so
  `timeout processing` is the engine's deadline plus 500 ms, as Envoy's `message_timeout`.
- A NOTIFY without `inkwall-request`, or with arguments the engine can't read (a method that
  isn't a token, a path not in origin form, an invalid Host, headers that don't parse, both
  `Transfer-Encoding` and `Content-Length`) gets `deny` with 400: only a misconfigured HAProxy
  sends one.
- **The body:** HAProxy sends it only with `option http-buffer-request`, and buffers at most
  `tune.bufsize` less `tune.maxrewrite` (16384 − 1024 bytes by default): a larger body is cut. A
  body shorter than its `Content-Length` counts as oversized, so the policy's `body.onOversize`
  decides (413 in block mode by default): raise `tune.bufsize` above the policy's body limit to
  inspect larger bodies. A body without `Content-Length` (chunked, or HTTP/2) can't say whether
  it was cut, so it counts as complete only when its frame is well under half the maximum frame
  size: `tune.maxrewrite` is at most half the buffer, so HAProxy's buffer holds at least that much
  before it is full. Under the defaults that is about 7 KB, headers included; larger chunked
  bodies count as oversized.
- **WebSocket:** HAProxy asks before it upgrades, with the `Upgrade` header, so the policy's
  WebSocket rules apply to the handshake as they are.
- The client address is `src`, HAProxy's client (from the [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) when HAProxy accepts it),
  resolved with `X-Forwarded-For` through `--trusted-proxies`.
- Detect mode answers `allow`; HAProxy still waits for the answer (SPOP 2.0 has no asynchronous
  mode any more).
- **The operator's probe** (bundle mode, [0002 §6.4](0002-system-architecture.md#64-haproxy-haproxy-kubernetes-ingress-controller-haproxy-ingress)): a request whose
  `X-Inkwall-Probe` header is `<nonce>.<MAC>`, the MAC an HMAC-SHA256 of the nonce, host and URI
  under the bundle's `probe_key`, is answered without inspection: `action=deny` (403) and the
  variable `probe`, another HMAC of them under the key, which the operator's per-route rules
  return with status 299 (`pkg/haproxyprobe`). Without a key, or with a wrong MAC, the request is
  inspected as any other.
- Routes are left uninspected with a condition on the message's `event`; the fail-closed rule
  must leave them out too.

### Responses through SPOE (design, #370)

Proposed, not built: how a policy's `responses` would be inspected through HAProxy, with the same
rules and budgets as through ext_proc ([§2](#response-inspection-v040)). Until it is built, a
policy with `responses.inspect` on an HAProxy route is `ResponsesNotInspected`.

- **The message.** A second SPOE message, `inkwall-response`, on the `on-http-response` event of
  the same SPOE scope: `status` (`status`), `headers` (`res.hdrs_bin`), `body` (`res.body`), and
  `request_id` (`var(txn.inkwall.request_id)`, which the request's answer set). HAProxy sends the
  body only after `http-response wait-for-body time <t> at-least <bytes>` (HAProxy 2.4 or later;
  we need 3.1 for SPOP 2.0 already), and at most what its buffer holds (`tune.bufsize` less
  `tune.maxrewrite`, as for requests, #336): a body cut there is oversized, so the policy's
  `responses.onOversize` decides, as a prefix through ext_proc. The route's rules send the message
  only when the request's answer said its policy inspects responses (`txn.inkwall.responses`),
  so other routes add nothing to their responses.
- **Tying the response to its request.** The request and its response are separate NOTIFY frames,
  possibly on different SPOP connections, so the engine keeps each request's open Coraza
  transaction (or, cheaper, the variables the response rules read: anomaly scores, paranoia
  level, the user's `tx` variables) keyed by request ID, in a table bounded by count and memory
  (by default 10,000 entries or 64 MiB) with a TTL of the route's timeout plus HAProxy's response
  timeout. An entry goes with its response, or at its TTL. A response whose request isn't there
  (evicted, an engine restart in between, another engine of a scaled-out agent pool) is a miss:
  in Block mode it gets the policy's failure mode for responses (by default fail closed: replaced
  with 502, as an uninspectable response through ext_proc); in Detect mode it passes, logged.
- **The verdict.** `txn.inkwall.response_action` (`allow` or `deny`) and `response_status`.
  Block mode replaces a response that leaks with `http-response return status 403` (`502` for
  oversized or uninspectable when the policy says Deny), with the engine's plain-text body and
  the request ID; Detect mode only logs. An unset `response_action` (the agent timed out or is
  down) follows the failure mode: a rule returns 502 first when it fails closed.
- **Costs.** One more SPOP round trip per inspected response (HAProxy waits for it: SPOP 2.0 is
  synchronous), the same evaluation cost as through ext_proc (about 0.3 ms per KiB of HTML,
  `BenchmarkEvaluateExchange`), and the table: a kept transaction is a few KiB, so 10,000
  responses in flight cost tens of MiB. Requests whose policies don't inspect responses keep
  nothing.
- **The operator** adds to the backend snippet, for the Ingresses whose policies inspect
  responses: the message's group, `http-response wait-for-body`, and the `http-response` rules
  above; and reports `Result.Responses` for HAProxy only when the controller's HAProxy is 3.1 or
  later (it is, for the controller versions it wires). The probe ([above](#4-spoe-haproxy-stream-processing-offload-engine)) covers the
  request filter only; a response probe (the engine answering a probe's response) would prove the
  response rules, as a follow-up.

**Open questions:**

1. Keep the Coraza transaction (exact, as ext_proc; memory per request) or only the variables
   (cheaper; the response rules lose request variables nothing else copies)?
2. The failure mode on a miss: a policy setting of its own, or the request's failure mode?
3. A scaled-out agent (several engine processes behind one HAProxy `mode spop` backend) sends the
   response to any of them: sticky balancing on the request ID (`balance hdr`-like for SPOP) or a
   shared table?
4. `wait-for-body` holds the whole response up to the buffer: should streamed responses (SSE,
   gRPC) skip the body by content type in HAProxy's rules, as the engine skips them through
   ext_proc?

`make haproxy-e2e` runs the configuration of [protecting HAProxy](../haproxy.md) with HAProxy 3.2 in
Docker. **Built:** `pkg/adapters/spoe`, run as `inkwall-engine spoe`, and since 0.4.0 the operator's
wiring of the HAProxy Kubernetes Ingress Controller ([0002 §6.4](0002-system-architecture.md#64-haproxy-haproxy-kubernetes-ingress-controller-haproxy-ingress)).

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
`CheckRequest` has no response: the API serves proxies, which ask before forwarding. The response
cases of `inkwallctl test --suite` (#385) are inspected in-process instead, by
`Handler.CheckExchange`, with the policy's exchange as ext_proc keeps it; so they need no API
change, and `--engine` can't run them.
**Not yet:** the gRPC `CheckService/Check` (defined in `api/engine/v1`, not served) and the
Traefik plugin.

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

**WebSocket messages** (#276): with `--websocket-messages`, the proxy wraps the connection Go's
reverse proxy hijacks for an upgrade, so what it copies to the upstream is only what was inspected
(`pkg/websocket` reads the frames; fuzzed). It removes `Sec-WebSocket-Extensions` from the handshake,
so no `permessage-deflate`. In block mode a text message is held until whole (fragments put
together, control frames passed at once) and inspected (`ARGS_POST`: JSON values by path, other
text as `message`); a denied one closes with 1008, a masked close frame to the upstream and, at the
next boundary between the upstream's frames, an unmasked one to the client. Past `--max-body-bytes`
a message is an oversized body (1009 under `deny`). Detect mode forwards at once and inspects a
copy. Only this adapter sees messages: ext_proc can't, for a compliant client
([0002 §6](0002-system-architecture.md#6-proxy-integrations), #313).

A denied gRPC call is answered as a gRPC server does ([§7](#7-denying-grpc-calls)).

"Standalone" in this heading means the engine runs on its own, without an ingress proxy. It is not
the cluster's [Standalone mode](../glossary.md#standalone) (no control plane).

---

## 7. Denying gRPC calls

A gRPC client reads the outcome of a call from its `grpc-status`, not from the HTTP status. Given
an HTTP error, it makes a status up from the HTTP one ([gRPC's mapping](https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md):
403 is `PERMISSION_DENIED`) and a message such as `unexpected HTTP status code received from
server: 403 (Forbidden)`. So a denial of a request whose one `Content-Type` is gRPC
(`application/grpc`, `application/grpc-web` or `application/grpc-web-text`, with any `+codec`
suffix, whatever the body) is answered in the gRPC [trailers-only](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#responses)
form (decided for v0.4.0, [#275](https://github.com/inkwall-dev/inkwall/issues/275)):

- **Headers, no body:** `content-type` of the request's variant, without codec
  (`application/grpc`, `application/grpc-web`, `application/grpc-web-text`); `grpc-status`;
  `grpc-message`; `x-request-id`.
- **`grpc-status`** from the verdict's HTTP status by gRPC's mapping, so a client sees the same
  code whether it reads our status or makes one up from the HTTP one: 403 `PERMISSION_DENIED` (7),
  503 `UNAVAILABLE` (14), 400 `INTERNAL` (13), and 413 `RESOURCE_EXHAUSTED` (8), which the mapping
  leaves `UNKNOWN`.
- **`grpc-message`:** the status text and the request ID, percent-encoded as the spec says:
  `Forbidden (request ID 0123abcd)`. gRPC clients usually log the message, and the request ID
  finds the security event.
- **HTTP status**, by adapter:
  - **Reverse proxy:** 200, as a gRPC server.
  - **ext_proc, gRPC:** the verdict's (403). Envoy answers a local reply to a gRPC request
    itself as gRPC: HTTP 200, `grpc-status` (ours, or the `grpc_status` field), and the body, if
    any, as `grpc-message`, which is why there is no body. A client Envoy doesn't take for gRPC
    (over HTTP/1.1) gets the 403 with the gRPC headers.
  - **ext_proc, gRPC-Web:** 200. Envoy doesn't take gRPC-Web for gRPC, and passes the answer as
    it is; the [gRPC-Web spec](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md)
    keeps trailers-only responses.
  - **SPOE:** 200. The engine answers with variables, and HAProxy's `http-request return`
    answers the call with them ([protecting HAProxy](../haproxy.md#grpc)); HAProxy can't set a
    `content-type` on a reply without a body, so an `http-after-response` rule sets it.
  - **forward-auth:** the verdict's (403): Traefik denies only on a non-2xx answer, and copies
    its headers to the client. gRPC clients that take a gRPC `content-type` for a gRPC answer
    (grpc-go does) read our status and message; others make up the same code from the 403.
- Envoy's access log and metrics count a denied gRPC call as HTTP 200, as for any gRPC error;
  the engine's security event and `inkwall_requests_total` count it as a denial.
- The `x-content-type-options: nosniff` header is kept; anything else, including detect mode,
  is unchanged.

The messages themselves aren't read yet ([gRPC](../grpc.md)).

---

## 8. Comparison

| | Transport | Body | Response | Proxy waits? | For | Status |
|---|---|---|---|---|---|---|
| ext_authz | gRPC call | Buffered, optional | No | Yes | Envoy fallback | Not yet |
| ext_proc | gRPC stream | Buffered (streamed in observability mode) | Yes (policies with `responses`) | Yes, or no (observability mode) | Envoy Gateway, Envoy, Istio, Contour | Built (Envoy Gateway, Istio, raw Envoy) |
| forward-auth | HTTP subrequest | If forwarded | No | Yes | Traefik (nginx `auth_request` speaks it too) | Built |
| SPOE | SPOP | Buffered, up to HAProxy's buffer | Designed, not built ([§4](#responses-through-spoe-design-370)) | Yes | HAProxy | Built (by hand or by the operator: [protecting HAProxy](../haproxy.md)) |
| `/v1/check` | HTTP (gRPC planned) | Yes | No | Yes | CLI, tests; a Traefik plugin planned | Built |
| Reverse proxy | HTTP proxying | Yes | Yes | It is the path | VMs, test reference | Built |

[Caddy](https://caddyserver.com/docs/) needs no protocol: the planned module compiles the engine into Caddy
([0002 §6.5](0002-system-architecture.md#65-caddy)).
