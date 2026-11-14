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
reports to the operator with its heartbeats, and inspects the request as any other (0002 §6.1,
proof by receipt). The operator probes
each gateway pod for Istio's routes before `Programmed` (#372).

### gRPC request streams, message by message (v0.6.0, #315)

With `body.grpcMessages: Inspect`, Envoy holds a gRPC call (`BUFFERED_PARTIAL`) until the client
ends its side or the body fills `body.maxBytes`. A client stream longer than that is cut (an
oversized body), and a bidirectional call whose client waits for the server never ends its side,
so it stalls in Block mode. So a policy can have each message inspected as it arrives.

**Decision: opt-in, a new field.** `spec.body.grpcStreams: PerMessage` (default `Buffer`, today's
behaviour; it needs `grpcMessages: Inspect` and body inspection, which a CEL rule checks), bundle
`BodyConfig.grpc_per_message`, the engine's `--grpc-streams per-message` (ext-proc only). Not on
by default for policies that already inspect messages, because it changes what they get: with
`Buffer` a call with an attack in its third message is denied before the application sees any of
it; per message, the first two have already been forwarded when the third is denied. An
application that acts on each message as it comes (writes a row) sees part of a call that then
fails. That trade is the user's to make, per policy. An engine before 0.6.0 ignores the field and
buffers, so such a policy is `Enforced=False` (`EnginesOutdated`) while one runs it.

**How (ext_proc).** A `POST` whose one `Content-Type` is `application/grpc` or
`application/grpc+proto`, on a policy with `PerMessage` and a route inspected with its body, is
decided on its headers (`Exchange` kept for its response as any request). The allow carries
`mode_override` with `request_body_mode: STREAMED`, so Envoy forwards the headers at once and
streams the body to the engine. `mode_override` replaces the whole processing mode for the rest
of the stream, so it also sets the response's stages as this request's policy needs them: sent
(with the route's body mode, from `protocol_config`) when it inspects responses, off otherwise.
The body goes through `pkg/streams`' gRPC splitter (#323's, fuzzed; its events now carry the text
fields by name, so exclusions name a field as for a buffered body, and say when the stream isn't
gRPC framing). Each message is checked by `Pipeline.CheckGRPCMessage`: a fresh evaluation of a
clean `POST` with the call's identity, path and content type, but not its query or other headers
(inspected with the call; run again, they would add the call's score to every message), whose
form arguments are the message's text fields. Each chunk is answered with a body mutation that
lets through only the complete, allowed messages before it; the message in progress is held. A
denied message gets an immediate response: before the upstream answered, Envoy sends it as the
call's trailers-only gRPC status (7, or 8 for an oversized message); after, Envoy, the response
headers already out, resets the stream. Either way the denied message and everything after it
never reach the upstream. Detect mode forwards each chunk unchanged and logs; in observability
mode Envoy streams the body anyway, and each message is inspected as it comes. gRPC-Web stays
buffered: browsers don't stream requests, and its text form is base64.

**Bounds.** Per message: the policy's `body.maxBytes` (a longer message is cut there and gets
`onOversize`, and the rest of it isn't held), so the engine holds at most `maxBytes` and a 5-byte
prefix per call, gzip messages decoded up to `maxBytes`. Per call: nothing more, deliberately. A
message count or byte cap per call would cut the long and never-ending streams this exists for.
What bounds a stream's CPU is what bounds requests: each message is one evaluation under the
engine's admission control (`--max-concurrent`, shared by every policy) and the policy's
`timeout`, so a slow drip costs nothing between messages, and a flood of tiny messages is shed
with the failure mode once every slot is busy, as a flood of requests is (fail closed: the call
ends with `UNAVAILABLE`), without queueing work (`TestGRPCMessagesShedUnderOverload`). A stream
can't take more of the engine than as many requests would; a client that wants to load it can
already send requests. Envoy's `message_timeout` applies to each ext_proc message, here each
chunk, so a long call isn't timed as a whole.

**A body that isn't gRPC.** A request that claims to be gRPC but whose body doesn't start with a
message prefix is inspected in full when buffered ([gRPC](../grpc.md#if-you-serve-no-grpc)). Per message, the
engine has already forwarded the headers when it sees that, and has no body to inspect as a form:
it denies the call (reason `grpc`, 403/`PERMISSION_DENIED`) in Block mode, whatever `onOversize`
says, since under `Allow` the body would otherwise pass uninspected.

**Wiring.** `mode_override` needs the filter's `allow_mode_override`. The operator sets it on a
route when one of its policies is `PerMessage`, through Envoy Gateway (`allowModeOverride`) and
Istio (both integrations); the configured body mode stays `BufferedPartial` for the route's other
requests. The override is per request, so a route serving gRPC and other traffic needs no policy
of its own. Traefik, HAProxy and the standalone proxy buffer the body before asking the engine: a
`PerMessage` policy is inspected there as `Buffer` (its messages are still inspected, so its status
claims nothing that isn't), and the guide says long streams stall there. Raw Envoy: the flag, and
`allow_mode_override: true` in the filter.

**Verified on raw Envoy** (`make raw-envoy-e2e`, with `hack/grpcecho`, a gRPC server without a
`.proto`): a client stream whose third message carries an attack is denied with
`PERMISSION_DENIED` after the first two reach the server, a bidirectional call (each client
message waits for the server's echo) passes in Block mode, and its attack in a later message is
denied. Envoy v1.39's deadlock for upgraded connections in `STREAMED` mode (#276) doesn't apply: a
gRPC client sends its headers and first message without waiting for the server.

**Built:** the field (CRD, bundle, flag), `Pipeline.GRPCStream` and `CheckGRPCMessage`, the
ext_proc request stream (sharing #323's per-event state with responses), `FuzzExtProcGRPCStream`
(whatever the chunking, only whole, allowed messages are let through, the body's own prefix),
`EnginesOutdated` for engines before 0.6.0, `allowModeOverride` in the Envoy Gateway and Istio
wiring, and the raw-envoy e2e above.

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
`Responses`: Traefik's, and HAProxy's while a controller pod's engine lacks `--response-messages`
([§4](#responses-through-spoe-370), #470; its `ResponsesWhy` then names the pods). Envoy Gateway's,
since 0.5.0 both Istio integrations', and since 0.6.0 HAProxy's do (#374): Istio's `EnvoyFilter` gives a route whose policies inspect responses
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
policy's `responses` fields. Only `ext-proc` and, since 0.6.0, `spoe` ([§4](#responses-through-spoe-370))
define them: the other adapters never see a response, so none can be told to inspect one. With `--operator` they are refused, as the other policy flags.

**Built (engine):** the bundle field, the Coraza response phases, the pipeline's `Exchange`
(`CheckExchange`, `CheckResponse`), decoding, events and metrics, the ext_proc response stages
(with `FuzzExtProcResponse`), and the flags, so raw Envoy can inspect responses with the policy
from flags (`make raw-envoy-e2e` checks a leaked SQL error is replaced in block mode and logged in
detect mode). **Built (operator):** the CRD field and its validation, the bundle field from it,
Envoy Gateway's response processing mode and buffer limit, `ResponsesNotInspected` for the
other proxies, the webhook's warning; envtest, and the kind e2e through Envoy Gateway (a leaked
SQL error replaced in Block mode, logged in Detect mode, and the policy not `Programmed` for its
Traefik Ingress). **Not yet:** see the next section.

### Streamed responses, the reverse proxy and Traefik (design, #323)

What is left of #274's scope, decided for v0.6.0. The response API above doesn't change, except for
one opt-in field for streams.

**The reverse proxy (`inkwall-engine proxy`).** It sees every response, so it inspects them as
ext_proc does, with the same `Exchange` and the same flags (`--inspect-responses`,
`--max-response-bytes`, `--oversize-response`; or the policy's `responses` in bundle mode). Go's
`ReverseProxy.ModifyResponse` runs before a byte is written to the client. There the proxy reads up
to `maxBytes` of a body the rules read (the `WantsBody` types, `gzip`/`deflate` decoded as for
ext_proc), evaluates it, and then:

- forwards the response, with the prefix it read put back in front of the rest of the body;
- or, in Block mode, replaces it with the denial (the rule's status, or 502 for `onOversize: Deny`).

The proxy removes `Accept-Encoding` on routes whose response bodies it inspects. A body the rules
don't read passes as it streams, without being held. This makes the proxy the reference for
responses too ([0002 §10](0002-system-architecture.md#10-testing-architecture)): the CRS suite's
response cases run through it and through ext_proc with the same verdicts. The response parser is
the pipeline's and is already fuzzed; a new `FuzzProxyResponse` fuzzes the proxy's own
read-and-replay path (cut bodies, lying `Content-Length`, encodings).

**Streamed responses** (Server-Sent Events, `text/event-stream`, and gRPC server streams,
`application/grpc*`). Holding a stream's body until `maxBytes` would stall it, possibly forever: an
SSE stream may never end. So streams aren't buffered. Each **event** (SSE: the lines up to a blank
line) or **message** (gRPC: one length-prefixed frame) is inspected on its own, as WebSocket messages
are (`CheckWebSocketMessage`). Each is evaluated as a response whose body is the event's `data` or
the message's text (the same text extraction as `grpcMessages` for requests), with the stream's
status and headers. It gets a fresh transaction, carrying the request's identity (request ID,
client IP, host, path) for exclusions and events but not the request's rules. A Coraza transaction
runs phase 4 once, and re-running the request's rules for each event would add its score to every
one.

Events and messages are cut at `maxBytes`, as a WebSocket message is: a cut one is oversized.
Holding an event while it is inspected delays only that event. Block mode holds each event until
it is decided, as the reverse proxy holds a WebSocket message. Detect mode forwards at once and
inspects a copy.

A denied event can't be answered with a status: the stream's headers, and maybe earlier events,
are already out. Block mode therefore **ends the stream** at that event, which the client never
gets: ext_proc answers it with an immediate response, which makes Envoy reset the stream (a gRPC
client sees `INTERNAL`/`CANCELLED`, an SSE client a dropped connection), and the proxy closes it.
The event (`phase: response`, with the event's or message's index) says why.

Through ext_proc, the engine switches such a response to `response_body_mode: STREAMED` with the
`mode_override` it already sends for bodies it doesn't read. That needs `allow_mode_override`,
which every route that inspects responses already gets, so the operator's wiring doesn't change.
Each `STREAMED` chunk is answered at once, unless it completes an event that Block mode holds.

**Decision: off by default.** Every event costs an evaluation; a token-by-token LLM stream is
hundreds of them. A binary gRPC message has the false positives of `grpcMessages`
([0002](0002-system-architecture.md)). So streams stay uninspected, as today, unless a policy asks
for it: `WAFPolicy.spec.responses.streams: Inspect` (default `Skip`; bundle
`ResponseConfig.streams`; the engine's `--response-streams`). An engine before 0.6.0 ignores the
field, so such a policy is `Enforced=False` (`EnginesOutdated`), as for the other fields. The SSE
parser is new and gets a fuzz target (`FuzzSSEEvents`); the gRPC framing is the request side's,
already fuzzed.

**Traefik: nothing built in; `ResponsesNotInspected` stays.** ForwardAuth asks before the request
is forwarded and never sees the response. The other options, and why not:

- **A Traefik Yaegi plugin calling the engine.** Traefik must download it from GitHub (the plugin
  catalog) or load it from a local directory the operator would have to mount into Traefik's pods.
  That means patching a Deployment the user's Helm owns, which 0004 §4.3 rules out. It also runs
  interpreted, and every response would be copied through it.
- **A WebAssembly plugin** (Traefik 3's `http-wasm`). It sees the response, but it can't open a
  connection. It would have to run its own Coraza inside Traefik, apart from the bundle and the
  engine's events: a second engine to keep equal.
- **The engine's reverse proxy in front of the app.** That changes the app's Service or pods, which
  the operator doesn't own.

A policy with `responses.inspect` on a Traefik route therefore stays `Programmed=False`
(`ResponsesNotInspected`), as since 0.4.0, and the Traefik guide says so. A user who needs
responses inspected behind Traefik routes the app through Envoy Gateway or Istio, or puts the
standalone reverse proxy (above) in front of the app themselves. Its responses are then inspected,
but with the policy from flags, outside the operator's status. A future Traefik release with a
response hook in ForwardAuth would change this.

**Order:** the reverse proxy's responses (engine), then streams (engine: ext_proc and the proxy,
with the flag and the bundle field), then the operator's `responses.streams` field with its
`EnginesOutdated` requirement and the Envoy Gateway and Istio kind e2e sections.

**Built (engine, ext_proc):** `pkg/streams` splits SSE and gRPC streams as they come (`Pending`
is what block mode holds, at most the limit and a few bytes; `FuzzSSEEvents` checks that any
chunking gives the same events), `Exchange.CheckEvent` inspects an event, the ext_proc adapter
switches such responses to `STREAMED` and answers each chunk with a body mutation that lets
through only complete, allowed events, `--response-streams` and the bundle's
`ResponseConfig.streams`. A gRPC call's exchange is now kept when its policy inspects streams.
The security event carries
`stream_event`. `make raw-envoy-e2e` checks a leaking SSE event never reaches the client.
**Built (operator):** `WAFPolicy.spec.responses.streams` (`Inspect` or `Skip`, the default; it
needs `inspect: true`), the bundle field from it, `Enforced=False` (`EnginesOutdated`) while an
engine before 0.6.0 runs the policy, and the Envoy Gateway and Istio kind e2e sections (a leaking
SSE event ends the stream through both Gateways, the events before it pass). Since the HAProxy
Ingress Controller sends responses too (#470), an integration reports whether it sends streamed
bodies (`Result.Streams`): HAProxy doesn't (§4: SPOE never holds them), so a policy with `streams:
Inspect` is `Programmed=False` (`ResponsesNotInspected`) on its Ingresses, as Traefik's routes are
for `responses`, rather than `Ready` while the events pass uninspected. **Built (the
reverse proxy):** a `streamBody` wraps the response's body: it splits it as it is read, inspects
each event, and gives out only bytes up to the end of the last allowed event (`Event.End`, the
offset the splitter reports), so the events before a denied one go out even when they came in the
same read; the denied one ends the copy with an error, which aborts the response. A stream holds
one event's limit of `--max-held-response-bytes` while open; past it, a new one gets the failure
mode. Through ext_proc, a chunk's answer is either its body or a reset, so events that share a
chunk with a denied one are dropped with it.

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
- **One frame per message.** HAProxy sends a message in one SPOE frame, of at most
  `tune.bufsize` − 4 bytes, or the engine's `max-frame-size` (its body limit plus 1 MiB) when that
  is lower. A message that doesn't fit, with its headers and other arguments, isn't cut: HAProxy
  sends none of it, sets `txn.inkwall.error` (`option set-on-error`) to 3 when encoding it fails
  against its own `max-frame-size`, or to 259 (0x100 + 3, from the SPOP connection) when it is over
  the size the engine announced, and gives no verdict.
  The documented configuration and, for `Block`-mode policies, the operator's snippet handle it as
  oversized, before the fail-closed rule: 413 for a request, 502 for a response (`txn.inkwall.error`
  3 or 259 and `txn.inkwall.responses` set). Detect mode leaves it out: it never blocks.
- **Bodies over HAProxy's buffer, decided (#336).** The engine sees at most HAProxy's buffer, and
  the rest is handled as oversized; we keep that limit, say it on the status and make it exact,
  rather than raise it:
  - *SPOP fragmentation* would send a larger body in several frames, but HAProxy 3.1 removed it
    (`doc/SPOE.txt` §3.2: the FIN flag on every frame; `option send-frag-payload` ignored), and
    SPOP 2.0 needs 3.1. HAProxy 3.4's large buffers (`tune.bufsize.large`, `wait-for-body
    use-large-buffer`) don't help: SPOE's `max-frame-size` stays at most `tune.bufsize` − 4, so a
    body in a large buffer would be a message over one frame.
  - *The operator raising `tune.bufsize`* in the controller's ConfigMap: rejected. The setting is
    global (every route and connection of the controller), the ConfigMap is the user's (the chart's
    `controller.config`, often owned by Helm or GitOps, which would revert it), and
    `global-config-snippet` is one string the operator can't own a part of. The operator would also
    need write access to ConfigMaps. Instead `Programmed`'s message names the buffer when a
    policy's `body.maxBytes`, or `responses.maxBytes` for a policy that inspects responses, is
    larger than it (#345), with the snippet to raise it.
  - *The cost of raising it*, measured with HAProxy 3.2.26 (200 connections, each with a request
    whose body fills the buffer held in inspection: about three buffers, the request channel's,
    the SPOE context's and the SPOP connection's): about 56 KiB per request at 16384, 190 KiB at
    81920, 628 KiB at 262144 and 2.4 MiB at 1 MiB. Idle and keep-alive connections hold no buffer
    (under 1 KiB at any size): HAProxy takes buffers from a pool only while data is in flight. So
    1,000 requests in inspection at once take about 55 MB at the default and 185 MB at 81920. The
    user sizes it ([protecting HAProxy](../haproxy.md#bodies) has the table).
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

### Responses through SPOE (#370)

Designed in #370; built for 0.6.0 in the engine (#469) and the operator (#470). A policy's
`responses` are inspected through HAProxy with the same rules and budgets as through ext_proc
([§2](#response-inspection-v040)) when HAProxy is configured to send them: by hand
([protecting HAProxy](../haproxy.md#responses)), or by the operator for the HAProxy Kubernetes
Ingress Controller (below).

- **Turning it on.** The agent keeps nothing for responses unless told HAProxy sends them:
  standalone, `--inspect-responses` (which also defines the policy's `responses`); in bundle mode,
  `--response-messages`, which the operator passes to the controller's pods. Without it, a bundle's
  policy with `responses.inspect` keeps nothing on HAProxy's routes, so states the configuration
  never asks for can't fill the table. The request message's optional argument `responses`
  (a boolean) narrows it per backend: `false` keeps nothing, so a backend without the response
  rules can't fill the table either.
- **The request's answer.** For a request let through whose policy inspects responses, the answer
  also sets `txn.inkwall.responses`, a 128-bit random key the engine keeps the request's inspection
  under, and `txn.inkwall.response_failure`, `closed` or `open`: the policy's failure mode,
  resolved for its mode. The key is not the request ID: a client may send its own `X-Request-Id`,
  and two requests with one ID would swap their inspections, and so their policies.
- **The message.** `inkwall-response`, in an SPOE group of the same name, which `http-response
  send-spoe-group` sends after `http-response wait-for-body` (HAProxy 2.4 or later; SPOP 2.0 needs
  3.1 already): a group rather than the `on-http-response` event, so that the body is there first.
  Its arguments: `status` (`status`), `headers` (`res.hdrs_bin`), `body` (`res.body`), `key`
  (`var(txn.inkwall.responses)`) and `failure` (`var(txn.inkwall.response_failure)`). The rules send
  it, wait for the body and remove the request's `Accept-Encoding` only when
  `txn.inkwall.responses` is set, so other routes add nothing to their responses; they wait for the
  body only for the media types the rules read (`rules.ResponseBodyTypes`).
- **The body.** At most HAProxy's buffer (`tune.bufsize` less `tune.maxrewrite`, #336), and what
  came within `wait-for-body`'s `time`. A body shorter than its `Content-Length` was cut: its prefix
  is inspected, and the policy's `responses.onOversize` decides, as through ext_proc. One without
  `Content-Length` counts as complete only when its frame is well under half the maximum frame
  size, as a request's body. A response too large for one frame gets 502 in Block mode, as above.
- **The verdict.** `txn.inkwall.response_action` (`allow` or `deny`, on every answer) and
  `txn.inkwall.response_status`: 403 for a leak (another status a rule names is returned as 403 by
  the sample rules), 502 for an oversized or uninspectable body under Deny, for a miss that fails
  closed and for a message the agent can't read, 503 when the evaluation failed (timeout, overload)
  and the policy fails closed. HAProxy's `http-response return` replaces the response, its headers
  and body dropped, with that status and a plain-text body naming the request ID. Detect mode only
  logs. An unset `response_action` (the agent down or timed out) is replaced with 502 by the first
  rule when `response_failure` is `closed`.
- **The table** (`pkg/adapters/spoe`, `pendingTable`). Bounded by entries
  (`--max-pending-responses`, 4096), by an estimate of their memory
  (`--max-pending-response-bytes`, 64 MiB) and by a TTL (`--response-ttl`, 1 minute, above HAProxy's
  usual `timeout server`: 30 s in the samples, 50 s in the controller). A state leaves with its
  response or at its TTL; expired states are swept, oldest first, on each request and response (the
  TTL is the same for all, so insertion order is expiry order), with no goroutine of its own. A kept
  Coraza transaction with the Core Rule Set measured about 77 KiB for a GET with a few headers, 124
  KiB with a 1 KiB urlencoded body, 198 KiB at 16 KiB and 454 KiB at 64 KiB (`runtime.MemStats`,
  500 transactions); the estimate, 128 KiB plus 6 bytes per body byte and 2 per header byte, is above
  each. So 64 MiB holds about 500 GETs in flight, well under the engine sidecar's 512 MiB limit; the
  design's first guess, "a few KiB" per state and 10,000 entries, was two orders of magnitude off.
- **A full table** refuses the new state, and the request gets its policy's failure mode as an
  overload (503 in block mode by default), logged: the alternatives were evicting the oldest state,
  whose response, possibly legitimate and slow, then misses and fails closed, or letting the request
  through with its response uninspected. Refusing up front keeps the failure on the request that
  can't be held, before it reaches the app.
- **A miss** (a response whose state isn't there: expired, the engine restarted, another engine)
  gets the failure mode HAProxy sent back with it: `open` passes, logged; `closed`, or none, gets
  502. Shutdown releases the states left: their responses go to the next engine as misses.
- **Costs.** One more SPOP round trip per inspected response, the evaluation as through ext_proc
  (about 0.3 ms per KiB of HTML, `BenchmarkEvaluateExchange`), the wait for the body, and the table
  above. Requests whose policies don't inspect responses keep nothing.
- **Metrics.** `inkwall_spoe_response_states_total{outcome}` (`kept`, `full`, `answered`,
  `expired`, `miss`), `inkwall_spoe_response_states` and `inkwall_spoe_response_state_bytes`.
- **Tests.** Unit tests through the agent with the Core Rule Set (block, detect, misses, the bounds,
  the TTL, Shutdown), `FuzzSPOEResponse`, and `make haproxy-e2e`: a response leaking a SQL error is
  replaced with 403 in block mode and passes, logged, in detect mode, through HAProxy 3.2.
- **The operator** (#470). The injected `spoe.conf` has two scopes: `inkwall`, whose request
  message sends `responses=bool(0)`, and `inkwall-responses`, whose request message sends
  `responses=bool(1)` and whose group `inkwall-response` sends the response. The engine of a
  controller pod gets `--response-messages`. An Ingress whose policies inspect responses gets the
  `inkwall-responses` filter and the response rules of `examples/haproxy/haproxy.cfg` (the
  `Accept-Encoding` removal, `wait-for-body`, the group, the fail-closed and `http-response return`
  rules) in its backend snippet, and the HAProxy integration reports `Result.Responses`, only once
  every running controller pod's engine has `--response-messages`: before, no Ingress gets the
  rules (a pod whose engine lacks the flag would keep nothing, and every response would miss), and
  the policy is `ResponsesNotInspected` with `Result.ResponsesWhy` naming the pods to restart. A
  pinned engine older than 0.6.0 doesn't know the flag, so it isn't injected with it, and the policy
  stays `ResponsesNotInspected`, rather than the engine crash-looping (`--response-messages` is a
  0.6.0 flag of `injection/version.go`, #536). `Enforced` gets no `EnginesOutdated` for it, unlike a
  field older engines ignore (#473): an engine older than 0.6.0 on an HAProxy pod never has the
  flag, so `Programmed` is already `False` (`ResponsesNotInspected`) and `Ready` with it, naming the
  pod; and `spec.responses` needs only 0.4.0 on Envoy's engines, which the engine records (they
  carry no adapter) couldn't tell apart. The probe covers the request filter only; a response
  probe would prove the response rules, as a follow-up.

**Open questions, resolved (#469):**

1. *The Coraza transaction or only its variables?* The transaction, as through ext_proc: the
   response rules see exactly what they see there (request variables, the user's `tx` variables,
   per-route exclusions), and the code path is the same (`pipeline.Exchange`). Its cost is bounded
   by the table, above; copying variables would save memory but give HAProxy's routes rules that
   behave differently from Envoy's.
2. *The failure mode on a miss?* The request's policy's failure mode (`failureMode`, resolved for
   its mode), carried by HAProxy in `txn.inkwall.response_failure`: no new policy field (the API
   stays as it is), and it is known on a miss, when the engine holds nothing. A miss that fails
   closed gets 502, as an uninspectable response; one that fails open passes, logged.
3. *A scaled-out agent?* Not supported for responses: the engine runs one per HAProxy (a sidecar in
   the controller's pod, or a process next to HAProxy), which is how the operator and the guide run
   it. HAProxy's `mode spop` backends offer no balancing on a transaction variable we could rely on,
   and a shared table would put a network hop and a store on every response. Behind several engines,
   responses that reach another engine miss and get the failure mode, which fails safe; the guide
   says so.
4. *Streamed responses and `wait-for-body`?* HAProxy waits for the body only of the media types the
   rules read, so Server-Sent Events, gRPC and downloads aren't held: their status and headers are
   inspected, as through ext_proc. `wait-for-body`'s `time` bounds the hold for the others; a body
   slower than it is inspected as far as it came, complete or not by the rules above.

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

**Responses** (#323, built for 0.6.0): with `--inspect-responses`, or a bundle policy's
`responses`, the proxy inspects responses as ext_proc does ([§2](#response-inspection-v040)), in
`ReverseProxy.ModifyResponse`, before anything is written to the client: it reads the first
`maxBytes` (and one byte) of a body the rules read, inspects the response, and forwards it with
that part put back in front of the rest, or replaces it (the denial, or 502 for `onOversize:
Deny`). Bodies the rules don't read aren't held. Held bodies are bounded: each to its limit, all
together to `--max-held-response-bytes` (64 MiB); past it, a response gets the failure mode as an
evaluation refused a slot (`ReasonOverload`, `Exchange.Refused`), and its share is given back when
the response's body is closed. The CRS suite's response rules run through it
(`TestCRSRegression`), and `FuzzProxyResponse` checks that a forwarded body arrives byte for
byte. `BenchmarkResponses` (the proxy end to end, an upstream on the loopback, 12-thread i7-1255U
shared with other jobs, 2026-11-13): a 16 KB HTML page 0.68 ms uninspected, 7.0 ms inspected
(0.39 ms per KiB, as ext_proc's evaluation); a 1 KB JSON body 1.3 ms; an image, whose body isn't
read, 0.79 ms (the kept transaction alone).

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
| SPOE | SPOP | Buffered, up to HAProxy's buffer | Yes (policies with `responses`; configured by hand until #470, [§4](#responses-through-spoe-370)) | Yes | HAProxy | Built (by hand or by the operator: [protecting HAProxy](../haproxy.md)) |
| `/v1/check` | HTTP (gRPC planned) | Yes | No | Yes | CLI, tests; a Traefik plugin planned | Built |
| Reverse proxy | HTTP proxying | Yes | Yes | It is the path | VMs, test reference | Built |

[Caddy](https://caddyserver.com/docs/) needs no protocol: the planned module compiles the engine into Caddy
([0002 §6.5](0002-system-architecture.md#65-caddy)).
