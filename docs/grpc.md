# gRPC

What the engine inspects in a [gRPC](https://grpc.io/docs/what-is-grpc/core-concepts/) call, what
it doesn't, and how it denies one. Fuller gRPC support (reading the messages, streaming) is
tracked in [#275](https://github.com/inkwall-dev/inkwall/issues/275).

## Contents

- [Which requests are gRPC calls](#which-requests-are-grpc-calls)
- [What is inspected](#what-is-inspected)
- [Denied calls](#denied-calls)
- [Streaming calls](#streaming-calls)
- [If you serve no gRPC](#if-you-serve-no-grpc)

## Which requests are gRPC calls

A request is a gRPC call when all of these hold:

- it is a `POST`;
- it has one `Content-Type`, and that is `application/grpc`, `application/grpc+proto`,
  `application/grpc-web` or `application/grpc-web+proto` (in any case, with or without
  parameters);
- its body is a sequence of gRPC messages, each a 5-byte prefix (a compressed flag of 0 or 1 and a
  4-byte length) and that many bytes. A body cut at the policy's `body.maxBytes` is checked as far
  as it goes, and must show at least one prefix.

Any other request is inspected as before, whatever its `Content-Type` says. That includes gRPC with
another codec (`application/grpc+json`) and gRPC-Web text (`application/grpc-web-text`), which the
Core Rule Set denies in `Block` mode, as any content type it doesn't know (rule 920420).

Before v0.3.1 every gRPC call was denied in `Block` mode, and logged in `Detect` mode: by rule
920420, and by rules that read the binary body as a form (920270 for its NUL bytes, 921150 for
the byte `0x0a` that starts most protobuf messages).

## What is inspected

- **Inspected**, as in any request, by the policy's rules and exclusions: the method, the path
  (`/package.Service/Method`), the query, and the headers, which carry the call's metadata. An
  attack there (say, `x-api-key: ${jndi:ldap://...}`) is denied as anywhere else. Metadata whose
  key ends in `-bin` is base64, which rules don't decode.
- **Not inspected**: the messages. They are binary [protobuf](https://protobuf.dev/), which text
  rules can't read. So `body.maxBytes` and `body.onOversize` don't apply to gRPC calls, and custom
  rules on `REQUEST_BODY` or `ARGS` don't see the messages.
- **Allowed**: the call's content type, which the Core Rule Set doesn't list (rule 920420).

## Denied calls

From v0.4.0, a denied call is answered as gRPC: its client gets status 7 (`PERMISSION_DENIED`)
and a message with the request ID, which finds the request's security event in the engine's log:

```
rpc error: code = PermissionDenied desc = Forbidden (request ID 0123abcd)
```

That holds for any request whose one `Content-Type` is gRPC (`application/grpc`,
`application/grpc-web`, `application/grpc-web-text`, with any `+codec`), whatever its body. The
answer is gRPC's trailers-only form: `grpc-status`, `grpc-message` and `x-request-id` in the
headers, no body. A call the engine can't inspect in time and denies (failure mode `Closed`) gets
14 (`UNAVAILABLE`), and an oversized body (only a request that claims to be gRPC can have one)
gets 8 (`RESOURCE_EXHAUSTED`).

| Proxy | gRPC | gRPC-Web |
|---|---|---|
| Envoy Gateway, raw Envoy | HTTP 200, gRPC status | HTTP 200, gRPC status |
| Traefik | HTTP 403, gRPC status | HTTP 403, gRPC status |
| Engine as reverse proxy | HTTP 200, gRPC status | HTTP 200, gRPC status |

Traefik's ForwardAuth denies only on an answer other than 2xx, so the HTTP status stays 403
there. Clients that read a gRPC answer by its content type, such as grpc-go, still report our
status and message; others report `PERMISSION_DENIED` from the 403 itself, as gRPC maps HTTP
statuses. Before v0.4.0, a denial was a plain-text HTTP 403: clients reported
`PERMISSION_DENIED`, with a message like `unexpected HTTP status code received from server: 403
(Forbidden)` (through Traefik) or `Forbidden` (through Envoy, which turned the 403 into a gRPC
status itself), and gRPC-Web clients got the 403 as it was.

Envoy counts a denied gRPC call as HTTP 200 in its access log and metrics, as any gRPC error. The
engine's security events and `inkwall_requests_total{action="deny"}` count it as a denial.

## Streaming calls

Unary, server-streaming and client-streaming calls work. A call is held until the client has sent
its whole request, or as much as the proxy buffers:

- **Envoy Gateway**, in `Block` mode, holds the call until the client ends its side or the body
  fills Envoy's buffer (`BufferedPartial`). A bidirectional call whose client waits for the server
  before ending its side stalls. Set `body.inspect: false` on the policy for such routes: Envoy
  then doesn't hold the body, and the headers are still inspected.
- **Traefik**'s ForwardAuth reads the whole body before asking the engine, whatever the policy
  says, and refuses bodies over 10 MiB (401). Bidirectional calls stall there too.

## If you serve no gRPC

A request that only claims to be gRPC, to get a JSON or form body past the rules, is inspected in
full: such a body doesn't start with a message prefix. An application that isn't gRPC but reads any
body however it is labelled could still get a body made to look like gRPC messages. If your routes
serve no gRPC, deny gRPC content types with a SecLang rule in a `WAFRuleSet`:

```
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/grpc" \
    "id:1000100,phase:1,deny,status:403,log,msg:'gRPC is not served here'"
```
