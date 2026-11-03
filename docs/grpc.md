# gRPC

What the engine inspects in a [gRPC](https://grpc.io/docs/what-is-grpc/core-concepts/) call, what
it doesn't, and how it denies one. Planned: streams inspected message by message
([#315](https://github.com/inkwall-dev/inkwall/issues/315)), messages read with their schema
([#316](https://github.com/inkwall-dev/inkwall/issues/316)), and server messages
([#317](https://github.com/inkwall-dev/inkwall/issues/317)).

## Contents

- [Which requests are gRPC calls](#which-requests-are-grpc-calls)
- [What is inspected](#what-is-inspected)
- [Inspecting the messages](#inspecting-the-messages)
- [Denied calls](#denied-calls)
- [Streaming calls](#streaming-calls)
- [If you serve no gRPC](#if-you-serve-no-grpc)

## Which requests are gRPC calls

A request is a gRPC call when all of these hold:

- it is a `POST`;
- it has one `Content-Type`, and that is `application/grpc`, `application/grpc+proto`,
  `application/grpc-web`, `application/grpc-web+proto`, `application/grpc-web-text` or
  `application/grpc-web-text+proto` (in any case, with or without parameters);
- its body is a sequence of gRPC messages, each a 5-byte prefix (a compressed flag of 0 or 1 and a
  4-byte length) and that many bytes. A body cut at the policy's `body.maxBytes` is checked as far
  as it goes, and must show at least one prefix.
- for gRPC-Web text, its body is those messages in base64, as gRPC-Web clients send them: groups
  of four characters, each piece the client encoded on its own ending with its `=` padding, no
  line breaks. It is decoded first (from v0.4.0); a body cut at `body.maxBytes` is decoded up to
  its last whole group.

Any other request is inspected as before, whatever its `Content-Type` says: gRPC with another
codec (`application/grpc+json`), or a gRPC-Web text body that isn't base64 of gRPC messages. The
Core Rule Set denies those in `Block` mode, as any content type it doesn't know (rule 920420).

Before v0.3.1 every gRPC call was denied in `Block` mode, and logged in `Detect` mode: by rule
920420, and by rules that read the binary body as a form (920270 for its NUL bytes, 921150 for
the byte `0x0a` that starts most protobuf messages).

## What is inspected

- **Inspected**, as in any request, by the policy's rules and exclusions: the method, the path
  (`/package.Service/Method`), the query, and the headers, which carry the call's metadata. An
  attack there (say, `x-api-key: ${jndi:ldap://...}`) is denied as anywhere else. Metadata whose
  key ends in `-bin` is base64, which rules don't decode.
- **Not inspected by default**: the messages. They are binary [protobuf](https://protobuf.dev/),
  which text rules can't read. So `body.maxBytes` and `body.onOversize` don't apply to gRPC calls,
  and custom rules on `REQUEST_BODY` or `ARGS` don't see the messages, unless the policy sets
  `body.grpcMessages: Inspect` ([below](#inspecting-the-messages)).
- **Allowed**: the call's content type, which the Core Rule Set doesn't list (rule 920420).

## Inspecting the messages

From v0.4.0, a policy can have the text in the messages inspected:

```yaml
spec:
  body:
    grpcMessages: Inspect # default: Skip
```

(The engine's flag, without the operator: `--grpc-messages inspect`.)

- **What is read:** the body, up to `body.maxBytes` (gRPC-Web text decoded from base64 first), as
  gRPC messages, each read as protobuf without its schema. A field whose bytes are printable UTF-8 is text, and a field whose bytes
  are a protobuf message is read as one, down to 16 levels. Numbers and binary bytes give nothing.
- **What the rules see:** each text field as a form argument (`ARGS`, `ARGS_POST`) named by its
  field numbers: `1` is field 1 of the message, `2.1` field 1 of the message in field 2. An
  attack in a field (`name: "1' OR '1'='1' -- "`) is denied as in a form. `REQUEST_BODY` stays
  empty. An exclusion names one as any argument (`when: {argument: "2.1"}`).
- **Compressed messages:** `grpc-encoding: gzip` is decompressed, up to 1 MiB per call. Another
  encoding can't be read.
- **What can't be read** is handled as an oversized body, by `body.onOversize`: denied in `Block`
  mode by default (`RESOURCE_EXHAUSTED`, HTTP 413), logged in `Detect` mode. That is a message
  cut at `body.maxBytes` (a client stream longer than the limit), compressed other than with
  gzip, not protobuf, or with more than 4,096 text fields. With long client streams, set
  `body.onOversize: Allow`: what fits under the limit is still inspected.
- **Argument limit:** the text fields count against the engine's argument limit (1,000 by
  default), as a form's or JSON body's do: more is denied (400, rule 200005).

**False positives.** Text in messages matches the rules as the same text in a form would. Binary
fields add their own: random bytes are sometimes printable, and a short run of them like `|W`
can match a command or SQL injection rule. Measured with the Core Rule Set at paranoia level 1,
that is about 1 message in 10,000 with four short random `bytes` fields, and none in real
protobuf messages carrying names, paths and text. That is why it is off by default: turn it on in
`Detect` mode first, read the events for a while, and add exclusions (`when: {argument: "3"}`) for binary
fields that match before `Block`. The measurement and the decision are in
[0002 §8.7](design/0002-system-architecture.md#87-grpc-messages).

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
