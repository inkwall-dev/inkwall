# gRPC

What the engine inspects in a [gRPC](https://grpc.io/docs/what-is-grpc/core-concepts/) call, what
it doesn't, and how it denies one.

## Contents

- [Which requests are gRPC calls](#which-requests-are-grpc-calls)
- [What is inspected](#what-is-inspected)
- [Inspecting the messages](#inspecting-the-messages)
- [Messages with their schema](#messages-with-their-schema)
- [Long streams: one message at a time](#long-streams-one-message-at-a-time)
- [Server messages](#server-messages)
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
  gRPC messages, each read as protobuf without its schema. A field whose bytes are UTF-8 is text,
  whatever its characters (a control character is read as a space, an invisible one as it is), and a field whose bytes are a protobuf message is
  read as one, down to 16 levels, as is a group (proto2 `group`, editions `DELIMITED`), from
  v0.6.2, v0.5.5 and v0.4.4: before, a group's text wasn't read
  ([GHSA-78c8-6gh2-87hw](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-78c8-6gh2-87hw)).
  A field of binary bytes gives its runs of at least 8 readable
  characters (a control character or a byte that isn't UTF-8 ends a run), and what lies between
  the fields of a nested message (its tags, lengths and numbers) its runs of at least 4. Numbers in the message
  itself give nothing.
- **What the rules see:** each text field as a form argument (`ARGS`, `ARGS_POST`) named by its
  field numbers (by its path with [the schema](#messages-with-their-schema)): `1` is field 1 of the message, `2.1` field 1 of the message in field 2. An
  attack in a field (`name: "1' OR '1'='1' -- "`) is denied as in a form. `REQUEST_BODY` stays
  empty. An exclusion names one as any argument (`when: {argument: "2.1"}`).
- **Compressed messages:** `grpc-encoding: gzip` is decompressed, up to 1 MiB per call. Another
  encoding can't be read.
- **What can't be read** is handled as an oversized body, by `body.onOversize`: denied in `Block`
  mode by default (`RESOURCE_EXHAUSTED`, HTTP 413), logged in `Detect` mode. That is a message
  cut at `body.maxBytes` (a client stream longer than the limit), compressed other than with
  gzip, not protobuf, or with more than 4,096 text fields. With long client streams, set
  `body.onOversize: Allow`: what fits under the limit is still inspected; or, through Envoy, have
  each message inspected as it comes ([below](#long-streams-one-message-at-a-time)).
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

## Messages with their schema

From v0.7.0, a policy that inspects messages can read them with their schema: the
[descriptor set](https://protobuf.dev/programming-guides/techniques/#self-description) of the
application's `.proto` files. Fields are then read by their types and named by their paths
(`ARGS:user.name`), not guessed and named by numbers (`ARGS:3.1`):

```sh
buf build -o orders.binpb                # or, with protoc:
protoc --include_imports --descriptor_set_out=orders.binpb orders/v1/*.proto
kubectl create configmap orders-schema --from-file=orders.binpb
kubectl label configmap orders-schema waf.inkwall.dev/rules=true
```

```yaml
spec:
  body:
    grpcMessages: Inspect # needed: a schema doesn't turn message reading on
    grpcSchema:
      configMapRef: {name: orders-schema, key: orders.binpb}
```

- **The ConfigMap** is in the policy's namespace, labeled `waf.inkwall.dev/rules=true` as a rule
  set's is, and holds the set in `binaryData` (`kubectl create configmap --from-file` puts it
  there), raw or gzipped: at most 1 MiB, 8 MiB gunzipped. The set must include its imports
  (`buf build` does; `protoc` with `--include_imports`). One set per policy: for several
  services, build one set from all of them.
- **The operator** compiles the set into the signed bundle; engines never parse descriptors and
  never fetch anything. A set that doesn't compile (not a `FileDescriptorSet`, an import it
  doesn't include, no service, over a bound) makes the policy `Accepted=False`,
  `InvalidGRPCSchema`, and the policy's previous version stays in force; a missing ConfigMap or
  key is `InvalidRef`. Engines before 0.7.0 read every message without the schema, and the policy
  is `Enforced=False`, `EnginesOutdated`.
- **The method** is the call's path (`/orders.v1.Orders/Create`): its input type reads every
  message of the call, buffered or [one at a time](#long-streams-one-message-at-a-time). A method
  the set doesn't describe is read without the schema, as before, never denied for it.
- **Each field by its type:** a `string` is text, whatever its bytes; a `bytes` field is text
  when it is printable UTF-8 of at least 8 bytes, and otherwise gives its runs of at least 12
  readable characters only (shorter random bytes are printable too often: they would match the
  rules); numbers, enums and bools give nothing; a nested message, a map entry (`labels.key`,
  `labels.value`) and a group are read by their types, down to 16 levels, a message also as text
  as without the schema (whole when printable, whole and flat when its tags, lengths and numbers
  are blank, and the runs between its fields). A field the schema declares a `string` is read
  whole whatever its bytes look like, so a printable tag or length byte, which keeps a field
  from being read whole without the schema, doesn't there. A
  `google.protobuf.Any` is read as the type its last `type_url` names (the one the application
  unpacks by), when the set has it, and also without the schema, as `payload.value`.
- **Every occurrence is read:** a field sent twice, and each member of a `oneof`, whichever the
  application keeps. Within limits: a message nested over 16 levels, with over 4,096 text fields,
  or whose reading would go past a budget linear in its size (64 bytes read per byte of the
  message) isn't read whole, and gets `body.onOversize`. A short `bytes` field (under 8 bytes, or
  binary with no run of 12) gives nothing, so text an application keeps in a short `bytes` field
  (`$(id)`) isn't read: such a field is best declared `string`.
- **What the set doesn't describe is still read**, without it: a field number the type doesn't
  have, or a field sent with another wire type (a string sent as a number), is read as before and
  named by its number under its parent (`user.7`). `inkwall_grpc_unknown_fields_total` counts
  them: a rising count means the set is older than the application.
- **Names** are the proto field names (not the JSON names) joined by dots, without indexes: every
  element of `items` gives `items.sku`, so one exclusion covers them all
  (`when: {argument: items.sku}`). An extension is `[package.extension]`. A path is cut at 256
  bytes.

**Moving a policy to a schema.** Its exclusions keep their syntax, but the names they match
change: `when: {argument: "3.1"}` no longer matches once that field is `user.name`. Put the
policy in `Detect` mode, add the schema, read the events (they name `ARGS:user.name`), rewrite the
exclusions by name, then go back to `Block`. The webhook warns of an exclusion whose argument is
only digits and dots on a policy with a schema.

**False positives.** With the schema, `bytes` fields no longer give short runs of random bytes:
in 100,000 messages of four random 1 to 24 byte `bytes` fields, none was denied (without the
schema, about 1 in 5,000 is). Text fields match the rules as the same text in a form would. Turn
it on in `Detect` mode first all the same: the design and the measurement are design 0013
([#316](https://github.com/inkwall-dev/inkwall/issues/316)).

## Long streams: one message at a time

From v0.6.0, through Envoy (Envoy Gateway, Istio, raw Envoy), a policy can have each message
inspected on its own as it arrives, instead of the body Envoy buffers:

```yaml
spec:
  body:
    grpcMessages: Inspect
    grpcStreams: PerMessage # default: Buffer
```

(The engine's flag, without the operator: `inkwall-engine ext-proc --grpc-messages inspect
--grpc-streams per-message`; Envoy's filter needs `allow_mode_override: true`.)

With `Buffer`, Envoy holds a call until the client has sent all of it, or `body.maxBytes`: a
client stream longer than that is cut and handled as an oversized body, and a bidirectional call
whose client waits for the server stalls. With `PerMessage`:

- **The call is decided on its path and metadata**, and then reaches the application at once.
  Envoy streams its body to the engine, which reads each message as it completes, whatever the
  chunks it comes in.
- **Each message is inspected on its own**, as its text fields (named by field numbers, as
  above, or by their paths with [the schema](#messages-with-their-schema)), with the policy's rules and exclusions, up to `body.maxBytes`. A longer message, or one
  compressed other than with gzip, gets `body.onOversize`. Long client streams and bidirectional
  calls work, however long they last.
- **Block mode** holds each message until it is inspected; an allowed one goes on to the
  application. A denied one ends the call with its gRPC status (`PERMISSION_DENIED`, or
  `RESOURCE_EXHAUSTED` for an oversized message) and the request ID; the application never gets
  it nor any message after it. If the application has already answered (a bidirectional call), the
  client sees the call reset instead. **Detect mode** forwards each message at once and logs the
  ones the rules flag, with `stream_event`, the message's index in the call.
- A body that isn't gRPC messages at all (a JSON body labelled gRPC) is denied, whatever
  `body.onOversize` says: under `Allow` it would otherwise pass uninspected.

**What changes, and why it is opt-in.** With `Buffer`, a client stream with an attack in its third
message is denied before the application sees anything of it. With `PerMessage` **the first two
messages have already reached the application** when the third is denied: the application may have
acted on them (written a row, started a job). That is the price of not holding the call. Choose
`PerMessage` for routes with long client streams or bidirectional calls, where an application
already handles calls that fail midway, and keep `Buffer` elsewhere.

**Cost.** Each message is one evaluation, so a call of many small messages costs more than the
same bytes buffered. Every evaluation goes through the engine's admission control and the policy's
`timeout`, as a request does: a flood of messages is shed with the failure mode (in `Block` mode by
default, the call ends with `UNAVAILABLE`), and never queues work. Memory per call is the message
in progress, at most `body.maxBytes` and its 5-byte prefix.

**Proxies.** Only Envoy streams a request body to the engine. Through Traefik, HAProxy and the
standalone proxy, `PerMessage` inspects the buffered body as `Buffer` does: messages are still
inspected, and long streams behave as below. gRPC-Web stays buffered everywhere: browsers don't
stream requests. An engine before 0.6.0 ignores `grpcStreams` and buffers: the policy is
`Enforced=False` (`EnginesOutdated`) while one runs it.

## Server messages

From v0.6.0, through Envoy, what a gRPC server sends back can be inspected for data leaks (a SQL
error, a stack trace, whatever your response rules look for), when the policy inspects responses
and their streams: `responses.inspect` and `responses.streams` (the engine's flags:
`--inspect-responses --response-streams inspect`; see [raw Envoy](raw-envoy.md#responses)). Off by
default: without `streams`, a gRPC response passes with only its status and headers inspected.

- **Each message** of a response, unary or a server stream, is inspected on its own as it comes, its
  text read as `grpcMessages` reads a request's (without a schema, gzip decoded), up to
  `responses.maxBytes`, with the response rules (the Core Rule Set's 95x data leakage rules and your
  phase 3 and 4 rules). In `Block` mode each message is held until it is inspected; a leaking one
  ends the call: Envoy resets the stream, so the client gets the messages before it but neither it
  nor any after, and sees the call fail (`INTERNAL` or `UNAVAILABLE`). A longer message is cut and
  gets `responses.onOversize`. `Detect` mode forwards at once and logs.
- **The call's status message** (`grpc-message`), where a server's error text goes, is inspected
  too, decoded, as one more event. When the server answers with an error and nothing else
  (trailers-only), Envoy still holds that answer, so a leak there is replaced by the engine's
  denial (`PERMISSION_DENIED`, with the request ID). When it comes in the trailers after messages,
  the engine asks Envoy for them, and a leak ends the call before the client gets the status.
- **Events** carry `phase: response` and `stream_event`, the message's index in the response (the
  status message counts as the last).

**False positives.** Binary fields in a response's messages can match a rule as a request's can
([above](#inspecting-the-messages)): turn it on in `Detect` mode first.

**Not inspected:** gRPC-Web responses (their trailers are framed in the body, and the text form is
base64). The status message is read through Envoy only; Traefik never shows the engine a
response.

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
| Istio | HTTP 200, gRPC status, as through Envoy Gateway | The same |
| HAProxy, with `haproxy.cfg`'s gRPC rules ([HAProxy](haproxy.md#grpc)) | HTTP 200, gRPC status | HTTP 200, gRPC status |
| Traefik | HTTP 403, gRPC status | HTTP 403, gRPC status |
| Engine as reverse proxy, with `--h2c` and `--upstream-h2c`, or over TLS ([below](#through-the-standalone-proxy)) | HTTP 200, gRPC status | HTTP 200, gRPC status |

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
  before ending its side stalls. With `grpcStreams: PerMessage` (from v0.6.0,
  [above](#long-streams-one-message-at-a-time)), the call isn't held: each message is inspected as
  it comes. Before v0.6.0, the workaround was `body.inspect: false` on such routes: Envoy then
  doesn't hold the body, and only the headers are inspected.
- **Istio** holds a call as Envoy Gateway does: its filter asks for the body
  (`BUFFERED_PARTIAL`) when a policy inspects bodies, and `grpcStreams: PerMessage` works the same.
- **HAProxy** sends the agent a body only with `option http-buffer-request`, which waits for the
  whole body or until HAProxy's buffer is full (about 15 KiB by default): a call is held as through
  Envoy Gateway, and a message past the buffer is handled as an oversized body
  ([bodies](haproxy.md#bodies)).
- **Traefik** reads the whole body before asking the engine, whatever the policy says, and refuses
  bodies over 10 MiB + 1 (413; 401 before Traefik v3.7, over 10 MiB). Bidirectional calls stall there too, with
  `PerMessage` or not: that can't be changed on the engine's side.
- **The standalone proxy** reads up to `--max-body-bytes` of the body before it decides, then
  streams the rest: a call is held as through Envoy Gateway, and a bidirectional call whose client
  waits for the server stalls unless the route is in `--skip-body-paths`.

### Through the standalone proxy

gRPC needs HTTP/2 from the client to the server. `inkwall-engine proxy` speaks it on both sides
when asked:

```sh
# Cleartext, as most in-cluster gRPC clients and servers:
inkwall-engine proxy --h2c --upstream http://grpc-server:50051 --upstream-h2c --mode block
# TLS, with the server's certificate from a private CA:
inkwall-engine proxy --tls-cert tls.crt --tls-key tls.key \
    --upstream https://grpc-server:50051 --upstream-ca ca.crt --mode block
```

HTTP/1.1 clients still work on the same listener. Streamed responses pass to the client as they
come. `--read-timeout` (60 s by default) bounds each call's request side over HTTP/2 too: for
long-lived streaming calls, raise it or set it to `0`. Unary, server-streaming and client-streaming
calls through grpc-go and a denied call are tested through the engine's `proxy` command, over h2c
and TLS.

## If you serve no gRPC

A request that only claims to be gRPC, to get a JSON or form body past the rules, is inspected in
full: such a body doesn't start with a message prefix. An application that isn't gRPC but reads any
body however it is labelled could still get a body made to look like gRPC messages. If your routes
serve no gRPC, deny gRPC on the policy (engines 0.5.0 or later):

```yaml
spec:
  body:
    grpc: Deny
```

A request with a gRPC or gRPC-Web content type (`application/grpc`, `application/grpc+json`,
`application/grpc-web`, `application/grpc-web-text`...) is then denied before any rule, whatever its
body, with reason `grpc`: 403, or the gRPC status `PermissionDenied` to a gRPC client, as other
denials. In `Detect` mode it is logged. Other content types, and the paths in `skip.paths`, are
unaffected. `inkwallctl test --policy` applies it too.
