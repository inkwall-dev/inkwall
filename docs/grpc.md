# gRPC

What the engine inspects in a [gRPC](https://grpc.io/docs/what-is-grpc/core-concepts/) call at
v0.3.1, and what it doesn't. Fuller gRPC support (reading the messages, streaming, a gRPC status on
a denial) is tracked in [#275](https://github.com/inkwall-dev/inkwall/issues/275).

## Contents

- [Which requests are gRPC calls](#which-requests-are-grpc-calls)
- [What is inspected](#what-is-inspected)
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

A denied call gets HTTP 403, which gRPC clients report as status 7 (`PERMISSION_DENIED`), through
Envoy Gateway and Traefik alike.

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
