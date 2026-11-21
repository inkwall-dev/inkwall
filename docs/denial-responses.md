# Denial responses

A denied client gets a short text body by default, `Forbidden`. A policy's `denyResponse` replaces
it with a page of your own, an HTML page for browsers or a JSON document for an API, with the
request ID in it, so a user can quote it to support and `inkwallctl explain request` finds the
event. `InkwallConfig.spec.engine.denyResponse` sets one for every policy that has none. They need
engines 0.7.0 or later.

## Contents

- [A first page](#a-first-page)
- [Fields](#fields)
- [Which denials use it](#which-denials-use-it)
- [The request ID](#the-request-id)
- [Through each proxy](#through-each-proxy)
- [Testing it](#testing-it)
- [Upgrading and rolling back](#upgrading-and-rolling-back)
- [Design decisions](#design-decisions)

## A first page

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: storefront, namespace: shop}
spec:
  targetRefs: [{kind: Ingress, name: storefront}]
  mode: Block
  denyResponse:
    contentType: text/html
    body: |
      <!doctype html>
      <title>Request blocked</title>
      <h1>This request was blocked</h1>
      <p>If you think this is a mistake, contact support with the reference
      <code>{{request_id}}</code>.</p>
```

An API's policy answers in JSON instead; `application/problem+json` is the
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem format:

```yaml
  denyResponse:
    contentType: application/problem+json
    body: '{"type":"about:blank","title":"Request blocked","request_id":"{{request_id}}"}'
```

And a default for every policy that sets none, in the InkwallConfig:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata: {name: default}
spec:
  engine:
    denyResponse:
      contentType: text/plain
      body: "Blocked by the firewall. Reference: {{request_id}}\n"
```

Both go in the policy bundle, so a change applies within seconds, without restarting a pod.

## Fields

| Field | Meaning |
|---|---|
| `contentType` | `text/html`, `text/plain`, `application/json` or `application/problem+json`, optionally with `; charset=utf-8`. Text types are served with `; charset=utf-8`, the JSON ones without a parameter. No other type (no JavaScript, SVG or XML), so a denial can't be made into active content other than the HTML you wrote. |
| `body` | At most 8 KiB (8,192 bytes of UTF-8, not characters), not empty. With a JSON type it must be a JSON document, which the webhook checks. |

The policy's `denyResponse` wins over the InkwallConfig's; without either, the engine's own body
applies (`denialFormat` still chooses text or JSON for it).

The status isn't configurable: a denial keeps its verdict's status (403, 413, 429, 502, 503). A
200 would make attacks look successful to the monitoring that counts denials, and break what
reads the status: `Retry-After` on a rate limit's 429, the gRPC status a call gets.

## Which denials use it

Every denial of the policy's verdicts:

| Status | Denial |
|---|---|
| 403 | A rule, an IP deny list, the WebSocket checks, `body.grpc: Deny` |
| 413 | A body over the limit, with `body.onOversize: Deny` |
| 429 | A rate limit, with its `Retry-After` |
| 503 | A request that couldn't be inspected in time, failing closed |
| 403, 502 | A response replaced: a leak the rules found, or one over `responses.maxBytes` |

Not these:

- A **gRPC call** keeps its gRPC denial: HTTP 200 (or the verdict's status over plain HTTP/2),
  the gRPC status, and the request ID in `grpc-message`, without a body a gRPC client couldn't
  read ([gRPC](grpc.md)).
- A **request the adapter can't read** (a forward-auth subrequest without `X-Forwarded-Method`, a
  Host the standalone proxy refuses) gets the fixed `400 Bad Request`: no policy decided it.
- A request **no policy covers** isn't denied at all; with `bootstrapMode: DenyAll`, an engine
  that has no bundle yet denies with its own body, since it has no policy.
- A stream already sent in part (a Server-Sent Events stream whose later event leaks) is cut, not
  replaced: its status went out already.

## The request ID

`{{request_id}}` is the only substitution, written exactly so (no spaces); each one is replaced
with the request ID, the one in `X-Request-Id`. Nothing else of the request goes in: no host, path
or header, so a page can't reflect what an attacker sent. Any other `{{...}}` stays as it is.

The request ID is the proxy's (Envoy's `x-request-id`) or the client's `X-Request-Id`, kept only
when it is at most 128 of `A-Z a-z 0-9 . _ : -`, else one the engine makes; no escaping changes
such an ID. It is escaped for the content type all the same: HTML-escaped for `text/html`, as in
a JSON string for the JSON types (put the token inside quotes: `"id":"{{request_id}}"`), as it is
for `text/plain`.

The client chooses the ID, within that alphabet: in HTML, put `{{request_id}}` only in text or in a
quoted attribute (`<code>{{request_id}}</code>`, `data-ref="{{request_id}}"`), never in an `href`
or `src` (`javascript:alert` is 16 such characters) nor in a `<script>` or `<style>`.

Every denial also carries `X-Request-Id`, `X-Content-Type-Options: nosniff` and its
`Content-Length`. A custom one carries two more:

| Header | Why |
|---|---|
| `Cache-Control: no-store` | The page names one request: no cache or proxy keeps it for another |
| `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:` | The page may style itself and show inline (`data:`) images; no script runs, nothing is loaded from anywhere, no form posts |

So write the page self-contained: styles in a `<style>` element or `style` attributes, images as
`data:` URLs, no external fonts, scripts or stylesheets.

## Through each proxy

| Proxy | Custom body |
|---|---|
| Traefik (ForwardAuth) | Yes: Traefik copies the engine's answer to the client |
| Envoy Gateway, Istio, raw Envoy (ext_proc) | Yes, in the immediate response |
| The standalone proxy | Yes |
| The check API (`POST /v1/check`) | `deny_content_type` and `deny_body` in the answer, and `Cache-Control` and `Content-Security-Policy` in its `response_headers`, for the caller to send; none of them for a gRPC call |
| HAProxy (SPOE) | No: HAProxy writes its own denials, so its routes keep its error page, and the policy's `Programmed` message says so ([HAProxy](haproxy.md)) |

## Testing it

`inkwallctl test` shows a policy's denial on each request it denies, and `--json` prints its body
with the request's ID:

```console
$ inkwallctl test --policy wafpolicy.yaml --ingress ingress.yaml --request attack.http
deny  403  GET /search?q=1'%20OR%20'1'='1  policy=shop/storefront  reason=rule  rules=942100,949110  ...  denial="text/html; charset=utf-8",212B  1.2ms
```

## Upgrading and rolling back

Upgrade the chart first (the CRD fields, the webhook, the operator), then the engines. An engine
before 0.7.0 ignores both fields and answers with its own body: while one runs a policy that sets
`denyResponse`, the policy is `Enforced=False`, reason `EnginesOutdated`, naming
`spec.denyResponse`. While the InkwallConfig sets `spec.engine.denyResponse`, the same holds for
every policy that sets none, naming the InkwallConfig's field. Rolling the operator back below
0.7.0 drops both without a word.

## Design decisions

- **The field is `denyResponse`**, not `response`, which would read as a typo of `responses`
  (response inspection) ([API compatibility](api-compatibility.md)).
- **The status stays the verdict's.** See [Fields](#fields).
- **One substitution, no template engine.** `{{request_id}}` is a literal token, replaced in a
  precompiled body; no conditionals, no request data, so a denial costs a copy of at most 8 KiB
  and can't be made to reflect an attack.
- **An allowlist of content types**, and the body checked where it is written: the CRD checks the
  type and the size in bytes, the webhook that a JSON body parses, and the engine the type, the
  size and UTF-8 again when it compiles the bundle (a bundle from elsewhere, `inkwallctl test
  --bundle`). The engine serves a JSON body that doesn't parse as it is, rather than refuse a
  bundle for it. A hand-made bundle with a `deny_response` the engine refuses (another content
  type, over 8 KiB, not UTF-8) is refused whole, as any invalid bundle is: the engine keeps the
  bundle it runs and reports the error, so the policy isn't `Enforced` (`EngineNack`).
- **Every verdict's denial, not the adapter's own.** A 400 for a request an adapter can't read
  has no policy; a gRPC call needs its gRPC status, not a body.
- **The policy's, then the InkwallConfig's, then the engine's**, resolved when the engine compiles
  the bundle: each policy's pipeline carries its denial, and its verdicts carry it to the adapter,
  so the request path does no lookup.
- **HAProxy keeps its own denials** for now: its `http-request deny` takes a fixed content type
  per rule, so a body per policy needs a rule per status and type, and a body as large as 8 KiB
  in a SPOE variable is bounded by the frame size HAProxy is configured with.
