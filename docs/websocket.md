# WebSocket

What the engine inspects in a [WebSocket](https://www.rfc-editor.org/rfc/rfc6455) at v0.4.0, and
what it doesn't. In short: the handshake is inspected, the messages after it are not. Message
inspection is tracked in [#276](https://github.com/inkwall-dev/inkwall/issues/276).

## Contents

- [Which requests are handshakes](#which-requests-are-handshakes)
- [What is inspected](#what-is-inspected)
- [Allowed origins and required headers](#allowed-origins-and-required-headers)
- [Through each proxy](#through-each-proxy)
- [Checking it worked](#checking-it-worked)

## Which requests are handshakes

A WebSocket starts with an HTTP request, the handshake: a `GET` with `Upgrade: websocket`,
`Connection: Upgrade`, `Sec-WebSocket-Key` and `Sec-WebSocket-Version: 13`. The server answers
`101 Switching Protocols`, and the connection then carries WebSocket messages, both ways, until one
side closes it.

The engine takes a request for a handshake when it has any one of `Upgrade: websocket`,
`Sec-WebSocket-Key` or `Sec-WebSocket-Version`. Any one is enough because proxies drop some:
Traefik's ForwardAuth doesn't pass `Upgrade` and `Connection` on to the engine, and a WebSocket
over HTTP/2 ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441)) has no `Sec-WebSocket-Key`. A
server doesn't upgrade a request without `Sec-WebSocket-Version`, so a real handshake can't hide
from this check; a request that only looks like one gets the WebSocket rules too.

## What is inspected

- **Inspected**, as in any request, by the policy's rules and exclusions: the path, the query and
  the headers of the handshake, including `Origin`, `Cookie` and `Sec-WebSocket-Protocol` (the
  subprotocols). An attack there (say, `?room=1' OR '1'='1`, or
  `Sec-WebSocket-Protocol: ${jndi:ldap://...}`) is denied as anywhere else, with a 403 **before
  the upgrade**: the connection is never upgraded, and the application never sees the handshake.
- **Checked**, when the policy sets `webSocket`: the handshake's origin and required headers
  ([below](#allowed-origins-and-required-headers)).
- **Not inspected**: the messages after the upgrade, text or binary, through any proxy. Rules on
  `REQUEST_BODY` or `ARGS` don't see them, and `body.maxBytes` doesn't limit them. Keep the
  application's own validation of what clients send it.

The [Core Rule Set](https://coreruleset.org/) doesn't deny legitimate handshakes: a browser's
handshake (Chrome's headers, with cookies, subprotocols and `permessage-deflate`) raises no rule at
any paranoia level, over HTTP/1.1 and HTTP/2, with or without the `Upgrade` and `Connection`
headers. No exclusion is needed for WebSocket routes.

## Allowed origins and required headers

A browser sends a page's cookies with a WebSocket handshake to any site the page opens one to,
and a WebSocket isn't subject to [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS). So a page on another site can open a
WebSocket to your application as the signed-in user, and read what comes back: cross-site
WebSocket hijacking. Only the `Origin` header tells, and many servers don't check it. A policy can:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata:
  name: chat
  namespace: web
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}
  mode: Block
  webSocket:
    allowedOrigins: ["https://app.example.com", "https://*.example.com"]
    requiredHeaders: [Authorization]
```

- `allowedOrigins`: the origins a handshake may come from, `scheme://host` or
  `scheme://host:port`, lower case, `http` or `https`. A host `*.example.com` matches any
  subdomain of `example.com`, not `example.com` itself. The port must match too: without one, the
  scheme's (443 for `https`). A handshake without `Origin`, with `Origin: null` or with two of
  them is denied. Empty: any origin.
- `allowMissingOrigin`: let a handshake without `Origin` pass the origin check. Browsers always
  send it; other clients (a mobile app, a service) may not, and aren't the target of cross-site
  hijacking. It needs `allowedOrigins`.
- `requiredHeaders`: headers a handshake must have, not empty, such as a token or a subprotocol.
  Their values aren't checked.

A handshake that doesn't meet them is denied with 403 in `Block` mode, before the rules run, and
gets no upgrade. In `Detect` mode it is upgraded, and logged as a security event with reason
`websocket` (or `rule`, when a rule matched too). Other requests, and routes in `skipPaths`, aren't
affected.

Engines before 0.4.0 ignore `webSocket`: while one runs a policy that sets it, the policy is
`Enforced=False`, reason `EnginesOutdated`. Without the operator, the engine's flags
`--websocket-origins`, `--websocket-allow-missing-origin` and `--websocket-required-headers` set
the same rules ([standalone proxy](standalone-proxy.md#flags)).

## Through each proxy

| Proxy | Handshake | Denial | Messages |
|---|---|---|---|
| Envoy Gateway, [raw Envoy](raw-envoy.md) (ext_proc) | Inspected on its headers | 403 before the upgrade | Not inspected |
| Traefik (ForwardAuth) | Inspected, without `Upgrade` and `Connection` | 403 before the upgrade | Not inspected |
| [Standalone proxy](standalone-proxy.md) | Inspected | 403 before the upgrade | Not inspected |

- **Envoy Gateway and raw Envoy**: Envoy sends a handshake's headers without ending the request,
  since the upgraded connection's data follows. The engine decides on the headers, and tells Envoy
  to send nothing more of the stream, so the WebSocket's data goes straight to the application.
  Before 0.4.0, in `Block` mode with body inspection, the engine waited for a body that comes only
  after the upgrade, and Envoy held the handshake until one of its timeouts; in `Detect` mode the
  engine logged every handshake as an oversized body when the connection closed. Raw Envoy proxies
  WebSockets only with `upgrade_configs: [{upgrade_type: websocket}]` on its
  `http_connection_manager` (Envoy Gateway sets it): the sample `envoy.yaml` doesn't.
- **Traefik**: ForwardAuth asks the engine before Traefik upgrades, so a denied handshake gets the
  engine's answer and no upgrade. Traefik doesn't pass the hop-by-hop headers `Upgrade` and
  `Connection` to the engine; `Sec-WebSocket-Key` and `Sec-WebSocket-Version` tell it's a handshake.
- **Standalone proxy**: the engine forwards an allowed upgrade to `--upstream` and copies the
  connection both ways.

## Checking it worked

Send a handshake from an origin the policy doesn't allow. In `Block` mode it gets 403, not 101:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    -H 'Origin: https://evil.example' https://chat.example.com/ws
403
```

The engine logs one `security event` with `"reason":"websocket"`, and counts it in
`inkwall_requests_total{action="deny",reason="websocket"}`. From an allowed origin the same command
prints `101` (and waits on the open connection: add `--max-time 2`).
