# Running the engine without Kubernetes

This guide runs `inkwall-engine` as a standalone [reverse proxy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling#forward_and_reverse_proxies) in front of any HTTP service, without
the operator.

## Contents

- [Prerequisites](#prerequisites)
- [Run the proxy](#run-the-proxy)
- [Flags](#flags)
- [Reloading the rules](#reloading-the-rules)
- [Other modes](#other-modes)
- [Checking it worked](#checking-it-worked)
- [Undoing it](#undoing-it)

## Prerequisites

- `inkwall-engine`, from the [releases page](https://github.com/inkwall-dev/inkwall/releases).
- An HTTP service to protect, here on `localhost:3000`.

## Run the proxy

Start the engine in front of the service. It listens on `:8480` and forwards allowed requests to
`--upstream`:

```sh
inkwall-engine proxy --upstream http://localhost:3000 --mode block
```

Point your clients, or the proxy in front of the service, at port 8480 instead of 3000. Start in
`detect` mode (the default), which logs matches but never blocks, tune [false positives](https://coreruleset.org/docs/concepts/false_positives_tuning/), then
switch to `block`.

## Flags

The main flags; `inkwall-engine proxy -h` lists them all:

| Flag | Default | Purpose |
|---|---|---|
| `--mode` | `detect` | `block` to enforce |
| `--paranoia-level` | `1` | [CRS](https://coreruleset.org/) [paranoia level](https://coreruleset.org/docs/concepts/paranoia_levels/), 1 to 4 |
| `--rules`, `--rules-before-crs` | | [SecLang](https://coraza.io/docs/seclang/) rules and exclusions, loaded after or before the CRS |
| `--watch-rules` | off | Reload `--rules` and `--rules-before-crs` when their content changes (checked every 2 s), as for a mounted ConfigMap; see [Reloading the rules](#reloading-the-rules) |
| `--skip-paths`, `--skip-body-paths` | | Paths not inspected at all, or without their body |
| `--disable-rule-groups` | | CRS attack families the app can't be vulnerable to, e.g. `php,java` |
| `--websocket-origins`, `--websocket-required-headers` | | Origins a [WebSocket](websocket.md) handshake may come from, headers it must have |
| `--websocket-messages` | `off` | `inspect` or `text-only`: inspect each text message a client sends on a [WebSocket](websocket.md#messages-through-the-standalone-proxy); a denied one closes it with 1008 |
| `--websocket-idle-timeout` | `0` (never) | Close a WebSocket with `1001` (going away) when nothing passes either way for this long. On shutdown, open WebSockets get `1001` in any case ([idle WebSockets](websocket.md#idle-websockets-and-shutdown)) |
| `--max-connections` | `0` (no limit) | Client connections open at a time, WebSockets included; past it, a new connection waits in the listen backlog until one closes. `inkwall_connections` and `inkwall_connection_limit_waits_total` count them |
| `--body-read-timeout` | `0` (off) | Time to read the part of a body that is inspected (`--max-body-bytes`); a client that stalls in it gets `408`. The rest streams to the upstream under `--read-timeout`: for long uploads, set `--read-timeout 0` and this one |
| `--max-body-bytes` | `65536` | Body bytes inspected; `--oversize-body` decides what happens to larger bodies |
| `--failure-mode` | `auto` | Requests that can't be inspected: rejected (503) in block mode, let through in detect mode |
| `--trusted-proxies` | | [CIDRs](https://www.rfc-editor.org/rfc/rfc4632) whose [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For) is trusted |
| `--trusted-hops` | `0` | [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For) entries, from the right, taken as proxies whatever their address (0 to 10), behind a trusted peer: see [client IP](client-ip.md#trusted-hops) |
| `--client-ip-header` | `x-forwarded-for` | `x-forwarded-for`, or `forwarded` ([RFC 7239](https://www.rfc-editor.org/rfc/rfc7239)) behind a proxy that sets or replaces it: a client can send either |
| `--listen`, `--admin-listen` | `:8480`, `:9480` | Proxy address; address of `/metrics`, `/healthz` and `/readyz` |
| `--h2c` | off | Also accept HTTP/2 without TLS (prior knowledge, as gRPC clients send it) on `--listen`; HTTP/1.1 still works |
| `--tls-cert`, `--tls-key` | | Serve TLS on `--listen`, HTTP/2 and HTTP/1.1 by ALPN; the files are read again when they change (a renewed certificate) |
| `--upstream-h2c` | off | Reach an `http://` upstream over HTTP/2 without TLS, as a [gRPC](grpc.md) server needs; WebSocket upgrades, HTTP/1.1 only, can't pass then |
| `--upstream-ca` | | CA certificates (PEM) for an `https://` upstream, instead of the system's. Over TLS the upstream gets HTTP/2 or HTTP/1.1, as ALPN settles |
| `--json-denials` | off | Answer a denied client that sends `Accept: application/json` with `{"error":"forbidden","status":403,"request_id":"..."}` instead of text. Every denial carries `X-Request-Id`, the request ID of its security event |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error`; security events are logged at `warn` |
| `--event-log-rate` | `10` | Security event lines per second for each policy and rule; the rest are counted in `inkwall_security_event_logs_suppressed_total` (`0`: no limit) |

## Reloading the rules

The engine reloads `--rules` and `--rules-before-crs` on `SIGHUP`, and with `--watch-rules` when
their content changes (a ConfigMap mounted as a volume is updated by swapping a symlink: one
reload). The new rules compile beside the old ones, which keep inspecting meanwhile; requests in
flight finish on the old rules, and the next ones get the new. If the new rules don't compile, the
old ones stay in force and the engine logs why:

```sh
kill -HUP "$(pidof inkwall-engine)"
```

Each reload is logged (`rules reloaded`, with the files' SHA-256, or `rules not reloaded` and the
error) and counted in `inkwall_rules_reloads_total{result="ok"|"error"}`. The other flags (mode,
paranoia level, skip paths...) still need a restart. In bundle mode the operator's bundles replace
the rules, and neither applies.

## Other modes

- `inkwall-engine forward-auth` answers [Traefik](https://doc.traefik.io/traefik/)'s [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) requests, on `127.0.0.1:9001`. This
  is the mode the operator injects.
- `inkwall-engine check` serves the `POST /v1/check` API
  ([`api/engine/v1`](../api/engine/v1/engine.proto)), on `127.0.0.1:9002`.
- `inkwall-engine ext-proc` serves [Envoy](https://www.envoyproxy.io/docs/envoy/latest/)'s [external processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) API over [gRPC](https://grpc.io/docs/),
  on `127.0.0.1:9003` (or a Unix socket, `--listen unix:/path`): see
  [protecting raw Envoy](raw-envoy.md).
- `inkwall-engine spoe` is an agent of [HAProxy](https://docs.haproxy.org/)'s [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt), on `127.0.0.1:9004` (or a Unix
  socket): see [protecting HAProxy](haproxy.md).

To test rules without running the engine, see [testing policies offline](testing-policies.md).

## Checking it worked

Send an attack through the proxy. In block mode it is rejected:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8480/?id=1%27%20OR%20%271%27%3D%271'
403
```

Each blocked or detected request logs one JSON line, `security event`, with the matched rule IDs.
Metrics are on `:9480/metrics`. Inspection adds about 0.5 ms per request
([baseline](design/0001-performance-first-architecture.md#31-measured-baseline-2026-10-03)).

## Undoing it

Point your clients back at the service, then stop the engine. It keeps no state.
