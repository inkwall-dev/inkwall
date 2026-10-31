# Running the engine without Kubernetes

This guide runs `inkwall-engine` as a standalone [reverse proxy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling#forward_and_reverse_proxies) in front of any HTTP service, without
the operator.

## Contents

- [Prerequisites](#prerequisites)
- [Run the proxy](#run-the-proxy)
- [Flags](#flags)
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
| `--skip-paths`, `--skip-body-paths` | | Paths not inspected at all, or without their body |
| `--disable-rule-groups` | | CRS attack families the app can't be vulnerable to, e.g. `php,java` |
| `--max-body-bytes` | `65536` | Body bytes inspected; `--oversize-body` decides what happens to larger bodies |
| `--failure-mode` | `auto` | Requests that can't be inspected: rejected (503) in block mode, let through in detect mode |
| `--trusted-proxies` | | [CIDRs](https://www.rfc-editor.org/rfc/rfc4632) whose [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For) is trusted |
| `--listen`, `--admin-listen` | `:8480`, `:9480` | Proxy address; address of `/metrics`, `/healthz` and `/readyz` |

## Other modes

- `inkwall-engine forward-auth` answers [Traefik](https://doc.traefik.io/traefik/)'s [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) requests, on `127.0.0.1:9001`. This
  is the mode the operator injects.
- `inkwall-engine check` serves the `POST /v1/check` API
  ([`api/engine/v1`](../api/engine/v1/engine.proto)), on `127.0.0.1:9002`.
- `inkwall-engine ext-proc` serves [Envoy](https://www.envoyproxy.io/docs/envoy/latest/)'s [external processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) API over [gRPC](https://grpc.io/docs/),
  on `127.0.0.1:9003` (or a Unix socket, `--listen unix:/path`).

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
