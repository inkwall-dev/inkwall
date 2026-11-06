# Protecting HAProxy

This guide puts Inkwall in front of an [HAProxy](https://docs.haproxy.org/) you configure yourself: on a host, in Docker, or
as a Deployment in Kubernetes. HAProxy's [SPOE](https://docs.haproxy.org/3.2/configuration.html#9.3) filter (Stream Processing Offload Engine) sends
each request to `inkwall-engine spoe`, an SPOE agent that runs next to HAProxy and answers with a
verdict, which HAProxy's rules act on. For the [HAProxy Kubernetes Ingress Controller](https://www.haproxy.com/documentation/kubernetes-ingress/), the operator
does it all: see [with the operator](#with-the-operator-haproxy-kubernetes-ingress-controller). For any other HAProxy, you add the
filter and the rules to your `haproxy.cfg`, as the rest of this guide shows.

The samples in [`examples/haproxy`](../examples/haproxy) are the files this guide shows, and
`make haproxy-e2e` runs them with HAProxy 3.2 in Docker.

## Contents

- [With the operator (HAProxy Kubernetes Ingress Controller)](#with-the-operator-haproxy-kubernetes-ingress-controller)
  - [Protecting an Ingress](#protecting-an-ingress)
  - [What the operator does](#what-the-operator-does)
  - [The probe, and Programmed](#the-probe-and-programmed)
  - [Limits](#limits)
  - [Uninstalling](#uninstalling)
- [Prerequisites](#prerequisites)
- [How it works](#how-it-works)
- [Run the engine next to HAProxy](#run-the-engine-next-to-haproxy)
- [Configure HAProxy](#configure-haproxy)
  - [The complete spoe.conf](#the-complete-spoeconf)
  - [The complete haproxy.cfg](#the-complete-haproxycfg)
  - [Block mode and detect mode](#block-mode-and-detect-mode)
  - [Timeout and failure mode](#timeout-and-failure-mode)
  - [Bodies](#bodies)
  - [gRPC](#grpc)
  - [WebSocket](#websocket)
  - [Routes left uninspected](#routes-left-uninspected)
- [The policy](#the-policy)
- [Client IP](#client-ip)
- [Checking it worked](#checking-it-worked)
- [Undoing it](#undoing-it)

## With the operator (HAProxy Kubernetes Ingress Controller)

<!-- versions: HAPROXY_CHART_VERSION -->
The operator protects the Ingresses of the [HAProxy Kubernetes Ingress Controller](https://www.haproxy.com/documentation/kubernetes-ingress/) (`haproxytech/kubernetes-ingress`,
3.1 or later: its HAProxy must be 3.1 or later; tested with 3.2.19, chart 1.54.4), installed with
nothing about Inkwall. Not [HAProxy Ingress](https://haproxy-ingress.github.io/) (`jcmoraisjr/haproxy-ingress`), another controller.

### Protecting an Ingress

1. Install Inkwall with the controller's namespace among the proxy namespaces
   (`injection.proxyNamespaces`, which includes `haproxy-controller`, where the controller's docs
   install it, by default), and `rbac.integrations.haproxy` granted (the default).
2. Restart the controller's pods once Inkwall is installed, so the Pod webhook gives them the
   engine: `kubectl -n haproxy-controller rollout restart deployment/<release>-kubernetes-ingress`.
   Until then the policy is `Programmed=False` (`PendingRestart`).
3. Target the Ingress with a `WAFPolicy`, as for any proxy:

   ```yaml
   apiVersion: waf.inkwall.dev/v1alpha1
   kind: WAFPolicy
   metadata: {name: shop, namespace: shop}
   spec:
     targetRefs: [{kind: Ingress, name: shop}]
     mode: Block
   ```

The operator recognises the controller by its IngressClass (`spec.controller:
haproxy.org/ingress-controller/<class>`, the controller's `--ingress.class`, `haproxy` by
default) and its pods by the chart's label
`app.kubernetes.io/name: kubernetes-ingress` (an `InkwallConfig` can name others).
`status.proxies` lists it.

### What the operator does

- **The controller's pods** get, from the Pod webhook, the engine as a native sidecar
  (`inkwall-engine spoe`, on a Unix socket in an `emptyDir` both mount), running as HAProxy's user
  when the container sets one, and, from the ConfigMap `inkwall-haproxy` the operator keeps in the
  controller's namespace, two files: `/usr/local/etc/haproxy/haproxy-aux.cfg`, the controller's
  [auxiliary configuration file](https://www.haproxy.com/documentation/kubernetes-ingress/ingress-tutorials/auxiliary-config-file/), with the agent's `mode spop` backend; and
  `/usr/local/etc/inkwall/spoe.conf`. A pod that mounts its own `haproxy-aux.cfg` keeps it, and the
  policy says the pod can't run the filter.
- **Each protected Ingress** gets two annotations: `haproxy.org/standalone-backend: "true"`, so
  that it has a backend of its own (Ingresses to one Service otherwise share one, and the
  controller would apply only one Ingress's snippet), and `haproxy.org/backend-config-snippet`,
  whose first lines, between `# inkwall:begin` and `# inkwall:end`, load the filter and deny on the
  engine's verdict, as [`haproxy.cfg`](#the-complete-haproxycfg) does: `option
  http-buffer-request` when a policy inspects bodies, the probe's rule, the fail-closed rule when
  the policies fail closed (`Block` mode by default), the gRPC answer and a rule per status. A
  snippet of your own on the Ingress stays, after the operator's lines; one on the Service comes
  before them. The previous value of `standalone-backend` is kept in
  `waf.inkwall.dev/haproxy-wired`, and restored when the Ingress is unprotected.
- **The failure mode:** the fail-closed rule is in the snippet when every policy on the Ingress
  fails closed, so HAProxy answers 503 while the engine is down; in `Detect` mode (failing open by
  default) it isn't, and requests pass uninspected.

### The probe, and Programmed

The controller tells no one about the snippets it uses: one HAProxy refuses is dropped with a line
in its log. So the operator **probes** each protected Ingress on each of the controller's pods,
directly at the pod's address and HTTP port (or HTTPS, for a host the Ingress has TLS for), and
the policy is `Programmed=True` only once every pod has answered:

- The probe is a `GET`, without a body, to the Ingress's host, at
  `<path>/.well-known/inkwall-probe/<nonce>` under a `Prefix` path (or the `Exact` path with
  `?inkwall-probe=<nonce>`), with an `X-Inkwall-Probe` header carrying a MAC under a key only the
  operator and the engines have. The engine answers it without inspecting it, and the Ingress's
  snippet returns status 299 with the engine's own MAC: so you see these requests, from the
  operator's pod, in HAProxy's access log, with status 299. They don't reach your app.
- If the probe gets anything else, HAProxy doesn't run the filter for that Ingress on that pod: the
  probe has reached your app (a 404 on that path, usually), and the policy is `Programmed=False`,
  reason `Unverified`, naming the pod and what came back. Its traffic through that pod isn't
  inspected.
- Until a probe has answered, the policy is `Unverified` too. The operator probes once a route,
  its policy or a pod changes, again every 20 seconds while it fails, and every 5 minutes once it
  answers; a few at a time.
- The operator must reach the controller pods' HTTP port: a NetworkPolicy that blocks it keeps
  the policies `Unverified`.

Other reasons the policy isn't `Programmed`: a running controller pod without the engine
(`SidecarMissing` or `PendingRestart`), and, as `WiringFailed`, a pod without the agent's files, or
a controller run with `--disable-config-snippets` covering backends.

### Limits

- **Bodies:** HAProxy sends the engine at most its buffer (about 15 KiB by default), and a body it
  cut is handled as oversized (413 in `Block` mode by default): raise `tune.bufsize` with the
  controller ConfigMap's `global-config-snippet` to inspect larger bodies (see [Bodies](#bodies)):

  ```yaml
  # The controller's ConfigMap (the chart's controller.config)
  data:
    global-config-snippet: |
      tune.bufsize 81920
  ```

  The operator doesn't change it, but says on the policy when its `body.maxBytes` (64 KiB when
  unset) is more than the buffer lets the engine see: `Programmed`'s message names the effective
  limit (`HAProxy's buffer (tune.bufsize 16384, HAProxy's default) lets the engine see at most
  about 15360 bytes of a request ...`). It reads `tune.bufsize` and `tune.maxrewrite` from the
  ConfigMap the controller's `--configmap` names, within a minute of a change. That is a note: the
  status stays as it is, since larger bodies still fail safe.
- `haproxy.org/standalone-backend` is forced to `true` on a protected Ingress.
- HTTP probing needs the controller's `http` container port, as the chart names it; with plain
  HTTP disabled (`--disable-http`) only hosts with TLS can be probed.

### Uninstalling

`helm uninstall` removes the operator's lines and restores `standalone-backend` on every Ingress it
wired; the controller then serves them uninspected. Running controller pods keep the engine until
they are restarted, and the ConfigMap `inkwall-haproxy` stays while they mount it: restart the
controller, then delete it.

## Prerequisites

<!-- versions: HAPROXY_VERSION -->
- HAProxy 3.1 or later, whose SPOE speaks SPOP 2.0 through a `mode spop` backend. The samples are
  tested with HAProxy 3.2.26 (`haproxy:3.2.26`).
- `inkwall-engine`, from the [releases page](https://github.com/inkwall-dev/inkwall/releases), or the image
  `ghcr.io/inkwall-dev/inkwall-engine`.

## How it works

1. HAProxy opens a few connections to the engine, starts each with a HELLO handshake, and then
   sends one NOTIFY frame per request, when the frontend's `http-request` rules are about to run:
   the method, path and query, HTTP version, headers, the body HAProxy buffered, the client address
   and whether the connection is TLS.
2. The engine inspects the request with the OWASP [Core Rule Set](https://coreruleset.org/) and answers with variables:
   `txn.inkwall.action` (`allow` or `deny`), `txn.inkwall.status` (the status to deny with: 403 for
   an attack, 413 for an oversized body, 503 when it can't inspect the request, 400 for a request
   it can't read) and `txn.inkwall.request_id`.
3. HAProxy's `http-request` rules deny on those variables, or let the request through. HAProxy
   holds the request until the engine answers, in block and in detect mode.

The responses aren't sent to the engine. [SPOE](design/0006-adapter-protocols.md#4-spoe-haproxy-stream-processing-offload-engine) has the details of the protocol.

## Run the engine next to HAProxy

The engine listens on a Unix socket or on loopback, so that only HAProxy reaches it. Run it where
HAProxy runs:

- **On a host**, as a process next to HAProxy's, on loopback:

  ```sh
  inkwall-engine spoe --listen 127.0.0.1:9004 --mode block
  ```

  and in `haproxy.cfg`, `server engine 127.0.0.1:9004 check inter 1s`. Or on a Unix socket,
  `--listen unix:/var/run/inkwall/spoe.sock` (`server engine unix@/var/run/inkwall/spoe.sock`, as
  in the samples): the engine creates the socket file as `0666`, so any user who can reach its
  directory can connect: keep the directory to HAProxy's and the engine's users (for example
  `0750`, owned by the engine's user and a group HAProxy is in).
- **In a pod**, as a sidecar in HAProxy's pod, on a Unix socket in an [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) both containers
  mount. The engine's image runs as user 65532: run HAProxy as 65532 too. Make the engine a
  [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) (an init container with `restartPolicy: Always`), so HAProxy starts only once
  the engine serves.
- **In Docker**, in HAProxy's network namespace (`--network container:<haproxy>`), on loopback or
  on a socket in a shared volume.

The engine's `/healthz`, `/readyz` and `/metrics` are on `:9480` (`--admin-listen`).

## Configure HAProxy

The SPOE filter takes its own configuration file, `spoe.conf`, which names the agent and the
message HAProxy sends it. `haproxy.cfg` loads it in the frontend, denies on the verdict, and
declares the engine as a `mode spop` backend.

### The complete spoe.conf

[`spoe.conf`](../examples/haproxy/spoe.conf):

<!-- examples/haproxy/spoe.conf: hack/haproxy/e2e.sh checks that this copy is the file. -->
```haproxy
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# SPOE configuration for the Inkwall engine's agent (inkwall-engine spoe),
# loaded by haproxy.cfg's `filter spoe`. HAProxy sends the message
# inkwall-request when the frontend's http-request rules are about to run;
# the agent answers with the variables txn.inkwall.action ("allow" or
# "deny"), txn.inkwall.status (the status to deny with),
# txn.inkwall.request_id and, for a denied gRPC call, txn.inkwall.grpc_*.
# See docs/haproxy.md.

[inkwall]
spoe-agent inkwall
    messages inkwall-request
    option var-prefix inkwall
    # txn.inkwall.error says why there is no verdict (1: timeout, ...).
    option set-on-error error
    # The engine's deadline (--timeout, 250ms by default) plus 500ms: the
    # engine decides a slow inspection itself, with its failure mode; this
    # is for a hung engine.
    timeout processing 750ms
    use-backend inkwall-engine
    register-var-names action status request_id error grpc_status grpc_message grpc_content_type

spoe-message inkwall-request
    args method=method path=pathq version=req.ver headers=req.hdrs_bin body=req.body ip=src https=ssl_fc
    # Every request but /healthz, a route left uninspected.
    event on-frontend-http-request unless { path /healthz }
```

The message's name, `inkwall-request`, and its argument names are what the engine reads: keep
them. The engine sets every variable it answers with on each answer, so an unset
`txn.inkwall.action` means HAProxy got no answer.

### The complete haproxy.cfg

[`haproxy.cfg`](../examples/haproxy/haproxy.cfg), for block mode, with the engine on a Unix socket
and the app at `app:80`:

<!-- examples/haproxy/haproxy.cfg: hack/haproxy/e2e.sh checks that this copy is the file. -->
```haproxy
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# HAProxy (3.1 or later) in front of an app, every request inspected by
# Inkwall before it is forwarded: block mode. The engine runs next to
# HAProxy (a process on the same host, or a sidecar in the same pod) and is
# its SPOE agent on a Unix socket:
#
#   inkwall-engine spoe --listen unix:/var/run/inkwall/spoe.sock --mode block
#
# HAProxy must run as the engine's user (65532 in the engine image) to
# connect to the socket. Check this file with `haproxy -c -f haproxy.cfg`.
# See docs/haproxy.md.

global
    log stdout format raw local0

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend web
    # HTTP/1.1, and HTTP/2 with prior knowledge (h2c).
    bind :8080
    # Wait for the body, up to HAProxy's buffer (tune.bufsize, 16 KiB by
    # default), before the agent is called: without it, bodies go
    # uninspected.
    option http-buffer-request
    filter spoe engine inkwall config /usr/local/etc/haproxy/spoe.conf
    # Fail closed: without a verdict (the engine is down, or hung), deny
    # with 503. Leave this rule out to fail open. /healthz is left
    # uninspected (spoe.conf), so it has no verdict.
    http-request deny deny_status 503 if !{ var(txn.inkwall.action) -m found } !{ path /healthz }
    # A denied gRPC call: HTTP 200 and the gRPC status in the headers
    # (http-after-response sets its Content-Type).
    http-request return status 200 hdr grpc-status "%[var(txn.inkwall.grpc_status)]" hdr grpc-message "%[var(txn.inkwall.grpc_message)]" hdr x-request-id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.grpc_status) -m found }
    # deny_status takes a fixed status: a rule per status the engine denies
    # with.
    http-request deny deny_status 400 hdr x-request-id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.status) -m int 400 }
    http-request deny deny_status 413 hdr x-request-id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.status) -m int 413 }
    http-request deny deny_status 503 hdr x-request-id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.status) -m int 503 }
    http-request deny deny_status 403 hdr x-request-id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.action) -m str deny }
    # The request ID of the engine's log, for the app.
    http-request set-header X-Request-Id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.request_id) -m found }
    http-after-response set-header content-type "%[var(txn.inkwall.grpc_content_type)]" if { var(txn.inkwall.grpc_content_type) -m found }
    default_backend app

backend app
    server app app:80

backend inkwall-engine
    mode spop
    timeout connect 5s
    timeout server 3m
    # HELLO health checks: an engine that stops answering is marked down
    # within a second, and HAProxy stops waiting for it.
    option spop-check
    server engine unix@/var/run/inkwall/spoe.sock check inter 1s
```

Check a changed configuration with `haproxy -c -f haproxy.cfg`. The order of the `http-request`
rules matters: the fail-closed rule first, then the gRPC answer, then a rule per status. Put your
own `http-request` rules after them, so a denied request goes no further.

`deny_status` takes a fixed status, so the configuration has a rule for each status the engine
denies with, and each carries the request ID in `x-request-id`:

| `txn.inkwall.status` | Why | HAProxy answers |
|---|---|---|
| 400 | A request the engine can't read (a malformed path, an invalid header) | 400 |
| 403 | An attack | 403 |
| 413 | A body over the inspected limit (`--oversize-body deny`) | 413 |
| 503 | The engine couldn't inspect the request (timeout, overload, error) and fails closed | 503 |
| any other (a rule of your own with `deny,status:418`, say) | | 403 |

The fail-closed rule's 503 has no request ID: the engine never saw the request. The engine doesn't
write the body of HAProxy's denials, so `--json-denials` doesn't apply here: HAProxy answers with
its own error page.

### Block mode and detect mode

The engine's `--mode` decides: in block mode it answers `deny` for an attack, in detect mode it
answers `allow` and logs what it would have blocked. `haproxy.cfg` is the same for both. HAProxy
waits for the answer either way (SPOP 2.0 has no asynchronous mode), so detect mode adds the same
latency as block mode.

Start in detect mode, tune [false positives](https://coreruleset.org/docs/concepts/false_positives_tuning/), then switch the engine to block mode.

### Timeout and failure mode

- **`timeout processing`** (`spoe.conf`): the engine's deadline (`--timeout`, 250 ms by default,
  or the largest `timeout` of your policies with the [policy from the operator](raw-envoy.md#the-policy-from-the-operator)) plus 500 ms.
  The engine decides a request it can't inspect in time itself, with its failure mode
  (`--failure-mode`); HAProxy's timeout is for an engine that hangs.
- **The fail-closed rule** (`haproxy.cfg`): when HAProxy gets no answer (the engine is stopped,
  restarting or hung), it sets no variable and goes on. The first rule,
  `http-request deny deny_status 503 if !{ var(txn.inkwall.action) -m found } ...`, denies those
  requests with 503: HAProxy fails closed, as the engine does in block mode by default. Leave it
  out to fail open, as the engine does in detect mode: with block mode and no such rule, stopping
  the engine lets attacks through.
- **`option spop-check`** (`haproxy.cfg`): HAProxy checks the engine with a HELLO handshake every
  second (`check inter 1s`), and marks it down when it doesn't answer, so requests aren't held
  for `timeout processing` while it is down.
- **`option set-on-error error`** (`spoe.conf`): `txn.inkwall.error` says why HAProxy got no
  answer, for your logs: see HAProxy's [SPOE errors](https://docs.haproxy.org/3.2/configuration.html#9.3).

### Bodies

HAProxy sends the body only with `option http-buffer-request`, and only what fits its buffer:
`tune.bufsize` less `tune.maxrewrite`, about 15 KiB by default. The engine inspects up to its body
limit (`--max-body-bytes`, 64 KiB by default, or the largest `body.maxBytes` of your policies), so
raise `tune.bufsize` above that limit in the `global` section to inspect bodies up to it:

```haproxy
global
    tune.bufsize 81920
```

A body HAProxy cut is handled as oversized (`--oversize-body`, or the policy's `body.onOversize`:
413 in block mode by default). With a `Content-Length` the engine sees that the body was cut; a
chunked or HTTP/2 body without one can't say, so the engine takes it as complete only when it is
well under half of HAProxy's buffer (about 7 KiB, headers included, under the defaults), and as
oversized above that. Without `option http-buffer-request`, bodies go uninspected, and are handled
as oversized too.

A larger `tune.bufsize` takes more memory per connection: see HAProxy's [`tune.bufsize`](https://docs.haproxy.org/3.2/configuration.html#3.2-tune.bufsize).

### gRPC

The engine tells a gRPC call (gRPC and gRPC-Web) by its `Content-Type`. A denied one also gets
`txn.inkwall.grpc_status`, `txn.inkwall.grpc_message` and `txn.inkwall.grpc_content_type`, and
`haproxy.cfg`'s `http-request return` and `http-after-response` rules answer it as a gRPC server
would: HTTP 200, with `grpc-status` 7 (`PERMISSION_DENIED`) and a `grpc-message` naming the request
ID in the headers. Without those two rules, a denied call gets the plain 403, which gRPC clients
also report as `PERMISSION_DENIED`. See [gRPC](grpc.md).

### WebSocket

HAProxy asks the agent about a WebSocket handshake as about any request, before it forwards it: the
handshake's URL and headers are inspected, a policy's `webSocket` rules apply (or
`--websocket-origins` and `--websocket-required-headers`), and a denied handshake gets 403 and no
upgrade. The messages after the upgrade aren't requests, and aren't sent to the agent: they are not
inspected. `hack/haproxy/e2e.sh` checks a handshake from a forbidden origin (403) and from an
allowed one (let through), without completing an upgrade. See [WebSocket](websocket.md).

### Routes left uninspected

The message's `event` takes a condition: `spoe.conf` leaves `/healthz` uninspected with
`event on-frontend-http-request unless { path /healthz }`. HAProxy doesn't call the engine for
those requests, so they have no verdict: the fail-closed rule must leave them out too, as
`haproxy.cfg`'s does with `!{ path /healthz }`. Otherwise they get 503.

The engine's `--skip-paths` (or a policy's `skipPaths`) does the same on the engine's side, but
HAProxy still calls the engine.

## The policy

Without Kubernetes, or without the operator, the engine's flags are the policy, as for the
[standalone proxy](standalone-proxy.md#flags): `--mode`, `--failure-mode`, `--timeout`,
`--paranoia-level`, `--rules` and `--rules-before-crs` ([SecLang](https://coraza.io/docs/seclang/) rules and exclusions),
`--skip-paths`, `--disable-rule-groups`, `--max-body-bytes`, and `--websocket-origins` with
`--websocket-required-headers` ([WebSocket](websocket.md)). Every request HAProxy sends gets that one
policy; `inkwall-engine spoe -h` lists the flags. To test rules before you deploy them, see
[testing policies offline](testing-policies.md).

With HAProxy in a cluster where Inkwall is installed, the engine can instead take `WAFPolicy`
objects from the operator (bundle mode: `--operator`), set up as for raw Envoy: see [the policy from
the operator](raw-envoy.md#the-policy-from-the-operator), with `inkwall-engine spoe` in place of
`inkwall-engine ext-proc`. The operator doesn't wire an HAProxy it doesn't know (only the HAProxy
Kubernetes Ingress Controller, [above](#with-the-operator-haproxy-kubernetes-ingress-controller)), so the policy is `Programmed=False`
(`ControllerUnsupported`) and `Ready=False`; `Enforced` reports the engines.

## Client IP

The engine takes the client's address from `src`, HAProxy's client, and walks `X-Forwarded-For`
right to left from it through `--trusted-proxies`. When HAProxy is the edge, `src` is the client:
leave `--trusted-proxies` empty, and an `X-Forwarded-For` a client sends is ignored.

Behind a load balancer, `src` is the load balancer, unless the client's address comes with the
connection:

- **The [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt)** (recommended): `accept-proxy` on the `bind` line, and turn it on
  at the load balancer. `src` is then the client. Only the load balancer may reach HAProxy's port:
  anyone else could claim any address.
- **[`externalTrafficPolicy: Local`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip)** on HAProxy's Service, for a load balancer that keeps the
  client's address.
- **An HTTP load balancer's `X-Forwarded-For`**: add the load balancer's [CIDRs](https://www.rfc-editor.org/rfc/rfc4632) to the engine's
  `--trusted-proxies`.

[Client IP behind a load balancer](client-ip.md) has the load balancers' settings.

## Checking it worked

Send a benign request and an attack through HAProxy (here on `localhost:8080`):

```console
$ curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8080/'
200
$ curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8080/?id=1%27%20OR%20%271%27%3D%271'
403
```

In detect mode, the attack gets 200. Either way the engine logs one JSON line, `security event`,
with the action (`deny` or `log`), the matched rule IDs, the client IP and the request ID, which
the denial's `X-Request-Id` header carries. Its metrics are on `:9480/metrics`, with
`adapter="spoe"`. If every request gets 503, HAProxy can't reach the engine: check that it runs,
the socket path, and that HAProxy runs as the engine's user; `txn.inkwall.error` says why.

## Undoing it

Remove the `filter spoe` line and the `http-request` and `http-after-response` rules on
`txn.inkwall.*` from the frontend, and the `inkwall-engine` backend, then reload HAProxy. Stop the
engine.
