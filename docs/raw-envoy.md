# Protecting raw Envoy

This guide puts Inkwall in front of an [Envoy](https://www.envoyproxy.io/docs/envoy/latest/) you configure yourself, outside [Envoy Gateway](https://gateway.envoyproxy.io/) and
[Istio](https://istio.io/latest/docs/): on a host, in Docker, or as a Deployment in Kubernetes. Envoy's
[ext_proc filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) sends each request to `inkwall-engine ext-proc`, which runs next to Envoy and
answers with a verdict. The operator doesn't configure Envoy for you: you add the filter to your
`envoy.yaml`, and take the policy either from the engine's flags or from an Inkwall operator in the
same cluster.

The samples in [`examples/raw-envoy`](../examples/raw-envoy) are the files this guide shows, and
the tests run them: `make raw-envoy-e2e` in Docker, `make kind-e2e-raw-envoy` on [kind](https://kind.sigs.k8s.io/).

## Contents

- [Prerequisites](#prerequisites)
- [How it works](#how-it-works)
- [Run the engine next to Envoy](#run-the-engine-next-to-envoy)
- [Configure Envoy](#configure-envoy)
  - [The complete envoy.yaml](#the-complete-envoyyaml)
  - [Block mode and detect mode](#block-mode-and-detect-mode)
  - [Timeout and failure mode](#timeout-and-failure-mode)
  - [Bodies](#bodies)
  - [Responses](#responses)
  - [Routes left uninspected](#routes-left-uninspected)
- [The policy from flags](#the-policy-from-flags)
- [The policy from the operator](#the-policy-from-the-operator)
  - [Read access to the bundle](#read-access-to-the-bundle)
  - [The trust ConfigMap](#the-trust-configmap)
  - [Deploy Envoy with the engine](#deploy-envoy-with-the-engine)
  - [The policy's status](#the-policys-status)
- [Client IP](#client-ip)
- [Checking it worked](#checking-it-worked)
- [Undoing it](#undoing-it)

## Prerequisites

- Envoy 1.33 or later, whose ext_proc filter tells the engine its processing mode. The samples are
  tested with Envoy v1.39.6 (`envoyproxy/envoy:v1.39.6`). `envoy.yaml` needs 1.36 for
  `status_on_error`: on 1.33 to 1.35, remove that setting, and Envoy answers 500 instead of 503
  when it can't reach the engine.
- `inkwall-engine`, from the [releases page](https://github.com/inkwall-dev/inkwall/releases), or the image
  `ghcr.io/inkwall-dev/inkwall-engine`.
- For [the policy from the operator](#the-policy-from-the-operator): Envoy in a Kubernetes cluster
  with Inkwall installed, Kubernetes 1.29 or later (for the engine as a native sidecar), and
  `kubectl`.

## How it works

1. Envoy opens one [gRPC](https://grpc.io/docs/) stream to the engine per HTTP request, and sends it the request
   headers, then the body.
2. The engine inspects the request with the OWASP [Core Rule Set](https://coreruleset.org/) and answers: continue, or an
   immediate response with its status (403 for an attack, 413 for an oversized body, 503 when it
   can't inspect the request).
3. In block mode Envoy holds the request until the answer comes. In detect mode Envoy sends a copy
   (ext_proc's `observability_mode`) and forwards the request without waiting; the engine logs
   what it would have blocked.

The responses aren't sent to the engine, unless you [turn response inspection on](#responses). [ext_proc](design/0006-adapter-protocols.md#2-ext_proc-envoy-external-processing) has the details of the protocol.

## Run the engine next to Envoy

The engine listens on a Unix socket or on loopback, so that only Envoy reaches it. Run it where
Envoy runs:

- **On a host**, as a process next to Envoy's, on loopback:

  ```sh
  inkwall-engine ext-proc --listen 127.0.0.1:9003 --mode block \
    --trusted-proxies 127.0.0.1/32,::1/128
  ```

  or on a Unix socket, `--listen unix:/var/run/inkwall/extproc.sock`. Envoy needs write
  permission on the socket file, which the engine creates as `0755` under the usual umask
  (`022`): run Envoy as the engine's user.
- **In a pod**, as a sidecar in Envoy's pod, on a Unix socket in an [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) both containers
  mount. The engine's image runs as user 65532: run Envoy as 65532 too. The engine is a
  [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) (an init container with `restartPolicy: Always`), so Envoy starts only once the
  engine serves; [`kubernetes.yaml`](../examples/raw-envoy/kubernetes.yaml) does this.
- **In Docker**, in Envoy's network namespace (`--network container:<envoy>`), on loopback or on a
  socket in a shared volume. `hack/raw-envoy/e2e.sh` runs it this way.

`--trusted-proxies 127.0.0.1/32,::1/128` trusts the `X-Forwarded-For` that Envoy sends: see
[client IP](#client-ip). The engine's `/healthz`, `/readyz` and `/metrics` are on `:9480`
(`--admin-listen`).

## Configure Envoy

### The complete envoy.yaml

[`envoy.yaml`](../examples/raw-envoy/envoy.yaml), for block mode, with the engine on a Unix socket
and the app at `app:80`:

<!-- examples/raw-envoy/envoy.yaml: hack/raw-envoy/e2e.sh checks that this copy is the file. -->
```yaml
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Envoy in front of an app, every request inspected by Inkwall before it is
# forwarded: block mode. The engine runs next to Envoy (a sidecar in the same
# pod, or a process on the same host) and serves ext_proc on a Unix socket:
#
#   inkwall-engine ext-proc --listen unix:/var/run/inkwall/extproc.sock \
#     --mode block --trusted-proxies 127.0.0.1/32,::1/128
#
# Envoy must run as the engine's user (65532 in the engine image) to connect
# to the socket. Check this file with `envoy --mode validate -c envoy.yaml`.
# See docs/raw-envoy.md.
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {address: 0.0.0.0, port_value: 8080}
      # Envoy holds a body for the engine up to this buffer (BUFFERED_PARTIAL
      # below): keep it at least the engine's --max-body-bytes (64 KiB by
      # default), or larger bodies are handled as oversized (--oversize-body).
      per_connection_buffer_limit_bytes: 1048576
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                # Envoy is the edge: X-Forwarded-For ends with the address of
                # its TCP peer, which the engine walks right to left
                # (--trusted-proxies). Behind a load balancer, see "Client IP"
                # in docs/raw-envoy.md.
                use_remote_address: true
                route_config:
                  virtual_hosts:
                    - name: app
                      domains: ["*"]
                      routes:
                        # A route left uninspected: the filter is off here.
                        - match: {path: /healthz}
                          route: {cluster: app}
                          typed_per_filter_config:
                            envoy.filters.http.ext_proc:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute
                              disabled: true
                        - match: {prefix: /}
                          route: {cluster: app}
                http_filters:
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      grpc_service:
                        envoy_grpc: {cluster_name: inkwall}
                      # The request headers, and the body in one message, held
                      # by Envoy until the engine answers; nothing of the
                      # response.
                      processing_mode:
                        request_header_mode: SEND
                        request_body_mode: BUFFERED_PARTIAL
                        request_trailer_mode: SKIP
                        response_header_mode: SKIP
                        response_body_mode: NONE
                        response_trailer_mode: SKIP
                      # The client's protocol (HTTP/1.1, HTTP/2, ...), for the
                      # rules.
                      request_attributes: [request.protocol]
                      # The engine's deadline (--timeout, 250ms by default)
                      # plus 500ms: the engine decides a slow request itself,
                      # with its failure mode; this is for a hung engine.
                      message_timeout: 0.75s
                      # An engine Envoy can't reach: rejected, as the engine's
                      # failure mode in block mode (closed). true lets the
                      # request through uninspected (--failure-mode open).
                      failure_mode_allow: false
                      # 503, as the engine answers a request it can't inspect;
                      # Envoy's default is 500.
                      status_on_error: {code: ServiceUnavailable}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    # The engine: gRPC (HTTP/2) on its Unix socket.
    - name: inkwall
      type: STATIC
      connect_timeout: 1s
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
      load_assignment:
        cluster_name: inkwall
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    pipe: {path: /var/run/inkwall/extproc.sock}
    # The app.
    - name: app
      type: STRICT_DNS
      connect_timeout: 1s
      load_assignment:
        cluster_name: app
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {address: app, port_value: 80}
```

Check a changed configuration with `envoy --mode validate -c envoy.yaml`. For an engine on loopback,
replace the `pipe` address with `socket_address: {address: 127.0.0.1, port_value: 9003}`, as
[`envoy-detect.yaml`](../examples/raw-envoy/envoy-detect.yaml) does.

### Block mode and detect mode

Envoy's settings and the engine's `--mode` go together:

| Engine `--mode` | Envoy | Effect |
|---|---|---|
| `block` | `processing_mode` as in `envoy.yaml`, no `observability_mode` | Attacks get 403; Envoy holds each request until the engine answers |
| `detect` | `observability_mode: true` and `request_body_mode: STREAMED`, as in [`envoy-detect.yaml`](../examples/raw-envoy/envoy-detect.yaml) | Nothing is blocked; Envoy doesn't wait; the engine logs each match |
| `detect` | as for `block` | Nothing is blocked, but each request waits for the engine |
| `block` | `observability_mode: true` | **Nothing is blocked**: Envoy ignores the engine's answers. Don't. |

Start in detect mode, tune [false positives](https://coreruleset.org/docs/concepts/false_positives_tuning/), then switch the engine and Envoy to block mode
together. `observability_mode` allows only `STREAMED` bodies: the engine gathers the chunks up to its
body limit.

### Timeout and failure mode

- **`message_timeout`**: the engine's deadline (`--timeout`, 250 ms by default, or the largest
  `timeout` of your policies in [bundle mode](#the-policy-from-the-operator)) plus 500 ms. The engine
  decides a request it can't inspect in time itself, with its failure mode; Envoy's timeout is for an
  engine that hangs.
- **`failure_mode_allow`**: what Envoy does when it can't reach the engine (stopped, restarting,
  hung). Match the engine's failure mode: `false` when it fails closed (`--failure-mode closed`, the
  default in block mode), `true` when it fails open (`--failure-mode open`, the default in detect
  mode). With `true` in block mode, stopping the engine lets attacks through.
- **`status_on_error`**: the status Envoy answers with when `failure_mode_allow` is `false`. Envoy's
  default is 500; `envoy.yaml` sets 503, as the engine answers a request it can't inspect.

### Bodies

`BUFFERED_PARTIAL` sends the body in one message, up to Envoy's buffer, and Envoy holds the request
until the engine answers it. Keep the listener's `per_connection_buffer_limit_bytes` (1 MiB in
`envoy.yaml`, also Envoy's default) at least the engine's body limit (`--max-body-bytes`, 64 KiB by
default, or the largest `body.maxBytes` of your policies): a body Envoy cuts at a smaller buffer is
handled as oversized (`--oversize-body`, or the policy's `body.onOversize`). With
`request_body_mode: NONE`, bodies go uninspected, and are handled as oversized too.

### Responses

New in 0.4.0, off by default. With `--inspect-responses`, the engine also inspects what the app
answers, for data leaks: the CRS's `RESPONSE-95x` rules find SQL errors, stack traces, directory
listings and source code, and your own `--rules` on `RESPONSE_*` variables run too. In block mode a
response that leaks is replaced with 403 and the same plain-text error as a denied request; in detect
mode it is logged (`"phase":"response"` in the security event, which never carries a snippet of the
response body). Envoy must send the responses: in `processing_mode`, and with `allow_mode_override`
next to it:

```yaml
processing_mode:
  request_header_mode: SEND
  request_body_mode: BUFFERED_PARTIAL   # STREAMED with observability_mode
  request_trailer_mode: SKIP
  response_header_mode: SEND
  response_body_mode: BUFFERED_PARTIAL  # STREAMED with observability_mode
  response_trailer_mode: SKIP
# A response whose body the rules don't read (an image, a download, Server-Sent
# Events) is decided on its headers, and Envoy neither buffers nor sends its body.
allow_mode_override: true
```

- **What is read:** the status and headers always; the body when its `Content-Type` is `text/plain`,
  `text/html`, `text/xml`, `application/json`, `application/xml` or `application/problem+json`, up
  to `--max-response-bytes` (512 KiB by default, 10 MiB at most). A `gzip` or `deflate` body is
  decoded first; the engine also removes `Accept-Encoding` from the requests it forwards, so most apps
  answer uncompressed.
- **Larger bodies:** their first `--max-response-bytes` are inspected, and then
  `--oversize-response` decides: `deny` replaces the response with 502 in block mode, `allow` lets it
  through; `auto` (the default) denies in block mode and allows in detect mode. A body in another
  encoding (`br`, `zstd`) or one Envoy cut short is handled the same way.
- **Envoy's buffer:** in block mode Envoy holds the response until the engine answers. Keep the app
  cluster's `per_connection_buffer_limit_bytes` (1 MiB by default) at least `--max-response-bytes`,
  or longer bodies arrive cut and are handled as oversized.
- **Cost:** one more evaluation per response, under the same `--timeout`, `--max-concurrent` and
  failure mode as the request (an overloaded engine replaces the response with 503 when it fails
  closed). Time to first byte grows by the body's buffering and its inspection. Responses are counted
  in `inkwall_responses_total` and timed in `inkwall_response_check_duration_seconds`.

[ext_proc](design/0006-adapter-protocols.md#response-inspection-v040) has the details. With the
policy [from the operator](#the-policy-from-the-operator), the policy's `responses` field
(`inspect`, `maxBytes`, `onOversize`) takes the place of the flags, which are refused with
`--operator`; Envoy must still send the responses, as above.

### Routes left uninspected

Turn the filter off on a route, a virtual host or a whole route configuration with
`typed_per_filter_config`, as `envoy.yaml` does for `/healthz`:

```yaml
typed_per_filter_config:
  envoy.filters.http.ext_proc:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute
    disabled: true
```

The engine's `--skip-paths` (or a policy's `skipPaths`) does the same on the engine's side, but Envoy
still calls the engine.

## The policy from flags

Without Kubernetes, or without the operator, the engine's flags are the policy, as for the
[standalone proxy](standalone-proxy.md#flags): `--mode`, `--failure-mode`, `--timeout`,
`--paranoia-level`, `--rules` and `--rules-before-crs` ([SecLang](https://coraza.io/docs/seclang/) rules and exclusions),
`--skip-paths`, `--disable-rule-groups`, `--max-body-bytes`, and for [responses](#responses)
`--inspect-responses`, `--max-response-bytes` and `--oversize-response`. Every request Envoy sends gets that
one policy; `inkwall-engine ext-proc -h` lists the flags. To test rules before you deploy them, see
[testing policies offline](testing-policies.md).

## The policy from the operator

With Envoy in a cluster where Inkwall is installed, the engine can take `WAFPolicy` objects from the
operator, as the engines it injects do (bundle mode: `--operator`). Raw Envoy isn't one of the
operator's integrations, so you set up what injection sets up for Traefik and Envoy Gateway: the
read access, the trust ConfigMap and the sidecar. [`examples/raw-envoy`](../examples/raw-envoy) is
a [kustomization](https://kubectl.docs.kubernetes.io/references/kustomize/) with all of it, in the namespace `raw-envoy`, and a `WAFPolicy`.

The policy's routes are hosts and paths. Describe Envoy's as an `Ingress` whose class no controller
serves (`ingressClassName: raw-envoy` in the sample), and target it; the engine matches each request's
`:authority` and path against them. A request no policy covers is allowed uninspected (`no-policy`).
The bundle's policies set the mode, failure mode, timeout and body limits; your `envoy.yaml` must
agree with them, as [above](#block-mode-and-detect-mode): use block mode's settings when any policy
blocks.

### Read access to the bundle

The operator's distribution server accepts an engine whose [ServiceAccount](https://kubernetes.io/docs/concepts/security/service-accounts/) may `get` the bundle
Secret, `inkwall-system/inkwall-bundle`, and the engine reads that Secret (and its chunk Secrets,
`inkwall-bundle-a-0` to `-b-7`, for a bundle over 900 KiB) when it starts while the operator is
down. The sample's `Role` and `RoleBinding`, `raw-envoy-bundle-reader` in `inkwall-system`, grant
this to the ServiceAccount `raw-envoy/envoy`. Give yours a name of its own: `inkwall-bundle-reader`
is the operator's, which it manages.

**The bundle holds every namespace's policies and rules.** Whoever may run a pod as that
ServiceAccount may read them, and connect an engine to the operator. That is why the operator
grants this access only to proxy pods in the proxy namespaces
([GHSA-r5cq-6vq5-q8qg](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-r5cq-6vq5-q8qg), [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces)). Grant it, as the sample does, only to a dedicated
ServiceAccount in a namespace where only the people who run Envoy create pods. Don't run your apps
in Envoy's namespace. `injection.proxyNamespaces` needn't list that namespace: the operator injects
and grants nothing there.

### The trust ConfigMap

The engine checks the operator's certificate with the operator's CA, and each bundle's signature
with the bundle keys. The operator keeps them in an `inkwall-trust` ConfigMap only in the namespaces
of the proxies it injects; in Envoy's namespace you keep it:

```sh
kubectl create namespace raw-envoy
kubectl -n inkwall-system get secret inkwall-operator-webhook-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
kubectl -n inkwall-system get secret inkwall-bundle-signing-key -o jsonpath='{.data.trusted-keys\.pub}' | base64 -d > trusted-keys.pub
kubectl -n raw-envoy create configmap inkwall-trust --from-file=ca.crt --from-file=trusted-keys.pub
```

Both are public. When the operator [rotates its signing key](key-rotation.md#when-a-rotation-waits),
the rotation waits until your engines trust the new key: create the ConfigMap again from the Secret
(`kubectl ... --dry-run=client -o yaml | kubectl apply -f -`). The engine rereads it when the kubelet
updates the file.

### Deploy Envoy with the engine

Set the engine image in [`kustomization.yaml`](../examples/raw-envoy/kustomization.yaml) to your
operator's version, then:

```sh
kubectl apply -k examples/raw-envoy
```

This creates Envoy (two replicas, Service `envoy`) with the engine as a native sidecar, the app
(`traefik/whoami`, Service `app`), the read access, the `Ingress` and a `WAFPolicy` in `Block` mode
for `app.example.com`. Envoy's configuration is `envoy.yaml`, as a generated ConfigMap: a change
rolls Envoy's pods. The engine's flags are those the operator gives the engines it injects:

- `--operator=inkwall-operator.inkwall-system.svc:9445`, and the operator's CA, a token for the
  audience `inkwall-operator` and the bundle keys, in a [projected volume](https://kubernetes.io/docs/concepts/storage/projected-volumes/);
- `--bundle-cache`, an `emptyDir` file, so a restarted engine enforces its last bundle at once;
- `--bundle-secret=inkwall-system/inkwall-bundle`, with a token and CA for the API server, for a new
  pod while the operator is down;
- `--bootstrap=deny`, not in the sample, to reject requests (503) instead of letting them through
  uninspected while an engine has no bundle at all.

The policy flags (`--mode`, `--rules`, ...) can't be combined with `--operator`.

### The policy's status

The operator doesn't wire raw Envoy: your `envoy.yaml` does. So the policy is
`Programmed=False`, reason `ControllerUnsupported` (its Ingress's class has no controller Inkwall
knows), and `Ready=False`. `Enforced` reports the engines: `True`, `every engine runs bundle <n> or
later`, once Envoy's engines run the policy.

```sh
kubectl -n raw-envoy get wafpolicy app -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'
```

## Client IP

The engine takes the client's address from `X-Forwarded-For`, walked right to left through
`--trusted-proxies`; Envoy, on loopback or the Unix socket, is `127.0.0.1`. With
`use_remote_address: true` (as in the samples), Envoy appends the address of its TCP peer to
`X-Forwarded-For` before the filter runs, so the engine sees that peer, whatever the client sent.

When Envoy is the edge, its peer is the client. Behind a load balancer, its peer is the load
balancer, unless the client's address comes with the connection:

- **The [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt)** (recommended): add Envoy's [proxy_protocol listener filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/proxy_protocol)
  to the listener, and turn it on at the load balancer. Only the load balancer may reach Envoy's
  port then: anyone else could claim any address.
- **[`externalTrafficPolicy: Local`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip)** on Envoy's Service, for a load balancer that keeps the
  client's address.
- **An HTTP load balancer's `X-Forwarded-For`**: set `xff_num_trusted_hops` in Envoy and add the
  load balancer's [CIDRs](https://www.rfc-editor.org/rfc/rfc4632) to the engine's `--trusted-proxies`, so both skip it.

[Client IP behind a load balancer](client-ip.md) has the load balancers' settings.

## Checking it worked

Send a benign request and an attack through Envoy (here on `localhost:8080`; in the sample's
cluster, `kubectl -n raw-envoy port-forward svc/envoy 8080:80`):

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: app.example.com' 'localhost:8080/'
200
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: app.example.com' 'localhost:8080/?id=1%27%20OR%20%271%27%3D%271'
403
```

In detect mode, the attack gets 200. Either way the engine logs one JSON line, `security event`,
with the action (`deny` or `log`), the matched rule IDs and the client IP:

```sh
kubectl -n raw-envoy logs deploy/envoy -c inkwall-engine | grep '"security event"' | tail -1
```

Its metrics are on `:9480/metrics`, with `adapter="extproc"`. If every request gets 503 in block
mode, Envoy can't reach the engine: check that it runs, the socket path, and that Envoy runs as the
engine's user.

## Undoing it

Remove the `envoy.filters.http.ext_proc` filter and the `inkwall` cluster from `envoy.yaml` (or turn
the filter off on the virtual host, as [above](#routes-left-uninspected)), reload Envoy, then stop
the engine. Remove the filter first: in block mode, Envoy answers 503 while the engine is stopped.
For the sample, `kubectl delete -k examples/raw-envoy` removes everything, the read access
included; delete the `inkwall-trust` ConfigMap with the namespace.
