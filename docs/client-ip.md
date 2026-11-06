# Client IP behind a load balancer

This guide gets the real client address to the engine when [Traefik](https://doc.traefik.io/traefik/) runs behind a load balancer. With
[Envoy Gateway](https://gateway.envoyproxy.io/), see [Envoy Gateway](#envoy-gateway); behind an HTTP load balancer (an AWS ALB,
a cloud L7 LB) that adds `X-Forwarded-For`, see [Behind an HTTP load balancer](#behind-an-http-load-balancer).

The engine gives the client's address to the rules ([SecLang](https://coraza.io/docs/seclang/)'s `REMOTE_ADDR`) and records it in
security events; the planned IP lists and rate limits will key on it too. Behind a load balancer
(LB), Traefik sees the LB, or a node, as its peer, and so does the engine, unless the real address
reaches Traefik. A wrong client IP is worse than none: a rule against one address would block the
LB, and every client would look like the same one.

There are two ways to get the address to Traefik: the [PROXY protocol](#the-proxy-protocol-recommended)
(recommended), or [`externalTrafficPolicy: Local`](#externaltrafficpolicy-local-without-the-proxy-protocol)
on Traefik's [Service](https://kubernetes.io/docs/concepts/services-networking/service/).

## Contents

- [Prerequisites](#prerequisites)
- [How the address reaches the engine](#how-the-address-reaches-the-engine)
- [Why not `X-Forwarded-For` from the LB](#why-not-x-forwarded-for-from-the-lb)
- [The PROXY protocol (recommended)](#the-proxy-protocol-recommended)
  - [Traefik (Helm chart `traefik/traefik`)](#traefik-helm-chart-traefiktraefik)
  - [Load balancers](#load-balancers)
- [`externalTrafficPolicy: Local` (without the PROXY protocol)](#externaltrafficpolicy-local-without-the-proxy-protocol)
- [Envoy Gateway](#envoy-gateway)
- [Behind an HTTP load balancer](#behind-an-http-load-balancer)
  - [Trusted proxies](#trusted-proxies)
  - [Trusted hops](#trusted-hops)
  - [What each proxy sends](#what-each-proxy-sends)
- [Checking it worked](#checking-it-worked)
- [Undoing it](#undoing-it)

## Prerequisites

- Inkwall installed, with the engine injected into Traefik's pods.
- Traefik exposed through a [`LoadBalancer` or `NodePort`](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types) Service, and access to its configuration
  (here, the [Helm chart `traefik/traefik`](https://github.com/traefik/traefik-helm-chart)) and to the load balancer's settings.

## How the address reaches the engine

1. Traefik learns the client's address: from the [PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt), or as the TCP peer when nothing
   rewrites it (`externalTrafficPolicy: Local`).
2. The [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) Middleware the operator creates (`trustForwardHeader: false`) sends Traefik's
   view of the client to the engine as [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For), replacing any the client sent.
3. The injected engine trusts `X-Forwarded-For` only from its loopback peer, Traefik
   (`--trusted-proxies=127.0.0.1/32,::1/128`), and walks it right to left.

Inkwall needs no setting for this: configure Traefik and the LB.

## Why not `X-Forwarded-For` from the LB

An HTTP LB could add `X-Forwarded-For`, and Traefik's `forwardedHeaders.trustedIPs` would keep it.
But the engine only sees it if the Middleware has `trustForwardHeader: true`, and then Traefik also
keeps a client-sent `X-Forwarded-Uri`, `-Method` and `-Host`: the engine would inspect a URI the
attacker chose, not the one the app serves (verified on Traefik v3.7.13; see
[0006](design/0006-adapter-protocols.md)). The operator therefore always sets `false`, and the
address has to come from the connection itself.

## The PROXY protocol (recommended)

The LB opens each TCP connection to Traefik with a PROXY header (v1 or v2) carrying the client's
address. Traefik accepts it from the addresses you trust and uses it as the connection's remote
address. It works for HTTP and TLS alike, and the LB never parses HTTP.

### Traefik (Helm chart `traefik/traefik`)

```yaml
ports:
  web:
    proxyProtocol:
      trustedIPs: ["10.0.0.0/16"]   # the LB's addresses only
  websecure:
    proxyProtocol:
      trustedIPs: ["10.0.0.0/16"]
```

Without Helm: `--entryPoints.web.proxyProtocol.trustedIPs=10.0.0.0/16` (and `websecure`).
Traefik detects the version (v1 or v2) by itself.

- **Trust only the LB's [CIDRs](https://www.rfc-editor.org/rfc/rfc4632)**, or the nodes' when [kube-proxy](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/) forwards from them (see below).
  Never `0.0.0.0/0` and never `insecure: true`: anyone who reaches Traefik could then claim any
  address, get past IP rules and frame others in your events.
- A PROXY header from an untrusted address is read and its address ignored; the connection
  keeps its real peer. A connection without a header is accepted from any address. Neither is
  logged as an error, so check an event's client IP after the change.
- `trustedIPs` must contain the peer Traefik actually sees. With `externalTrafficPolicy: Cluster`
  (the default) on an LB that targets nodes, that is the node that forwarded the packet, not the
  LB; with the LB targeting pods directly, it is the LB.
- Turn the PROXY protocol on at both ends at once. A Traefik expecting it still accepts plain
  connections, so enable Traefik first, then the LB.
- In-cluster clients calling the LB's address may be routed straight to Traefik by kube-proxy,
  without the LB and without a header: they show up with their own pod or node address.

### Load balancers

| Load balancer | How to send the PROXY header |
|---|---|
| AWS NLB ([AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/service/annotations/)) | `service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: "*"` (v2), or `aws-load-balancer-target-group-attributes: proxy_protocol_v2.enabled=true`. Don't combine with instance targets and `externalTrafficPolicy: Local` ([NLB guide](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/service/nlb/)). |
| AWS Classic ELB (in-tree provider) | The same annotation, `"*"`: PROXY v1 on every backend ([cloud-provider-aws](https://github.com/kubernetes/cloud-provider-aws/blob/master/docs/service_controller.md)). |
| GCP | A GKE `LoadBalancer` Service (passthrough Network LB) keeps the client's address but has no PROXY option: use `externalTrafficPolicy: Local`. A proxy Network LB (target TCP proxy) sends v1 with `--proxy-header=PROXY_V1` ([docs](https://cloud.google.com/load-balancing/docs/tcp/setting-up-tcp)). |
| Azure | Azure Load Balancer is layer 4 and keeps the client's address; we found no PROXY option: use `externalTrafficPolicy: Local`. Behind Private Link Service, `service.beta.kubernetes.io/azure-pls-proxy-protocol: "true"` sends v2 ([cloud-provider-azure](https://cloud-provider-azure.sigs.k8s.io/topics/pls-integration/)); its health probes then carry the header too. |
| DigitalOcean | `service.beta.kubernetes.io/do-loadbalancer-enable-proxy-protocol: "true"` ([annotations](https://github.com/digitalocean/digitalocean-cloud-controller-manager/blob/master/docs/controllers/services/annotations.md)). |
| Hetzner Cloud | `load-balancer.hetzner.cloud/uses-proxyprotocol: "true"` ([hcloud-cloud-controller-manager](https://github.com/hetznercloud/hcloud-cloud-controller-manager)). |
| MetalLB, kube-vip | Don't proxy connections, so send no header: use `externalTrafficPolicy: Local` ([MetalLB](https://metallb.io/usage/), [kube-vip](https://kube-vip.io/docs/usage/kubernetes-services/)). |
| HAProxy in front of the cluster | `server traefik 10.0.0.5:443 send-proxy-v2 check` (`send-proxy` for v1) in a `mode tcp` backend ([configuration](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)). |

Annotations go on Traefik's Service, with the chart's `service.annotations`. Check them against
your provider's current docs; the cloud controllers change them.

## `externalTrafficPolicy: Local` (without the PROXY protocol)

For a `NodePort` or `LoadBalancer` Service whose LB doesn't rewrite the source address (passthrough
LBs, MetalLB, kube-vip), set on Traefik's Service:

```yaml
service:
  spec:
    externalTrafficPolicy: Local
```

kube-proxy then delivers only to Traefik pods on the node that received the packet, without
[SNAT](https://kubernetes.io/docs/tutorials/services/source-ip/), so Traefik sees the client's address. Trade-offs
([Kubernetes docs](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip)):

- Nodes without a ready Traefik pod drop the traffic; an LB learns this from the
  `healthCheckNodePort`, a NodePort reached directly doesn't. Run Traefik on every node that takes
  traffic (a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)), or spread it with [anti-affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity).
- The LB weighs nodes, not pods: a node with two Traefik pods gets the same share as one with one.
- With MetalLB in layer 2 mode, only the leader node's pods get traffic.

## Envoy Gateway

Through Envoy Gateway, the engine runs in each Envoy pod and gets the request from Envoy's
[ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) filter on a Unix socket, which it trusts as a loopback peer. Envoy sets
`X-Forwarded-For` before the filter runs, ending with the address of its own TCP peer, and the
engine walks it right to left as above. So, as with Traefik, Envoy must see the client as its
peer: turn the PROXY protocol on in a `ClientTrafficPolicy` for the Gateway, or set
`externalTrafficPolicy: Local` on the Envoy Service through your `EnvoyProxy`, as Envoy Gateway's
[client traffic policy](https://gateway.envoyproxy.io/docs/tasks/traffic/client-traffic-policy/) docs show.

Envoy Gateway applies one `ClientTrafficPolicy` per Gateway. The operator creates its own,
`inkwall-waf-<gateway>`, which raises Envoy's buffer limit so the engine gets whole bodies, only
for a Gateway that has none of yours, and deletes it once you add yours. Your
`connection.bufferLimit` then caps the bodies inspected: set it to at least the largest
`body.maxBytes` of your policies (Envoy's default buffer is 32 KiB). Below it, bodies over your
buffer are handled as oversized (`body.onOversize`), and the policy's `Programmed` condition is
`WiringFailed`, naming your ClientTrafficPolicy. If you delete yours, the operator creates its own
again.

Behind an HTTP load balancer, Envoy keeps its `X-Forwarded-For` and appends the LB's address: see
[Behind an HTTP load balancer](#behind-an-http-load-balancer). Check it as below, with the engine's
logs in an Envoy pod (`-c inkwall-engine`). The kind end-to-end test checks it through Envoy
Gateway, with and without a trusted proxy.

## Behind an HTTP load balancer

An HTTP (layer 7) LB, such as an AWS Application Load Balancer, a GCP external Application Load
Balancer or Azure Application Gateway, ends the client's connection and opens its own to the
proxy, adding the client's address to `X-Forwarded-For`. The proxy's peer is then the LB, and so is
every event's `client_ip`, until the engines trust the LB's entry. The InkwallConfig says which
(`spec.engine.clientIP`, engines 0.5.0 or later):

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  engine:
    clientIP:
      trustedProxies: [10.0.0.0/16]   # the LB's addresses: here, the VPC's subnets
      # trustedHops: 1                # or: one LB, whatever its address
```

The engine walks `X-Forwarded-For` from the right. It skips the entries of the proxy beside it
(always trusted, on the loopback), then `trustedHops` entries, then entries from `trustedProxies`.
The first other entry is the client. Entries may carry a port (`198.51.100.7:4711`,
`[2001:db8::1]:4711`). The settings apply to pods injected after the change: Envoy Gateway rolls its
Envoy pods itself, and other proxies' pods need a restart (`kubectl rollout restart`).

**A wrong setting lets clients choose their address.** `X-Forwarded-For` is a request header: any
client can send one, and the LB keeps it, adding the address it saw to the right. Trust only what
is in front of the proxy, and only if every request goes through it:

- If the proxy can also be reached directly, not only through the LB (a public `LoadBalancer`
  Service next to the ALB, a NodePort), a client that does so can send any `X-Forwarded-For`. With
  `trustedHops: 1`, its own forged entry is taken as the LB's, and the one left of it as the client.
  Prefer `trustedProxies` with the LB's own addresses, and close other paths to the proxy.
- `trustedProxies: [0.0.0.0/0]` trusts every address: the webhook warns, and any client chooses
  its address.
- Count the hops: an ALB behind a CDN that appends too (CloudFront) is two hops.

### Trusted proxies

List the addresses the LB connects from:

| Load balancer | Its addresses |
|---|---|
| AWS ALB | Addresses in the subnets it was created in: the VPC CIDR, or those subnets' CIDRs. The ALB appends the client to `X-Forwarded-For` by default ([`routing.http.xff_header_processing.mode: append`](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html)). |
| GCP external Application LB | `35.191.0.0/16` and `130.211.0.0/22`; it appends `<client>, <LB>` ([docs](https://cloud.google.com/load-balancing/docs/https#x-forwarded-for_header)): with `trustedProxies` only, also list the LB's own address, or use `trustedHops: 2`. |
| Azure Application Gateway | Its subnet's CIDR; it appends `<client>:<port>` ([docs](https://learn.microsoft.com/en-us/azure/application-gateway/how-application-gateway-works#modifications-to-the-request)). |

Check these against your provider's current docs.

### Trusted hops

When the LB's addresses aren't known in advance, `trustedHops: N` takes the N entries right of
the proxy's own as proxies, whatever their address. It is only as safe as the guarantee that every
request passes those N proxies.

### What each proxy sends

| Proxy | What the engine gets | Trusting the LB works |
|---|---|---|
| Envoy Gateway | Envoy's `X-Forwarded-For`: the LB's header, with the LB's address appended (Envoy Gateway's default, `useRemoteAddress`). | Yes. |
| Istio (Gateway API or ingress gateway) | The same, from the gateway's Envoy. Istio's own `numTrustedProxies` changes what Istio decides on, not the engine's `X-Forwarded-For`. | Yes. |
| HAProxy | HAProxy's peer (the LB) as the engine's peer, and the request's `X-Forwarded-For` as received. | Yes, with `trustedProxies`. `trustedHops` needs a trusted peer: list the LB. |
| Traefik | Traefik's own view of the client only: its ForwardAuth replaces the header (see [Why not `X-Forwarded-For` from the LB](#why-not-x-forwarded-for-from-the-lb)). | No: use the [PROXY protocol](#the-proxy-protocol-recommended). |

The engine can also read `Forwarded` (RFC 7239) instead, with `--client-ip-header=forwarded`, when
it runs on its own ([standalone proxy](standalone-proxy.md)) behind a proxy that sets or replaces
that header. The InkwallConfig doesn't offer it: the proxies the operator wires append their peer to
`X-Forwarded-For` only, so in `Forwarded` nothing would tell the client's own entries from the LB's.

## Checking it worked

Send a request that a policy blocks or detects through the LB, then read the engine's
`security event` log line in a Traefik pod (or the event in your control plane):

```sh
kubectl -n <traefik namespace> logs deploy/<traefik> -c inkwall-engine | grep '"security event"' | tail -1
```

Its `client_ip` should be your address, not the LB's, a node's or a pod's. The [kind](https://kind.sigs.k8s.io/) end-to-end test
(`make kind-e2e-traefik`) checks this with a PROXY header for a public address, a client-sent
`X-Forwarded-For` that must not change it, and a PROXY header from an untrusted source that must be
ignored.

## Undoing it

Undo the changes in the reverse order: turn the PROXY protocol off on the LB first, then remove
`proxyProtocol` from Traefik's entry points. A Traefik that expects the PROXY protocol still accepts
plain connections, but requests the LB sends with a PROXY header fail on a Traefik that doesn't
expect one.
To undo `externalTrafficPolicy: Local`, set it back to `Cluster`, the default. In both cases the
engine sees the LB's or a node's address again.
