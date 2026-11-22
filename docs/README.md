# Inkwall docs

Every doc in this repository, by topic, with the question each one answers.

## Contents

- [Get started](#get-started)
- [Guides](#guides)
- [Reference](#reference)
- [Design](#design)
- [Contributing](#contributing)

## Get started

- [Quickstart](quickstart.md): how do I see Inkwall block an attack in five minutes, on a local
  cluster?
- [README](../README.md): what is Inkwall, and how do I install it and protect my first route?
- [Helm chart](../deploy/helm/inkwall/README.md): what does the chart install, which values can I
  set, how do I uninstall it, and what happens when the operator or the engine is down?

## Guides

- [Running Inkwall in production](production.md): what do I set and check before production
  traffic depends on Inkwall?
- [Upgrading](upgrading.md): how do I upgrade an installation, and what changes on the way?
- [Client IP behind a load balancer](client-ip.md): how does the engine see the real client
  address behind a load balancer?
- [Rate limits](rate-limits.md): how do I limit a client's requests to a policy's routes, what
  does a limited client get, and why does each engine count on its own?
- [LLM APIs](llm-apis.md): how do I cap what clients send to an OpenAI-compatible or Anthropic
  API (models, prompt size, output tokens, roles, tools), and what can't a WAF do for an LLM?
- [Denial responses](denial-responses.md): how do I give denied clients an HTML page or a JSON
  document of my own, with the request ID in it, and which denials use it?
- [Rotating the bundle signing key](key-rotation.md): how do I replace the key that signs policy
  bundles, on demand or on a schedule?
- [Connecting to a control plane](control-plane.md): how do I connect a cluster to a control plane,
  what does the operator send it, and how do I disconnect?
- [GitOps](gitops.md): which fields does the operator write, and how do I keep Argo CD and Flux
  from reporting them as drift?
- [Testing policies offline](testing-policies.md): how do I test rules, `WAFPolicy` objects and
  the cluster's bundle with `inkwallctl`, locally or in CI?
- [Migrating from ingress-nginx's ModSecurity](migrating-from-ingress-nginx.md): how do I turn
  ingress-nginx's ModSecurity annotations into `WAFPolicy` objects, and what needs a human?
- [gRPC](grpc.md): what does the engine inspect in a gRPC call, and what doesn't it?
- [WebSocket](websocket.md): what does the engine inspect in a WebSocket, and how do I allow only
  my own origins?
- [Protecting routes served by Istio](istio.md): how does the operator protect the HTTPRoutes of
  Istio's Gateways and the VirtualServices of its ingress gateways, and what does a policy's
  status say there?
- [Protecting raw Envoy](raw-envoy.md): how do I protect an Envoy I configure myself with the
  engine's ext_proc adapter, with policies from flags or from the operator?
- [Protecting HAProxy](haproxy.md): how does the operator protect the Ingresses of the HAProxy
  Kubernetes Ingress Controller, how do I protect an HAProxy I configure myself with the engine's
  SPOE agent, and what does HAProxy do when the engine is down?
- [Troubleshooting](troubleshooting.md): is Inkwall working in this cluster, and what do I do when
  it isn't?
- [Using Inkwall from an AI assistant](mcp.md): how do I let Claude Code, Cursor or another MCP
  client answer questions about my cluster with Inkwall's read-only tools?
- [Monitoring](monitoring.md): how do I scrape Inkwall's metrics, install its alerts and dashboard,
  and what do I do when an alert fires?
- [The audit log of policy changes](audit-log.md): who changed which policy, rule set, IP list or
  `InkwallConfig`, when, and what changed?
- [Exporting security events to a SIEM](siem-export.md): how do I send blocked and detected
  requests to Splunk, Elastic, Loki, Datadog, Sentinel or an OpenTelemetry Collector?
- [Running the engine without Kubernetes](standalone-proxy.md): how do I put the engine in front
  of any HTTP service as a reverse proxy, and which flags does it take?

## Reference

- [API compatibility](api-compatibility.md): what may change in the `waf.inkwall.dev` API between
  releases, how a change is announced, and what v1.0.0 will freeze?
- [Chart values](../deploy/helm/inkwall/README.md#values): what does each chart value do?
- [Operator](../operator/README.md): what does the operator do, and how do I develop it?
- [Diagrams](diagrams/README.md): which diagrams do the docs use, and how do I change one?
- [Glossary](glossary.md): what does an Inkwall term, or an outside concept the docs use, mean,
  and where is its authoritative source?

## Design

- [Design documents](design/README.md): which design documents exist, and what is their status?
- [0001 — Performance-First Architecture](design/0001-performance-first-architecture.md): how does
  Inkwall keep the latency it adds within budget, and what happens when it fails?
- [0002 — System Architecture](design/0002-system-architecture.md): which components, protocols
  and proxy integrations make up Inkwall?
- [0004 — Kubernetes Operator](design/0004-operator.md): how does the operator inject the engine,
  wire the proxy and distribute policy bundles?
- [0005 — Component Map and Rule Engine Choice](design/0005-component-map.md): where does each
  component run, and why is the engine built on Coraza?
- [0006 — Adapter Protocols Primer](design/0006-adapter-protocols.md): how does each proxy ask the
  engine for a verdict?
- [0007 — Inkwall Rule Engine](design/0007-inkwall-engine.md): how will Inkwall's own Core Rule
  Set evaluator reach the latency budgets Coraza cannot?
- [0008 — Assistants](design/0008-assistants.md): how can users get answers faster: `inkwallctl explain`,
  an MCP server for the AI assistants they already use, a docs assistant and a GitHub bot, and the
  security rules every one of them follows.
- [0009 — Rate Limits](design/0009-rate-limits.md): how does a policy limit a client's requests,
  what does a limited client get, and why does each engine count on its own?
- [0010 — Exporting Security Events to a SIEM](design/0010-siem-export.md): how do security events
  reach a SIEM (Splunk, Elastic, Loki, Datadog), with or without the control plane?
- [0011 — Geo Blocking](design/0011-geo-blocking.md): how does a policy allow or deny clients by
  country, where does the country database come from, and how does it reach the engines?

## Contributing

- [Contributing](../CONTRIBUTING.md): how do I write commit messages, name branches and cut a
  release?
- [Code of Conduct](../CODE_OF_CONDUCT.md): how do we expect people in the community to behave?
- [Security policy](../SECURITY.md): how do I report a vulnerability, and which versions get fixes?
