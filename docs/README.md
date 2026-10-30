# Inkwall docs

Every doc in this repository, by topic, with the question each one answers.

## Get started

- [README](../README.md): what is Inkwall, and how do I install it and protect my first route?
- [Helm chart](../deploy/helm/inkwall/README.md): what does the chart install, which values can I
  set, and how do I uninstall it?

## Guides

- [Upgrading](upgrading.md): how do I upgrade an installation, and what changes on the way?
- [Client IP behind a load balancer](client-ip.md): how does the engine see the real client
  address behind a load balancer?
- [Rotating the bundle signing key](key-rotation.md): how do I replace the key that signs policy
  bundles, on demand or on a schedule?
- [Connecting to a control plane](control-plane.md): how do I connect a cluster to a control plane,
  what does the operator send it, and how do I disconnect?
- [GitOps](gitops.md): which fields does the operator write, and how do I keep Argo CD and Flux
  from reporting them as drift?
- [Testing policies offline](testing-policies.md): how do I test rules, `WAFPolicy` objects and
  the cluster's bundle with `inkwallctl`, locally or in CI?
- [Running the engine without Kubernetes](standalone-proxy.md): how do I put the engine in front
  of any HTTP service as a reverse proxy, and which flags does it take?

## Reference

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

## Contributing

- [Contributing](../CONTRIBUTING.md): how do I write commit messages, name branches and cut a
  release?
- [Code of Conduct](../CODE_OF_CONDUCT.md): how do we expect people in the community to behave?
- [Security policy](../SECURITY.md): how do I report a vulnerability, and which versions get fixes?
