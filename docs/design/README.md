# Design documents

The numbered design documents behind Inkwall, and the status of each. They describe the target
design and say, section by section, what is built and what is not yet. Start with 0002 for the big
picture; the [glossary](../glossary.md) defines the terms all of them use.

| # | Title | Status | What it covers |
|---|---|---|---|
| [0001](0001-performance-first-architecture.md) | Performance-First Architecture | Draft | Latency budgets, the request pipeline, failure behaviour, measurements |
| [0002](0002-system-architecture.md) | System Architecture | Draft | Components, configuration, protocols, proxy integrations, decisions |
| [0004](0004-operator.md) | Kubernetes Operator | Draft | Injection, wiring, policy bundles, status, uninstall, scale |
| [0005](0005-component-map.md) | Component Map and Rule Engine Choice | Draft | Where each component runs, key flows, why Coraza |
| [0006](0006-adapter-protocols.md) | Adapter Protocols Primer | Draft | How each proxy asks the engine for a verdict |
| [0007](0007-inkwall-engine.md) | Inkwall Rule Engine | Draft | Inkwall's own rule engine for the [OWASP Core Rule Set](https://coreruleset.org/) (CRS), to reach the latency budgets |
| [0008](0008-assistants.md) | Assistants | Draft | `inkwallctl explain`, an MCP server for AI assistants, a docs assistant and a GitHub bot; the security rules for all of them |
| [0009](0009-rate-limits.md) | Rate Limits | Draft | Per-engine rate limits in tier T1: the `WAFPolicy` API, 429 with `Retry-After` per adapter, the engine's bounded table, observability, tests |
| [0010](0010-siem-export.md) | Exporting Security Events to a SIEM | Draft | Security events from the operator to a SIEM over OTLP or JSON: API, schema, buffering, security, status |
| [0011](0011-geo-blocking.md) | Geo Blocking | Draft | Allow or deny clients by country in tier T1: the `WAFPolicy` API, the user's MMDB compiled by the operator into a country table, its distribution, lookup cost, status, tests |
| [0012](0012-llm-api-protection.md) | Protecting LLM APIs | Draft | LLM API endpoints against the OWASP Top 10 for LLM Applications: what a WAF can and can't do per risk, request caps, injection signatures, leak checks on streamed responses, token-weighted rate limits, the false-positive corpus |

There is no 0003: no document with that number was ever published in this repository.

To add a document: number it sequentially, copy the header block (Status, Date, Updated, Owner,
and Depends on if any), add a short summary paragraph, and add a row here.
