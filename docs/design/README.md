# Design documents

The numbered design documents behind Inkwall, and the status of each. They describe the target
design and say, section by section, what is built and what is not yet. Start with 0002 for the big
picture; its [glossary](0002-system-architecture.md#13-glossary) defines the terms all of them use.

| # | Title | Status | What it covers |
|---|---|---|---|
| [0001](0001-performance-first-architecture.md) | Performance-First Architecture | Draft | Latency budgets, the request pipeline, failure behaviour, measurements |
| [0002](0002-system-architecture.md) | System Architecture | Draft | Components, configuration, protocols, proxy integrations, decisions |
| [0004](0004-operator.md) | Kubernetes Operator | Draft | Injection, wiring, policy bundles, status, uninstall, scale |
| [0005](0005-component-map.md) | Component Map and Rule Engine Choice | Draft | Where each component runs, key flows, why Coraza |
| [0006](0006-adapter-protocols.md) | Adapter Protocols Primer | Draft | How each proxy asks the engine for a verdict |
| [0007](0007-inkwall-engine.md) | Inkwall Rule Engine | Draft | Inkwall's own rule engine for the OWASP Core Rule Set (CRS), to reach the latency budgets |

There is no 0003: no document with that number was ever published in this repository.

To add a document: number it sequentially, copy the header block (Status, Date, Updated, Owner,
and Depends on if any), add a short summary paragraph, and add a row here.
