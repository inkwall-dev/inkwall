# Diagrams

The SVGs here are generated with [Archify](https://github.com/tt-a1i/archify) (MIT), vendored at
v3.2.0 in [`.claude/skills/archify`](../../.claude/skills/archify). Each SVG follows the reader's
light or dark theme. The vendored copy leaves out upstream's pre-rendered example pages
(`examples/*.html`, about 13 MB); nothing in the build reads them.

| Diagram | Source | Used in |
|---|---|---|
| [System overview](system-overview.svg) | [`src/system-overview.architecture.json`](src/system-overview.architecture.json) | [README](../../README.md#how-it-works) |
| [Engine internals](engine-internals.svg) | [`src/engine-internals.architecture.json`](src/engine-internals.architecture.json) | [0005 §3](../design/0005-component-map.md#3-engine-internals) |
| [Verdict lifecycle](verdict-lifecycle.svg) | [`src/verdict-lifecycle.lifecycle.json`](src/verdict-lifecycle.lifecycle.json) | [0001 §7](../design/0001-performance-first-architecture.md#7-failure-behaviour) |
| [Traefik forward-auth](forward-auth.svg) | [`src/forward-auth.sequence.json`](src/forward-auth.sequence.json) | [0006 §3](../design/0006-adapter-protocols.md#3-forward-auth-traefik-forwardauth-nginx-auth_request) |
| [Check API](check-api.svg) | [`src/check-api.sequence.json`](src/check-api.sequence.json) | [0006 §5](../design/0006-adapter-protocols.md#5-v1check-inkwalls-own-api) |
| [Reverse proxy](reverse-proxy.svg) | [`src/reverse-proxy.sequence.json`](src/reverse-proxy.sequence.json) | [0006 §6](../design/0006-adapter-protocols.md#6-reverse-proxy-standalone-mode) |

## Changing a diagram

1. Edit its JSON in `src/`. The schemas are in `.claude/skills/archify/schemas/`. With Claude Code,
   ask it to "use Archify" to update the diagram; the skill is loaded from this repository.
2. Run `make diagrams` (needs Node 18+ and Chrome; `ARCHIFY_CHROME` sets Chrome's path). Archify
   validates each source, renders it, checks the result in a real browser, and exports the SVG.
   Any failure stops the run with the reason. The interactive HTML, with node details and source
   links, is written to `.archify/<name>/<name>.html` and is not committed.
3. Commit the JSON and the SVG together. The export is deterministic, so an unchanged source leaves
   the SVG unchanged.

## Source citations

Everything except the system overview describes the code as built. Those diagrams pin a commit in
`meta.repository.revision`, and each component, participant or state cites the lines that implement
it. `make diagrams` checks that every cited range exists at that commit. When the code changes, move
the revision forward and update the line ranges it reports. The system overview shows the target
design, so it cites nothing.

Cards (for example the "not built yet" list in the engine diagram) appear in the interactive HTML
but not in the SVG export, so the docs keep that information as text next to the image.
