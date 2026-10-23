# Diagrams

The images used in the docs. They are exported SVGs that follow the reader's light or dark theme;
the tool and sources used to draw them are kept outside the repository.

| Diagram | Used in |
|---|---|
| [System overview](system-overview.svg) | [README](../../README.md#how-it-works) |
| [Engine internals](engine-internals.svg) | [0005 §3](../design/0005-component-map.md#3-engine-internals) |
| [Verdict lifecycle](verdict-lifecycle.svg) | [0001 §7](../design/0001-performance-first-architecture.md#7-failure-behaviour) |
| [Traefik forward-auth](forward-auth.svg) | [0006 §3](../design/0006-adapter-protocols.md#3-forward-auth-traefik-forwardauth-nginx-auth_request) |
| [Check API](check-api.svg) | [0006 §5](../design/0006-adapter-protocols.md#5-v1check-inkwalls-own-api) |
| [Reverse proxy](reverse-proxy.svg) | [0006 §6](../design/0006-adapter-protocols.md#6-reverse-proxy-standalone-mode) |

To change a diagram, regenerate the SVG and replace the file here, keeping its name so the links
still work. Diagrams of the engine describe the code as built, so update them when that code
changes.
