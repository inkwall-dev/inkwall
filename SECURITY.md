# Security Policy

Inkwall is a security product, so vulnerabilities in it matter twice: they can expose the
services it protects. Thank you for reporting responsibly.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for security problems.**

Report privately through GitHub:
[**Report a vulnerability**](https://github.com/inkwall-dev/inkwall/security/advisories/new)
(Security tab → "Report a vulnerability").

Please include:

- the affected component (engine, a specific adapter, operator, Helm chart, CLI) and version or
  commit,
- the proxy / ingress controller and version involved, if any,
- steps to reproduce, ideally a minimal request or manifest,
- the impact you observed (bypass, crash, privilege escalation, data exposure, ...).

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Initial assessment and severity | within 7 days |
| Fix or mitigation for confirmed issues | depends on severity; critical issues are prioritized over all other work |
| Public disclosure | coordinated with you, by default within 90 days of the report or when a fix is released, whichever comes first |

We will keep you informed throughout, credit you in the advisory unless you prefer otherwise, and
request a CVE for confirmed vulnerabilities. Fixes are announced through
[GitHub Security Advisories](https://github.com/inkwall-dev/inkwall/security/advisories) and the
release notes.

## Scope

**In scope** — everything in this repository:

- `inkwall-engine`, including request parsing and normalization, adapters, and policy bundle
  handling,
- `inkwall-operator`, its admission webhooks, RBAC, and sidecar injection,
- the Helm chart and default configuration,
- `inkwallctl`.

Examples of what we especially want to hear about:

- **Bypasses caused by Inkwall itself**, for example the engine parsing or normalizing a request
  differently from the proxy in front of it, so an attack passes inspection.
- Ways to make the engine fail open, crash, or consume unbounded CPU or memory (for example
  regular expression denial of service) with crafted traffic.
- Accepting a tampered or unsigned policy bundle.
- Privilege escalation through the operator, webhooks, or the injected sidecar.
- Leaking request data (bodies, credentials, redacted headers) into logs or events.

**Report elsewhere:**

- Detection gaps in the **OWASP Core Rule Set** rules themselves (a payload that CRS does not
  match even when Inkwall passes the request correctly):
  [CRS security policy](https://github.com/coreruleset/coreruleset/security/policy).
- Vulnerabilities in **OWASP Coraza**: [Coraza security policy](https://github.com/corazawaf/coraza/security/policy).
- Vulnerabilities in a proxy or ingress controller (Envoy, HAProxy, ingress-nginx, Traefik, Caddy):
  that project's own security process.

If you are unsure where an issue belongs, report it here and we will route it.

## Supported versions

Inkwall has not had a release yet. Once it does, security fixes are provided for the **latest three
minor versions**, as described in [CONTRIBUTING.md](CONTRIBUTING.md#release-branches-and-patches).

## Safe harbor

We will not pursue legal action against researchers who act in good faith: test only against
systems you own or are authorized to test, avoid privacy violations and service disruption, do not
exfiltrate data beyond what is needed to demonstrate the issue, and give us reasonable time to fix
it before disclosure.
