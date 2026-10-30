# Security Policy

This policy covers how to report a vulnerability, what is in scope, which versions get fixes, and
safe harbor for researchers.

A vulnerability in Inkwall can expose the services it protects. Thank you for reporting
responsibly.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for security problems.** Report privately
through GitHub: [**Report a vulnerability**](https://github.com/inkwall-dev/inkwall/security/advisories/new)
(Security tab → "Report a vulnerability"). Include:

- the affected component (engine, adapter, operator, Helm chart, CLI) and version or commit;
- the proxy or [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/) and its version, if any;
- steps to reproduce, ideally a minimal request or manifest;
- the impact you observed (bypass, crash, privilege escalation, data exposure, ...).

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 7 days |
| Fix or mitigation | by severity; critical issues come before all other work |
| Public disclosure | coordinated with you; by default 90 days after the report or when a fix is released, whichever comes first |

We keep you informed, credit you in the advisory unless you prefer otherwise, and request a [CVE](https://www.cve.org/) for
confirmed vulnerabilities. Fixes are announced in
[GitHub Security Advisories](https://github.com/inkwall-dev/inkwall/security/advisories) and the
release notes.

## Scope

**In scope:** everything in this repository: `inkwall-engine` (request parsing and normalization,
adapters, policy bundle handling), `inkwall-operator` ([admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/), [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), [sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
injection), the [Helm](https://helm.sh/docs/) chart and its defaults, and `inkwallctl`. In particular:

- bypasses caused by Inkwall itself, e.g. the engine parsing or normalizing a request differently
  from the proxy in front of it;
- crafted traffic that makes the engine fail open, crash, or use unbounded CPU or memory (e.g.
  [regular expression denial of service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS));
- accepting a tampered or unsigned policy bundle;
- privilege escalation through the operator, its webhooks or the injected sidecar;
- request data (bodies, credentials, redacted headers) leaking into logs or events.

**Report elsewhere:**

- detection gaps in the **[OWASP Core Rule Set](https://coreruleset.org/)** itself (a payload CRS doesn't match even when
  Inkwall passes the request correctly): [CRS security policy](https://github.com/coreruleset/coreruleset/security/policy);
- vulnerabilities in **[OWASP Coraza](https://coraza.io/)**: [Coraza security policy](https://github.com/corazawaf/coraza/security/policy);
- vulnerabilities in a proxy or ingress controller ([Envoy](https://www.envoyproxy.io/docs/envoy/latest/), [HAProxy](https://docs.haproxy.org/), [ingress-nginx](https://kubernetes.github.io/ingress-nginx/), [Traefik](https://doc.traefik.io/traefik/), [Caddy](https://caddyserver.com/docs/)):
  that project's security process.

If you are unsure where an issue belongs, report it here and we will route it.

## Supported versions

Security fixes are provided for the **latest three minor versions**, as described in
[CONTRIBUTING.md](CONTRIBUTING.md#release-branches-and-patches).

## Safe harbor

We will not pursue legal action against researchers acting in good faith: test only systems you own
or are authorized to test, avoid privacy violations and service disruption, don't exfiltrate more
data than needed to demonstrate the issue, and give us reasonable time to fix it before disclosure.
