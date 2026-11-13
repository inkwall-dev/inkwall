# Troubleshooting

This guide checks whether Inkwall works in a cluster, says what every condition reason means and
what to do about it, explains a policy that isn't `Ready` and a denied request, finds the rule
behind a denial, moves a policy from `Detect` to `Block`, and says what happens when a component
is down.

## Contents

- [Cluster status](#cluster-status)
  - [Permissions](#permissions)
  - [JSON output](#json-output)
- [Conditions](#conditions)
  - [WAFPolicy](#wafpolicy)
  - [WAFRuleSet and ClusterWAFRuleSet](#wafruleset-and-clusterwafruleset)
  - [InkwallConfig](#inkwallconfig)
- [Explaining a policy or a denial](#explaining-a-policy-or-a-denial)
  - [Explain a policy](#explain-a-policy)
  - [Explain a denied request](#explain-a-denied-request)
  - [Permissions of explain](#permissions-of-explain)
  - [JSON output of explain](#json-output-of-explain)
- [Finding a denial](#finding-a-denial)
  - [What a denied client sees](#what-a-denied-client-sees)
- [From Detect to Block](#from-detect-to-block)
- [When something is down](#when-something-is-down)

## Cluster status

`inkwallctl status` answers "is Inkwall working in this cluster?" from the current kubeconfig
context, read only:

```console
$ inkwallctl status
InkwallConfig: mode Standalone, suspended no
Operator: 2/2 replicas ready in inkwall-system, version 0.5.0
Bundle: version 7, 4096 bytes compressed

Proxies:
  CONTROLLER                     INTEGRATION  SUPPORT      REQUESTS  RESPONSES  WS MESSAGES  GRPC MESSAGES
  traefik.io/ingress-controller  traefik      Full         yes       no         no           yes
  k8s.io/ingress-nginx           -            Unsupported  no        no         no           no
  k8s.io/ingress-nginx: Inkwall has no integration for this controller

Policies: 2 of 2 Ready

Engines: 2 connected
  VERSION  CURRENT  BEHIND  REJECTED
  v0.5.0   2        0       0

OK: nothing needs attention.
```

It reports:

- **The InkwallConfig**: its mode and whether inspection is suspended.
- **The operator**: its replicas and the version they run, and the bundle it publishes.
- **The proxies** the cluster's IngressClasses and GatewayClasses name: whether Inkwall wires
  them, and what the engine inspects through each. Responses are inspected through Envoy Gateway
  only, and WebSocket messages only through the standalone proxy.
- **The policies that aren't `Ready`**, grouped by the reason of their `Ready` condition, with
  its message. `kubectl get wafpolicies -A` shows the same reason in its `REASON` column.
- **The engines**: how many run the current bundle, are behind, or rejected it, by engine
  version. Engines behind, rejecting the bundle, or of another version than the operator are
  named by pod, with what to do: an engine of another version runs until its pod restarts.

Without `inkwallctl`, the InkwallConfig's status has the cluster view too: the bundle version and
size against its limit, the engines by state, the signing key and its rotation, and whether the
integrations' selectors apply:

```sh
kubectl get inkwallconfig default
kubectl get inkwallconfig default -o jsonpath='{.status.bundle}{"\n"}{.status.engines}{"\n"}{.status.signingKey}{"\n"}'
```

It exits 0 when nothing needs attention, 1 when something does (the report ends with what), and 2
on an error. Flags: `--kubeconfig`, `--context`, `--namespace` (the operator's, default
`inkwall-system`), `-o json`.

### Permissions

It only reads. The permissions it needs:

| Resource | Where | Verbs |
|---|---|---|
| `inkwallconfigs`, `wafpolicies` (`waf.inkwall.dev`) | cluster | `get`, `list` |
| `pods` | the operator's namespace | `list` |
| `configmaps` | the operator's namespace | `list` (the engine reports, labeled `waf.inkwall.dev/engines=true`) |
| `secrets`, name `inkwall-bundle` | the operator's namespace | `get` (the bundle's version and size; the bundle is signed policy, no credentials) |

Without the pods or the Secret it reports what it can, with a warning.

### JSON output

`-o json` prints one object. Its fields are only ever added to, never renamed or removed, so
scripts can rely on them:

| Field | Meaning |
|---|---|
| `healthy` | `false` when something needs attention (the exit status is then 1) |
| `problems` | What needs attention, one sentence each |
| `warnings` | What couldn't be read |
| `config.exists`, `config.mode`, `config.suspended` | The InkwallConfig `default` (`exists: false`: there is none, every setting is its default) |
| `config.conditions[]` | Its conditions: `type`, `status`, `reason`, `message` |
| `operator.namespace`, `operator.versions[]`, `operator.pods`, `operator.ready` | The operator's replicas and the image tags they run |
| `bundle.version`, `bundle.compressedBytes`, `bundle.chunks` | The bundle the operator publishes; `null` when it can't be read |
| `proxies[]` | `controller`, `integration`, `support` (`Full`, `Partial`, `Unsupported`), `message`, `ingressClasses[]`, `gatewayClasses[]`, and `inspects`: `requests`, `responses`, `webSocketMessages`, `grpcMessages` |
| `policies.total`, `policies.ready` | WAFPolicy counts |
| `policies.notReady[]` | `reason` and `policies[]` (`namespace`, `name`, `message`); `Unknown` when the operator hasn't reported on a policy's generation yet |
| `engines.total`, `engines.leftOut` | Connected engines; `leftOut` didn't fit the operator's reports |
| `engines.byVersion[]` | `version`, and how many are `current`, `behind`, `rejected` |
| `engines.attention[]` | `namespace`, `pod`, `version`, `state`, `applied`, `rejected`, `rejectError`, `outdated` (not the operator's version), `hint` |

For example, the policies that aren't `Ready`:

```sh
inkwallctl status -o json | jq -r '.policies.notReady[] | .reason as $r | .policies[] | "\(.namespace)/\(.name) \($r): \(.message)"'
```

## Conditions

`kubectl describe` shows an object's conditions; each has a reason and a message that names what
to fix. `kubectl get wafpolicies -A` shows the `Ready` condition's reason.

### WAFPolicy

A policy is `Ready` when it is `Accepted`, `Programmed` and `Enforced`. Otherwise `Ready` takes
the reason of the first of these that isn't `True` (and `Suspended` before any): fix that one.
`inkwallctl explain policy <namespace>/<name>` walks the conditions and prints the cause and the
fix from these tables ([Explaining a policy or a denial](#explaining-a-policy-or-a-denial)).

**Ready**: its own reasons, while a condition isn't reported yet.

<!-- reasons: WAFPolicy Ready -->
| Reason | Meaning | Fix |
|---|---|---|
| `Ready` | `Accepted`, `Programmed` and `Enforced`: the policy is in force on every target. | |
| `NotAccepted` | The operator hasn't reported `Accepted` on this generation yet. It lasts seconds. | If it lasts, check that the operator runs: `inkwallctl status`. |
| `NotProgrammed` | The operator hasn't reported `Programmed` on this generation yet. It lasts seconds. | If it lasts, check that the operator runs: `inkwallctl status`. |
| `NotEnforced` | The operator hasn't reported `Enforced` on this generation yet. It lasts seconds. | If it lasts, check that the operator runs: `inkwallctl status`. |
<!-- end reasons -->

**Accepted**: the policy is valid, and in the bundle.

<!-- reasons: WAFPolicy Accepted -->
| Reason | Meaning | Fix |
|---|---|---|
| `Accepted` | Valid, and in the bundle the engines get. | |
| `InvalidRef` | A rule set, ConfigMap or key the policy (or its rule set) names doesn't exist, or isn't labeled `waf.inkwall.dev/rules=true`. Or a rule set bound with `placement: BeforeCRS` can't load there: the built-in CRS, or SecLang with `SecRuleRemoveBy*` or `SecRuleUpdate*`. | Create it, or fix the name. The message names it. Move those directives to a rule set placed `AfterCRS` (the default). |
| `RuleCompileError` | Rules in the policy's rule set don't compile, or use a directive Inkwall doesn't allow. | Fix the rules; `inkwallctl test --rule-set` shows the error before you apply. |
| `Conflict` | An older policy targets the same route and applies to it: a route has one policy. | Merge the policies, or target other routes. |
| `TargetUnsupported` | A target's match rules (an IngressRoute's, HTTPRoute's or VirtualService's) aren't ones the router can match, so its requests can't be told apart. | Use the forms the message lists (`Host`, `Path`, `PathPrefix`; exact and prefix paths). |
| `BundleTooLarge` | The bundle with this version of the policy is over 7,200 KiB compressed, so it isn't published; engines keep the previous one. | Move shared inline rules into one rule set that the policies reference; see [InkwallBundleNearSizeLimit](monitoring.md#inkwallbundlenearsizelimit). |
<!-- end reasons -->

**Programmed**: the policy's targets are wired to the engine in their proxy.

<!-- reasons: WAFPolicy Programmed -->
| Reason | Meaning | Fix |
|---|---|---|
| `Programmed` | Every target is wired, in a proxy whose pods run the engine. | |
| `NoTargets` | None of the policy's targets exists. | Fix `targetRefs`, or create the route. |
| `ControllerUnsupported` | A target is served by a proxy Inkwall has no integration for, or is of a kind not wired yet. | Target routes of a supported proxy; `inkwallctl status` lists the proxies. |
| `IntegrationDisabled` | The operator may not wire the proxy that serves a target: its ClusterRole isn't granted (`rbac.integrations`). | Set the chart value to `true` (or `auto` once the proxy is installed), and `helm upgrade`. |
| `InjectionDisabled` | The chart's `injection.enabled` is `false`: no proxy pod gets the engine, so nothing is wired. | Turn injection on. |
| `SidecarMissing` | The proxy's pods don't run the engine: none is in the proxy namespaces, the InkwallConfig's selector doesn't match them, they were created while the operator was down, or they opted out. Their traffic isn't inspected. | Add the namespace to `injection.proxyNamespaces`, fix the selector, or restart the pods the message names. |
| `PendingRestart` | Proxy pods started before Inkwall run without the engine (or Envoy Gateway is replacing its pods with ones that have it). | Restart them: `kubectl rollout restart`. |
| `Pending` | Wired, but not in force yet: the proxy hasn't loaded the configuration. | Wait; if it lasts, check the proxy's logs. |
| `Unverified` | Wired, but the operator's probe hasn't proven the filter on every pod (HAProxy, Istio), or got another answer than the engine's: the filter isn't on the route. Also every Istio route in `Detect` mode, whose answer Envoy discards. | HAProxy: check the controller has the operator's snippets ([HAProxy](haproxy.md)). Istio: see [the operator's probe](istio.md#the-operators-probe); another `EnvoyFilter` may remove or bypass Inkwall's. |
| `NotProbeable` | The operator's probe can't target an Istio route (a rule whose every match is a regular expression, a server with mutual TLS or passthrough, or header or query match values over TLS, which the probe doesn't send to a certificate it doesn't verify), so its filter can't be proven; the message says which. | Add an exact or prefix match to the rule, or accept it unproven: [Istio](istio.md#the-operators-probe). |
| `WiringFailed` | The operator couldn't change the proxy's objects (a conflict, a webhook, permissions). | The message names the object and the error; `kubectl -n inkwall-system logs deploy/inkwall-operator` has more. |
| `ResponsesNotInspected` | The policy inspects responses, but a target's proxy can't send them to the engine (only Envoy Gateway can). Its requests are inspected; the policy isn't `Programmed`, so it doesn't claim the responses are. | Remove `responses`, or target routes Envoy Gateway serves. |
| `Unwired` | `helm uninstall` (the unwire hook) unwired the routes and stopped the operator. | Reinstall to protect the routes again. |
<!-- end reasons -->

**Enforced**: every connected engine runs a bundle with this version of the policy.

<!-- reasons: WAFPolicy Enforced -->
| Reason | Meaning | Fix |
|---|---|---|
| `Enforced` | Every engine runs the bundle, or a later one. | |
| `NotInBundle` | The policy's current spec isn't in a published bundle yet. | Wait; if it lasts, see `Accepted`. |
| `NoEngines` | No engine is connected to the operator. | Check the proxy pods run the engine (`Programmed`), and that engines reach the operator ([InkwallEngineDisconnected](monitoring.md#inkwallenginedisconnected)). |
| `EnginesBehind` | Some engines don't run the bundle yet. | Usually seconds; if it lasts, `inkwallctl status` names them. |
| `EngineNack` | An engine rejected the bundle; the message names it and why (often an engine older than the operator, or a key it doesn't trust). | Restart the engine's pod so it runs the operator's version; see [InkwallBundleRejected](monitoring.md#inkwallbundlerejected). |
| `EnginesOutdated` | An engine runs the bundle, but is too old to enforce a field the policy sets, which it ignores. | Restart the pod the message names. |
| `EnginesUnreported` | An operator replica's engine report is full, so not every engine is known. | Run more operator replicas, or fewer proxy pods per replica. |
| `Suspended` | The InkwallConfig suspends inspection: every engine allows every request. | `kubectl patch inkwallconfig default --type merge -p '{"spec":{"suspend":false}}'`. |
<!-- end reasons -->

### WAFRuleSet and ClusterWAFRuleSet

`Accepted`, with the reasons `Accepted`, `InvalidRef` (a ConfigMap or key that doesn't exist, or
an unknown built-in rule set) and `RuleCompileError` (rules that don't compile), as above.

### InkwallConfig

<!-- reasons: InkwallConfig -->
| Condition | Reason | Meaning | Fix |
|---|---|---|---|
| `Suspended` | `Suspended` | The bundle the engines get suspends inspection (`spec.suspend`). | Resume when ready. |
| `Suspended` | `NotSuspended` | Inspection runs. | |
| `SigningKeyRotation` | `Idle` | No signing key rotation is in progress. | |
| `SigningKeyRotation` | `Publishing` | A rotation published the next key; the active one signs until every engine trusts it. The message, and `status.signingKey.waitingFor`, say what it waits for. | If it lasts, restart the engines the message names ([key rotation](key-rotation.md#when-a-rotation-waits)). |
| `SigningKeyRotation` | `Retiring` | The new key signs; the previous one stays trusted until every engine runs a bundle the new one signed. | As for `Publishing`. |
| `IntegrationsConfigured` | `Configured` | The integrations' proxy pod selectors apply. | |
| `IntegrationsConfigured` | `InvalidSelector` | A `spec.integrations` selector can't be applied (an unknown operator); the operator keeps the selectors it runs with. | Fix the selector the message names. |
| `EngineConfigured` | `Configured` | The engine is injected with every `spec.engine` setting. | |
| `EngineConfigured` | `EngineTooOld` | `spec.engine.image` pins an engine release too old for some settings (`logLevel`, `policyMetrics`, `jsonDenials`, `clientIP.trustedHops` need 0.5.0): it is injected without them, since it would exit on a flag it doesn't know. The message names them. | Pin a newer engine, or remove the settings. |
| `EngineConfigured` | `EngineVersionUnknown` | `spec.engine.image`'s tag isn't a release (`latest`, a digest alone, a custom build), so the engine is injected without the settings some release doesn't know. | Tag the image with its version, such as `:0.6.0` or `:0.6.0@sha256:...`. |
| `EngineRollout` | `RollingOut` | `spec.engine.rollout: Automatic`: the operator evicted a proxy pod for a new engine and waits for its replacement. | |
| `EngineRollout` | `Done` | No proxy pod the operator injects needs a new engine. | |
| `EngineRollout` | `Paused` | An eviction was refused (a PodDisruptionBudget) or a replacement isn't ready in time; nothing else is evicted. The message says which. | Relax the budget, or fix the replacement pod the message names (is the Pod webhook answering?). |
| `ControlPlaneConnected` | `Connected` | Connected to the control plane. | |
| `ControlPlaneConnected` | `InvalidEndpoint` | `spec.controlPlane.endpoint` isn't a valid address. | Fix it. |
| `ControlPlaneConnected` | `EnrollmentTokenMissing` | The enrollment token Secret, or its `token` key, is missing. | Create it ([control plane](control-plane.md)). |
| `ControlPlaneConnected` | `EnrollmentTokenNotInOperatorNamespace` | The token Secret isn't in the operator's namespace. | Move it there. |
| `ControlPlaneConnected` | `EnrollmentTokenRejected` | The control plane refused the token: unknown, expired or used. | Store a new token. |
| `ControlPlaneConnected` | `EnrollFailed` | Enrolling failed for another reason; the message says which. | Retry is automatic; fix what the message names. |
| `ControlPlaneConnected` | `CertificateRejected` | The control plane rejected the cluster's certificate. | Store a new enrollment token. |
| `ControlPlaneConnected` | `CertificateExpired` | The cluster's certificate expired before it was renewed. | Store a new enrollment token. |
| `ControlPlaneConnected` | `ClusterDisabled` | The control plane removed or disabled the cluster. | Change the configuration to try again. |
| `ControlPlaneConnected` | `Unreachable` | The control plane can't be reached; the operator retries. Engines enforce as before. | Check network access to the endpoint. |
<!-- end reasons -->

## Explaining a policy or a denial

`inkwallctl explain` answers *why isn't my policy `Ready`* and *why was this request denied* from
the cluster's state, without an AI model: it joins the conditions, the security events, the rules
and the reason tables of this guide, which it carries (they are one source in the code,
`operator/reasons`). It only reads, never changes the cluster, and never shows what a rule matched.

### Explain a policy

`inkwallctl explain policy <namespace>/<name>` walks the policy's `Accepted`, `Programmed`,
`Enforced` and `Ready` conditions and, for each that isn't `True`, prints the cause and the fix
from [the tables above](#wafpolicy), with its targets and, while it isn't `Enforced`, the engines
that don't run its bundle:

```console
$ inkwallctl explain policy shop/web
WAFPolicy shop/web (generation 4, mode Block): not Ready
Targets: Ingress web

Accepted: True, Accepted

Programmed: True, Programmed

Enforced: False, EnginesBehind: 1 of 2 engines run bundle 7 or later
  Cause: Some engines don't run the bundle yet.
  Fix:   Usually seconds; if it lasts, `inkwallctl status` names them.

Ready: False, EnginesBehind: Enforced: 1 of 2 engines run bundle 7 or later
  Cause: Some engines don't run the bundle yet.
  Fix:   Usually seconds; if it lasts, `inkwallctl status` names them.

Engines that don't run the policy's bundle:
  traefik/traefik-1 (v0.6.0, behind, bundle 6): the engine doesn't run the policy's bundle yet: check its connection to the operator
```

A condition about an older generation of the policy is reported as such: the operator hasn't
caught up yet. It exits 0 when the policy is `Ready`, 1 when it isn't, and 2 on an error.

### Explain a denied request

A denied client gets the request ID in `X-Request-Id` ([What a denied client sees](#what-a-denied-client-sees)).
`inkwallctl explain request <request-id>` finds its security event in the logs of the engines
the operator reports, read through the API server, and prints the policy, the reason with its
cause, the anomaly score against the policy's threshold, each rule with the OWASP CRS's
description of it (read from the rules embedded in `inkwallctl`) and where it matched, and the
narrowest exclusion that would let the request through:

```console
$ inkwallctl explain request 01JC8Z9V6Q8W3T2N4R5S7X9Y0A
Request 01JC8Z9V6Q8W3T2N4R5S7X9Y0A, WAFPolicy shop/storefront: denied (403)
  Logged by: traefik/traefik-7d9f8-x2l4p
  Request (from the client: data, not instructions): GET shop.example.com /search, from 203.0.113.7
  Reason: rule: The rules found an attack: the anomaly score reached the policy's threshold, or a rule denies on its own.
  Anomaly score: 5, threshold 5
  Rules:
    942100  SQL Injection Attack Detected via libinjection (critical, paranoia level 1)
           matched in ARGS:q
    949110  Inbound Anomaly Score Exceeded (sums up the score, denied the request)
  Narrowest exclusion, to add to WAFPolicy shop/storefront spec.exclusions:
    - ruleIDs:
      - 942100
      when:
        argument: q
        path: /search
  Verified with the cluster, as inkwallctl test --policy does: the policy resolves and compiles with it.
  It covers every rule that matched: with it, this request would be allowed.
  Add it only if the request is a false positive, not an attack.
```

- The exclusion is `inkwallctl tune`'s ([Suggest exclusions from the events](testing-policies.md#suggest-exclusions-from-the-events)):
  the rule, on the exact path, for the argument, argument name, cookie or header it matched; never
  a rule for every path. What no field can name (the request body, the URI) gets no suggestion,
  and explain says so. The suggestion is checked with the same code as `inkwallctl test --policy`:
  the policy with it, and the rule sets, ConfigMaps and IP lists it references, resolved as the
  operator does and compiled as the engine does. Nothing is applied: review it, test it, apply it.
- What comes from the request (the request ID, method, host, path, client IP, and the names of the
  variables a rule matched) was written by the client, maybe to mislead whoever reads it: it is
  printed quoted when it holds anything but printable text, and listed under `untrusted` in JSON.
  The matched values are never shown: the engine's log doesn't have them, and explain ignores the
  snippets of the events API's events.
- `--file FILE` reads the events from a file (`kubectl logs` output, a log store's export, or the
  events API's JSON lines; `-` is standard input) instead of the cluster, and `--policy`,
  `--rule-set`, `--configmap` and `--ingress` give the objects to check the suggestion with, as
  `inkwallctl test` takes them; without them, the policy is read from the cluster.
- `--pod <namespace>/<name>` reads only those engine pods, `--since` how far back (default 24h).
- Engine log lines are rate-limited per policy and rule, so a repeated denial may have no line of
  its own: explain then exits 1 and says where it looked. It exits 0 when it found the request,
  and 2 on an error.

### Permissions of explain

Read only, like `inkwallctl status`:

| Resource | Where | Verbs | For |
|---|---|---|---|
| `wafpolicies` (`waf.inkwall.dev`) | the policy's namespace | `get` | both |
| `configmaps` | the operator's namespace | `list` | the engine reports: which pods run an engine (without `--pod`), and the engines behind |
| `pods`, `pods/log` | the engine pods' namespaces | `get` | `explain request`, without `--file` |
| `wafrulesets`, `clusterwafrulesets`, `wafiplists`, and the `configmaps` rule sets read from | as referenced | `get` | checking the suggestion, without `--policy` |

What it may not read makes the answer smaller, with a warning: a suggestion it can't check is
marked not verified.

### JSON output of explain

`-o json` prints one object, for scripts and for assistants: `inkwallctl mcp` serves the same answers
to an AI assistant ([Using Inkwall from an AI assistant](mcp.md)).
As for `inkwallctl status`, its fields are only ever added to, never renamed or removed.

`explain policy`:

| Field | Meaning |
|---|---|
| `kind` | `PolicyExplanation` |
| `namespace`, `name`, `generation`, `mode` | The policy |
| `ready` | `true` when `Ready` is `True` for this generation (the exit status is then 0) |
| `targets[]` | `kind`, `name`, `sectionName` |
| `conditions[]` | `type`, `status`, `reason`, `message`, `current` (`false`: about an older generation), and for one that isn't `True`, `cause` and `fix` from this guide |
| `engines[]` | While the policy isn't `Enforced`: the engines that don't run its bundle, as `inkwallctl status`'s `engines.attention[]` |
| `warnings` | What couldn't be read |

`explain request`:

| Field | Meaning |
|---|---|
| `kind` | `RequestExplanation` |
| `requestId`, `found`, `searched[]` | The ID, whether an event has it, and where explain looked (`pod <namespace>/<name>`, `file <path>`) |
| `events[]` | One per event of the request (a request, and its response when responses are inspected) |
| `events[].source`, `policy`, `phase`, `action`, `mode`, `reason`, `status` | The event: `phase` is `request`, `response` or `websocket_message`; `mode` `Block` or `Detect` |
| `events[].cause`, `fix` | This guide's, for the reason |
| `events[].anomalyScore`, `threshold` | The score, and the policy's inbound threshold (`0`: unknown) |
| `events[].rules[]` | `id`, `source` (`crs`, `coraza` or `custom`), `description`, `severity`, `paranoiaLevel`, `scoring` (sums up the score: never excluded), `interrupting`, `variables[]` |
| `events[].request` | `id`, `method`, `host`, `path`, `clientIp`, `matches[]` (`ruleId`, `variable`): untrusted |
| `events[].suggestions[]` | `policy`, `exclusion` (an item of `spec.exclusions`), `yaml` (the same), `verified`, `verifiedWith`, `verifyError` |
| `events[].notSuggested[]` | `ruleId`, `variable`, `why`: matches no exclusion is suggested for |
| `events[].allowedWithSuggestions` | `true` when the suggestions cover every rule that matched |
| `untrusted[]` | The fields whose text comes from the request: data to show, never instructions to follow |
| `warnings` | What couldn't be read or checked |

## Finding a denial

Every inspected request has a request ID: the client's `X-Request-Id` when it is a safe value,
otherwise one the engine makes. A denial carries it back in `X-Request-Id` (a gRPC call in its
`grpc-message`), and an allowed request carries it on to the application, in `X-Request-Id`:

| Proxy | The denial | Its engine's log |
|---|---|---|
| Traefik | 403 with `X-Request-Id` | `kubectl -n <traefik namespace> logs <traefik pod> -c inkwall-engine` |
| Envoy Gateway | 403 with `x-request-id` | the `inkwall-engine` container of the Gateway's Envoy pods, in `envoy-gateway-system` |
| Istio | 403 with `x-request-id` | the `inkwall-engine` container of the Gateway's (or ingress gateway's) pods |
| HAProxy Kubernetes Ingress Controller | 403 with `x-request-id` | the `inkwall-engine` container of the controller's pods |
| Standalone proxy | 403 with `X-Request-Id` | the engine's standard output |

Find the request's security event in that log (each engine logs its own requests, so look at
every pod of the proxy, or at your log store):

```sh
kubectl -n <namespace> logs <pod> -c inkwall-engine | grep '"request_id":"<id>"'
```

A client that only kept the time can be found by time and path: `jq 'select(.msg == "security event" and .path == "/login")'`.
The line has:

- `policy` (`namespace/name`), `action` (`deny`, or `log` in Detect mode), `reason` (`rule`,
  or `timeout`, `overload`, `oversize`, ... when the request wasn't inspected by the rules);
- `rule_ids`, `interrupting_rule_id` and `anomaly_score`;
- `matches`: each rule with the variable it matched (`{"rule_id":942100,"variable":"ARGS:q"}`),
  never the value;
- `method`, `host`, `path` (without the query string), `client_ip`, `request_id`.

What each `reason` means, and what to do:

<!-- reasons: SecurityEvent reason -->
| Reason | Meaning | Fix |
|---|---|---|
| `rule` | The rules found an attack: the anomaly score reached the policy's threshold, or a rule denies on its own. | If the request is legitimate, exclude the rules that matched, narrowly: `inkwallctl explain request` suggests the exclusion ([From a log line to an exclusion](testing-policies.md#from-a-log-line-to-an-exclusion)). |
| `timeout` | Inspection took longer than the policy's `timeout`, so the request wasn't inspected; the policy's `failureMode` decided. | Raise `timeout`, or give the engine more CPU. |
| `error` | The rules engine failed on the request; the policy's `failureMode` decided. | The engine's log around the event says why; report it if it repeats. |
| `overload` | Every inspection slot of the engine was busy, so the request wasn't inspected; the policy's `failureMode` decided. | Run more proxy replicas, or give the engine more CPU; see [InkwallEvaluationSlotsSaturated](monitoring.md#inkwallevaluationslotssaturated). |
| `oversize` | The body is over what the policy inspects (`body.maxBytes`), and `body.onOversize` is `Deny` (the default in `Block` mode). | Raise `body.maxBytes`, or set `body.onOversize: Allow` to forward such bodies uninspected. |
| `websocket` | A WebSocket handshake didn't meet the policy's `webSocket` settings: its origin, or a required header. | Add the origin to `webSocket.allowedOrigins`, or fix the client. |
| `ip-deny` | The client IP is in a WAFIPList of the policy's `ipLists.deny`. | If the client is legitimate, remove its address from the list; check the client IP the engine resolved (`client_ip`). |
| `grpc` | A gRPC call, on a policy that refuses them (`body.grpc: Deny`). | Set `body.grpc: Allow` if the route serves gRPC ([gRPC](grpc.md)). |
<!-- end reasons -->

A rule that matched a legitimate value is a false positive: exclude it for that argument, as
[From a log line to an exclusion](testing-policies.md#from-a-log-line-to-an-exclusion) shows.
Lines are rate-limited per policy and rule (`suppressed` counts what was left out), so a
repeated denial may not have its own line; the events sent to the operator are complete.

### What a denied client sees

Every proxy answers a denial the same way: the status, `X-Request-Id` (the request ID of the
security event, also on the 400 for a request an adapter can't read), and a short text body,
`Forbidden`. A denied gRPC call gets a gRPC status instead, with the request ID in its
`grpc-message` ([gRPC](grpc.md)).

| Status | Why |
|---|---|
| 403 | The rules found an attack (or a rule of your own denies with another status: HAProxy turns any other into 403) |
| 413 | A body over the inspected limit, with `body.onOversize: Deny` |
| 503 | The request couldn't be inspected in time (timeout, overload) and the policy fails closed |
| 400 | The proxy sent the engine a request it can't read |

With `InkwallConfig.spec.engine.jsonDenials: true` (the engine's `--json-denials`), a client that
accepts `application/json` gets `{"error":"forbidden","status":403,"request_id":"..."}` instead of
the text body, through Traefik, Envoy Gateway, Istio and the standalone proxy. HAProxy writes its
own denials, so it keeps its error page there.

## From Detect to Block

1. **Run in `Detect`** on the real traffic for long enough to see its variety: a week, or a
   release cycle. Requests that would be denied pass, and are logged with `"action":"log"`.
2. **Review the events**: count them by rule and variable
   (`jq -r 'select(.msg == "security event") | .matches[] | "\(.rule_id) \(.variable)"' | sort | uniq -c | sort -rn`),
   and `inkwall_rule_matches_total` by `rule_id`. Separate attacks from false positives.
3. **Exclude narrowly**: a rule for one argument, or one path, never a whole rule set
   (`exclusions[].when`). Lower the paranoia level only if many rules fire on normal traffic.
4. **Test offline**: keep the false positives and real attacks as files, and run
   `inkwallctl test --policy ... --expect allow` and `--expect deny` on them, in CI too
   ([Testing policies](testing-policies.md)).
5. **Check the cluster** is ready: `inkwallctl status` exits 0, every policy is `Ready`.
6. **Switch** `mode: Block`, one policy at a time, and watch `inkwall_requests_total{action="deny"}`
   and the events. Going back is `mode: Detect`, applied within seconds.

## When something is down

**The engine.** Each proxy pod's engine answers its own pod's requests; while it is down:

| Proxy | What clients get |
|---|---|
| Traefik | 500, in Detect as in Block mode: ForwardAuth has no fail-open setting |
| Envoy Gateway | 500, unless every policy on the route fails open (`failureMode: Open`, or Detect without one): then requests pass uninspected |
| Istio | 503 (504 when the engine doesn't answer in time), unless every policy on the route fails open |
| HAProxy | 503 when every policy on the Ingress fails closed (Block mode by default); otherwise requests pass uninspected ([HAProxy](haproxy.md)) |
| Standalone proxy | Nothing: the proxy is the engine |

The pod isn't ready while its engine isn't, so its Service sends it no new connections: run
several proxy replicas. The kubelet restarts a crashed or hung engine. See
[When the engine is down](../deploy/helm/inkwall/README.md#when-the-engine-is-down).

**The operator.** Traffic is unaffected: engines keep their bundle. Policy changes don't reach
them until it is back, and `inkwallctl status` reports no operator replica ready. New Traefik,
HAProxy and Istio ingress gateway pods get the engine from the operator's Pod webhook: it fails
open while no policy blocks (new pods run without the engine: `SidecarMissing`), and closed once
one does (new pods can't start). See
[When the operator is down](../deploy/helm/inkwall/README.md#when-the-operator-is-down).

**The webhook alone** (the operator runs, its webhook isn't reachable from the API server):
saving a WAFPolicy or rule set is refused (the InkwallConfig stays editable), and new proxy pods
behave as when the operator is down.
Check the webhook Service's endpoints and any network policy between the API server and
`inkwall-system`.
