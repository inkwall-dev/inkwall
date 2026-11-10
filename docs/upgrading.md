# Upgrading

This guide upgrades an Inkwall installation from 0.5.x to 0.6.0, from 0.4.x to 0.5.0, from 0.4.0 to 0.4.1, from 0.3.x to 0.4.0, from 0.3.0 to 0.3.1, from 0.2.x (0.2.0 to 0.2.2) to
0.3.0, and from 0.1.x (0.1.0 to 0.1.5) to 0.2.2, the latest 0.2 release, and lists what changes on
the way. From 0.1.x, upgrade to 0.2.2 first, then to 0.3.0.

## Contents

- [From 0.5.x to 0.6.0](#from-05x-to-060)
- [From 0.4.x to 0.5.0](#from-04x-to-050)
- [From 0.4.0 to 0.4.1](#from-040-to-041)
- [From 0.3.x to 0.4.0](#from-03x-to-040)
  - [What's new in 0.4.0](#whats-new-in-040)
  - [What changes by itself in 0.4.0](#what-changes-by-itself-in-040)
  - [Upgrading the chart to 0.4.0](#upgrading-the-chart-to-040)
  - [Checking 0.4.0 worked](#checking-040-worked)
  - [Rolling back to 0.3.x](#rolling-back-to-03x)
- [From 0.3.0 to 0.3.1](#from-030-to-031)
- [From 0.2.x to 0.3.0](#from-02x-to-030)
  - [Before you upgrade](#before-you-upgrade)
  - [What's new in 0.3.0](#whats-new-in-030)
  - [What changes by itself in 0.3.0](#what-changes-by-itself-in-030)
  - [Upgrading the chart to 0.3.0](#upgrading-the-chart-to-030)
  - [Protecting HTTPRoutes](#protecting-httproutes)
  - [Checking 0.3.0 worked](#checking-030-worked)
  - [Rolling back to 0.2.x](#rolling-back-to-02x)
- [From 0.1.x to 0.2.2](#from-01x-to-022)
  - [Prerequisites](#prerequisites)
  - [What's new](#whats-new)
  - [What changes by itself](#what-changes-by-itself)
  - [Upgrading the chart](#upgrading-the-chart)
  - [Checking it worked](#checking-it-worked)
  - [Rolling back](#rolling-back)

## From 0.5.x to 0.6.0

What's new:

- **Rule sets before the CRS** (#423). A `WAFPolicy`'s rule set binding takes an optional
  `placement: BeforeCRS` (the default is `AfterCRS`, where every rule set loaded until now): the
  rule set then loads before the CRS's initialization, as the standalone engine's
  `--rules-before-crs`, so its `setvar:tx.…` and `ctl:ruleRemoveById` rules change what the CRS
  does (see the [README](../README.md#protect-a-route)). Such a rule set can't use
  `SecRuleRemoveBy*` or `SecRuleUpdate*` (the policy is `Accepted=False`, `InvalidRef`). Upgrade
  the chart first, for the CRD field; a policy that sets it is `Enforced=False`
  (`EnginesOutdated`) until every engine runs 0.6.0, since an older engine loads the rule set
  after the CRS. `inkwallctl test --policy` honours it. Policies without it don't change.
- **`inkwallctl explain`** says why a policy isn't `Ready` (`explain policy <namespace>/<name>`:
  the cause and the fix of each condition that isn't `True`) and why a request was denied
  (`explain request <request-id>`: the rules with their CRS descriptions, the score against the
  threshold, and the narrowest exclusion, checked as `inkwallctl test --policy` does), with
  `-o json` for scripts. It only reads; `explain request` reads the engines' logs, so it needs
  `get` on `pods/log` ([Explaining a policy or a denial](troubleshooting.md#explaining-a-policy-or-a-denial)).

## From 0.4.x to 0.5.0

What's new:

- **Automatic engine rollout (opt-in).** Proxy pods started before Inkwall, or running another
  engine image than the one configured, are `PendingRestart` until you restart them: that is still
  the default (`spec.engine.rollout: Manual`). With
  `kubectl patch inkwallconfig default --type=merge -p '{"spec":{"engine":{"rollout":"Automatic"}}}'`
  the operator evicts them one at a time through the Eviction API, respecting
  PodDisruptionBudgets, and waits for each replacement to be ready with the new engine before the
  next, for the Traefik, HAProxy and Istio ingress gateway pods it injects (not a pod with the
  engine in its own spec: that one keeps its image until you change it). A refused eviction or a
  replacement not ready within 5 minutes pauses it: `kubectl get inkwallconfig default -o
  jsonpath='{.status.conditions[?(@.type=="EngineRollout")].message}'` says why. Upgrade the chart
  first, for the new CRD field and the `pods/eviction` permission. With it, an engine upgrade
  after a chart upgrade needs no restart by hand.
- **Standalone mode reloads its rules without a restart**: on `SIGHUP`, or with `--watch-rules`
  when the files change ([reloading the rules](standalone-proxy.md#reloading-the-rules)).
- **gRPC and HTTP/2 through the standalone proxy**: `--h2c`, `--tls-cert`/`--tls-key`,
  `--upstream-h2c` and `--upstream-ca` ([gRPC](grpc.md#through-the-standalone-proxy)). Its
  upstream connections are now kept for reuse (128 idle per host instead of Go's default 2).
- **Limits for the standalone proxy's long-lived connections**: `--websocket-idle-timeout`,
  `--max-connections` and `--body-read-timeout`, all off by default. On shutdown the proxy now
  closes open WebSockets with `1001` (going away) instead of dropping them, and a client whose body
  read times out gets `408` instead of `400`.
- **Responses through Istio.** A policy with `responses.inspect` now has the responses of its
  Istio HTTPRoutes and VirtualServices inspected, as through Envoy Gateway: a response that leaks
  is replaced with 403 in `Block` mode and logged in `Detect` mode. Such a policy was
  `Programmed=False` (`ResponsesNotInspected`) on Istio's routes; it is `Programmed` once the
  operator has rewritten their `EnvoyFilter` objects. Routes whose policies don't inspect
  responses keep sending none to the engine. See [Istio](istio.md#settings).
- **IP allow and deny lists.** A `WAFIPList` lists client addresses (CIDRs), and
  `WAFPolicy.spec.ipLists: {allow: [...], deny: [...]}` names lists in the policy's namespace: a
  denied client gets 403 (logged in `Detect` mode) before any rule, an allowed one isn't inspected.
  They match the client IP the engine resolves, so get that right first
  ([client IP](client-ip.md)). Upgrade the chart first, for the new CRD; a policy with lists is
  `Enforced=False` (`EnginesOutdated`) until every engine runs 0.5.0. `inkwallctl test` reads
  `WAFIPList` files and takes `--client-ip`.
- **Refuse gRPC where none is served.** `body.grpc: Deny` on a `WAFPolicy` denies requests with a
  gRPC or gRPC-Web content type, instead of the SecLang rule `docs/grpc.md` suggested. Upgrade the
  chart first, for the CRD field; a policy that sets it is `Enforced=False` (`EnginesOutdated`)
  until every engine runs 0.5.0.

- **The CRS's own settings on a policy.** The CRS rule set binding of a `WAFPolicy` takes an
  optional `crs` block: `allowedMethods` (for REST APIs that send `PUT`, `PATCH` or `DELETE`),
  `allowedRequestContentTypes`, `detectionParanoiaLevel` (log the rules of a higher paranoia level
  without blocking on them) and `outboundAnomalyThreshold` (see the [README](../README.md#protect-a-route)).
  Upgrade the chart first, for the new CRD fields. An engine before 0.5.0 ignores the block, and a
  policy that sets it is `Enforced=False` (`EnginesOutdated`) until every engine runs 0.5.0.
  `inkwallctl migrate ingress-nginx` now maps `tx.allowed_methods`,
  `tx.allowed_request_content_type`, `tx.detection_paranoia_level` and
  `tx.outbound_anomaly_score_threshold` to these fields instead of marking them `TODO`.
- **Exclusions for a cookie, a header or an argument name.** An exclusion's `when` takes
  `cookie`, `header` or `argumentName` besides `argument` (at most one of the four), for false
  positives on a session cookie, a `Referer` or a JSON header: `{ruleIDs: [942100], when: {cookie:
  session}}`. Upgrade the chart first, for the new CRD fields. An engine before 0.5.0 ignores these
  exclusions (the rules still look at the cookie or header), and a policy that has one is
  `Enforced=False` (`EnginesOutdated`) until every engine runs 0.5.0. `inkwallctl migrate
  ingress-nginx` now converts `!REQUEST_COOKIES:name`, `!REQUEST_HEADERS:name` and
  `!ARGS_NAMES:name` targets instead of keeping them as SecLang.
- **The client IP behind an HTTP load balancer.** `InkwallConfig.spec.engine.clientIP` takes
  `trustedProxies` (the load balancer's CIDRs) and `trustedHops`, for Envoy Gateway, Istio and
  HAProxy behind an AWS ALB or another load balancer that appends to `X-Forwarded-For`
  ([client IP](client-ip.md#behind-an-http-load-balancer)). Upgrade the chart first, for the new
  CRD field; engines injected before the change keep their settings until their pods are
  re-created (Envoy Gateway re-creates its own). A wrong setting lets clients choose their address.

What changes by itself:

- **The InkwallConfig reports the cluster's state.** Its status gains `bundle` (version, size and
  limit), `engines` (connected, current, behind, rejected, outdated), `signingKey` (the active key,
  the rotation's phase and what it waits for), and the conditions `SigningKeyRotation` and
  `IntegrationsConfigured` (`False`, with the error, when a `spec.integrations` selector can't be
  applied: until now only logged). `kubectl get inkwallconfig` shows the bundle version, the
  engines and the key's phase. Upgrade the chart first, for the new CRD fields: an older CRD drops
  them. See [key rotation](key-rotation.md#checking-it-worked).
- **Policy condition metrics and Events.** The operator reports `inkwall_operator_policies`
  (policies by condition, status and reason), the signing key's age and rotation phase, and failed
  bundle publishes, and records a Kubernetes Event on a policy when its `Ready`, `Programmed` or
  `Enforced` condition changes. Its ClusterRole gains `events` `create` and `patch` in every
  namespace. See [monitoring](monitoring.md#operator).
- **Istio routes are proven before they are `Programmed`.** The operator now sends its signed probe
  through every Istio gateway pod, on every listener a protected HTTPRoute or VirtualService is
  served on, and the engine answers it ([the operator's probe](istio.md#the-operators-probe)).
  After the upgrade, Istio policies are `Unverified` until the probes have answered (seconds, once
  the gateways' engines are 0.5.0: restart Istio's ingress gateways; Istio rolls the Gateway API
  pods itself). Some stay out of `Programmed`, and so out of `Ready`: routes whose policies are
  all in `Detect` mode stay `Unverified` (Envoy discards the engine's answer in observability
  mode), and routes the probe can't reach are `NotProbeable` (a rule whose every match is a
  regular expression, a server with mutual TLS or passthrough, or a match on header or query
  values over TLS, which the probe doesn't send there: they may be secrets). Before, they were `Programmed`
  without proof that the filter was on the route. Alerts on `Ready` should expect it.
- **In Detect mode, the responses of flagged requests are inspected** (with `responses.inspect`):
  a request the rules flag is let through, and an SQL error or a leak in its response is now its
  own event, as for any request. The request's event may list a few more rules than before: the
  rules run to the end instead of stopping where Block mode would.
- **ForwardAuth refuses an invalid `X-Forwarded-Host`** (one with a path, a space or other
  characters a Host can't have) with 400, as the reverse proxy refuses such a Host: the rules
  would read one host and the application another. Traefik sends the client's Host, which it
  validates already, so its requests aren't affected.
- **Enforced checks the newest field a policy needs.** A policy with fields of 0.4.0 and 0.5.0
  (`webSocket` and `ipLists`, say) was `Enforced` while a 0.4.x engine ran it; it is now
  `EnginesOutdated` until every engine runs 0.5.0.
- **The chart keeps the operator's settings of the Pod webhooks** (`failurePolicy`,
  `objectSelector`, `namespaceSelector`). The operator sets `failurePolicy` to `Fail` while a
  policy blocks; an upgrade used to render `Ignore` until the operator set it again, and Helm 4,
  which applies server-side, refused the upgrade (a conflict with the operator's fields). An
  upgrade now renders the live values; the operator applies a new proxy namespace list or
  integration permissions once it restarts. With Helm 4, roll back to 0.4.x with `helm rollback
  --force-conflicts`. The chart also passes Helm 4's `helm lint --strict` (its `license` moved to an
  `artifacthub.io/license` annotation). Helm 3 and 4 are both tested.
- **Istio ingress gateways' `EnvoyFilter` is split.** The VirtualServices' filters move from
  `inkwall-istio-ingress` into shards `inkwall-istio-ingress-00` to `-31` in the same namespace;
  `inkwall-istio-ingress` keeps the engine's cluster. One object passed etcd's size limit at about
  1,200 protected VirtualServices per namespace of gateway pods, and they were all
  `WiringFailed`. While the operator rewrites them, Envoy may reject a configuration with a filter
  in both and keep the one before, still inspected. GitOps tools that ignore the operator's
  objects by label need no change.
- **WebSocket messages are scored on their own** (the standalone proxy's
  `--websocket-messages`): a message is inspected without the handshake's query arguments and
  headers, so a handshake that scored below the threshold no longer adds its score to every
  message, and each message costs about a third less. Attacks in messages are still denied.
- **`Enforced` counts the engines that serve the policy.** A policy's `Enforced` condition (and
  its `EnginesBehind`, `EngineNack` and `EnginesOutdated` reasons) now counts only the engines on
  the proxy pods that serve its routes, once the operator has wired them all. An engine of one
  proxy that is behind, rejects a bundle or is too old no longer makes the policies of another
  proxy `Enforced=False`. A policy whose routes aren't all wired, and an engine whose pod the
  operator doesn't know, still count everywhere. `inkwall_operator_engines` gets an
  `integration` label (`unknown` for engines not matched to a proxy): sum over it for the old
  totals.
- **Security event log lines say where rules matched, and are rate-limited.** Each line has
  `matches`, the rule and the variable it matched (`{"rule_id":942100,"variable":"ARGS:q"}`),
  never the value. An engine logs at most 10 lines per second for each policy and rule (the
  engine's `--event-log-rate`); the rest are counted in
  `inkwall_security_event_logs_suppressed_total`, and still go to the operator. A log pipeline
  that counts attacks from the lines should count from the metrics or the events instead.
- **`inkwallctl test` prints `rule@variable` and the score** (`matches=942100@ARGS:q  score=5`),
  after `interrupting=`; `--json` has `matches` and `anomaly_score`. A script that parses the
  text output by position should take the time from the end of the line.
- **The engine has `--log-level`**, and `InkwallConfig.spec.engine.logLevel` sets it on engines
  injected from then on. Unset, nothing changes.
- **Security events carry fewer snippets.** An engine no longer sends what a rule matched in an
  argument or header whose name looks like a credential (`password`, `token`, `api_key`,
  `session`, `card`, ...), or in a raw query string or body that names one: the event keeps the
  rule and the variable, with an empty snippet. `InkwallConfig.spec.events.redact` redacts more
  headers and arguments, or every snippet: see
  [Redacting security events](../deploy/helm/inkwall/README.md#redacting-security-events). Engines
  still on 0.4.x ignore `spec.events.redact` until their pods restart with 0.5.0.
- **Less engine memory for the CRS.** Policies that differ only in their paranoia level, inbound
  anomaly threshold, `body.maxBytes` or `responses.maxBytes` now share one compiled CRS (about
  2.1 MiB and 10–30 ms less for each combination that used to compile its own). The engine sets
  the paranoia level and threshold on each request. Detection is unchanged, and SecLang that sets
  `tx.blocking_paranoia_level` or `tx.inbound_anomaly_score_threshold` still wins over the policy's
  fields.
- **`X-Forwarded-For` entries with a port** (`198.51.100.7:4711`, `[2001:db8::1]:4711`) are read
  as addresses. Before, such an entry ended the walk, and the address right of it was the client.
- **A request body exactly `body.maxBytes` long is inspected.** Before, Coraza's own limit denied
  it (status 413 and no rule ID, in Block mode). Bodies over the limit are handled by
  `body.onOversize`, as before.
- **`kubectl get wafpolicies` has a `REASON` column**, the `Ready` condition's reason, before
  `BUNDLE`. A script that reads the columns by position should use `-o jsonpath` or
  `-o custom-columns`. `inkwallctl status` is new: see
  [Troubleshooting](troubleshooting.md#cluster-status).
- **New engine metrics, and two that change** (#356). `inkwall_rule_matches_total`,
  `inkwall_adapter_errors_total`, `inkwall_bundle_compile_seconds`, `inkwall_rule_sets`,
  `inkwall_bundle_applied_timestamp_seconds` and the `inkwall_websocket_*` metrics are new;
  `inkwall_policy_requests_total` is opt-in. `inkwall_bundle_updates_total` has a `reason` label on
  rejected bundles. WebSocket messages the engine's proxy inspects are counted in
  `inkwall_websocket_messages_total`, no longer in `inkwall_requests_total`, so a dashboard of
  requests drops on routes with busy WebSockets. `inkwall_requests_total` now also counts the
  requests no policy covers (reason `no-policy`, also before the first bundle) and those let
  through while inspection is suspended (`suspended`), which 0.4 left out (#535): its totals rise
  by them.
- **Every denial carries `X-Request-Id`** (#366), the request ID of its security event: the
  engine's reverse proxy and Traefik's ForwardAuth answered without it before, and so did the 400
  for a request an adapter can't read. `InkwallConfig.spec.engine.jsonDenials` (the engine's
  `--json-denials`) answers clients that accept `application/json` with a JSON body; off by
  default.
- **NetworkPolicies, off by default** (#387): `networkPolicy.enabled` in the chart, for clusters
  that deny traffic by default. See
  [Network flows](../deploy/helm/inkwall/README.md#network-flows) for what connects to what.
- **The chart checks its values** (#386). A `values.schema.json` makes `helm install`, `upgrade`
  and `template` fail on a key the chart doesn't have, a wrong type, or a value outside its set,
  naming it, where 0.4.x ignored them. A typo such as `rbac.integration.traefik` was silently
  ignored before. Run `helm upgrade ... --dry-run` first, and fix or remove what it names. `helm
  upgrade --reuse-values` from 0.4.x passes (CI checks it). New values: `global.imageRegistry`,
  `global.imagePullSecrets`, `operator.image.digest`, `engine.image.digest`, `operator.extraEnv`,
  `extraVolumes`, `extraVolumeMounts` and `topologySpreadConstraints` (see
  [Private registries](../deploy/helm/inkwall/README.md#private-registries)).
- **A monitoring kit, off by default** (#381): `metrics.serviceMonitor`, `metrics.podMonitor`,
  `metrics.prometheusRule` and `metrics.dashboard` in the chart. See [Monitoring](monitoring.md).
- **`inkwallctl tune` is new** (#383): it suggests the narrowest exclusions from Detect mode's
  security events. See [Suggest exclusions from the events](testing-policies.md#suggest-exclusions-from-the-events).
- **`inkwallctl test --suite` is new** (#385, experimental format): a file of cases, each a
  request and optionally its response, with the verdict expected; `--junit` writes the results for
  CI. See [Test suites](testing-policies.md#test-suites). The other `inkwallctl test` flags are
  unchanged.

## From 0.4.0 to 0.4.1

0.4.1 is a patch release with security fixes: upgrade the chart as for 0.4.0, then restart the
pods that run the engine (Traefik, Istio's Gateways, HAProxy and the Envoy Gateway proxies) so
their engines are 0.4.1. What changes by itself:

- **Rule sets can't use `@inspectFile` or `@rbl`.** These operators reach outside the engine (a
  program, a DNS query). The webhook and the operator reject rule sets that use them, and the
  engine never runs them. A rule set that already uses them keeps loading, but those rules never
  match, and editing it is rejected until they are removed. Look for them in your rule sets.
- **Path exclusions apply only to plain paths.** An exclusion with a `path` now applies only to a
  request path that is plain ASCII, without `%`, `;`, `\`, `//` or `.` and `..` segments, as
  skip paths already did. A request with any other path gets the policy's rules without that
  exclusion.
- **The response to an upgrade request is inspected unless it is a 101.** On a route whose
  policy inspects responses (Envoy Gateway, raw Envoy), an upstream that ignores `Upgrade` and
  answers with an ordinary response has that response inspected. WebSockets work as before.
- **The standalone proxy inspects the headers it forwards.** Headers that the `Connection` header
  names, which the proxy drops, are no longer inspected either.
- **The engine sets a Go memory limit.** It sets `GOMEMLIMIT` to 90% of its container's memory
  limit, as the operator does, unless `GOMEMLIMIT` is set. The injected engine gets that limit as
  `MEMORY_LIMIT` from the downward API. A request body over the inspected limit keeps only the
  inspected part in the engine's memory.

## From 0.3.x to 0.4.0

### What's new in 0.4.0

- **Raw Envoy.** An Envoy you configure yourself can call the engine's ext_proc adapter, with the
  policy from the engine's flags or from the operator: see [protecting raw Envoy](raw-envoy.md).
  Nothing changes in an existing installation.
- **WebSocket handshake rules.** A `WAFPolicy`'s new `spec.webSocket` sets the origins a WebSocket
  handshake may come from and the headers it must have; one that doesn't meet them is denied with
  403 before the upgrade (`Block`), or logged with reason `websocket` (`Detect`). The engine's
  `--websocket-origins`, `--websocket-allow-missing-origin` and `--websocket-required-headers`
  flags do the same without the operator. See [WebSocket](websocket.md).
- **Istio.** The operator protects the HTTPRoutes of Istio's Gateways (Istio 1.28 or later): it
  adds the engine to a Gateway's pods through the ConfigMap the Gateway names, and an
  `EnvoyFilter` sends the protected routes to it. `WAFPolicy` targets may also be Istio
  `VirtualService` objects (`group: networking.istio.io`), served by Istio's ingress gateways,
  whose pods get the engine from the Pod webhook. See [Istio](istio.md). The chart upgrades the
  CRDs with the new target kind; if you install them yourself, apply 0.4.0's.
- **WebSocket messages, through the standalone proxy.** `inkwall-engine proxy --websocket-messages
  inspect` (or `text-only`) inspects each text message a client sends, up to `--max-body-bytes`; in
  `block` mode a denied one closes the WebSocket with 1008 before the application gets it. Through
  Envoy Gateway, Istio, raw Envoy and Traefik, only the handshake is inspected, as in 0.3.x: see
  [WebSocket](websocket.md#through-each-proxy).
- **gRPC messages.** `body.grpcMessages: Inspect` on a `WAFPolicy` (`--grpc-messages inspect`
  without the operator) has the rules read the text in gRPC calls' messages. It is off by
  default: try it in `Detect` mode first. See [inspecting the messages](grpc.md#inspecting-the-messages).
  The chart upgrades the CRDs with it; if you install them yourself, apply 0.4.0's. A policy
  that sets it isn't `Enforced` (`EnginesOutdated`) while an engine before 0.4.0 runs it.
- **Response inspection.** A `WAFPolicy` with `responses: {inspect: true}` (and optionally
  `maxBytes`, 64 KiB by default, and `onOversize`) inspects the app's responses too, for data
  leaks (the CRS's `RESPONSE-95x` rules: SQL errors, stack traces, directory listings), and in
  Block mode replaces a response that leaks with 403. Off unless you set it: existing policies are
  unchanged. Only through Envoy Gateway, whose Envoy pods get the 0.4.0 engine as the operator
  updates them; Traefik's ForwardAuth can't send responses to the engine, so such a policy on a
  Traefik route is `Programmed=False` (`ResponsesNotInspected`), as on an Istio route (its
  filter sends no response phase yet), and the webhook warns of its
  Ingress and IngressRoute targets. Like `webSocket`, such a policy isn't `Enforced` (`EnginesOutdated`) while an
  engine before 0.4.0 runs it. For raw Envoy, `inkwall-engine ext-proc --inspect-responses`
  (see [responses](raw-envoy.md#responses)). Security events get a `phase` field (`request` or
  `response`), and the engine two metrics, `inkwall_responses_total` and
  `inkwall_response_check_duration_seconds`. The `WAFPolicy` CRD gets the field: the chart
  upgrades the CRDs (`crds.install`); if you install them yourself, apply the new ones first.
- **HAProxy.** `inkwall-engine spoe` is an agent of [HAProxy](https://docs.haproxy.org/)'s [SPOE](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt) (HAProxy 3.1
  or later), on `127.0.0.1:9004` or a Unix socket. You configure HAProxy yourself: see
  [protecting HAProxy](haproxy.md). Nothing changes in an existing installation.
- **Bundles carry a probe key** (`probe_key`, derived from the signing key): the first bundle after
  the upgrade is a new version with the same policies. Engines before 0.4.0 ignore it.
- **The HAProxy Kubernetes Ingress Controller** (3.1 or later) is wired by the operator: a
  `WAFPolicy` on one of its Ingresses gives the controller's pods the engine (restart them after the
  upgrade) and the Ingress a backend snippet of its own, and the policy is `Programmed` once the
  operator's probe has proven the filter on every pod (`Unverified` until then). The new
  `inkwall-operator-haproxy` ClusterRole is granted by `rbac.integrations.haproxy` (`true` by
  default), and `haproxy-controller` joins the default `injection.proxyNamespaces`. See [with the
  operator](haproxy.md#with-the-operator-haproxy-kubernetes-ingress-controller). When a policy's
  `body.maxBytes` (64 KiB by default) is more than HAProxy's buffer lets the engine see (about
  15 KiB unless you raise `tune.bufsize`), `Programmed`'s message says so.

### What changes by itself in 0.4.0

- **A new ClusterRole, `inkwall-operator-haproxy`**, granted by default (`rbac.integrations.haproxy:
  true`, also with `--reuse-values`): it writes the backend snippet annotations of the HAProxy
  Kubernetes Ingress Controller's Ingresses. A second Pod webhook, `haproxy.pods.waf.inkwall.dev`,
  injects the engine into that controller's pods, and `haproxy-controller` is a default proxy
  namespace. A cluster without that controller is unaffected.
- **A new ClusterRole, `inkwall-operator-istio`**, granted by default (`rbac.integrations.istio:
  true`, also with `--reuse-values`): it writes `EnvoyFilter` objects and ConfigMaps, and patches
  Gateways. Set it to `auto` to grant it only when the cluster serves Istio's API, or `false`
  never to; without it the operator disables the Istio integration ([integration
  permissions](../deploy/helm/inkwall/README.md#integration-permissions)).
- **A Pod webhook and a ClusterRole for Istio's ingress gateways.** Pods labelled `istio:
  ingressgateway` (the label of Istio's `gateway` chart released as `istio-ingressgateway`) in the
  proxy namespaces get the engine when they are created, as Traefik's do, also before any policy
  targets a VirtualService; the ClusterRole `inkwall-operator-istio-ingress`
  (`rbac.integrations.istioIngress`, `true` by default) reads VirtualServices and Istio's Gateways
  and writes `EnvoyFilter` objects. While a policy is in `Block` mode, such pods can't start while
  the operator is down, as Traefik's ([when the operator is down](../deploy/helm/inkwall/README.md#when-the-operator-is-down)).
  Set `rbac.integrations.istioIngress=false` to leave them alone.
- **Two more default proxy namespaces, `istio-ingress` and `istio-system`**, where Istio's docs put
  Gateways. If you set `injection.proxyNamespaces`, the value is kept: add your Istio Gateways'
  namespaces to it. Changing the value restarts the operator.
- **WebSockets through Envoy Gateway.** The engine decides a handshake on its headers. In 0.3.x, a
  policy in `Block` mode with body inspection held every handshake until one of Envoy's timeouts,
  and one in `Detect` mode logged every handshake as an oversized body.
- **`WAFPolicy` gains `spec.webSocket`** (`allowedOrigins`, `allowMissingOrigin`,
  `requiredHeaders`), and a new reason, `EnginesOutdated`, on `Enforced`: a policy that sets
  `webSocket` isn't `Enforced` while an engine before 0.4.0 runs it, since that engine ignores the
  field. Restart Traefik and the Envoy Gateway proxies after the upgrade, so their engines are
  0.4.0. Events and `inkwall_requests_total` have a new reason, `websocket`.
- **A denied gRPC call gets a gRPC status.** A request with a gRPC `Content-Type` that the engine
  denies is answered with `grpc-status` 7 (`PERMISSION_DENIED`) and a `grpc-message` naming the
  request ID, not a plain-text 403. Through Envoy Gateway, raw Envoy and the engine's reverse
  proxy the HTTP status is 200, as for any gRPC error (so Envoy's access log shows 200 for these
  denials); through Traefik it stays 403. Clients reported `PERMISSION_DENIED` before as well, but
  gRPC-Web clients got the 403 as it was. See [denied calls](grpc.md#denied-calls).
- **gRPC-Web text calls pass.** A `POST` with `Content-Type: application/grpc-web-text` whose body
  is base64 of gRPC messages is a gRPC call, as a binary gRPC-Web one is: its path and metadata
  are inspected, and its messages with `body.grpcMessages: Inspect`. In 0.3.x the Core Rule Set
  denied every one in `Block` mode (rule 920420) and logged it in `Detect` mode. A body that isn't
  such base64 is still inspected as any request, and denied. See [gRPC](grpc.md).

### Upgrading the chart to 0.4.0

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.4.0 \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   The chart upgrades the CRDs too (`crds.install`). If you install the CRDs yourself, apply the
   new ones first:

   ```sh
   helm template inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.4.0 \
     --show-only templates/crds.yaml | kubectl apply --server-side -f -
   ```

2. Wait for the operator:

   ```sh
   kubectl -n inkwall-system rollout status deployment/inkwall-operator
   ```

3. Restart the proxies whose pods the Pod webhook injects, so they run the 0.4.0 engine: Traefik,
   and the HAProxy Kubernetes Ingress Controller and Istio's ingress gateways if you run them.
   The operator updates Envoy Gateway's and Istio Gateways' pods itself.

   ```sh
   kubectl -n <traefik namespace> rollout restart deployment/<traefik>
   ```

If Argo CD or Flux installs the chart, change the chart version in Git instead: see
[GitOps](gitops.md#installing-the-chart-with-a-gitops-tool).

### Checking 0.4.0 worked

```sh
helm -n inkwall-system list
kubectl get wafpolicy -A
kubectl -n <traefik namespace> get pods -l app.kubernetes.io/name=traefik \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}'
```

It worked if the release shows chart version 0.4.0, the policies are `Ready`, and Traefik's pods
run the `inkwall-engine:0.4.0` image. A policy that sets `webSocket`, `responses` or
`body.grpcMessages` stays `Enforced=False` (`EnginesOutdated`) until every engine that runs it is
0.4.0. Send an attack through a protected route, as in the
[README](../README.md#protect-a-route), to check it's blocked.

### Rolling back to 0.3.x

0.3.x doesn't wire Istio or the HAProxy Kubernetes Ingress Controller, nor unwire them. Before
`helm rollback`, unprotect them: remove the HTTPRoutes of Istio Gateways, the `VirtualService`
targets and the Ingresses the HAProxy controller serves from every policy's `targetRefs`, or
delete those policies. The operator then removes its `EnvoyFilter` objects, takes the engine out
of the Istio Gateways' ConfigMaps ([undoing it](istio.md#undoing-it)), and restores the HAProxy
Ingresses' annotations ([what the operator does](haproxy.md#what-the-operator-does)). Wait until
the first command finds no resources and the second prints nothing:

```sh
kubectl get envoyfilters.networking.istio.io -A -l app.kubernetes.io/managed-by=inkwall-operator
kubectl get ingresses -A \
  -o jsonpath='{range .items[?(@.metadata.annotations.waf\.inkwall\.dev/haproxy-wired)]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'
```

The fields 0.4.0 added to `WAFPolicy`, `spec.webSocket`, `spec.responses` and
`spec.body.grpcMessages`, aren't in 0.3.x's CRD: the API server drops them when it reads the
policies, and may drop them from storage at the next write. So a policy that relies on them
loses those checks after the rollback (handshake rules, response inspection, gRPC message
inspection), with nothing in its status to say so. Note them before rolling back, and set them
again after upgrading to 0.4.0 again.

Then roll back, and restart Traefik (and any HAProxy controller or Istio ingress gateway that ran
the engine) so its pods run the older engine again:

```sh
helm -n inkwall-system rollback inkwall
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```

## From 0.3.0 to 0.3.1

0.3.1 is a patch release: upgrade the chart as for 0.3.0. What changes by itself:

- **A suspended cluster is reported on every policy.** While `InkwallConfig.spec.suspend` is
  `true`, every `WAFPolicy` is `Enforced=False` and `Ready=False`, reason `Suspended`; in 0.3.0
  they could stay `Ready=True` while nothing was inspected. The `InkwallConfig` has a new
  `Suspended` condition. See [suspending inspection](../deploy/helm/inkwall/README.md#suspending-inspection).
- **A policy left out of a bundle too large to publish says so.** When the bundle doesn't fit its
  Secrets (over 7,200 KiB compressed), the policies it would add or change are `Accepted=False` and
  `Ready=False`, reason `BundleTooLarge`, until it fits. In 0.3.0 they kept the conditions of their
  previous spec, `Accepted=True` included, while engines ran that previous spec.
- **Suspending works when the bundle is too large.** In 0.3.0, `spec.suspend` did nothing while
  the bundle was too large to publish; now the bundle the engines run is published again,
  suspended.

## From 0.2.x to 0.3.0

0.3.0 protects [Gateway API](https://gateway-api.sigs.k8s.io/) [`HTTPRoute`](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) objects served by [Traefik's Gateway API
provider](https://doc.traefik.io/traefik/routing/providers/kubernetes-gateway/) or by [Envoy Gateway](https://gateway.envoyproxy.io/). `Ingress` and `IngressRoute` targets are wired as before.

### Before you upgrade

- Inkwall 0.2.x installed with the chart, the values you installed it with, and
  [Helm](https://helm.sh/docs/) 3.14 or later.
- [Kubernetes](https://kubernetes.io/docs/concepts/overview/) 1.29 or later, as before. CI now tests 0.3.0 on Kubernetes 1.34 (the upgrade
  test and [envtest](glossary.md#envtest)) and on kind's newest, 1.37. The Gateway API's v1.7 CRDs need
  Kubernetes 1.31 or later.
- **Check the policies that target an `HTTPRoute`.** 0.2.x accepted such targets but never
  enforced them: those policies were `Accepted=False` (`TargetUnsupported`). From 0.3.0, every
  `HTTPRoute` they target that Traefik or Envoy Gateway serves is wired and inspected, in the
  policy's mode. List them, and set `mode: Detect` on any you aren't sure of:

  ```sh
  kubectl get wafpolicy -A -o json |
    jq -r '.items[] | select(any(.spec.targetRefs[]; .kind == "HTTPRoute")) | "\(.metadata.namespace)/\(.metadata.name) \(.spec.mode // "Detect")"'
  ```

- **Remove `spec.engine.socketDir` from your `InkwallConfig`**, if you set it. It never had an
  effect: Envoy Gateway's engine socket is in `/var/run/inkwall-socket`, and Traefik reaches the
  engine over loopback TCP. It is deprecated: setting or changing it draws a warning, and it will
  be removed from a later API version. An `InkwallConfig` that has it keeps working. One created
  before 0.3.0 may hold its old default, `/var/run/inkwall`; it is ignored, and keeping it as it
  is draws no warning.
- **Check how the chart grants the integrations' permissions.** The default,
  `rbac.integrations.*: true` (also with `--reuse-values`, which has no such values), grants every
  integration's role, as 0.2.x did, so a proxy installed after Inkwall is protected. If you opt
  into `auto`, the chart grants an integration's role only if its proxy's CRDs are installed when
  you run `helm upgrade`: run `helm upgrade` again once a proxy is installed, or its integration
  stays disabled (`IntegrationDisabled`). If Argo CD or Flux installs the chart, keep both values
  `true` or `false` in Git: Argo CD renders without asking the cluster, so `auto` grants every
  role, and Flux asks only when it upgrades the release ([GitOps](gitops.md)).
- **List your proxies' namespaces in `injection.proxyNamespaces`**, if a proxy runs outside
  `traefik`, `kube-system` and `envoy-gateway-system`
  ([proxy pods only in the proxy namespaces](#what-changes-by-itself-in-030)). Otherwise
  `helm upgrade` stops and changes nothing, naming the namespaces to add. Helm checks this only
  when it can reach the cluster: `helm template` and Argo CD can't, so check it yourself there.
  If you set the value under 0.2.2, add Envoy Gateway's namespace to it before you protect an
  `HTTPRoute` that Envoy Gateway serves.
- Anything that parses the `Enforced` condition's message (alerts, scripts) needs the new text:
  see [below](#what-changes-by-itself-in-030).

### What's new in 0.3.0

The upgrade adds no new kinds, and changes the CRDs as follows:

| Object | Field | |
|---|---|---|
| `WAFPolicy` | `spec.targetRefs[*].kind: HTTPRoute` (`group: gateway.networking.k8s.io`), optional `sectionName` | Now resolved and wired: through Traefik's Gateway API provider (an `ExtensionRef` filter to the `inkwall-waf` Middleware), or through Envoy Gateway (an `EnvoyExtensionPolicy` calling the engine over [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)). `sectionName` protects one named rule of the route, and takes precedence over a policy on the whole route |
| `WAFPolicy` | `status.bundleVersion` | Now the first bundle that enforces the policy as it is now, not the newest bundle: a bundle that changes only other policies leaves it (#187) |
| `InkwallConfig` | `status.proxies` | The proxy controllers named by the cluster's IngressClasses and GatewayClasses, their integration, and how far Inkwall wires their routes: `Full`, `Partial` or `Unsupported`. Written into an existing `InkwallConfig` `default` only |
| `InkwallConfig` | `spec.engine.socketDir` | Deprecated and ignored ([above](#before-you-upgrade)); no default, no path rule |

The `ValidatingWebhookConfiguration` gets a webhook for `InkwallConfig`, with
`failurePolicy: Ignore`: it only warns, so the `InkwallConfig` stays editable while the operator
is down.

Each integration's permissions move into a `ClusterRole` of its own, `inkwall-operator-traefik`
and `inkwall-operator-envoy-gateway`; the base `inkwall-operator` role keeps what the resolver and
discovery read (routes, Gateways and classes). Traefik's role writes its Middlewares and the
references to them in Ingresses, IngressRoutes and now HTTPRoutes; Envoy Gateway's writes its
`EnvoyProxy`, `EnvoyExtensionPolicy`, `Backend` and `ClientTrafficPolicy` objects and patches
Gateways. The new chart values `rbac.integrations.traefik` and `rbac.integrations.envoyGateway`
choose which are granted ([integration permissions](../deploy/helm/inkwall/README.md#integration-permissions)):

| Value | Default | |
|---|---|---|
| `rbac.integrations.traefik`, `envoyGateway` | `true` | `true` always grants the role, `false` never. `auto` grants it when the cluster serves the proxy's API group (`traefik.io/v1alpha1`, `gateway.envoyproxy.io/v1alpha1`) at install or upgrade time; when Helm can't ask the cluster (`helm template`, `--dry-run=client`), every role. A value missing from your release (`--reuse-values`) means `true` |

The operator checks its permissions when it starts, and every minute. An integration it lacks some
of is disabled instead of stalling the others: a policy on its proxy's routes is `Programmed=False`
with the new reason `IntegrationDisabled`, naming the permissions missing, and
`InkwallConfig.status.proxies` lists the proxy as `Unsupported`. Without Traefik's role, the Pod
webhook selects no pod, so Traefik's pods start without an engine nothing would wire. When a role
is granted or revoked, each replica restarts after a random delay (`--selector-restart-max-delay`).

Besides `rbac.integrations`, the chart value `injection.proxyNamespaces` (with the operator flag
`--proxy-namespaces`) is new from 0.2.0 or 0.2.1, and its default gains `envoy-gateway-system`
from 0.2.2 ([below](#what-changes-by-itself-in-030)). No other chart values change, and no other
operator flags are added.
The operator now sets the Go runtime's soft memory limit
([`GOMEMLIMIT`](https://go.dev/doc/gc-guide#Memory_limit)) to 90% of its container's memory limit
(`operator.resources.limits.memory`, 512Mi by default), so its garbage collector works harder near
the limit instead of letting the heap double. Without a memory limit, Kubernetes gives it the
node's allocatable memory, so the limit is then harmless. To change it, change
`operator.resources.limits.memory`.

New operator [metrics](https://prometheus.io/docs/concepts/data_model/):

| Metric | |
|---|---|
| `inkwall_operator_wired_targets{integration}` | Policy targets wired to the engine, by integration (`traefik`, `envoy-gateway`) |
| `inkwall_operator_wiring_failures{integration}` | Targets that couldn't be wired (`Programmed=False`, `WiringFailed`) |
| `inkwall_operator_engines_left_out` | Engines left out of a replica's engine report, over the ConfigMap's size limit; while any are, `Enforced` is `False` (`EnginesUnreported`) |
| `inkwall_operator_request_stats_dropped_total{reason}` | Policies' request counts dropped on their way to a control plane ([connecting to a control plane](control-plane.md)) |
| `inkwall_operator_state_engines_left_out` | Engines left out of the state sent to a control plane, over its message limit |

`inkwall-engine` gets the `ext-proc` command, Envoy's [external processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) over gRPC, which
the operator uses for Envoy Gateway ([running the engine without Kubernetes](standalone-proxy.md)).
`inkwallctl` gets `migrate ingress-nginx` ([migrating from ingress-nginx](migrating-from-ingress-nginx.md)), and
`inkwallctl test --ingress` reads Traefik `IngressRoute` and Gateway API `HTTPRoute` objects, as the
operator reads them, and checks their fields strictly: a misspelled field is an error
([testing policies](testing-policies.md)).

### What changes by itself in 0.3.0

Without any configuration on your part, the upgrade changes the following:

- **`HTTPRoute` targets are enforced**, as [above](#before-you-upgrade).
- **Proxy pods only in the proxy namespaces**, the fix for
  [GHSA-r5cq-6vq5-q8qg](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-r5cq-6vq5-q8qg).
  The operator looks for Traefik's and Envoy Gateway's pods only in the namespaces of
  `injection.proxyNamespaces`: `traefik`, `kube-system` and `envoy-gateway-system` by default.
  Only pods there get the engine and read access to the bundle; a pod with a proxy's labels
  elsewhere is an ordinary pod. Until a proxy's namespace is listed, its pods get no engine and
  its routes are not wired (served uninspected, `Programmed=False`, `SidecarMissing`); so when
  pods that run the engine are in a namespace the value doesn't list, `helm upgrade` stops with
  `pods with the Inkwall engine run in namespace(s) <namespaces>, which injection.proxyNamespaces
  doesn't list` and changes nothing. Add them ([step 1](#upgrading-the-chart-to-030)), or set
  `{*}` to keep the old behaviour. See
  [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces). 0.2.2 already has
  this, with `traefik` and `kube-system` by default: from 0.2.2, only the default's
  `envoy-gateway-system` is new.
- **The `Enforced` condition's messages no longer count engines.** `Enforced=True` says
  `every engine runs bundle 42 or later`, and `EnginesBehind` says `some engines don't run bundle
  42 yet`, instead of `5/6 engines on bundle 42`. So engines that come and go (a proxy rollout)
  no longer rewrite every policy's status. `inkwall_operator_engines{state}` has the counts.
  `EngineNack` says `some engines rejected bundle 42 (first: shop/traefik-abc: error)`, naming
  the first engine that rejected it.
- **A new reason, `EnginesUnreported`**: `Enforced=False` while a replica's engine report leaves
  engines out (thousands of engines on one replica), and a key rotation waits meanwhile.
- **A policy's status is written only when it changes.** `status.bundleVersion` moves only when a
  bundle changes what the policy enforces (#187), and `Enforced` and `Ready` are written only when
  they change (#212). The `BUNDLE` column of `kubectl get wafpolicy` therefore differs between
  policies. Policies upgraded from 0.2.x keep their version until their next change.
- **`Programmed=False` after uninstall.** The `helm uninstall` hook now sets `Programmed=False`
  and `Ready=False`, reason `Unwired`, on every policy whose routes it unwired. In 0.2.x they kept
  `Programmed=True`.
- **Request counts.** Engines count, per policy, the requests they allow, deny and detect, with
  their latency, and the operator sends the totals to a connected control plane (GitOps or
  Managed mode, if the control plane asks for them). `Standalone` sends nothing.
- **Limits on what an engine sends.** The operator refuses an engine whose `Hello` or heartbeat
  carries oversized fields (an ID over 253 bytes, say), keeps the first 1,000 security events of
  a message and counts the rest as dropped, and cuts a rejection's error to 1 KiB. Engines from
  0.2.x stay well within these limits.
- **Less of the cluster in the operator's cache.** It caches proxy pods with one informer per
  integration selector. Before, custom `InkwallConfig` selectors that shared no label key with
  Envoy Gateway's made it cache and watch every pod in the cluster.
- **Your `ClientTrafficPolicy` wins.** When you add a `ClientTrafficPolicy` for a Gateway that has
  the operator's (`inkwall-waf-<gateway>`), the operator deletes its own, and your
  `connection.bufferLimit` then caps the bodies inspected ([client IP](client-ip.md#envoy-gateway)).
  One below a policy's `body.maxBytes` (32 KiB when unset, under the engine's 64 KiB) makes the
  policy's `Programmed` condition `WiringFailed`.

Traefik's pods keep their 0.2.x engine until they restart, so restart Traefik after the upgrade.
The 0.2.x engine keeps enforcing its rules, but misses what 0.3.0 changed in the engine: it sends
no request counts, and it matches an `HTTPRoute`'s wildcard hostname against a single DNS label,
not the several the Gateway API allows (`*.example.com` then doesn't cover `a.b.example.com`).
Envoy Gateway's pods need no restart: 0.2.x never put an engine in them. They get the 0.3.0
engine with a Gateway's first protected route, and Envoy Gateway rolls them itself whenever the
operator changes their `EnvoyProxy`, such as for a new engine image. An engine image set in
`InkwallConfig.spec.engine.image` stays as it is: change it to 0.3.0 yourself.

### Upgrading the chart to 0.3.0

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.3.0 \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   If a proxy runs in a namespace other than `traefik`, `kube-system` or `envoy-gateway-system`,
   add the [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces), with the
   defaults you still need, e.g. `--set 'injection.proxyNamespaces={traefik,ingress}'`. Otherwise
   the upgrade stops, naming the namespaces to add ([above](#before-you-upgrade)).

   The chart upgrades the CRDs too (`crds.install`). If you install the CRDs yourself, apply the
   new ones first:

   ```sh
   helm template inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.3.0 \
     --show-only templates/crds.yaml | kubectl apply --server-side -f -
   ```

2. Wait for the operator:

   ```sh
   kubectl -n inkwall-system rollout status deployment/inkwall-operator
   ```

3. Restart Traefik, so its pods run the 0.3.0 engine ([above](#what-changes-by-itself-in-030)):

   ```sh
   kubectl -n <traefik namespace> rollout restart deployment/<traefik>
   ```

If Argo CD or Flux installs the chart, change the chart version in Git instead: see
[GitOps](gitops.md#installing-the-chart-with-a-gitops-tool). If they manage your `HTTPRoute`
objects or Envoy Gateway's `EnvoyProxy` objects, read [GitOps](gitops.md) for the fields the
operator now writes there.

### Protecting HTTPRoutes

To protect `HTTPRoute` objects, the proxy that serves them needs the Gateway API:

- **Traefik:** install the Gateway API CRDs (the [standard channel](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api)) and turn on
  Traefik's Gateway API provider (`providers.kubernetesGateway.enabled=true` in its chart). The
  operator wires the HTTPRoutes whose parent Gateway has a GatewayClass of controller
  `traefik.io/gateway-controller`.
- **Envoy Gateway** (v1.9; not with `mergeGateways`, nor Envoy as a DaemonSet): turn on its
  Backend API, which the engine's socket needs, with
  `--set config.envoyGateway.extensionApis.enableBackend=true` on its chart, as in the
  [README](../README.md#install). The operator puts the engine into the Envoy pods through each
  Gateway's `EnvoyProxy`, and Envoy Gateway rolls them: no restart on your part.

The operator looks for the Gateway API's and Envoy Gateway's CRDs every 30 s, so they can be
installed before or after the upgrade. Then target the routes, as in the
[README](../README.md#protect-a-route):

```yaml
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: web}
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: api, sectionName: orders}
```

A route of another Gateway API controller is resolved into the bundle, but not wired: the policy
is `Programmed=False` (`ControllerUnsupported`). To see which controllers Inkwall wires, create
an `InkwallConfig` named `default` if you have none, and read its `status.proxies`.

### Checking 0.3.0 worked

```sh
helm -n inkwall-system list
kubectl get wafpolicy -A
kubectl get inkwallconfig default -o jsonpath='{range .status.proxies[*]}{.controllerName} {.support}{"\n"}{end}'
kubectl -n <traefik namespace> get pods -l app.kubernetes.io/name=traefik \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}'
```

It worked if the release shows chart version 0.3.0, the policies are `Ready`, the proxies you run
are `Full`, and Traefik's pods run the `inkwall-engine:0.3.0` image. Send an attack through a
protected route, as in the [README](../README.md#protect-a-route), to check it's blocked.

### Rolling back to 0.2.x

0.2.x neither wires nor unwires HTTPRoutes. Before `helm rollback`, unprotect them: remove the
`HTTPRoute` entries from every policy's `targetRefs`, or delete those policies. The operator then
removes its filters from the HTTPRoutes, takes the engine out of the `EnvoyProxy` objects, points
the Gateways it pointed at its own `EnvoyProxy` (`spec.infrastructure.parametersRef`) back at none,
and deletes its Envoy Gateway objects. Wait until the first command prints nothing (no HTTPRoute,
Gateway or `EnvoyProxy` still carries its mark) and the second finds no resources (none of its
`EnvoyExtensionPolicy`, `Backend`, `ClientTrafficPolicy` or `EnvoyProxy` objects is left):

```sh
kubectl get httproutes.gateway.networking.k8s.io,gateways.gateway.networking.k8s.io,envoyproxies.gateway.envoyproxy.io -A \
  -o jsonpath='{range .items[?(@.metadata.annotations.waf\.inkwall\.dev/wired)]}{.kind} {.metadata.namespace}/{.metadata.name}{"\n"}{end}'
kubectl get envoyextensionpolicies.gateway.envoyproxy.io,backends.gateway.envoyproxy.io,clienttrafficpolicies.gateway.envoyproxy.io,envoyproxies.gateway.envoyproxy.io \
  -A -l app.kubernetes.io/managed-by=inkwall-operator
```

Then roll back, and restart Traefik so its pods run the older engine again:

```sh
helm -n inkwall-system rollback inkwall
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```

0.2.x's CRD has no `status.proxies`, so the API server drops it.

## From 0.1.x to 0.2.2

### Prerequisites

- Inkwall 0.1.x installed with the chart, and the values you installed it with.
- [Helm](https://helm.sh/docs/) 3.14 or later, for
  [`--reset-then-reuse-values`](https://helm.sh/docs/helm/helm_upgrade/).

### What's new

From 0.1.1 or later, the upgrade changes no [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).
From before 0.1.5, it adds one chart value, `injection.proxyNamespaces` ([below](#what-changes-by-itself)),
with the operator flag `--proxy-namespaces`. The operator gets two more flags, with the defaults it used before; set them with
`operator.extraArgs` if you need others:

| Flag | Default | |
|---|---|---|
| `--signing-key-grace` | `1m` | The least time each phase of a [signing key rotation](key-rotation.md) lasts |
| `--selector-restart-max-delay` | `30s` | When the `InkwallConfig`'s integration selectors change, each replica restarts after a random delay up to this |

From 0.1.0, the upgrade also adds fields to the existing CRDs, and makes some existing fields take
effect. It adds no new kinds.

| Object | Field | |
|---|---|---|
| `WAFPolicy` | `spec.targetRefs[*].kind: IngressRoute` (`group: traefik.io`) | Protect [Traefik](https://doc.traefik.io/traefik/) [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) objects |
| `InkwallConfig` | `spec.signingKey.rotationInterval` | Rotate the signing key on a schedule ([key rotation](key-rotation.md)) |
| `InkwallConfig` | [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) `waf.inkwall.dev/rotate-signing-key` | Rotate it now |
| `InkwallConfig` | `spec.mode: GitOps` or `Managed`, `spec.controlPlane` | Connect to a control plane ([control plane](control-plane.md)). In 0.1.0 they existed but did nothing |
| `InkwallConfig` | [condition](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties) `ControlPlaneConnected` | The connection's state |
| `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` | [label](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) `inkwall.dev/source: saas` | Objects written by the control plane in [Managed mode](glossary.md#cluster-mode) |

It adds these chart values, all off or idle by default:

| Value | Default | |
|---|---|---|
| `controlPlane.caBundle` | `""` | The control plane's CA, if private |
| `controlPlane.enrollmentToken` | `""` | Its one-time enrollment token |
| `controlPlane.eventsBufferMiB` | `64` | Each operator replica's buffer of security events while the control plane is unreachable |

Nothing connects to a control plane until you set `spec.mode` to `GitOps` or `Managed`:
`Standalone` stays the default. An `InkwallConfig` already set to `GitOps` or `Managed` under 0.1.0
starts connecting after the upgrade.

### What changes by itself

Without any configuration on your part, the upgrade from any 0.1.x changes the following:

- **Proxy pods only in the proxy namespaces**, the fix for
  [GHSA-r5cq-6vq5-q8qg](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-r5cq-6vq5-q8qg).
  The operator now looks for Traefik's pods only in the namespaces of the new value
  `injection.proxyNamespaces`: `traefik` and `kube-system` by default. Only pods there get the
  engine and read access to the bundle; a pod with Traefik's labels elsewhere is an ordinary pod.
  If Traefik runs in another namespace, list it when you upgrade ([step 1](#upgrading-the-chart)). Until then, its pods get no engine
  and its routes are not wired (served uninspected, `Programmed=False`, `SidecarMissing`); so
  when pods that run the engine are in a namespace the value doesn't list, `helm upgrade` stops
  with `pods with the Inkwall engine run in namespace(s) <namespaces>, which
  injection.proxyNamespaces doesn't list` and changes nothing. Add them, or set `{*}` to keep the
  old behaviour. Helm checks this only when it can reach the cluster: not with `helm template`,
  nor in Argo CD. See [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces).
  Already in 0.1.5.
- **Bundles split into chunks past 900 KiB.** A [bundle](glossary.md#bundle) of up to 900 KiB
  compressed stays in the [Secret](https://kubernetes.io/docs/concepts/configuration/secret/) `inkwall-bundle`, as before. A larger one, which 0.1.x
  couldn't publish, is split into Secrets named `inkwall-bundle-a-0`… or `inkwall-bundle-b-0`…,
  labelled `waf.inkwall.dev/bundle-chunk`, up to 7,200 KiB. The `inkwall-bundle-reader` Role, which
  lets Traefik's engines read the bundle, now also grants `get` on every chunk name. If you run an
  engine with `--bundle-secret` and a Role of your own, add the chunk names to it. Engines from
  0.1.x can't read a chunked Secret when they start, and refuse a streamed bundle over 4 MiB
  decompressed: they keep their last bundle, or wait for the operator.
- **The engine's answer to Traefik capped.** Each `inkwall-waf` ForwardAuth
  [Middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) gets
  `maxResponseBodySize: 65536`, except on Traefik before v3.7, whose CRD has no such field. Already
  set since 0.1.2.
- **The engine enforces its cached bundle from its first request.** A restarted engine container
  no longer answers before it applies its cached bundle
  ([GHSA-9x6c-5v2m-835r](https://github.com/inkwall-dev/inkwall/security/advisories/GHSA-9x6c-5v2m-835r),
  also fixed in 0.1.3). The fix is in the engine, so it takes effect when Traefik restarts.

From 0.1.0, the upgrade also changes the following:

- **A finalizer on every `WAFPolicy`.** The operator adds the
  [finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)
  `waf.inkwall.dev/unwire`. A deleted policy then waits until the operator has unwired its
  routes. If you manage policies with [Argo CD](https://argo-cd.readthedocs.io/en/stable/) or [Flux](https://fluxcd.io/flux/), read [GitOps](gitops.md).
- **Unwiring when the engine can't be injected.** With `injection.enabled=false`, or when no
  running pod matches Traefik's selector, the operator unwires every route it wired and reports
  `Programmed=False` (reason `InjectionDisabled` or `SidecarMissing`), so the routes keep working,
  uninspected. 0.1.0 left them wired. The `helm uninstall` hook now also runs with injection off,
  and removes the finalizers.
- **Signing keys in a new format.** The Secret `inkwall-bundle-signing-key` and the `inkwall-trust`
  [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) get `trusted-keys.pub`, the list of keys engines accept. The key doesn't change.
  New engines read `trusted-keys.pub`; engines from 0.1.0 keep reading `ed25519.pub`, which
  stays.
- **New webhooks.** The [`ValidatingWebhookConfiguration`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) gets webhooks for deleting objects
  labelled `inkwall.dev/source: saas`. Unlabelled objects never reach them.
- **An events buffer** on each operator pod: an
  [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) of
  `controlPlane.eventsBufferMiB` + 16 MiB. It stays empty in Standalone.

Traefik pods keep their 0.1.x engine until they restart. That engine keeps working, but misses the
engine fixes made since, doesn't read chunks, and, from 0.1.0, holds up any signing key
rotation: restart Traefik after the upgrade. An engine image set in
`InkwallConfig.spec.engine.image` stays as it is: change it to 0.2.2 yourself.

### Upgrading the chart

1. Upgrade the chart, with the values you installed it with:

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.2.2 \
     --namespace inkwall-system --reset-then-reuse-values
   ```

   If Traefik runs in a namespace other than `traefik` or `kube-system`, add the
   [proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces), e.g.
   `--set 'injection.proxyNamespaces={ingress}'`. Otherwise the upgrade stops with the message
   above, naming the namespaces to add.

   `--reset-then-reuse-values` takes the new chart's defaults, then your values. Passing your
   values file again (`-f values.yaml`) works too. Avoid `--reuse-values`, which keeps the old
   values without the new defaults. From 0.1.0, it failed on 0.1.1 with
   `nil pointer evaluating interface {}.caBundle`; the chart defaults those values since 0.1.2
   (#143).

   The chart upgrades the CRDs too (`crds.install`, on by default). If you install the CRDs
   yourself, apply the new ones first:

   ```sh
   helm template inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version 0.2.2 \
     --show-only templates/crds.yaml | kubectl apply --server-side -f -
   ```

2. Wait for the operator:

   ```sh
   kubectl -n inkwall-system rollout status deployment/inkwall-operator
   ```

3. Restart Traefik, so its pods get the new engine:

   ```sh
   kubectl -n <traefik namespace> rollout restart deployment/<traefik>
   ```

If Argo CD or Flux
installs the chart, change the chart version in Git instead: see
[GitOps](gitops.md#installing-the-chart-with-a-gitops-tool).

### Checking it worked

```sh
helm -n inkwall-system list
kubectl get wafpolicy -A
kubectl get wafpolicy -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.metadata.finalizers}{"\n"}{end}'
kubectl -n <traefik namespace> get pods -l app.kubernetes.io/name=traefik \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.initContainers[?(@.name=="inkwall-engine")].image}{"\n"}{end}'
kubectl get middlewares.traefik.io -A --field-selector metadata.name=inkwall-waf \
  -o jsonpath='{range .items[*]}{.metadata.namespace} {.spec.forwardAuth.maxResponseBodySize}{"\n"}{end}'
```

It worked if the release shows chart version 0.2.2, the policies are `Ready` and carry
`waf.inkwall.dev/unwire`, Traefik's pods run the `inkwall-engine:0.2.2` image, and each
`inkwall-waf` Middleware has `maxResponseBodySize` 65536 (none on Traefik before v3.7). Send an
attack through a protected route, as in the [README](../README.md#protect-a-route), to check it's
blocked.

### Rolling back

0.1.x can't read a bundle split into chunks, and never publishes a bundle over 900 KiB. Before
`helm rollback`, check there are no chunks:

```sh
kubectl -n inkwall-system get secret -l waf.inkwall.dev/bundle-chunk
```

If there are, shrink the policies until the bundle fits again: 0.2.2 then stores it in
`inkwall-bundle` alone, and deletes the chunks. Otherwise the rolled-back operator can't read the
bundle and builds nothing. Then delete `inkwall-bundle` and its chunks, so it builds a new one, if
the policies fit:

```sh
kubectl -n inkwall-system delete secret inkwall-bundle
kubectl -n inkwall-system delete secret -l waf.inkwall.dev/bundle-chunk
```

Rolling back to 0.1.0 needs more: 0.1.0 doesn't know the finalizer, `IngressRoute` targets, Managed
mode or key rotation. Before `helm rollback`:

1. Switch to `Standalone` if you set another mode
   ([disconnecting](control-plane.md#disconnecting)), and wait for any signing key rotation to
   finish (the Secret's `waf.inkwall.dev/rotation-phase` is empty).
2. Delete the policies that target an `IngressRoute`.
3. Remove the finalizer from every policy, or none of them can be deleted under 0.1.0:

   ```sh
   kubectl get wafpolicy -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}' |
     while read -r ns name; do
       kubectl -n "$ns" patch wafpolicy "$name" --type merge -p '{"metadata":{"finalizers":null}}'
     done
   ```

Then roll back, and restart Traefik so its pods run the older engine again:

```sh
helm -n inkwall-system rollback inkwall
kubectl -n <traefik namespace> rollout restart deployment/<traefik>
```
