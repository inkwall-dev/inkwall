# Running Inkwall in production

A checklist for a cluster whose traffic depends on Inkwall. Each item says what to set or check,
and links to the guide that explains it.

## Contents

- [Versions](#versions)
- [The operator](#the-operator)
- [The engines](#the-engines)
- [Detect, then Block](#detect-then-block)
- [False positives](#false-positives)
- [Failure modes](#failure-modes)
- [Client IP](#client-ip)
- [Network policies](#network-policies)
- [The signing key](#the-signing-key)
- [Monitoring](#monitoring)
- [Logs and security events](#logs-and-security-events)
- [The emergency switch](#the-emergency-switch)
- [Upgrades](#upgrades)
- [Scale](#scale)

## Versions

- [ ] **Pin the chart.** Install with `--version <version>`, not whatever is latest, and keep
  the version in Git if a GitOps tool installs it ([GitOps](gitops.md#installing-the-chart-with-a-gitops-tool)).
  The chart's images default to its `appVersion`; `operator.image.digest` and `engine.image.digest`
  pin them by digest ([chart values](../deploy/helm/inkwall/README.md#values)).
- [ ] **Verify what you install**: the images, the chart and the binaries are signed with cosign
  v3 ([Install](../README.md#install)).
- [ ] **Run a supported release**: the latest three minor versions get security fixes
  ([SECURITY.md](../SECURITY.md#supported-versions)).
- [ ] **Run supported proxies**: Kubernetes 1.29 or later; **Traefik v3.7 or later** (before
  v3.7, Traefik forwards `Upgrade: h2c`, and requests on such a connection reach the app
  uninspected: [WebSocket](websocket.md#through-each-proxy)); Envoy Gateway v1.9 or later;
  Istio 1.28 or later; HAProxy 3.1 or later; raw Envoy 1.33 or later ([Limits](../README.md#limits)).

## The operator

- [ ] **Keep two replicas or more** (`operator.replicas`, 2 by default). One leads; all serve the
  webhooks. The chart adds a PodDisruptionBudget (`minAvailable: 1`) and prefers to put the
  replicas on different nodes. Spread them across zones with `operator.topologySpreadConstraints`.
- [ ] **Know what depends on it.** Traffic doesn't: engines keep enforcing their last bundle. But
  the validating webhook fails closed, so while no replica answers, saving a `WAFPolicy` or rule
  set is refused. And while a policy is in `Block` mode, the Pod webhook fails closed too: new
  Traefik, HAProxy and Istio ingress gateway pods can't start, so those proxies can't scale or
  replace pods ([when the operator is down](../deploy/helm/inkwall/README.md#when-the-operator-is-down)).
  Give the operator an `operator.priorityClassName` that outranks the workloads it protects.
- [ ] **Size its memory.** It requests 100m CPU and 128Mi, with a 1Gi limit, and sets
  `GOMEMLIMIT` to 90% of the limit (`operator.resources`). Exporting security events to SIEMs
  adds its buffer and requests: `values.yaml` gives the formula; geo blocking adds up to about 100 MiB on the leader while it compiles a country database. Its memory grows with the policies and
  routes, not with the engines: see [Scale](#scale) for the numbers, and raise the limit for a
  cluster near them.

## The engines

- [ ] **Run several replicas of each proxy.** An engine runs in each proxy pod and answers only
  that pod's requests. While it is down, its pod isn't ready, so its Service sends it no new
  connections ([when the engine is down](../deploy/helm/inkwall/README.md#when-the-engine-is-down)).
  Give the proxies PodDisruptionBudgets too.
- [ ] **Size the engines** with `InkwallConfig.spec.engine.resources`. The default requests 100m
  CPU and 128Mi, with a 512Mi memory limit and no CPU limit. Keep it so: CPU throttling shows as
  tail latency on every request. The engine sets `GOMEMLIMIT` to 90% of its memory limit, unless
  `GOMEMLIMIT` is set. Its memory grows with the distinct rule sets in the bundle: about 20 MiB
  for the first Core Rule Set, and 2.1 MiB for each further one. Paranoia levels, thresholds,
  body limits and exclusions don't add one.
- [ ] **Give it CPU.** An engine evaluates at most two requests per CPU at once; past that,
  requests get the policy's failure mode, with reason `overload`
  ([InkwallEvaluationSlotsSaturated](monitoring.md#inkwallevaluationslotssaturated)).
- [ ] **New settings reach new pods.** The engine's settings apply to pods injected from then on:
  restart the proxy pods after a change (`kubectl rollout restart`); Envoy Gateway rolls its
  Envoy pods itself. For upgrades, `spec.engine.rollout: Automatic` replaces the pods that run
  another engine image than the one configured, one at a time, through the Eviction API, which
  respects their PodDisruptionBudgets.
- [ ] **Choose what a new engine does without a bundle** (`spec.engine.bootstrapMode`). With no
  cached bundle, the bundle Secret unreadable and the operator unreachable, it waits up to
  10 seconds, then allows every request (`AllowAll`, the default) or rejects them (`DenyAll`)
  until a bundle arrives.

## Detect, then Block

- [ ] **Start every policy in `Detect` mode** (the default), on real traffic, for a week or a
  release cycle. Exclude the false positives narrowly, test the policy offline, then switch to
  `Block` one policy at a time ([From Detect to Block](troubleshooting.md#from-detect-to-block)).
- [ ] **Before Block mode, allow the methods a REST API uses.** The CRS allows only GET, HEAD,
  POST and OPTIONS, so rule 911100 denies PUT, PATCH and DELETE. In the false-positive run that
  was most of the denials at paranoia level 1, 14 to 15% of the requests of Gitea and Directus. No
  exclusion names a method. List the methods in the rule set binding instead:

  ```yaml
  spec:
    ruleSets:
    - ref: {kind: ClusterWAFRuleSet, name: owasp-crs-v4}
      crs:
        allowedMethods: [GET, HEAD, POST, OPTIONS, PUT, PATCH, DELETE]
  ```
- [ ] **Explain and tune.** `inkwallctl explain request <request-id>` says why a request was
  denied and the narrowest exclusion; `inkwallctl tune` suggests exclusions from the events
  ([Explaining a policy or a denial](troubleshooting.md#explaining-a-policy-or-a-denial),
  [Suggest exclusions](testing-policies.md#suggest-exclusions-from-the-events)).
- [ ] **Test in CI**: keep the attacks and the false positives as files, and run
  `inkwallctl test` on every change to a policy ([Run the tests in CI](testing-policies.md#run-the-tests-in-ci)).
- [ ] **Check the status, not only the object.** A policy protects its routes once it is `Ready`
  (`Programmed`: its routes are wired; `Enforced`: every engine runs it). `inkwallctl status`
  exits 1 when something needs attention ([Cluster status](troubleshooting.md#cluster-status)).

## False positives

What a default policy denies of a real application's traffic, nothing excluded: the built-in CRS
in `Block` mode, `inkwallctl test --har` on recorded traffic (every denial is a false positive).

| Application | Requests | Paranoia level 1 | Paranoia level 2 |
|---|---|---|---|
| Juice Shop | 560 | 4.11% | 8.21% |
| Gitea | 335 | 15.22% | 27.16% |
| WordPress | 762 | 2.1% | 3.94% |
| Directus | 147 | 14.29% | 40.14% |

The traffic is each application's users and scripts, with free text, code and JSON that are hard
on a WAF; the rates fall as you add exclusions. Your own application differs: start in `Detect`
mode, or replay a HAR file of your traffic with `inkwallctl test --har`. Levels 3 and 4, and the
rules behind each rate, are in the
[full tables](../CONTRIBUTING.md#battle-test). Latency per proxy for 0.7.0 is in the release notes.

## Failure modes

- [ ] **Set `failureMode` and `timeout` per policy.** A request the engine can't inspect within
  the policy's `timeout` (250ms by default, at most 1s) gets its `failureMode`: unset, `Closed`
  (503) in `Block` mode and `Open` in `Detect` mode. Raise `timeout` for routes that take large
  bodies.
- [ ] **Know what each proxy does when the engine is down.** Traefik answers 500 in both modes,
  since its ForwardAuth can't fail open. Envoy Gateway (500) and Istio (503) let requests through
  only when every policy on the route fails open. HAProxy answers 503 when every policy on the
  Ingress fails closed ([When something is down](troubleshooting.md#when-something-is-down)).

## Client IP

- [ ] **Behind a load balancer, make the engine see the client.** Otherwise every client is the
  load balancer, for IP lists and in every event. Use the PROXY protocol or
  `externalTrafficPolicy: Local`; behind an HTTP load balancer, set
  `spec.engine.clientIP.trustedProxies` to its addresses ([Client IP](client-ip.md)).
- [ ] **Trust only what is in front of the proxy.** A wrong `trustedProxies` or `trustedHops`
  lets clients choose their address; close every path to the proxy that skips the load balancer
  ([Behind an HTTP load balancer](client-ip.md#behind-an-http-load-balancer)).

## Network policies

- [ ] **Turn on the chart's** with `networkPolicy.enabled: true`, narrowed with
  `networkPolicy.webhookFrom` and `metricsFrom`, and `networkPolicy.egress.enabled: true`
  ([Network flows](../deploy/helm/inkwall/README.md#network-flows)).
- [ ] **Open the proxy namespaces' side yourself.** The chart doesn't own them: let the engines
  reach the operator's distribution port (9445) and the API server, and Prometheus reach their
  `inkwall-admin` port. With egress limited, also let the operator reach the gateway pods of
  Envoy Gateway, Istio and the HAProxy controller for its probe, or their policies stay
  `Unverified`.
- [ ] **Keep the proxy namespaces trusted.** A pod in one of `injection.proxyNamespaces` with a
  proxy's labels gets the engine and read access to the bundle, which holds every namespace's
  policies. List only namespaces where only the people who run the proxy create pods
  ([Proxy namespaces](../deploy/helm/inkwall/README.md#proxy-namespaces)).

## The signing key

- [ ] **Rotate it on a schedule**: `spec.signingKey.rotationInterval` on the `InkwallConfig`
  (`2160h` for 90 days, at least `1h`). Traffic is unaffected, and a rotation waits for every
  engine to trust the new key ([Rotating the bundle signing key](key-rotation.md)).
- [ ] **Guard the release namespace.** The key is the Secret `inkwall-bundle-signing-key` there.
  Whoever can read it can sign a bundle every engine trusts. `helm uninstall` keeps it, so a
  reinstall goes on with the same key.

## Monitoring

- [ ] **Turn on the monitoring kit**: `metrics.serviceMonitor`, `podMonitor`, `prometheusRule`
  and `dashboard` ([Monitoring](monitoring.md)). Prometheus must be able to scrape pods in the
  proxy namespaces.
- [ ] **Route the alerts.** Each has a runbook: [InkwallEngineDisconnected](monitoring.md#inkwallenginedisconnected),
  [InkwallBundleRejected](monitoring.md#inkwallbundlerejected),
  [InkwallRequestsUninspected](monitoring.md#inkwallrequestsuninspected),
  [InkwallEvaluationSlotsSaturated](monitoring.md#inkwallevaluationslotssaturated),
  [InkwallAdapterErrors](monitoring.md#inkwalladaptererrors),
  [InkwallEnginesBehind](monitoring.md#inkwallenginesbehind),
  [InkwallWiringFailures](monitoring.md#inkwallwiringfailures) and
  [InkwallBundleNearSizeLimit](monitoring.md#inkwallbundlenearsizelimit).
- [ ] **Serve the operator's metrics over HTTPS** with `metrics.secure.enabled`
  ([Metrics over HTTPS](monitoring.md#metrics-over-https)).

## Logs and security events

- [ ] **Collect the engines' logs.** Each security event is a JSON line, `"msg":"security event"`,
  in the `inkwall-engine` container of the proxy pods. Keep `spec.engine.logLevel` at `Info` or
  `Warn`: `Error` hides the events (they still go to the operator).
- [ ] **Keep the audit log of policy changes.** Each change of a policy, rule set, IP list or
  `InkwallConfig` is a `"msg":"policy change"` line in the operator's log, from every replica:
  ship it with the rest ([The audit log](audit-log.md)). The API server's audit log stays the
  authoritative record.
- [ ] **Redact what your events must not carry.** Snippets of credentials, cookies and response
  bodies are never sent; `spec.events.redact` adds header and argument names, or turns snippets
  off ([Redacting security events](../deploy/helm/inkwall/README.md#redacting-security-events)).

## The emergency switch

- [ ] **Know how to suspend inspection.** `spec.suspend: true` on the `InkwallConfig` named
  `default` makes every engine allow every request within seconds, and removes nothing. If the
  `InkwallConfig` lives in Git, change it there, or your GitOps tool undoes the switch
  ([Suspending inspection](../deploy/helm/inkwall/README.md#suspending-inspection)). Going back
  from `Block` to `Detect` on one policy is the narrower switch.

## Upgrades

- [ ] **Read the version's notes** in [Upgrading](upgrading.md) before each upgrade, and follow
  [every upgrade](upgrading.md#every-upgrade): the chart, then the proxies' pods.
- [ ] **Keep engines at the operator's version.** A policy that uses a field the engines don't
  know yet stays `Enforced=False` (`EnginesOutdated`) until they run a release that does.

## Scale

The operator's design targets (0004 §8), measured by `make scale-test SCALE=full`:

| | Target | Measured |
|---|---|---|
| `WAFPolicy` objects | 5,000 | 5,000, each with 10 routes |
| Routes | 50,000 | 50,000 |
| Engines per cluster | 500 | 500 |
| Change to every engine, p95 | under 10 s | 4–5 s at 5,000 policies and 500 engines |
| Operator memory | under 512 MiB | a peak RSS of 400–420 MiB at 5,000 policies and 500 engines; under 200 MiB at 1,000 |
| Bundle, compressed | 900 KiB in one Secret, 7,200 KiB in chunks | 134 KiB at 5,000 policies |

A cluster near these numbers should raise `operator.resources.limits.memory`. The bundle is the
hard limit: past 7,200 KiB compressed, policy changes are refused (`BundleTooLarge`), and
[InkwallBundleNearSizeLimit](monitoring.md#inkwallbundlenearsizelimit) fires at 80%. The details
are in [0004 §8](design/0004-operator.md#8-scale-targets-v1).
