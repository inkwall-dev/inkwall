# Testing policies offline

This guide tests rules, `WAFPolicy` objects and the cluster's [policy bundle](glossary.md#bundle) with `inkwallctl test`,
on your machine or in CI, before they block real traffic.

## Contents

- [Prerequisites](#prerequisites)
- [Test a request](#test-a-request)
- [Test `WAFPolicy` objects](#test-wafpolicy-objects)
- [Test the cluster's bundle](#test-the-clusters-bundle)
- [From a log line to an exclusion](#from-a-log-line-to-an-exclusion)
- [Run the tests in CI](#run-the-tests-in-ci)
- [Checking it worked](#checking-it-worked)

## Prerequisites

- `inkwallctl`, from the [releases page](https://github.com/inkwall-dev/inkwall/releases). `inkwallctl version`
  prints which release it is.
- The requests to test: a URL, a file of raw [HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) requests (`--request`), or a browser [HAR](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
  file (`--har`).

## Test a request

`inkwallctl test` checks each request in-process, with the same engine and rule flags as
`inkwall-engine` (`--rules`, [`--paranoia-level`](https://coreruleset.org/docs/concepts/paranoia_levels/), `--disable-rule-groups`, ...). Unlike the engine,
its `--mode` defaults to `block`. `inkwallctl test -h` lists every flag.

```console
$ inkwallctl test 'http://shop.example.com/?id=1%27%20OR%20%271%27%3D%271'
deny  403  GET /?id=1%27%20OR%20%271%27%3D%271  reason=rule  rules=942100,949110  interrupting=949110  matches=942100@ARGS:id,949110@TX:blocking_inbound_anomaly_score  score=5  847µs
```

Each line shows the verdict, the status, the request, why, the matched rule IDs, where each rule
matched (`rule@variable`: rule 942100 matched the query argument `id`), the request's
[anomaly score](https://coreruleset.org/docs/concepts/anomaly_scoring/) and the time the check
took. `--json` prints the same as `matches` (`rule_id`, `variable`) and `anomaly_score`.

## Test `WAFPolicy` objects

Give `--policy` the policies, with the rule sets (`--rule-set`), [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) (`--configmap`) and
[Ingresses](https://kubernetes.io/docs/concepts/services-networking/ingress/), Traefik [IngressRoutes](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) or Gateway API [HTTPRoutes](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) (`--ingress`) they use. `inkwallctl` resolves them as the operator does, sends each
request to the policy of its host and path (`policy=` names it), and compiles them as the engine
does.

```console
$ inkwallctl test --policy wafpolicy.yaml --rule-set wafruleset.yaml --configmap configmap.yaml \
    --ingress ingress.yaml --request requests.http
allow      GET /products/42  policy=shop/storefront  580µs
deny  403  GET /?id=1%27%20OR%20%271%27%3D%271  policy=shop/storefront  reason=rule  rules=942100,949110  interrupting=949110  matches=942100@ARGS:id,949110@TX:blocking_inbound_anomaly_score  score=5  623µs
log        GET /api/orders?debug=true  policy=shop/api  reason=rule  rules=100100  interrupting=100100  matches=100100@ARGS:debug  20µs
allow      GET /?id=1%27%20OR%20%271%27%3D%271  reason=no_policy  0s
```

- A file, or a directory of `.yaml`, `.yml` and `.json` files, may hold several YAML documents of
  any of these kinds, or `kubectl get -o yaml` output. Each object is read by its kind, whichever
  flag named the file.
- Fields are checked as the API server's strict field validation does: a misspelled field is an
  error, not a setting silently left out. In an IngressRoute's routes, `inkwallctl` checks `match`
  and `kind`, and takes `services`, `middlewares` and the other fields Traefik reads as they are.
- Without `--ingress`, a single policy applies to every request; several policies need the
  Ingresses, IngressRoutes or HTTPRoutes they target.
- An IngressRoute's match rules are read as the operator reads them: `Host`, `Path` and
  `PathPrefix`, joined by `&&`. A policy whose IngressRoute has any other rule isn't enforced, and
  `inkwallctl` says which rule.
- An HTTPRoute is read as the operator reads it: its hostnames × its rules' matches (only the rule
  a policy's `sectionName` names), with `Exact` and `PathPrefix` paths and methods. Its wildcard
  hostnames cover subdomains at any depth, an Ingress's one label. A policy whose
  HTTPRoute has a regular expression path, or headers or query parameter matches, isn't enforced,
  and `inkwallctl` says which match.
- Objects the operator would reject, such as a missing rule set or rules that don't compile, are
  errors.
- Objects without a namespace go to `--namespace` (default `default`), as with `kubectl apply -n`.
- The inspection deadline is raised to 10 s, so a slow CI runner can't turn a verdict into a
  timeout.

## Test the cluster's bundle

To test what the cluster enforces, save the bundle [Secret](https://kubernetes.io/docs/concepts/configuration/secret/) and its public key, and give both to
`inkwallctl`, which checks the bundle's signature:

```sh
kubectl -n inkwall-system get secret inkwall-bundle -o yaml > bundle.yaml
kubectl -n inkwall-system get secret inkwall-bundle -o jsonpath='{.data.ed25519\.pub}' > bundle.pub
inkwallctl test --bundle bundle.yaml --bundle-key bundle.pub --har traffic.har
```

A bundle too large for one Secret is split into chunk Secrets. `inkwallctl` then prints the
`kubectl get secret` command that saves the bundle Secret with its chunks.

## From a log line to an exclusion

Before you move a policy from `Detect` to `Block`, look for false positives in the engines'
security event lines. Each says which rules matched and where, by the variable's name only: the
engine never logs what a rule matched.

```sh
kubectl -n <proxy namespace> logs <proxy pod> -c inkwall-engine | grep '"security event"' | tail -1
```

```json
{"level":"WARN","msg":"security event","policy":"shop/storefront","action":"log","reason":"rule","rule_ids":[942100,949110],"matches":[{"rule_id":942100,"variable":"ARGS:q"},{"rule_id":949110,"variable":"TX:blocking_inbound_anomaly_score"}],"anomaly_score":5,"method":"GET","host":"shop.example.com","path":"/search", ...}
```

Here rule 942100 matched the query argument `q` of `/search` (949110 only adds up the score). If
`q` is a free-text search field that legitimately holds SQL-like text, turn that rule off for that
argument on that path, not everywhere:

```yaml
spec:
  exclusions:
  - ruleIDs: [942100]
    when:
      path: /search
      argument: q
```

`ARGS:q`, `ARGS_GET:q` and `ARGS_POST:q` all name the argument `q`. A match on a header
(`REQUEST_HEADERS:User-Agent`) or a cookie can't be excluded by argument: exclude the rule on the
path instead, or fix the client. Then check the exclusion with `inkwallctl test --policy` before
it reaches the cluster: the request that matched no longer shows `942100@ARGS:q`, and an attack in
another argument still gets `deny`.

Each engine logs at most 10 security event lines per second for each policy and rule (the
engine's `--event-log-rate`), so a scanner or one false positive on a busy route doesn't flood the
logs. The lines left out are counted in `inkwall_security_event_logs_suppressed_total{policy}`,
and the next line that gets through says how many in `suppressed`. The events sent to the operator
aren't limited.

## Run the tests in CI

Keep sample attacks and legitimate traffic next to your policies, and fail the build on a wrong
verdict with `--expect allow` or `--expect deny`:

```yaml
- run: |
    inkwallctl test --policy k8s/waf/ --expect deny --request test/waf/attacks.http
    inkwallctl test --policy k8s/waf/ --expect allow --har test/waf/legitimate.har
```

## Checking it worked

`inkwallctl test` exits 0 when every request gets the `--expect` verdict, 1 on a wrong verdict and
2 on an error. It changes nothing in the cluster, so there is nothing to undo.
