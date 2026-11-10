# Testing policies offline

This guide tests rules, `WAFPolicy` objects and the cluster's [policy bundle](glossary.md#bundle) with `inkwallctl test`,
on your machine or in CI, before they block real traffic.

## Contents

- [Prerequisites](#prerequisites)
- [Test a request](#test-a-request)
- [Test `WAFPolicy` objects](#test-wafpolicy-objects)
- [Test the cluster's bundle](#test-the-clusters-bundle)
- [From a log line to an exclusion](#from-a-log-line-to-an-exclusion)
- [Suggest exclusions from the events](#suggest-exclusions-from-the-events)
- [Test suites](#test-suites)
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

`ARGS:q`, `ARGS_GET:q` and `ARGS_POST:q` all name the argument `q`. A match on an argument's name
(`ARGS_NAMES:q`), a cookie (`REQUEST_COOKIES:session`) or a header (`REQUEST_HEADERS:Referer`) is
excluded with `when.argumentName`, `when.cookie` or `when.header`. What no field names (the
request body, the URI) can only be excluded for the whole path. Then check the exclusion with `inkwallctl test --policy` before
it reaches the cluster: the request that matched no longer shows `942100@ARGS:q`, and an attack in
another argument still gets `deny`.

For one request, `inkwallctl explain request <request-id>` does all this: it finds the event by
the request ID the client got in `X-Request-Id`, describes each rule, and prints the narrowest
exclusion, checked as `inkwallctl test --policy` does ([Explain a denied request](troubleshooting.md#explain-a-denied-request)).

Each engine logs at most 10 security event lines per second for each policy and rule (the
engine's `--event-log-rate`), so a scanner or one false positive on a busy route doesn't flood the
logs. The lines left out are counted in `inkwall_security_event_logs_suppressed_total{policy}`,
and the next line that gets through says how many in `suppressed`. The events sent to the operator
aren't limited.

## Suggest exclusions from the events

`inkwallctl tune` does the same for many events at once: it groups them by policy, path, rule and
variable, and suggests the narrowest exclusion for each group, a rule on one exact path for one
argument, argument name, cookie or header. Give it the engines' logs (`--from-logs`), or events
from the events API, one JSON object per line:

```sh
kubectl -n traefik logs -l app.kubernetes.io/name=traefik -c inkwall-engine --since=168h >engine.log
inkwallctl tune --from-logs engine.log
```

```console
15 security events

WAFPolicy shop/storefront: 13 logged requests would be denied in Block mode
  942100@ARGS:q on /search: 6 times, 4 client IPs (request IDs req-q0, req-q1, req-q2)
  942440@REQUEST_COOKIES:session_hint on /account: 1 time, 1 client IP (request IDs req-c1)
  932100@REQUEST_BODY on /upload: 1 time, 1 client IP (request IDs req-b1)
    not suggested: no exclusion field names REQUEST_BODY: --broad would turn the rule off for every variable on the path
  Suggested exclusions:
    rules 942440, on /account, for cookie session_hint
    rules 942100, on /search, for argument q
```

- The anomaly score rules (949110 and the other 949, 959 and 980 rules) are never suggested:
  the rules that added to the score are what to tune.
- It never suggests a rule off for every path. A rule off for every variable on a path, for what
  no exclusion field names, only with `--broad`. A path a policy can't hold (`;`, `%`) and a name
  outside the exclusion syntax get no suggestion.
- `--min-count` leaves out what was seen fewer times. Many client IPs for one group point to a
  false positive; one client IP, to a scanner or an attack: check each group before you add it.
- `-o yaml` writes the exclusions to add, by policy. With `--policy` (and `--rule-set`,
  `--configmap`, `--ingress`, as `inkwallctl test` takes them), it checks the policies with the
  exclusions added as `inkwallctl test --policy` does, and writes the policies with the exclusions
  appended, ready to apply:

```sh
inkwallctl tune --from-logs -o yaml --policy wafpolicy.yaml --rule-set wafruleset.yaml engine.log >tuned.yaml
inkwallctl test --policy tuned.yaml --rule-set wafruleset.yaml --expect deny --request attacks.http
```

## Test suites

A suite keeps the requests and the verdicts they must get in one file: `inkwallctl test --suite`
checks each case and exits 1 when one fails. Cases can also hold the upstream's response, to test
the [response rules](design/0006-adapter-protocols.md#response-inspection-v040) (data leaks)
offline. The format is **experimental**: it may change in a minor release.

```yaml
# Paths are relative to the suite file. policy, ruleSet, configMap and ingress take a path or a
# list, as the flags of the same name; or bundle and bundleKey. Without any, the flags apply.
policy: wafpolicy.yaml
ingress: route.yaml
cases:
  - name: a login form passes
    request: {method: POST, uri: /login, host: shop.example.com, body: "user=alice&password=b"}
    expect: {action: allow}
  - name: SQL injection is denied
    request: {url: "http://shop.example.com/search?q=1' OR '1'='1"}
    expect: {action: deny, status: 403, rules: [942100], policy: shop/web}
  - name: every recorded attack is denied
    request: {file: attacks.http}
    expect: {action: deny}
  - name: an SQL error page is not leaked
    request: {uri: "/item?id=7", host: shop.example.com}
    response:
      status: 500
      headers: {Content-Type: text/html}
      body: "You have an error in your SQL syntax; check the manual"
    expect: {action: deny, phase: response}
```

```console
$ inkwallctl test --suite suite.yaml --junit results.xml
ok    a login form passes
      request   allow      POST /login  policy=shop/web  904µs
...
ok    an SQL error page is not leaked
      request   allow      GET /item?id=7  policy=shop/web  287µs
      response  deny  403  GET /item?id=7  policy=shop/web  reason=rule  rules=951230,959100  interrupting=959100  matches=951230@RESPONSE_BODY,959100@TX:blocking_outbound_anomaly_score  score=5  290µs
4 of 4 case(s) passed
```

- **`request`**: inline, a `url`, or a `uri` with a `host` (default `localhost`), with `method`
  (default `GET`, or `POST` with a `body`), `headers` and `body` (a form by default, as
  `curl -d`); or a `file` of raw HTTP requests (a `.har` file is read as HAR), whose every request
  must meet the expectation. `clientIP` sets the client IP (default `--client-ip`, or 127.0.0.1).
- **`response`**: `status` (default 200), `headers` and `body`. The response is inspected
  in-process, as the engine does after a request it let through: its body only when the
  `Content-Type` is one the rules read (text, HTML, XML, JSON), up to the policy's
  `responses.maxBytes`. With a policy, only if it sets `spec.responses.inspect`; with the flags,
  as the engine with `--inspect-responses`. A denied request's response isn't inspected.
  `--engine` can't check responses: the check API has no response.
- **`expect`**: any of `action` (`allow`, `deny` or `log`), `status`, `rules` (each must match),
  `exactRules` (exactly these match), `notRules` (none of these matches), `policy`
  (`namespace/name`) and `phase` (`request` or `response`). The rules are the request's and the
  response's. The verdict is the response's when it was inspected and isn't `allow` while the
  request's is not, else the request's.

A failing case says what was expected and what the verdict was:

```console
FAIL  an SQL error page is not leaked: action allow, want deny; phase request, want response (the response wasn't inspected: with --policy or --bundle, the policy must set spec.responses.inspect)
```

`--junit FILE` writes the results as [JUnit XML](https://github.com/windyroad/JUnit-Schema), which
CI systems show as test reports: a test case per case, a failure with the expectation and the
actual verdicts. [`examples/tests/suite.yaml`](../examples/tests/suite.yaml) is a complete suite.

## Run the tests in CI

Keep sample attacks and legitimate traffic next to your policies, and fail the build on a wrong
verdict with `--expect allow` or `--expect deny`:

```yaml
- run: |
    inkwallctl test --policy k8s/waf/ --expect deny --request test/waf/attacks.http
    inkwallctl test --policy k8s/waf/ --expect allow --har test/waf/legitimate.har
```

Or keep the cases and their expectations in a [suite](#test-suites), and hand the JUnit report to
your CI's test reporter:

```yaml
- run: inkwallctl test --suite test/waf/suite.yaml --junit waf-results.xml
```

## Checking it worked

`inkwallctl test` exits 0 when every request gets the `--expect` verdict (or every case of the
`--suite` passes), 1 on a wrong verdict and 2 on an error. It changes nothing in the cluster, so there is nothing to undo.
