# Testing policies offline

This guide tests rules, `WAFPolicy` objects and the cluster's [policy bundle](glossary.md#bundle) with `inkwallctl test`,
on your machine or in CI, before they block real traffic.

## Contents

- [Prerequisites](#prerequisites)
- [Test a request](#test-a-request)
- [Test `WAFPolicy` objects](#test-wafpolicy-objects)
- [Test the cluster's bundle](#test-the-clusters-bundle)
- [Run the tests in CI](#run-the-tests-in-ci)
- [Checking it worked](#checking-it-worked)

## Prerequisites

- `inkwallctl`, from the [releases page](https://github.com/inkwall-dev/inkwall/releases).
- The requests to test: a URL, a file of raw [HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) requests (`--request`), or a browser [HAR](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
  file (`--har`).

## Test a request

`inkwallctl test` checks each request in-process, with the same engine and rule flags as
`inkwall-engine` (`--rules`, [`--paranoia-level`](https://coreruleset.org/docs/concepts/paranoia_levels/), `--disable-rule-groups`, ...). Unlike the engine,
its `--mode` defaults to `block`. `inkwallctl test -h` lists every flag.

```console
$ inkwallctl test 'http://shop.example.com/?id=1%27%20OR%20%271%27%3D%271'
deny  403  GET /?id=1%27%20OR%20%271%27%3D%271  reason=rule  rules=942100,949110  interrupting=949110  847µs
```

Each line shows the verdict, the status, the request, why, the matched rule IDs and the time the
check took.

## Test `WAFPolicy` objects

Give `--policy` the policies, with the rule sets (`--rule-set`), [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) (`--configmap`) and
[Ingresses](https://kubernetes.io/docs/concepts/services-networking/ingress/) or Traefik [IngressRoutes](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) (`--ingress`) they use. `inkwallctl` resolves them as the operator does, sends each
request to the policy of its host and path (`policy=` names it), and compiles them as the engine
does.

```console
$ inkwallctl test --policy wafpolicy.yaml --rule-set wafruleset.yaml --configmap configmap.yaml \
    --ingress ingress.yaml --request requests.http
allow      GET /products/42  policy=shop/storefront  580µs
deny  403  GET /?id=1%27%20OR%20%271%27%3D%271  policy=shop/storefront  reason=rule  rules=942100,949110  interrupting=949110  623µs
log        GET /api/orders?debug=true  policy=shop/api  reason=rule  rules=100100  interrupting=100100  20µs
allow      GET /?id=1%27%20OR%20%271%27%3D%271  reason=no_policy  0s
```

- A file, or a directory of `.yaml`, `.yml` and `.json` files, may hold several YAML documents of
  any of these kinds, or `kubectl get -o yaml` output. Each object is read by its kind, whichever
  flag named the file.
- Without `--ingress`, a single policy applies to every request; several policies need the
  Ingresses or IngressRoutes they target.
- An IngressRoute's match rules are read as the operator reads them: `Host`, `Path` and
  `PathPrefix`, joined by `&&`. A policy whose IngressRoute has any other rule isn't enforced, and
  `inkwallctl` says which rule.
  <!-- TODO(v0.3.0): after #216, --ingress also reads HTTPRoutes (gateway.networking.k8s.io/v1): add them to the kinds above and say how their hostnames, matches and sectionName are read. -->
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
