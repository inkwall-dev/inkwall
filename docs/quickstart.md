# Quickstart

This guide goes from nothing to an attack blocked by Inkwall in about five minutes, on a local
[kind](https://kind.sigs.k8s.io/) cluster, with the released chart and images and Traefik in front of a demo app. You
see the attack logged in `Detect` mode first, then denied in `Block` mode.

## Contents

- [Prerequisites](#prerequisites)
- [Create the cluster](#create-the-cluster)
- [Install Inkwall](#install-inkwall)
- [Install Traefik](#install-traefik)
- [Protect the demo app](#protect-the-demo-app)
- [Block](#block)
- [Checking it worked](#checking-it-worked)
- [Clean up](#clean-up)
- [Next](#next)

## Prerequisites

[Docker](https://docs.docker.com/get-started/), [kind](https://kind.sigs.k8s.io/docs/user/quick-start/), [kubectl](https://kubernetes.io/docs/tasks/tools/) and [Helm](https://helm.sh/docs/intro/install/) 3, and `curl`.

## Create the cluster

<!-- quickstart: cluster -->
```sh
kind create cluster --name inkwall-quickstart
```

## Install Inkwall

The latest release of the chart, with its operator and engine images:

<!-- quickstart: inkwall -->
```sh
helm install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall \
  --namespace inkwall-system --create-namespace
kubectl -n inkwall-system rollout status deployment/inkwall-operator --timeout=3m
```

## Install Traefik

After Inkwall: the operator injects the engine into Traefik's pods when they are created.

<!-- versions: TRAEFIK_CHART_VERSION -->
<!-- quickstart: traefik -->
```sh
helm repo add traefik https://traefik.github.io/charts
helm install traefik traefik/traefik --version 42.3.1 --namespace traefik --create-namespace
kubectl -n traefik rollout status deployment/traefik --timeout=3m
```

Traefik's pod has the engine now, an `inkwall-engine` sidecar beside `traefik`:

```sh
kubectl -n traefik get pods -o jsonpath='{.items[0].spec.initContainers[*].name}{" "}{.items[0].spec.containers[*].name}{"\n"}'
```

## Protect the demo app

[`examples/traefik`](../examples/traefik) is a demo app ([whoami](https://github.com/traefik/whoami)), its Ingress for
`shop.example.com`, and a `WAFPolicy` on the Ingress in `Detect` mode: attacks are logged, not
blocked.

<!-- quickstart: protect -->
```sh
kubectl apply -k 'https://github.com/inkwall-dev/inkwall//examples/traefik?ref=main'
kubectl -n shop rollout status deployment/web --timeout=3m
kubectl -n shop wait wafpolicy/web --for=condition=Ready --timeout=3m
kubectl -n traefik port-forward service/traefik 8000:80 >/dev/null &
sleep 2
```

Send a SQL injection through Traefik. In `Detect` mode the app still answers, with 200:

<!-- quickstart: detect -->
```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' 'http://127.0.0.1:8000/?id=1%27%20OR%20%271%27%3D%271'
```

The engine logged it as a security event, with the rules that matched and where:

```sh
kubectl -n traefik logs deployment/traefik -c inkwall-engine | grep '"security event"' | tail -1
```

```json
{"level":"WARN","msg":"security event","policy":"shop/web","action":"log","reason":"rule","rule_ids":[942100,949110],"matches":[{"rule_id":942100,"variable":"ARGS:id"},...],"path":"/",...}
```

On a real application, run in `Detect` mode until the events show only attacks, excluding what
they show to be false positives: see [From a log line to an exclusion](testing-policies.md#from-a-log-line-to-an-exclusion).

## Block

<!-- quickstart: block -->
```sh
kubectl -n shop patch wafpolicy web --type merge -p '{"spec":{"mode":"Block"}}'
kubectl -n shop wait wafpolicy/web --for=condition=Ready --timeout=3m
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' 'http://127.0.0.1:8000/?id=1%27%20OR%20%271%27%3D%271'
```

The attack gets 403 now, and an ordinary request still passes:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' 'http://127.0.0.1:8000/products?id=42'
```

## Checking it worked

`kubectl get wafpolicy -n shop` shows the policy `Ready`, in `Block` mode, and
`inkwallctl status` ([releases page](https://github.com/inkwall-dev/inkwall/releases)) reports the cluster healthy:

```console
$ kubectl get wafpolicy -n shop
NAME   MODE    READY   REASON   BUNDLE   AGE
web    Block   True    Ready    3        1m
```

## Clean up

<!-- quickstart: cleanup -->
```sh
kill %1 2>/dev/null
kind delete cluster --name inkwall-quickstart
```

## Next

- Protect your own routes: [Protect a route](../README.md#protect-a-route), and the other proxies'
  examples: [`examples/envoy-gateway`](../examples/envoy-gateway), [`examples/istio`](../examples/istio),
  [`examples/haproxy`](../examples/haproxy), [`examples/raw-envoy`](../examples/raw-envoy).
- Test policies before they reach the cluster: [Testing policies](testing-policies.md).
- When something isn't `Ready`: [Troubleshooting](troubleshooting.md).
