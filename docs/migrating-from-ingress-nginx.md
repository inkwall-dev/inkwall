# Migrating from ingress-nginx's ModSecurity

[ingress-nginx](glossary.md#ingress-nginx) is retired upstream. This guide converts its
[ModSecurity](glossary.md#modsecurity) settings into `WAFPolicy` objects with
`inkwallctl migrate ingress-nginx`, so the routes keep their WAF when they move to Traefik, or to
HTTPRoutes served by Traefik or Envoy Gateway.

## Contents

- [Prerequisites](#prerequisites)
- [Convert the settings](#convert-the-settings)
- [Target HTTPRoutes or IngressRoutes](#target-httproutes-or-ingressroutes)
- [What is converted](#what-is-converted)
- [Read the summary](#read-the-summary)
- [Check the objects offline](#check-the-objects-offline)
- [Apply them](#apply-them)
- [Differences to know](#differences-to-know)
- [Checking it worked](#checking-it-worked)

## Prerequisites

- `inkwallctl`, from the [releases page](https://github.com/inkwall-dev/inkwall/releases).
- The Ingresses and the ingress-nginx controller's [ConfigMap](glossary.md#configmap): read from the
  cluster (`--cluster`, which needs `get` on the ConfigMap and `list` on Ingresses), or saved as
  YAML (`-f`).
- Inkwall installed on the cluster the Ingresses move to: see the [README](../README.md).

## Convert the settings

From the cluster of the current kubeconfig context:

```sh
inkwallctl migrate ingress-nginx --cluster --output waf/
```

Or from files, such as `kubectl get -o yaml` output or the manifests kept in Git:

```sh
kubectl get ingress -A -o yaml > ingresses.yaml
kubectl -n ingress-nginx get configmap ingress-nginx-controller -o yaml > nginx-config.yaml
inkwallctl migrate ingress-nginx -f ingresses.yaml -f nginx-config.yaml --output waf/
```

Without `--output`, the objects are printed to stdout. `inkwallctl` only reads: it never changes
the cluster.

| Flag | Default | Meaning |
|---|---|---|
| `-f` | | File or directory of Ingresses and the ConfigMap; `-` reads stdin. Repeatable |
| `--cluster` | | Read from the cluster instead (`--kubeconfig`, `--context`) |
| `--namespace` | all, or `default` with `-f` | With `--cluster`, only this namespace; with `-f`, the namespace of objects that don't name one |
| `--controller-configmap` | `ingress-nginx/ingress-nginx-controller` | The controller's ConfigMap, whose settings apply to every Ingress |
| `--ingress-class` | `nginx` | Ingresses of another class are left out; Ingresses without a class are converted, with a note |
| `--annotation-prefix` | `nginx.ingress.kubernetes.io` | The controller's `--annotations-prefix` |
| `--output` | stdout | Directory to write one file per Ingress into |
| `--target` | `ingress` | What the policies target: `ingress`, or `httproute` / `ingressroute` for the routes replacing the Ingresses ([below](#target-httproutes-or-ingressroutes)) |

## Target HTTPRoutes or IngressRoutes

If the Ingresses move to Gateway API `HTTPRoute`s or Traefik `IngressRoute`s (for example with
`ingress2gateway`), point the policies at those routes instead:

```sh
inkwallctl migrate ingress-nginx -f ingresses.yaml -f nginx-config.yaml -f httproutes.yaml \
  --target httproute --output waf/
inkwallctl migrate ingress-nginx --cluster --target ingressroute --output waf/
```

The routes are read from the `-f` files, or with `--cluster` listed from the cluster (`list` on
`httproutes` or `ingressroutes`). Each Ingress is matched to its routes by what they match, not by
name: a route replaces it when it matches only hosts and paths of the Ingress, in the same
namespace. Hosts and paths are compared as the operator expands them, so `/api/` and `/api` are
the same prefix, but a prefix and an `Exact` path are not.

- A route matching exactly the Ingress's hosts and paths becomes the target. Several routes that
  share them (one per path, say) all become targets.
- When an `HTTPRoute` also carries other hosts or paths, a [named rule](glossary.md#httproute) of
  it that matches only the Ingress's paths becomes the target, with `sectionName`.
- Anything else is `TODO` and never guessed: no route matches only the Ingress's hosts and paths
  (the policy then keeps targeting the Ingress), or a host or path of the Ingress isn't matched by
  any target (it is unprotected until one is). A route that also matches other hosts, any host,
  only some methods, headers or query parameters would change what the policy covers, so it is
  never picked.

[`inkwallctl test`](testing-policies.md) routes requests through HTTPRoutes and IngressRoutes
(`--ingress httproutes.yaml`), so policies retargeted to them can be checked offline as below.
Give it the Ingresses too when some policies still target them (`TODO`).

## What is converted

Each Ingress on which ModSecurity runs gets a `WAFPolicy` of the same name that targets it (or,
with `--target`, the routes replacing it). The
settings are combined as ingress-nginx combines them: the ConfigMap's `enable-modsecurity`,
`enable-owasp-modsecurity-crs` and `modsecurity-snippet` first, then the Ingress's annotations
`enable-modsecurity`, `enable-owasp-core-rules`, `modsecurity-snippet` and
`modsecurity-transaction-id`. `enable-modsecurity: "false"` on an Ingress turns ModSecurity off for
it, and the other annotations do nothing without ModSecurity on.

- A canary Ingress (`canary: "true"`) gets no policy: ingress-nginx serves its traffic with the main
  Ingress's settings, and the main Ingress's policy covers the same hosts and paths.
- Ingresses whose policies match the same host and path are marked `check`: only one policy applies
  to a request (the oldest), so merge their settings into the one that should.
- nginx's own ModSecurity directives (`modsecurity`, `modsecurity_rules`...) in the
  `configuration-snippet` or `server-snippet` annotations, or the ConfigMap's `http-snippet`,
  `server-snippet` or `location-snippet`, are not read: they are `TODO`.

| ingress-nginx | `WAFPolicy` |
|---|---|
| `enable-owasp-core-rules`, `enable-owasp-modsecurity-crs`, `Include .../nginx-modsecurity.conf` | The built-in OWASP CRS v4 |
| `SecRuleEngine On` / `DetectionOnly` | `mode: Block` / `mode: Detect`; ingress-nginx's own `modsecurity.conf` sets `DetectionOnly` |
| `SecRuleEngine Off` | No policy |
| `setvar:tx.paranoia_level` or `tx.blocking_paranoia_level`, `tx.inbound_anomaly_score_threshold` (in a `SecAction`) | `ruleSets[].paranoiaLevel`, `inboundAnomalyThreshold` |
| `SecRuleRemoveById 942100 ...` | `exclusions` |
| `SecRuleUpdateTargetById 942100 "!ARGS:password"` | `exclusions` with `when.argument` |
| `SecRule REQUEST_FILENAME "@beginsWith /api/" "...,ctl:ruleRemoveById=942100"`, or `@streq` | `exclusions` with `when.path: /api/*` (or the exact path; an `@streq` path with `*` is `TODO`) |
| A range of CRS rules in such a rule, `ctl:ruleRemoveById=941100-941199` | `exclusions` with the IDs of the CRS rules in it |
| `ctl:ruleRemoveTargetById=942100;ARGS:q` in such a rule | `exclusions` with `when.path` and `when.argument` |
| `ctl:ruleEngine=Off` / `ctl:requestBodyAccess=Off` in such a rule | `skip.paths` / `skip.bodyPaths` |
| `SecRequestBodyAccess`, `SecRequestBodyLimit`, `SecRequestBodyLimitAction` | `body.inspect`, `body.maxBytes`, `body.onOversize` |
| `SecRequestBodyLimitAction ProcessPartial` without `SecRequestBodyLimit` | `body.onOversize: Allow` and `body.maxBytes` of `modsecurity.conf`'s limit (12.5 MiB) capped at 10 MiB; `TODO` when `modsecurity.conf` isn't loaded |
| `Include .../modsecurity.conf` after body directives | `TODO`: the file sets them again, so those above it are left out |
| Other `SecRule` and `SecAction` rules, and `SecRuleRemoveById` ranges, tags and messages to remove | Kept as they are in a `WAFRuleSet` named `<ingress>-modsecurity`, loaded after the CRS |

A policy that tunes the CRS or adds rules refers to a `ClusterWAFRuleSet` named `owasp-crs-v4` with
the built-in CRS, which is written alongside. Policies that only use the CRS's defaults leave
`ruleSets` empty.

## Read the summary

The summary on stderr lists, for each Ingress, every setting and what became of it:

```text
Ingress files/cloud: WAFPolicy files/cloud (Detect), WAFRuleSet files/cloud-modsecurity
  mapped  annotation modsecurity-snippet, line 1: Include /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf: the built-in OWASP CRS v4
  TODO    annotation modsecurity-snippet, line 5: not migrated: SecRequestBodyNoFilesLimit 131072: no equivalent in Inkwall
  check   annotation modsecurity-snippet, line 8: not migrated: SecAuditLog /dev/stdout: ModSecurity's own logs; the engine logs verdicts itself (protection is unchanged)
```

- `mapped`: converted to an equivalent setting.
- `check`: converted or left out with a difference worth knowing, such as a mode chosen because no
  `SecRuleEngine` was set, or audit log settings (the engine logs verdicts itself).
- `TODO`: not migrated; it needs a human. Nothing is dropped or weakened silently: a rule that
  can't be converted faithfully is listed here and left out of the objects. Typical ones are
  `Include` of other files, exclusions keyed on anything but the path (`@contains`, `@rx`, headers),
  `ctl:ruleRemoveById` ranges reaching outside the CRS's IDs (900000-999999), `ctl:ruleRemoveByTag`, CRS variables without a `WAFPolicy` field
  (`tx.allowed_methods`), and rules the engine rejects.

Each file with something not migrated says so in a comment at the top. `inkwallctl migrate` exits
0 when everything was converted, 1 when something is marked `TODO`, and 2 on an error.

## Check the objects offline

Before applying them, replay attacks and legitimate traffic against the objects with
[`inkwallctl test`](testing-policies.md):

```sh
inkwallctl test --policy waf/ --ingress ingresses.yaml --expect deny --request attacks.http
inkwallctl test --policy waf/ --ingress ingresses.yaml --expect allow --har legitimate.har
```

## Apply them

```sh
kubectl apply -f waf/
kubectl get wafpolicy -A
```

The policies target the Ingresses by name, so they follow them to their new controller: once the
Ingress is served by Traefik, the operator wires it to the engine. A policy whose Ingress is still
served by ingress-nginx is accepted but not programmed. Policies converted with `--target` target
the routes instead, and apply once those routes serve the traffic.

## Differences to know

- **CRS version.** Inkwall runs CRS v4; older ingress-nginx releases shipped CRS v3. Rule IDs
  mostly carry over, but check exclusions of v3 rules. v3's `tx.paranoia_level` is mapped to v4's
  blocking paranoia level.
- **Responses.** Inkwall inspects requests only: the CRS's response rules (`RESPONSE-95x`) and
  `tx.outbound_anomaly_score_threshold` have no equivalent.
- **Body limits.** Inkwall inspects up to `body.maxBytes` (64 KiB by default, 10 MiB at most) and,
  in Block mode, rejects larger bodies with 413. ingress-nginx's `modsecurity.conf` allowed bodies of
  up to 12.5 MiB with files and 128 KiB without. Set `body.maxBytes` or `body.onOversize: Allow` on
  routes that take large uploads.
- **Rule ranges.** A `ctl:ruleRemoveById` range becomes the IDs of the CRS rules in it today; rules
  a later CRS adds to the range are not excluded (the summary marks these `check`).
- **Order.** Kept rules load after the CRS, while snippet rules in ingress-nginx could load before
  it. Path exclusions apply from the start of the request, as `ctl` rules in phase 1 did; a `ctl`
  rule in phase 2 (`phase:2`, `phase:request` or no `phase`) is marked `check`, since the excluded
  rules' phase 1 checks are now off on its path too.
- **Failure mode.** In Block mode, a request that can't be inspected in time is rejected (503); see
  `failureMode` on the policy.

Start the converted policies in `Detect` mode if ingress-nginx ran in `DetectionOnly`, and switch to
`Block` once the verdicts look right.

## Checking it worked

`kubectl get wafpolicy -A` shows each policy `Ready` once its Ingress is served by Traefik, and an
attack on the route is answered 403 in Block mode:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.com' "http://$TRAEFIK/?id=1%27%20OR%20%271%27%3D%271"
```

To undo the migration, delete the objects: `kubectl delete -f waf/`.
