# GitOps: fields the operator writes

This guide lists every field the operator writes on objects you own, and shows how to configure
Argo CD and Flux so they neither report it as drift nor undo it.

## Contents

- [Prerequisites](#prerequisites)
- [What the operator writes](#what-the-operator-writes)
- [When there is drift](#when-there-is-drift)
- [Argo CD](#argo-cd)
  - [Deleting policies with Argo CD](#deleting-policies-with-argo-cd)
  - [Managed mode](#managed-mode)
- [Flux](#flux)
- [Installing the chart with a GitOps tool](#installing-the-chart-with-a-gitops-tool)
  - [Argo CD](#argo-cd-1)
  - [Flux](#flux-1)
- [Checking it worked](#checking-it-worked)
- [Undoing it](#undoing-it)

## Prerequisites

- Inkwall installed ([chart README](../deploy/helm/inkwall/README.md)), with `WAFPolicy`
  objects that target your [`Ingress`](https://doc.traefik.io/traefik/routing/providers/kubernetes-ingress/)
  or [`IngressRoute`](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/) objects
  served by [Traefik](https://doc.traefik.io/traefik/).
- Those routes applied by [Argo CD](https://argo-cd.readthedocs.io/en/stable/) or by
  [Flux](https://fluxcd.io/flux/).

## What the operator writes

To protect a route, the operator adds its
[ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) [Middleware](https://doc.traefik.io/traefik/middlewares/overview/),
`inkwall-waf`, to it. It changes only its own entries, keeps yours in order, and removes only
its own entries when the route is no longer protected. It writes with
[JSON merge patches](https://www.rfc-editor.org/rfc/rfc7386), under the
[field manager](https://kubernetes.io/docs/reference/using-api/server-side-apply/#managers)
`inkwall-operator`.

| Object | Field | Value |
|---|---|---|
| `Ingress` (Traefik's) | [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) `traefik.ingress.kubernetes.io/router.middlewares` | `<namespace>-inkwall-waf@kubernetescrd` added first; your entries kept after it |
| `Ingress` | annotation `waf.inkwall.dev/wired` | `<namespace>-inkwall-waf@kubernetescrd`: marks what the operator added |
| `IngressRoute` (`traefik.io`) | `spec.routes[*].middlewares` | `{name: inkwall-waf}` added first in every route; your entries kept after it |
| `IngressRoute` | annotation `waf.inkwall.dev/wired` | `inkwall-waf` |
| `WAFPolicy` | `metadata.finalizers` | `waf.inkwall.dev/unwire` ([finalizer](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)): the operator unwires the policy's routes before it can be deleted |
| `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet`, `InkwallConfig` | `status` | Conditions, bundle version |

Objects the operator creates and owns are not in your Git repository, and [GitOps](https://opengitops.dev/) tools don't
track them: the Middleware `inkwall-waf` in each namespace with a protected route, the [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/)
`inkwall-trust` in each Traefik namespace, and the [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) and ConfigMaps in `inkwall-system`.
They carry the [label](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) `app.kubernetes.io/managed-by: inkwall-operator`.

The engine is injected into Traefik's pods when they are created, by a mutating
[admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/).
Traefik's [`Deployment`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) or [`DaemonSet`](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) isn't changed, so it doesn't drift.

The operator never writes your `InkwallConfig`'s spec or annotations. Bump
`waf.inkwall.dev/rotate-signing-key` in Git to rotate the signing key
([key rotation](key-rotation.md)).

## When there is drift

A GitOps tool compares the fields your manifest sets. The operator's fields cause drift only
when your manifest sets the same field:

| Your manifest | Drift |
|---|---|
| An `Ingress` without the `router.middlewares` annotation | None |
| An `Ingress` with its own `router.middlewares` annotation | The annotation |
| Any `IngressRoute` | `spec.routes`. Traefik's CRD doesn't declare a [list type](https://kubernetes.io/docs/reference/using-api/server-side-apply/#merge-strategy) for `routes`, so the whole list is one value to the API server and to both tools |
| A `WAFPolicy` without `metadata.finalizers` | None |
| `status` | None: both tools ignore it |

Undoing the drift is worse than seeing it: the tool removes Inkwall's Middleware, and the route
is not inspected until the operator puts it back. It puts it back as soon as it sees the change,
because it watches Ingresses and IngressRoutes, but the tool undoes it again on its next sync.

## Argo CD

Argo CD's [`ignoreDifferences`](https://argo-cd.readthedocs.io/en/stable/user-guide/diffing/)
removes fields from both sides before it compares. Add these rules to every [Application](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#applications) that
deploys protected routes:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: shop
  namespace: argocd
spec:
  # project, source, destination as before
  ignoreDifferences:
    # Only needed for Ingresses whose manifest sets this annotation.
    - group: networking.k8s.io
      kind: Ingress
      jsonPointers:
        - /metadata/annotations/traefik.ingress.kubernetes.io~1router.middlewares
    - group: traefik.io
      kind: IngressRoute
      jqPathExpressions:
        # A route with only Inkwall's Middleware: its whole list.
        - '.spec.routes[]? | select(.middlewares == [{"name": "inkwall-waf"}]) | .middlewares'
        # A route with yours too: only Inkwall's entry.
        - '.spec.routes[]?.middlewares[]? | select(.name == "inkwall-waf")'
  syncPolicy:
    syncOptions:
      - ApplyOutOfSyncOnly=true
```

- In a [JSON pointer](https://www.rfc-editor.org/rfc/rfc6901), `/` in a key is written `~1`, so
  the annotation `traefik.ingress.kubernetes.io/router.middlewares` becomes
  `traefik.ingress.kubernetes.io~1router.middlewares`.
- Argo CD runs each [jq](https://jqlang.org/manual/) expression as a deletion, in order. The first
  expression removes a list that holds only Inkwall's entry. The second removes Inkwall's entry
  from a list that also holds yours, so your own Middlewares still show up in the diff.
- `waf.inkwall.dev/wired` and the finalizer need no rule: your manifests don't set them.

`ignoreDifferences` only affects the diff. A sync still applies your manifest as it is, and that
removes Inkwall's entry from the route until the operator adds it back. The
[sync option](https://argo-cd.readthedocs.io/en/stable/user-guide/sync-options/)
`ApplyOutOfSyncOnly=true` makes a sync skip objects that don't differ, so routes you didn't change
keep their wiring. A route you change in Git is applied, and the operator wires it again right
after.

Two trade-offs to know:

- With the `Ingress` rule, Argo CD ignores the whole annotation, including your own Middlewares in
  it. A change you make to that annotation alone doesn't mark the Ingress OutOfSync, so with
  `ApplyOutOfSyncOnly=true` it isn't applied. Change another field of the Ingress in the same
  commit, or run one manual sync with "Apply out of sync only" turned off; either applies the
  Ingress, and the operator wires it again right after.
- `RespectIgnoreDifferences=true` would keep the live value of ignored fields during a sync, so
  Inkwall's entry would stay. For the `Ingress` annotation it also keeps your old Middlewares
  instead of applying your change. For `IngressRoute`, Argo CD merges custom resources' lists as a
  whole, and we haven't verified how it treats an ignored entry inside `spec.routes`. Don't rely
  on it there.

### Deleting policies with Argo CD

When Argo CD prunes a `WAFPolicy`, the deletion waits for the `waf.inkwall.dev/unwire` finalizer:
the operator unwires the policy's routes, then removes it. If the operator is gone, for example
because its Application was deleted without the chart's pre-delete hook, the policy stays in
`Terminating`. Remove the finalizer as the
[chart README](../deploy/helm/inkwall/README.md#uninstalling) shows.

### Managed mode

In [Managed mode](control-plane.md#managed-mode), objects labelled `inkwall.dev/source: saas` come
from the control plane, and the validating webhook refuses changes from anyone else, Argo CD
included. Don't keep them in Git. Your unlabelled objects are not affected.

## Flux

Flux's [kustomize-controller](https://fluxcd.io/flux/components/kustomize/) applies manifests with
[server-side apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/), as the
field manager `kustomize-controller`, forcing ownership of the fields in your manifests. At each
interval it does a dry run and applies again when the result differs from the cluster. Fields your
manifest doesn't set belong to other managers and are left alone.

So, as in the table above: an `Ingress` without its own `router.middlewares` annotation never
drifts. An `Ingress` with one, and every `IngressRoute`, is reset at each interval: Flux removes
Inkwall's entry, and the operator adds it back.

Flux 2.9 (kustomize-controller v1.9) and later have
[`spec.ignore`](https://fluxcd.io/flux/components/kustomize/kustomizations/) on the
`Kustomization`. It takes JSON pointers, scoped to some objects, which Flux leaves out of both
drift detection and the apply:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: shop
  namespace: flux-system
spec:
  interval: 10m
  path: ./shop
  prune: true
  sourceRef:
    kind: GitRepository
    name: shop
  ignore:
    # Only needed for Ingresses whose manifest sets this annotation.
    - paths:
        - /metadata/annotations/traefik.ingress.kubernetes.io~1router.middlewares
      target:
        group: networking.k8s.io
        kind: Ingress
    # One path per route of the IngressRoute: /spec/routes/0, /spec/routes/1, ...
    - paths:
        - /spec/routes/0/middlewares
      target:
        group: traefik.io
        kind: IngressRoute
        name: web
```

- Flux's paths are plain JSON pointers. A pointer can't pick one list entry by its content, so the
  whole `middlewares` list of a route is ignored, yours included. After the first apply, Flux no
  longer applies changes to an ignored field. To change your own Middlewares on a protected route,
  remove the rule, change them, and add the rule back.
- A rule without `target` applies to every object of the Kustomization. Scope each one.

With an older Flux, or to keep Flux off a protected route entirely, annotate the route in Git with
`kustomize.toolkit.fluxcd.io/ssa: IfNotPresent`: Flux creates it and never updates it afterwards.
Edit it with `kubectl` from then on, or remove the annotation to let Flux manage it again.

## Installing the chart with a GitOps tool

The operator also changes objects of the Inkwall [Helm](https://helm.sh/docs/) chart itself, in its
`MutatingWebhookConfiguration` `inkwall-operator-mutating`:

| Field | Why |
|---|---|
| `webhooks[*].failurePolicy` | `Fail` while a policy is in block mode, else `Ignore` (the chart's value) |
| `webhooks[*].objectSelector` | Follows an `InkwallConfig` integration selector, when you set one |
| `webhooks[*].clientConfig.caBundle` | The webhook CA, injected by the operator (or by [cert-manager](https://cert-manager.io/docs/)) |

The same `caBundle` is injected into `ValidatingWebhookConfiguration` `inkwall-operator-validating`.
The chart doesn't set `caBundle`, so it doesn't drift. A tool that resets `failurePolicy` to
`Ignore` lets Traefik pods start without the engine while the operator is down, even though a
policy blocks; the operator sets it back once it sees the change.

The `InkwallConfig` is not part of the chart, because the chart installs its CRD. Keep it, and
your policies, in Git apart from the chart: in another Argo CD Application, or in a Flux
Kustomization whose `dependsOn` names the one that installs the chart. The validating webhook
refuses `WAF*` objects while no operator replica answers, so let the tool retry until the operator
is ready.

Upgrade the chart with the tool, not with `helm upgrade`. The chart's values (such as
`controlPlane.enrollmentToken`) then live in Git: create the token Secret yourself rather than
committing the token ([control plane](control-plane.md#enrolling-a-cluster)).

### Argo CD

In the Application that installs the chart:

```yaml
spec:
  ignoreDifferences:
    - group: admissionregistration.k8s.io
      kind: MutatingWebhookConfiguration
      name: inkwall-operator-mutating
      jqPathExpressions:
        - .webhooks[]?.failurePolicy
        - .webhooks[]?.objectSelector
        - .webhooks[]?.clientConfig.caBundle
    - group: admissionregistration.k8s.io
      kind: ValidatingWebhookConfiguration
      name: inkwall-operator-validating
      jqPathExpressions:
        - .webhooks[]?.clientConfig.caBundle
  syncPolicy:
    syncOptions:
      - RespectIgnoreDifferences=true
```

Webhook configurations are built-in types whose `webhooks` list is merged by name, so
`RespectIgnoreDifferences=true` keeps the operator's values during a sync. Argo CD runs the chart's
`helm.sh/hook: pre-delete` Job as a
[PreDelete hook](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-hooks) when the
Application is deleted with its resources, so the routes are unwired and the finalizers removed
before the operator goes.

### Flux

[helm-controller](https://fluxcd.io/flux/components/helm/) compares a `HelmRelease` with the cluster only when
[drift detection](https://fluxcd.io/flux/components/helm/helmreleases/#drift-detection) is on. If
you turn it on, ignore the fields above. The mutating configuration has one webhook:

```yaml
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: inkwall
  namespace: inkwall-system
spec:
  interval: 10m
  chartRef:
    kind: OCIRepository
    name: inkwall
  driftDetection:
    mode: enabled
    ignore:
      - paths:
          - /webhooks/0/failurePolicy
          - /webhooks/0/objectSelector
        target:
          kind: MutatingWebhookConfiguration
          name: inkwall-operator-mutating
```

## Checking it worked

1. The application shows as synced: `Synced` in Argo CD, or a `Ready` Kustomization with no drift
   reported (`flux diff kustomization <name> --path <dir>` shows no change to the routes).
2. After a sync, and after the next Flux interval, the routes are still wired:

   ```sh
   kubectl -n shop get ingress web \
     -o jsonpath='{.metadata.annotations.traefik\.ingress\.kubernetes\.io/router\.middlewares}{"\n"}'
   kubectl -n shop get ingressroute web -o jsonpath='{.spec.routes[*].middlewares[*].name}{"\n"}'
   ```

   Each prints `shop-inkwall-waf@kubernetescrd` or `inkwall-waf` first.
3. The policies are `Ready`, and stay so across syncs:

   ```sh
   kubectl get wafpolicy -A
   ```

## Undoing it

Remove the `ignoreDifferences` rules, sync options, `spec.ignore` rules or
`kustomize.toolkit.fluxcd.io/ssa` annotations you added. Nothing in the cluster changes. As long
as a policy protects a route, the tool reports the drift again. To stop the operator writing to a
route, remove the route from the policy's `targetRefs` or delete the policy: the operator removes
its entries and its annotation, and leaves yours.
