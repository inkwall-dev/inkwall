# The audit log of policy changes

Who created, changed or deleted which `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet`, `WAFIPList`
or `InkwallConfig`, when, and what changed. The operator writes one log line for each change, records
a Kubernetes Event on the object, and counts it in a metric. It is always on, and needs no setting.

## Contents

- [Where it comes from](#where-it-comes-from)
  - [Deletes while the operator is unreachable](#deletes-while-the-operator-is-unreachable)
- [The log line](#the-log-line)
- [What is never logged](#what-is-never-logged)
- [Events](#events)
- [The metric](#the-metric)
- [Shipping the log](#shipping-the-log)
- [The API server's audit log](#the-api-servers-audit-log)
- [The control plane](#the-control-plane)

## Where it comes from

The operator's validating webhooks get every create, update and delete of the five kinds, with the
user who sent it and the object before and after. Once a webhook admits a request, the replica that
served it records the change. It records nothing for:

- a request the webhook refuses (a rule that doesn't compile, or someone other than the operator
  editing the control plane's objects in `Managed` mode);
- a dry run (`kubectl apply --dry-run=server`, `kubectl diff`): the webhooks are registered with
  `sideEffects: NoneOnDryRun`;
- an update that leaves the spec as it was: labels, annotations and finalizers, such as the
  operator's own wiring annotations and its `waf.inkwall.dev/unwire` finalizer. The status is a
  subresource, which the webhooks never see.

Deletes of most objects don't need the operator, and still don't: their webhook fails open
(`failurePolicy: Ignore`). Deleting the control plane's objects (`inkwall.dev/source: saas`) goes
to a webhook that fails closed, as before. The `InkwallConfig` webhook fails open for every
operation.

What the log can miss, or hold twice: it is the operator's view, not the API server's (see
[below](#the-api-servers-audit-log)).

- A change made while the operator is down isn't recorded.
- A request that a later step refuses (another webhook, a quota) may be recorded although it was
  never saved.
- One change can be recorded twice. A patch or server-side apply that sends no `resourceVersion` is
  retried by the API server when another write gets in first, and each try is admitted again.
  The two lines name the same user, object and change.

### Deletes while the operator is unreachable

A delete waits for the webhook's answer. When the operator's pods are down, the API server
fails at once (no endpoints, or the connection is refused) and the delete goes through. When the
operator can't be reached but doesn't refuse (a network partition, a hung pod), each delete of
these kinds waits the webhook's full timeout, 2 s, before it goes through. A namespace being
deleted deletes its objects one by one, so a namespace with 1,000 policies, rule sets and IP lists
takes about 33 minutes to go. To shorten it, lower the chart's `webhook.timeoutSeconds` (1 s at
least: every Inkwall webhook takes it), or bring the operator back, or scale it up, before
deleting.

## The log line

Each change is one JSON line in the operator's log, at `INFO`, with `"msg":"policy change"` and
`"logger":"audit"`:

```json
{"time":"2026-11-21T10:04:12.311Z","level":"INFO","msg":"policy change","logger":"audit","operation":"update","kind":"WAFPolicy","namespace":"shop","name":"checkout","uid":"6f1c2a4e-0000-4000-8000-000000000001","generation":3,"resourceVersion":"4711","user":"alice","groups":["system:authenticated","platform"],"groupsOmitted":0,"serviceAccount":"","operator":false,"changes":[{"path":"spec.mode","old":"Detect","new":"Block"},{"path":"spec.skip.paths","added":1,"addedItems":["\"/static/*\""]}],"changesOmitted":0}
```

| Field | |
|---|---|
| `operation` | `create`, `update` or `delete` |
| `kind`, `namespace`, `name`, `uid` | The object (`namespace` is empty for `ClusterWAFRuleSet` and `InkwallConfig`) |
| `generation` | The object's `metadata.generation` after the change; on a delete, its last |
| `resourceVersion` | The version the update or delete applied to; empty on a create |
| `user`, `groups` | Who sent the request, as the API server authenticated them: its first 16 groups |
| `groupsOmitted` | The user's other groups, counted |
| `serviceAccount` | `namespace/name` when the user is a ServiceAccount, else empty |
| `operator` | `true` when the operator made the change itself: its control plane's objects in `Managed` mode |
| `changes` | The spec's changed fields, below |
| `changesOmitted` | Changes left out to keep `changes` under 4 KiB |

Each entry of `changes` is one changed field of the spec, by its path (`spec.mode`,
`spec.engine.clientIP.trustedProxies`, `spec.selector.matchLabels["app.kubernetes.io/name"]`):

- a value: `old` and `new`, each absent when unset, cut to 128 bytes. An empty object set or
  unset shows as `{}`, so a switch such as `spec.engine.clientIP: {}` is seen;
- a list: `added` and `removed`, the number of items added and removed, and `addedItems` and
  `removedItems`, the first 5 of each as JSON, each cut to 256 bytes; or `reordered: true` when it
  holds the same items in another order. A list compares whole items: a field changed inside one
  item (a rate limit's `requests`, a rule set binding's `crs`) shows as that item removed and the
  changed one added. In a large item, cut to 256 bytes, the changed field may be past the cut.

A create lists every field it sets as `new`, a delete every field the object had as `old`. Field
names and their meaning are stable: a new field may be added, none is renamed or removed within
`v1alpha1`.

## What is never logged

No Secret's contents: these kinds only name Secrets (`caSecretRef`, `enrollmentSecretRef`,
`urlSecretRef`, ...), and the webhooks don't read them. The names are shown.

- `userInfo.extra` is never read: it can carry tokens or session data.
- The URLs, whose path or query may hold a token, show only their scheme and host:
  `spec.events.export.sinks[].json.url`, `.otlp.endpoint` and `spec.controlPlane.endpoint` become
  `https://intake.example.com`, never their path, query or user information.
- Under `spec.events.export`, a field whose name holds `header` is never shown (`<redacted>`):
  a sink's headers carry its credentials.
- No field of the five kinds holds a credential today. One added later, named `token`, `password`,
  `secret`, `apiKey`, `privateKey` or `credentials`, or ending in one of them (`bearerToken`,
  `clientSecret`), shows `<redacted>`, with every value under it; its path is still listed.
  Fields named `key` (a rate limit's key, a ConfigMap's or Secret's key) aren't credentials and
  are shown.
- The same rules apply inside list items, such as `spec.events.export.sinks`.

What the log does hold, from the specs:

- **Rules written inline** in a rule set (`spec.source.seclang`), cut to 128 bytes. They hold what
  their author wrote, which may include a value a rule compares with, such as a key in an
  `@streq`. The control plane gets them too.
- **IP addresses**: a `WAFIPList`'s entries, up to 5 added and 5 removed per change, and the
  trusted proxies. An address can be personal data: keep the log as you keep other logs that hold
  client addresses.

## Events

Each change is also a `Normal` Event on the object, from `inkwall-operator`: reason `Created`,
`Changed` or `Deleted`, and a short note with the user (`the operator` for its own changes) and up
to 8 changed paths. Each change is an Event of its own, never counted into another one's series,
so a note always names the change's own user:

```sh
kubectl get events -n shop --field-selector reason=Changed,involvedObject.kind=WAFPolicy
```

```text
Changed by alice: spec.mode, spec.skip.paths
```

Events about cluster-scoped objects go to the `default` namespace. Each replica records at most 100
at once, then 5 a second; past that, changes are still logged and counted. Events expire (one hour
by default, the API server's `--event-ttl`): the log line is the record to keep.

## The metric

`inkwall_operator_policy_changes_total{kind, operation}` counts the changes each replica's webhook
recorded ([Monitoring](monitoring.md#operator)). Sum it over the replicas:

```promql
sum by (kind, operation) (increase(inkwall_operator_policy_changes_total[1h]))
```

## Shipping the log

The lines go to the operator's standard output with its other logs. Every replica serves the
webhooks, and each change is logged by the one replica that admitted it: collect them all. With a
log collector that parses JSON, keep the lines with `msg` `policy change`, for example in
[Fluent Bit](https://docs.fluentbit.io/manual/pipeline/filters/grep):

```ini
[FILTER]
    Name   grep
    Match  kube.inkwall-system.inkwall-operator*
    Regex  msg ^policy change$
```

## The API server's audit log

The [Kubernetes audit log](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) stays the
authoritative record: the API server writes it for every request it handles, whatever happens to
the webhooks, with its outcome. A webhook only sees what the API server sends it, and only when
it can reach the operator. This log is the WAF-focused one: only Inkwall's kinds, spec changes
only, each with a readable summary of what changed, for the people who own the policies. To match
a line with the API server's record, use the object, the user and the time.

## The control plane

When the cluster is [connected to a control plane](control-plane.md), the operator sends it a
[snapshot of every object](control-plane.md#what-the-operator-sends), with its generation and
spec, within 5 seconds of a change. The snapshots carry no user and no diff: the `generation` of a
log line is the generation of the object in the next snapshot. In `Managed` mode, the control
plane's objects are written by the operator, so their changes are logged with `operator: true`: who
changed them is in the control plane's own audit log.
