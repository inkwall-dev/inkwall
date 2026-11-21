# API compatibility

What may change in Inkwall's Kubernetes API (`waf.inkwall.dev`) from one release to the next, how
a change is announced, and what v1.0.0 will freeze. This is a draft for #64: it applies from 0.7.0,
and v1.0.0 makes it binding.

## Contents

- [Scope](#scope)
- [Before v1: v1alpha1](#before-v1-v1alpha1)
- [From v1](#from-v1)
- [How a change is announced](#how-a-change-is-announced)
- [Getting to v1](#getting-to-v1)
- [Naming decisions](#naming-decisions)

## Scope

The policy covers what users write and what tools read:

- the kinds `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet`, `WAFIPList` and `InkwallConfig`: their
  fields, defaults, validation, list semantics (`listType`, which server-side apply relies on)
  and status conditions, with their types and reasons;
- the labels and annotations users set or read: `inkwall.dev/source`, `waf.inkwall.dev/inject`,
  `waf.inkwall.dev/rotate-signing-key` and `waf.inkwall.dev/rules`.

It doesn't cover the policy bundle's format (`api/bundle/v1`, between the operator and the engines
of one release, which the operator gates by engine version), the operator's command-line flags,
metrics (see [Monitoring](monitoring.md)), or the condition messages: they say what to do, and
change to say it better. Scripts should test a condition's type, status and reason, never its
message.

## Before v1: v1alpha1

`v1alpha1` may still change, but not by surprise:

- **Additions** can come in any minor release: a new optional field, a new kind, a new enum value
  where the field says the set may grow.
- **Deprecations** keep the old field working for at least one minor release: the field's
  description starts saying `Deprecated:`, the webhook warns when it's set, and the operator
  prefers the new field when both are set. Setting both to contradicting values is refused.
- **Tightenings** (validation that would refuse objects stored today) first ship as webhook
  warnings. The schema enforces them only at v1, whose Kubernetes floor (1.31, #720) has
  [validation ratcheting](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-ratcheting),
  so an object stored before can still be updated as long as the update doesn't touch the invalid
  field.
- **Removals** of a field that does something wait for v1. A field the operator ignores can be
  deprecated in a minor release, and removed at v1.
- **Behaviour** of an existing object doesn't change on an upgrade unless the release notes say so
  in [Upgrading](upgrading.md). Defaults that only the engine used to apply move into the API and
  the bundle with the same values (#718), so that a newer engine can't change a stored policy.

## From v1

From v1.0.0, within `v1`:

- fields, enum values, defaults, list types and condition types aren't removed or renamed, and a
  field's meaning doesn't change;
- validation doesn't get stricter;
- new optional fields, kinds and enum values may come in minor releases. An enum documented as an
  open set (`status.signingKey.phase`, condition reasons) may get values, so clients should handle
  unknown ones;
- a field can be deprecated, with a warning, but stays until a `v2`, which would be served next to
  `v1` with conversion.

## How a change is announced

Every change to the API is in the release's section of [Upgrading](upgrading.md), with what to do.
A deprecation also appears in the field's description (`kubectl explain`) and as a warning from
`kubectl apply`. A deprecated field gets its own entry in the v1.0 upgrade preflight below.

## Getting to v1

v1.0.0 serves `v1` as the storage version next to `v1alpha1`:

- **WAFPolicy** gets a conversion webhook, for the fields that move: the binding-level CRS settings
  go under `ruleSets[].crs` (#714), `ruleSets[].ref.namespace` is dropped (#715), and
  `ipLists.allow`/`deny` items become `{kind, name}` references, so a `ClusterWAFIPList` can be added
  later (#715). Writes to WAFPolicies already go through the operator's webhook.
- **InkwallConfig, WAFRuleSet, ClusterWAFRuleSet and WAFIPList** use `conversion: None`: their
  `v1` is `v1alpha1` without the ignored or deprecated fields, which the API server prunes on read.
  A conversion webhook on the InkwallConfig would make `spec.suspend`, the emergency switch,
  depend on the operator being up.
- **A preflight** (`inkwallctl` or a Helm pre-upgrade hook) lists objects that still use
  deprecated fields, and the upgrade stops until they're moved. It doesn't rewrite them: a GitOps
  tool would put them back. It refuses, for example, `InkwallConfig.spec.engine.jsonDenials` (use
  `denialFormat`, #713) and a policy whose `ref.namespace` names another namespace.
- **Storage migration**: after the upgrade, every object is rewritten once in `v1` and `v1alpha1`
  is removed from the CRDs' `status.storedVersions`.

## Naming decisions

Names that look inconsistent, and stay:

- **`spec.source.seclang`** on `WAFRuleSet` and `ClusterWAFRuleSet`, not `secLang`. SecLang is the
  name of one language, and the field holds text in it; renaming it would break every rule set for
  nothing.
- **`builtin: crs-v4`**, the only enum value that isn't CamelCase. It names a rule set, like a
  package identifier, rather than a mode.
- **The `inkwall.dev/source` label**, while the annotations are `waf.inkwall.dev/*`. Every object
  the control plane wrote carries it, and the webhooks' object selectors match it; renaming it
  would mean accepting both names for a release, for no gain.
- **`bootstrapMode: AllowAll | DenyAll`, `failureMode: Open | Closed`, `onOversize: Allow | Deny`**:
  three vocabularies for "let through or refuse". They answer different questions (an engine
  without any policy, a request that couldn't be inspected in time, a body over the limit), and
  renaming `bootstrapMode` would need an InkwallConfig conversion webhook, which it must not have.
- **`engine.policyMetrics`** stays a bool. A `metrics` block can be added next to it later.
- **Custom denial responses**, when they come, are `spec.denyResponse`, not `spec.response`, which
  would read as a typo of `spec.responses` (response inspection).
