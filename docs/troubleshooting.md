# Troubleshooting

This guide checks whether Inkwall works in a cluster, and what to do when it doesn't.

## Contents

- [Cluster status](#cluster-status)
  - [Permissions](#permissions)
  - [JSON output](#json-output)

## Cluster status

`inkwallctl status` answers "is Inkwall working in this cluster?" from the current kubeconfig
context, read only:

```console
$ inkwallctl status
InkwallConfig: mode Standalone, suspended no
Operator: 2/2 replicas ready in inkwall-system, version 0.5.0
Bundle: version 7, 4096 bytes compressed

Proxies:
  CONTROLLER                     INTEGRATION  SUPPORT      REQUESTS  RESPONSES  WS MESSAGES  GRPC MESSAGES
  traefik.io/ingress-controller  traefik      Full         yes       no         no           yes
  k8s.io/ingress-nginx           -            Unsupported  no        no         no           no
  k8s.io/ingress-nginx: Inkwall has no integration for this controller

Policies: 2 of 2 Ready

Engines: 2 connected
  VERSION  CURRENT  BEHIND  REJECTED
  v0.5.0   2        0       0

OK: nothing needs attention.
```

It reports:

- **The InkwallConfig**: its mode and whether inspection is suspended.
- **The operator**: its replicas and the version they run, and the bundle it publishes.
- **The proxies** the cluster's IngressClasses and GatewayClasses name: whether Inkwall wires
  them, and what the engine inspects through each. Responses are inspected through Envoy Gateway
  only, and WebSocket messages only through the standalone proxy.
- **The policies that aren't `Ready`**, grouped by the reason of their `Ready` condition, with
  its message. `kubectl get wafpolicies -A` shows the same reason in its `REASON` column.
- **The engines**: how many run the current bundle, are behind, or rejected it, by engine
  version. Engines behind, rejecting the bundle, or of another version than the operator are
  named by pod, with what to do: an engine of another version runs until its pod restarts.

It exits 0 when nothing needs attention, 1 when something does (the report ends with what), and 2
on an error. Flags: `--kubeconfig`, `--context`, `--namespace` (the operator's, default
`inkwall-system`), `-o json`.

### Permissions

It only reads. The permissions it needs:

| Resource | Where | Verbs |
|---|---|---|
| `inkwallconfigs`, `wafpolicies` (`waf.inkwall.dev`) | cluster | `get`, `list` |
| `pods` | the operator's namespace | `list` |
| `configmaps` | the operator's namespace | `list` (the engine reports, labeled `waf.inkwall.dev/engines=true`) |
| `secrets`, name `inkwall-bundle` | the operator's namespace | `get` (the bundle's version and size; the bundle is signed policy, no credentials) |

Without the pods or the Secret it reports what it can, with a warning.

### JSON output

`-o json` prints one object. Its fields are only ever added to, never renamed or removed, so
scripts can rely on them:

| Field | Meaning |
|---|---|
| `healthy` | `false` when something needs attention (the exit status is then 1) |
| `problems` | What needs attention, one sentence each |
| `warnings` | What couldn't be read |
| `config.exists`, `config.mode`, `config.suspended` | The InkwallConfig `default` (`exists: false`: there is none, every setting is its default) |
| `config.conditions[]` | Its conditions: `type`, `status`, `reason`, `message` |
| `operator.namespace`, `operator.versions[]`, `operator.pods`, `operator.ready` | The operator's replicas and the image tags they run |
| `bundle.version`, `bundle.compressedBytes`, `bundle.chunks` | The bundle the operator publishes; `null` when it can't be read |
| `proxies[]` | `controller`, `integration`, `support` (`Full`, `Partial`, `Unsupported`), `message`, `ingressClasses[]`, `gatewayClasses[]`, and `inspects`: `requests`, `responses`, `webSocketMessages`, `grpcMessages` |
| `policies.total`, `policies.ready` | WAFPolicy counts |
| `policies.notReady[]` | `reason` and `policies[]` (`namespace`, `name`, `message`); `Unknown` when the operator hasn't reported on a policy's generation yet |
| `engines.total`, `engines.leftOut` | Connected engines; `leftOut` didn't fit the operator's reports |
| `engines.byVersion[]` | `version`, and how many are `current`, `behind`, `rejected` |
| `engines.attention[]` | `namespace`, `pod`, `version`, `state`, `applied`, `rejected`, `rejectError`, `outdated` (not the operator's version), `hint` |

For example, the policies that aren't `Ready`:

```sh
inkwallctl status -o json | jq -r '.policies.notReady[] | .reason as $r | .policies[] | "\(.namespace)/\(.name) \($r): \(.message)"'
```
