# Connecting to a control plane

This guide connects a cluster to an optional Inkwall [control plane](glossary.md#control-plane), explains what the operator
sends it, and shows how to disconnect.

## Contents

- [What the control plane does and doesn't do](#what-the-control-plane-does-and-doesnt-do)
- [Modes](#modes)
- [Prerequisites](#prerequisites)
- [Enrolling a cluster](#enrolling-a-cluster)
- [Checking the connection](#checking-the-connection)
- [Certificate renewal](#certificate-renewal)
- [What the operator sends](#what-the-operator-sends)
  - [During an outage](#during-an-outage)
- [Managed mode](#managed-mode)
- [Disconnecting](#disconnecting)

## What the control plane does and doesn't do

The control plane is a separate service that sees many clusters in one place. This repository
contains only the cluster side: the operator's client and the protocol,
[`api/controlplane/v1`](../api/controlplane/v1/controlplane.proto).

- **Enforcement never depends on it.** Engines enforce the bundle the operator signs with the
  cluster's own key, whether or not the control plane is reachable. If the connection drops,
  traffic is unaffected.
- **Only the operator connects**, and only its [leader](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election) enrolls. Engines never connect to it, so
  they need no egress.
- **It never sends signed bundles.** In [Managed mode](glossary.md#cluster-mode) it sends policy objects. The operator writes
  them as [custom resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/),
  and they go through the same validation and signing as your own.
- **`Standalone`, the default, never connects.** Installing or upgrading the chart connects
  nothing.

## Modes

`InkwallConfig.spec.mode` sets the mode:

| Mode | Policy comes from | Connects | Writes `WAF*` objects |
|---|---|---|---|
| `Standalone` (default) | Your `WAFPolicy` and rule set objects | No | No |
| `GitOps` | Your objects; the control plane gets a read-only copy | Yes | No |
| `Managed` | The control plane, written as objects [labelled](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) `inkwall.dev/source: saas` | Yes | Yes, only its own labelled objects |

`spec.controlPlane` (`endpoint` and `enrollmentSecretRef`) is required in `GitOps` and
`Managed` mode and ignored in `Standalone`.

## Prerequisites

- Inkwall 0.1.1 or later, installed with the [Helm](https://helm.sh/docs/) chart
  ([chart README](../deploy/helm/inkwall/README.md); from 0.1.0, see [upgrading](upgrading.md)).
  Helm 3.14 or later for `--reset-then-reuse-values`.
- From the control plane:
  - its address, used below as `grpcs://<control-plane-address>:<port>`;
  - a one-time enrollment token. The protocol gives a token a one-hour lifetime, so enroll soon
    after you get it;
  - its CA certificate, if its server certificate doesn't come from a public CA.
- Egress from the operator's pods in `inkwall-system` to that address over
  [gRPC](https://grpc.io/docs/) with [TLS](https://www.rfc-editor.org/rfc/rfc8446).

## Enrolling a cluster

1. Give the operator the CA (if private) and the token. With the chart:

   ```sh
   helm upgrade --install inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
     --namespace inkwall-system --create-namespace --reset-then-reuse-values \
     --set-file controlPlane.caBundle=ca.crt \
     --set controlPlane.enrollmentToken=<token>
   ```

   The chart stores the CA in the
   [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/)
   `inkwall-control-plane-ca` and passes it to the operator (`--control-plane-ca`). It stores the
   token in the Secret `inkwall-enrollment`, key `token`. For a release whose name doesn't contain
   `inkwall`, the names are `<release>-inkwall-control-plane-ca` and `<release>-inkwall-enrollment`.

   A value passed with `--set` ends up in the Helm release history. If that is a concern, or if
   your values live in Git, leave `controlPlane.enrollmentToken` empty and create the
   [Secret](https://kubernetes.io/docs/concepts/configuration/secret/) yourself. It must be in
   the operator's namespace:

   ```sh
   kubectl -n inkwall-system create secret generic inkwall-enrollment --from-literal=token=<token>
   ```

2. Point the cluster at the control plane. The `InkwallConfig` isn't part of the chart, because a
   release can't create a custom resource whose CRD it installs. Apply it yourself:

   ```sh
   kubectl apply -f - <<'YAML'
   apiVersion: waf.inkwall.dev/v1alpha1
   kind: InkwallConfig
   metadata:
     name: default
   spec:
     mode: GitOps
     controlPlane:
       endpoint: grpcs://<control-plane-address>:<port>
       enrollmentSecretRef:
         name: inkwall-enrollment
         namespace: inkwall-system
   YAML
   ```

   The `InkwallConfig` must be named `default`, and the endpoint must have the form
   `grpcs://host:port`.

The leader generates an [ECDSA P-256](https://csrc.nist.gov/pubs/fips/186-5/final) key, sends a
[certificate signing request](https://www.rfc-editor.org/rfc/rfc2986) with the token, and
stores the certificate and key it gets back in the Secret `inkwall-control-plane-identity`
(type `kubernetes.io/tls`, plus `cluster-id`). From then on the cluster authenticates with
that client certificate ([mutual TLS](https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2));
the token isn't used again. If the response is lost, the retry reuses the same key, so the token
isn't wasted.

## Checking the connection

```sh
kubectl get inkwallconfig default \
  -o jsonpath='{.status.conditions[?(@.type=="ControlPlaneConnected")]}{"\n"}'
```

`status: "True"`, reason `Connected`, and a message with the cluster ID and the certificate's
expiry mean the cluster is connected. Otherwise the reason says why:

| Reason | Meaning | What to do |
|---|---|---|
| `EnrollmentTokenMissing` | The Secret doesn't exist or has no `token` key | Create it (step 1) |
| `EnrollmentTokenNotInOperatorNamespace` | `enrollmentSecretRef` names another namespace | Move the Secret to the operator's namespace |
| `EnrollmentTokenRejected` | The token is unknown, expired or already used | Put a new token in the Secret's `token` key |
| `EnrollFailed` | Enrollment failed for another reason; retried | See the message |
| `Unreachable` | No connection, or the stream ended; retried with backoff | Check the address, egress and CA |
| `InvalidEndpoint` | The endpoint isn't `grpcs://host:port` | Fix `spec.controlPlane.endpoint` |
| `CertificateRejected` | The control plane rejected the cluster's certificate; the operator deleted it | Put a new token in the Secret |
| `CertificateExpired` | The certificate expired while the cluster was offline; the operator deleted it | Put a new token in the Secret |
| `ClusterDisabled` | The control plane removed or disabled this cluster | Change the `InkwallConfig` to try again |

The operator rereads the token Secret every few seconds, so a new token is used without a restart.
The leader logs `cluster enrolled` once and `control plane connection ended; retrying` on each
failure:

```sh
kubectl -n inkwall-system logs deploy/inkwall-operator | grep -i 'control plane\|enrolled'
```

`kubectl logs deploy/...` shows one pod. With two replicas, check both if the line isn't there.

## Certificate renewal

The control plane decides how long the cluster's certificate is valid. The leader renews it over
the open connection two thirds of the way through its lifetime with a new key, and asks again
every minute until it gets one. The new certificate replaces the old one in
`inkwall-control-plane-identity`, and the condition message shows the new expiry. Nothing needs
doing.

Renewal needs a valid certificate. If the cluster stays offline past the expiry, the operator
deletes the identity and reports `CertificateExpired`. Enroll again with a new token. To see the
expiry:

```sh
kubectl -n inkwall-system get secret inkwall-control-plane-identity -o jsonpath='{.data.tls\.crt}' |
  base64 -d | openssl x509 -noout -enddate
```

## What the operator sends

The leader holds one **primary** connection. Over it the operator sends:

- **Hello:** the replica's pod name, the operator and Kubernetes versions, the mode, the
  `kube-system` namespace [UID](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids), and the last [policy snapshot](glossary.md#policy-snapshot) applied.
- **Cluster state:** every `WAFPolicy`, `WAFRuleSet`, `ClusterWAFRuleSet` and `InkwallConfig`,
  each with its name, namespace, labels, generation, spec (JSON) and status conditions. Also the
  number of running [Traefik](https://doc.traefik.io/traefik/) pods and how many have the engine,
  each connected engine (pod, node, version, the bundle version it runs or rejected), and the
  bundle version and content hash.
  The leader sends it after connecting, within 5 seconds of a change, when asked, and every
  5 minutes.
- **Heartbeats**, and certificate renewal requests.

Every replica holds its own **events** connection, which carries the security events and request
counts of the engines connected to that replica. It opens only if the control plane accepts events
or request counts, which it says when the connection opens. Otherwise events stay in the engines'
logs, as in `Standalone`.
The engine redacts each event before it leaves the pod
([`api/events/v1`](../api/events/v1/events.proto)): method, host, path without the query string,
client IP, user agent, request ID, status, matched rule IDs with at most 64 bytes of each matched
value, the policy and the action. It never includes bodies, query strings, `Authorization`
headers or cookies.

The **request counts** are, per policy, how many requests the engines allowed, denied and detected,
and how long inspecting them took (a histogram from 50 µs to about 0.8 s). Each replica sums its
engines' counts and sends them every 10 seconds, for the policies whose counts changed. They are
per policy only: no routes, paths, hosts or client addresses. Requests that no policy covers aren't
counted.

The operator never sends Secrets, ConfigMaps (a rule set's `configMapRef` is sent as a reference,
not its contents) or request bodies. Rules written inline in a rule set's spec are part of the spec,
so they are sent.

### During an outage

While the control plane is unreachable, each replica keeps the events in a buffer on disk: an
[`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) of
`controlPlane.eventsBufferMiB` (default 64 MiB). The buffer survives container restarts, but not
the pod being deleted or rescheduled. When it is full, the oldest events are dropped, and the next
batch says how many. After reconnecting, the replica resends everything not acknowledged. The
control plane removes duplicates by event ID. Switching to `Standalone`, or a control plane that
stops accepting events, empties the buffer.

Request counts need no buffer: each replica keeps its running totals in memory and sends them all
again after reconnecting. A replica that restarts starts again from zero. It keeps the totals of
at least 4096 policies; past that, it forgets those no longer in a bundle.

The operator's [Prometheus metrics](https://prometheus.io/docs/concepts/metric_types/)
(`:8080/metrics` on each replica) show the buffer and what was dropped:

| Metric | |
|---|---|
| `inkwall_operator_events_buffered` | Events in this replica's buffer, not yet acknowledged |
| `inkwall_operator_events_forwarded_total` | Events sent, resends included |
| `inkwall_operator_events_buffer_errors_total` | Batches that couldn't be written to the buffer (dropped) |
| `inkwall_operator_request_stats_dropped_total{reason}` | Policies' request counts dropped: `not_in_bundle` (an engine reported a policy the replica's bundle doesn't have), `latency_buckets` (latency counted in other buckets), `evicted` (totals forgotten) |

```sh
kubectl -n inkwall-system port-forward deploy/inkwall-operator 8080 &
curl -s localhost:8080/metrics | grep -E '^inkwall_operator_(events|request_stats)'
```

## Managed mode

With `mode: Managed`, policies come from the control plane:

```sh
kubectl patch inkwallconfig default --type merge -p '{"spec":{"mode":"Managed"}}'
```

The leader applies each policy snapshot all or nothing. It first does a [server-side dry run](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run) of
every object, so the CRD schema and the [validating webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) check each one. One refused object
refuses the whole snapshot, and nothing changes. Then it writes the `WAFPolicy`, `WAFRuleSet` and
`ClusterWAFRuleSet` objects labelled `inkwall.dev/source: saas`, deletes the labelled objects the
snapshot no longer has, and acknowledges it. The bundle builder signs them with the cluster's key
like any other policy, and their `Enforced` condition goes back to the control plane.

- While the cluster is in Managed mode, the validating webhook refuses anyone but the operator
  creating, editing or deleting a labelled object, or adding or removing the label. Change them
  in the control plane, not with `kubectl`. Deleting their namespace still works.
- Your own unlabelled objects stay yours. The operator never overwrites one: a snapshot with an
  object of the same name is refused.
- Rule sets from the control plane carry their rules inline: `configMapRef` is refused.
- To list the control plane's objects:

  ```sh
  kubectl get wafpolicy,wafruleset,clusterwafruleset -A -l inkwall.dev/source=saas
  ```

## Disconnecting

1. Switch back to `Standalone`:

   ```sh
   kubectl patch inkwallconfig default --type merge -p '{"spec":{"mode":"Standalone"}}'
   ```

   Within a few seconds every replica closes its connections, empties its events buffer, and the
   `ControlPlaneConnected` condition goes away. Objects written in Managed mode stay, as ordinary
   objects you can edit or delete; they keep their label.

2. Check it:

   ```sh
   kubectl get inkwallconfig default -o jsonpath='{.spec.mode} {.status.conditions[?(@.type=="ControlPlaneConnected")].reason}{"\n"}'
   ```

   It prints `Standalone` and no reason.

3. Optional: to make the cluster forget its identity, remove the CA and token from the chart
   values (this deletes the chart's token Secret, if the chart created it), then delete the
   certificate. While `inkwall-control-plane-identity` exists and its certificate is valid,
   switching back to `GitOps` or `Managed` reconnects without a new token.

   ```sh
   helm upgrade inkwall oci://ghcr.io/inkwall-dev/charts/inkwall --version <version> \
     --namespace inkwall-system --reset-then-reuse-values \
     --set controlPlane.enrollmentToken= --set controlPlane.caBundle=
   kubectl -n inkwall-system delete secret inkwall-control-plane-identity
   ```

   If you created the token Secret yourself, delete it too
   (`kubectl -n inkwall-system delete secret inkwall-enrollment`). Remove the cluster on the
   control plane's side as well.
