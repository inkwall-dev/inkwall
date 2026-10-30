# Rotating the bundle signing key

This guide replaces the key the operator signs [policy bundles](glossary.md#bundle) with, on demand or on a schedule,
without interrupting traffic.

## Contents

- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Rotate now](#rotate-now)
- [Rotate on a schedule](#rotate-on-a-schedule)
- [What engines accept during a rotation](#what-engines-accept-during-a-rotation)
- [Checking it worked](#checking-it-worked)
- [When a rotation waits](#when-a-rotation-waits)
- [Undoing it](#undoing-it)

## How it works

The operator signs every policy bundle with an [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) key.
It generates the key on first use and keeps it in the
[Secret](https://kubernetes.io/docs/concepts/configuration/secret/) `inkwall-bundle-signing-key`
in its namespace. Engines check each bundle's signature against the public keys in the
`inkwall-trust` [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) of
their pod's namespace (file `trusted-keys.pub`), and reject a bundle signed with any other key.

A rotation never signs with a key an engine doesn't trust yet:

1. **Publishing.** The operator generates the next key and adds its public key to every
   `inkwall-trust` ConfigMap. The old key still signs. The [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/) updates the
   [mounted ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/#mounted-configmaps-are-updated-automatically)
   in each pod within a minute or two, and the engine rereads its keys every 10 seconds without
   restarting. The operator waits until every connected engine reports the new key.
2. **Retiring.** The new key signs. The operator signs the current policies again as a new bundle
   version, and keeps the old public key trusted until every connected engine runs a bundle the
   new key signed.
3. **Done.** The old key is removed from the ConfigMaps. Only the new key is trusted.

Each phase lasts at least one minute, the time the kubelet may take to update a mounted ConfigMap
(the operator's `--signing-key-grace`).

## Prerequisites

- Inkwall 0.1.1 or later.
- Every engine from 0.1.1 or later. An older engine never reports the new key, so the rotation
  waits for it. Restart [Traefik](https://doc.traefik.io/traefik/) after upgrading the chart, so
  its pods get the current engine:

  ```sh
  kubectl -n <traefik namespace> rollout restart deployment/<traefik>
  ```

- An `InkwallConfig` named `default`. If there is none, create one; an empty spec keeps every
  default:

  ```sh
  kubectl apply -f - <<'YAML'
  apiVersion: waf.inkwall.dev/v1alpha1
  kind: InkwallConfig
  metadata:
    name: default
  YAML
  ```

## Rotate now

Give the `InkwallConfig` a new value of the `waf.inkwall.dev/rotate-signing-key`
[annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/).
Any value works; each new value starts one rotation. A timestamp is convenient:

```sh
kubectl annotate inkwallconfig default --overwrite waf.inkwall.dev/rotate-signing-key="$(date +%s)"
```

A new value set while a rotation runs starts another rotation once the current one is done.

If the `InkwallConfig` lives in Git, change the annotation there instead and let your [GitOps](https://opengitops.dev/) tool
apply it. The operator only reads the annotation; it never writes it, so the tool shows no drift.

## Rotate on a schedule

Set `spec.signingKey.rotationInterval` on the `InkwallConfig`. A key rotates once it has signed
for that long. The minimum is `1h`:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata:
  name: default
spec:
  signingKey:
    rotationInterval: 2160h # 90 days
```

Without `rotationInterval`, the key rotates only when you ask.

## What engines accept during a rotation

| Phase (`waf.inkwall.dev/rotation-phase` on the Secret) | Signs with | `trusted-keys.pub` holds |
|---|---|---|
| none (between rotations) | the active key | the active key |
| `Publishing` | the old key | the old key and the next key |
| `Retiring` | the new key | the new key and the previous key |

An engine accepts a bundle signed by any key in its `trusted-keys.pub`. It looks the key up by the
key ID in the signed bundle (the first 8 bytes of the key's [SHA-256](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), in hex). A bundle signed
with a key it doesn't trust is rejected: the engine logs `bundle rejected`, counts it in
`inkwall_bundle_updates_total{result="rejected"}`, and keeps enforcing the bundle it has. Once
its key file changes, it reconnects and gets the bundle again.

Traffic is unaffected in every phase. A bundle signed again with the new key and the same
policies is not compiled again.

## Checking it worked

Watch the phase on the signing key Secret. It reads `Publishing`, then `Retiring`, then nothing:

```sh
kubectl -n inkwall-system get secret inkwall-bundle-signing-key \
  -o jsonpath='{.metadata.annotations.waf\.inkwall\.dev/rotation-phase}{"\n"}'
```

Compare the key that signs with the key that signs the bundle being served. When the rotation
is done, both are the new key, and `trusted-keys.pub` holds one key (32 bytes):

```sh
kubectl -n inkwall-system get secret inkwall-bundle-signing-key -o jsonpath='{.data.key-id}' | base64 -d; echo
kubectl -n inkwall-system get secret inkwall-bundle -o jsonpath='{.metadata.annotations.waf\.inkwall\.dev/key-id}{"\n"}'
kubectl -n inkwall-system get secret inkwall-bundle-signing-key -o jsonpath='{.data.trusted-keys\.pub}' | base64 -d | wc -c
```

The [leader](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election) logs each step: `signing key rotation started: new key published`,
`signing key rotation: switched to the new key` and
`signing key rotation done: previous key retired`, and, while it waits, what it waits for.

```sh
kubectl -n inkwall-system logs deploy/inkwall-operator | grep 'signing key rotation'
```

Your policies stay `Ready` throughout:

```sh
kubectl get wafpolicy -A
```

## When a rotation waits

The leader logs what it waits for, and names up to three engines. For example:
`key <id> published; 1/3 engines don't trust it yet: traefik/traefik-6d9f-abcde`.

- **An engine from before 0.1.1.** It reports no keys, and the log says
  `reports no keys: an engine older than key rotation`. Restart its pod so it gets the current
  engine.
- **An engine you configured yourself**, outside a pod the operator injected. It reads its keys
  from `--bundle-key`. During a rotation, copy the Secret's `trusted-keys.pub` into that file; the
  engine rereads it when it changes:

  ```sh
  kubectl -n inkwall-system get secret inkwall-bundle-signing-key \
    -o jsonpath='{.data.trusted-keys\.pub}' | base64 -d > trusted-keys.pub
  ```

- **An engine that doesn't run the new key's bundle yet** (in `Retiring`). It is usually
  reconnecting. Check its logs for `bundle rejected`.

Only connected engines count. An engine that is disconnected during the switch and comes back
with only the old key rejects the new bundles and keeps its last bundle. Restart its pod.

Reinstalling the chart keeps the Secret, so a rotation in progress continues.

## Undoing it

A rotation can't be stopped or reversed once it starts: it runs to the end, and the old key is
gone. To stop scheduled rotations, remove `spec.signingKey.rotationInterval`.

Don't delete or edit `inkwall-bundle-signing-key` by hand: the operator manages it. If it is
deleted, the operator recreates it with the keys it holds in memory, so engines keep trusting
them.

A compromised key stays trusted until the rotation retires it, which waits for every connected
engine. Restart engines that hold up the rotation so it finishes quickly.
