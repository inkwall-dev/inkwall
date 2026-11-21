# 0013 — gRPC Messages with Their Schema

- Status: Draft
- Date: 2026-11-21
- Updated: 2026-11-21
- Owner: noureldin
- Depends on: [0002 — System Architecture](0002-system-architecture.md),
  [0004 — Kubernetes Operator](0004-operator.md),
  [0011 — Geo Blocking](0011-geo-blocking.md)

Since v0.4.0, `body.grpcMessages: Inspect` reads a gRPC call's protobuf messages without their
schema ([0002 §8.7](0002-system-architecture.md#87-grpc-messages), `pkg/grpcwire`): it guesses
which fields are text, names them by field numbers (`2.1`), and has a small false positive rate
from binary fields, which is why it is off by default. This document decides how a policy gives
the engine the messages' schema, so that fields are read by type and named by name
(`ARGS:user.name`): where the schema comes from, where it is compiled, how it reaches engines, how
a message is decoded with it, what the rules see, what it costs, how it fails, and how it is
tested. **Nothing here is built yet** (#316).

[Terms](../glossary.md) used here:

- **Engine:** `inkwall-engine`. **Policy:** a `WAFPolicy`. **Bundle:** the signed snapshot of all
  policies that every engine enforces (`api/bundle/v1`).
- **Descriptor set:** a [`FileDescriptorSet`](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/descriptor.proto),
  the binary form of `.proto` files that `protoc --descriptor_set_out` and `buf build` write.
- **Schema:** what the operator compiles a descriptor set into for engines
  ([§5.2](#52-the-compiled-schema)).
- **Described method:** a method (`/package.Service/Method`) the schema has; its input type is the
  message type its requests are read as.
- **Schema-less reading:** today's `grpcwire.Strings`.

## Contents

- [1. Goals and scope](#1-goals-and-scope)
- [2. What the schema fixes](#2-what-the-schema-fixes)
- [3. Where the schema comes from](#3-where-the-schema-comes-from)
  - [3.1 Options](#31-options)
  - [3.2 Why not server reflection](#32-why-not-server-reflection)
  - [3.3 The ConfigMap](#33-the-configmap)
- [4. API](#4-api)
- [5. Compiling and distributing](#5-compiling-and-distributing)
  - [5.1 The operator compiles](#51-the-operator-compiles)
  - [5.2 The compiled schema](#52-the-compiled-schema)
  - [5.3 In the bundle, not on its own stream](#53-in-the-bundle-not-on-its-own-stream)
  - [5.4 Bounds](#54-bounds)
- [6. Reading a message with its schema](#6-reading-a-message-with-its-schema)
  - [6.1 From the path to the type](#61-from-the-path-to-the-type)
  - [6.2 Each field by its kind](#62-each-field-by-its-kind)
  - [6.3 Names](#63-names)
  - [6.4 What the rules see](#64-what-the-rules-see)
  - [6.5 Per adapter and per stream](#65-per-adapter-and-per-stream)
  - [6.6 Why not dynamicpb](#66-why-not-dynamicpb)
- [7. Performance and memory](#7-performance-and-memory)
- [8. Failure modes](#8-failure-modes)
- [9. Security](#9-security)
- [10. Observability](#10-observability)
- [11. Testing](#11-testing)
- [12. Rollout and compatibility](#12-rollout-and-compatibility)
- [13. Decisions](#13-decisions)
- [14. Open questions](#14-open-questions)

## 1. Goals and scope

**In v0.7.0:**

- `WAFPolicy.spec.body.grpcSchema`: a descriptor set from a ConfigMap in the policy's namespace
  ([§3](#3-where-the-schema-comes-from), [§4](#4-api)).
- The operator validates it and compiles it into a compact schema in the signed bundle; engines
  never parse descriptors and never fetch anything ([§5](#5-compiling-and-distributing)).
- Messages of described methods read by type: `string` fields as text, `bytes` fields by their
  readable runs, numbers skipped, nested messages, maps, oneofs, `Any` and groups followed, named
  by field names ([§6](#6-reading-a-message-with-its-schema)).
- Everything the schema doesn't describe (an undescribed method, an unknown field, a field sent with
  another wire type) still read schema-less: the schema changes the reading only of the fields it
  types ([§6.2](#62-each-field-by-its-kind), [§9](#9-security)).
- The same reading in every adapter and in ext_proc's per-message streams
  ([§6.5](#65-per-adapter-and-per-stream)).

**Later, not in v0.7.0:**

- Server reflection, by the operator or the engine ([§3.2](#32-why-not-server-reflection)).
  An `inkwallctl` command that fetches a set by reflection from the user's machine is
  [open question 1](#14-open-questions).
- Reading gRPC *responses* with the schema. The compiled schema carries each method's output type
  so that this needs no format change; `pkg/streams` response splitters stay schema-less.
- Denying undescribed methods ([open question 2](#14-open-questions)).
- Turning `grpcMessages` on by default ([open question 4](#14-open-questions)).
- A schema in the standalone engine without the operator ([open question 5](#14-open-questions)).

## 2. What the schema fixes

Protobuf's wire format doesn't say whether a length-delimited field is a string, bytes or a
message. `grpcwire.field` therefore reads it every way that fits: UTF-8 bytes are text, bytes that
parse as a message are read as one (and as text when printable), other bytes give runs of at least
8 readable characters (`minBinaryRun`). Three problems follow, all from the guess:

| Problem | Today | With the schema |
|---|---|---|
| False positives from `bytes` fields | A random 1–24 byte field is sometimes valid UTF-8, read whole as text: `|W`, `` `W `` match 932250, 932340, 942190; about 1 message in 10,000 with four such fields (`TestGRPCMessagesFalsePositives`, `pkg/pipeline/grpc_fp_test.go`) | A `bytes` field gives only its runs of ≥ 8 readable characters, which measured no false positive above the baseline (0002 §8.7) |
| Names | `2.1`: exclusions and events name numbers (`when: {argument: "2.1"}`) | `user.name` |
| Double reading | A field that is both UTF-8 and a message is read both ways | Read once, by its type |

The expectation to verify ([§11](#11-testing)): with types known, binary false positives disappear
and only text-field matches remain, as for forms and JSON.

## 3. Where the schema comes from

### 3.1 Options

| Option | For | Against |
|---|---|---|
| (a) A descriptor set the user supplies, in a ConfigMap | Built with the application (`buf build`, `protoc`), reviewed in Git, versioned with it; the operator already reads labelled ConfigMaps (`resolver.RulesLabel`); no network | The user must keep it current; 1 MiB per ConfigMap |
| (b) The same in a Secret | — | A schema isn't a credential; one kind is enough, as 0011 §3.2 rejected a second |
| (c) An OCI artifact (Buf Schema Registry, any registry) | No size limit; versioned | The operator needs egress and registry credentials; the same objections as a downloaded geo database (0011 open question 1) |
| (d) Server reflection, called by the operator | No file to maintain | [§3.2](#32-why-not-server-reflection) |
| (e) Server reflection, called by each engine | — | Engines have no egress by design (D4, [0002 §3.4](0002-system-architecture.md#34-control-plane-optional)); every engine could get a different answer |

**Decision: (a) for v0.7.0.**

### 3.2 Why not server reflection

The [reflection service](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md)
(`grpc.reflection.v1.ServerReflection`) answers with the file descriptors of a server's services.
It looks free, and it isn't:

- **Trust.** The schema decides what the WAF reads. Fetched from the application, it comes from the
  thing the WAF protects. A compromised pod, or anything that answers on the Service's address
  during a rollout, can serve a schema that declares every `string` field `bytes`, so the engine
  reads only runs of 8 or more characters and short attacks (`'--`, `;id`) pass. Nothing reviews
  it: it changes when a pod says so, not when a commit does. A user-supplied set is as trusted as
  the policy next to it ([§9](#9-security)).
- **Network.** The operator would dial every gRPC application. The operator's pod holds the
  bundle signing key; its NetworkPolicy (`deploy/helm`) would need egress to every namespace with
  gRPC routes, and through service meshes, mTLS client certificates per mesh.
- **Auth and availability.** Hardened servers turn reflection off or put it behind auth. Which
  pod is asked, when, and what happens when two versions answer differently in a rollout would all
  need a design, and the answer still wouldn't be in Git for GitOps tools.

What reflection is good for is *producing* the file once, by the person who owns the service: [open
question 1](#14-open-questions).

### 3.3 The ConfigMap

```sh
buf build -o orders.binpb --exclude-source-info          # or:
protoc --include_imports --descriptor_set_out=orders.binpb orders/v1/*.proto
kubectl create configmap orders-schema --from-file=orders.binpb
kubectl label configmap orders-schema waf.inkwall.dev/rules=true
```

- **Namespace:** the policy's, only, as a `WAFRuleSet`'s `configMapRef` (`ConfigMapKeyRef`,
  `operator/api/v1alpha1/wafruleset_types.go`). A policy can't read another namespace's ConfigMap.
- **Label:** `waf.inkwall.dev/rules=true`, the label the operator's ConfigMap cache already selects
  ([0004 §4.5](0004-operator.md#45-resolver)). A label selector can't OR two keys, and a second
  cache for a second label buys nothing; the label's docs become "a ConfigMap the operator reads".
- **Value:** a key of `binaryData`, raw or gzipped (by its magic bytes). A ConfigMap holds at most
  1 MiB; a gzipped value is read through a limit of 8 MiB decompressed. The set must include its
  imports (`--include_imports`; `buf build` does by default): the operator refuses an unresolved
  import ([§8](#8-failure-modes)). Source info is dropped if present.

## 4. API

```yaml
spec:
  body:
    grpcMessages: Inspect
    grpcSchema:
      configMapRef: {name: orders-schema, key: orders.binpb}
```

| Field | Type | Meaning |
|---|---|---|
| `grpcSchema.configMapRef` | `ConfigMapKeyRef` (name, key) | The descriptor set, in the policy's namespace |

- **Validation (CEL):** `grpcSchema` needs `grpcMessages: Inspect`, as `grpcStreams: PerMessage`
  does today (`BodySpec`, `wafpolicy_types.go`). A schema never turns message reading on by
  itself: a policy that reads no messages has nothing to read with it.
- **One set per policy.** A policy whose routes serve several services uses one set built from all
  of them (`buf build` over a workspace, or several `protoc` inputs). Merging sets in the operator
  would have to decide conflicting definitions of one file; the build tools already do.
- **Older engines.** `requirement` in `operator/internal/distribution/status.go` gains
  `spec.body.grpcSchema` at 0.7.0: while an older engine runs the bundle the policy is
  `Enforced=False`, `EnginesOutdated`. Such an engine ignores the schema and reads schema-less,
  which reads at least as much, with the false positives of today: never weaker.
- **Exclusions** keep their syntax; the names they match change ([§12](#12-rollout-and-compatibility)).
  Field paths fit `ArgumentPattern` (`^[A-Za-z0-9_.\-\[\]]+$`, ≤ 256): proto identifiers are
  letters, digits and `_`, and extensions are written in brackets ([§6.3](#63-names)).

## 5. Compiling and distributing

### 5.1 The operator compiles

As for the country table ([0011 §4.2](0011-geo-blocking.md#42-the-operator-compiles-a-country-table)),
the engine never parses the user's format. The resolver (`operator/resolver`), on every build:

1. reads the ConfigMap value (≤ 1 MiB, ≤ 8 MiB gunzipped) and unmarshals a `FileDescriptorSet`;
2. builds it with `protodesc.NewFiles`, which checks names, imports, field numbers, types and
   cycles in imports, behind `recover`;
3. walks every service's methods and every message reachable from their input and output types,
   checking the bounds of [§5.4](#54-bounds);
4. writes the compiled schema ([§5.2](#52-the-compiled-schema)), and caches it by the SHA-256 of the
   ConfigMap value, so an unchanged set is compiled once per operator process.

Cost, measured on the 87 files linked into the engine (Envoy's, gRPC's, protobuf's; 458 messages,
2,518 fields; 208 KB without source info, 58 KB gzipped), on an i7-1255U: `protodesc.NewFiles` in
5.6 ms. Real service sets are smaller.

Rejected: shipping the descriptor set itself and running `protodesc` in every engine. The engine
would parse the user's richest format (options, extensions, editions features) at every bundle
apply, on every pod, and carry enum values, comments and options it never uses.

### 5.2 The compiled schema

New messages in `api/bundle/v1/bundle.proto`:

```proto
// GRPCSchema is a policy's descriptor set, compiled (design 0013 §5.2).
message GRPCSchema {
  // Hex SHA-256 of methods and messages as serialized: names the schema
  // in BodyConfig.grpc_schema_id, and in the engine's cache.
  string id = 1;
  repeated GRPCMethod methods = 2;   // sorted by path
  repeated GRPCMessage messages = 3; // referenced by index
  string source = 4;                 // "namespace/configmap/key", for explain
}
message GRPCMethod {
  string path = 1;      // "/package.Service/Method"
  uint32 input = 2;     // index into messages
  uint32 output = 3;    // index into messages (responses, later)
}
message GRPCMessage {
  string full_name = 1;            // for Any's type_url
  repeated GRPCField fields = 2;   // sorted by number
  bool any = 3;                    // google.protobuf.Any
}
message GRPCField {
  uint32 number = 1;
  string name = 2;           // the proto name, or "[pkg.ext]" for an extension
  GRPCFieldKind kind = 3;
  uint32 message = 4;        // MESSAGE and GROUP: index into messages
  bool repeated = 5;         // a repeated scalar may come packed
}
enum GRPCFieldKind {
  GRPC_FIELD_KIND_UNSPECIFIED = 0;
  GRPC_FIELD_KIND_STRING = 1;
  GRPC_FIELD_KIND_BYTES = 2;
  GRPC_FIELD_KIND_MESSAGE = 3;
  GRPC_FIELD_KIND_GROUP = 4;
  GRPC_FIELD_KIND_VARINT = 5;   // int*, uint*, sint*, bool, enum
  GRPC_FIELD_KIND_FIXED32 = 6;  // fixed32, sfixed32, float
  GRPC_FIELD_KIND_FIXED64 = 7;  // fixed64, sfixed64, double
}
```

Only what reading needs survives: no enum values (an enum is a varint, and huge enums cost
nothing), no options, no comments, no services beyond their method paths. A map is the repeated
entry message protobuf defines it as (`key = 1`, `value = 2`), so it needs no kind of its own.
Messages reachable from no method are dropped, except those an `Any` may name: every message of
the set is kept when any reachable message has an `Any` field.

### 5.3 In the bundle, not on its own stream

0011 sent the country table on its own stream message because it is megabytes, shared by every
policy, and changes twice a week on the vendor's schedule. A schema is the opposite: tens of
kilobytes, per application, changing when the application deploys, which is when policies change
too. So:

- `Bundle.grpc_schemas` (repeated `GRPCSchema`, each once, as `rule_sets` are) and
  `BodyConfig.grpc_schema_id`. The field numbers are the next free ones when this lands (today
  `Bundle` 13 and `BodyConfig` 7; design 0012 may take a `Bundle` number first). Two policies with
  the same set share one entry.
- It is signed with the bundle, chunked into the bundle's Secrets (`pkg/bundlesecret`, 8 chunks of
  900 KiB; [0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)), counted against the
  7,200 KiB budget, and over that, `Accepted=False`, `BundleTooLarge`, as any policy. No new stream
  message, no capability, no Secret format, no cold-start path: the bundle already has all of them.
- A compiled schema is about 18 bytes per field before compression (estimate, measured by the
  implementation): the 2,518-field set above about 45 KB, under 20 KB compressed.

### 5.4 Bounds

Checked by the operator (refused with `InvalidGRPCSchema`, [§8](#8-failure-modes)) and again by the
engine on load (a failure there is an invalid bundle, `Nack`ed; the bundle is signed, so only a bug
gets there):

| Bound | Value | Why |
|---|---|---|
| Source | 1 MiB, 8 MiB gunzipped | ConfigMap size; a small gzip can't expand without end |
| Methods | 4,096 | A large gateway's services |
| Messages | 16,384 | |
| Fields | 65,536 in all, 4,096 per message | Engine memory ([§7](#7-performance-and-memory)) |
| Name | 128 bytes per field name, 512 per full name and method path | Keep paths excludable |
| Compiled | 1 MiB serialized per schema | A seventh of the bundle budget |

Engine checks: every index in range, methods sorted and unique, fields sorted by number and unique
per message, kinds known, `message` set exactly for `MESSAGE` and `GROUP`. A recursive type
(`message Node { repeated Node children = 1; }`) is valid: the walk is bounded by the data and the
depth limit, not the schema.

## 6. Reading a message with its schema

New package `pkg/grpcschema`: `Load(*bundlev1.GRPCSchema) (*Schema, error)` and
`(*Schema).Method(path) *Message`; `grpcwire` gains `Fields(msg []byte, t *grpcschema.Message,
lim Limits, out []Field) ([]Field, bool)`, the schema-aware sibling of `Strings`, with the same
`Limits` (depth 16, 4,096 fields: `grpcTextLimits` in `pkg/pipeline/grpc.go`), the same `recover`,
and the same `ok` meaning "read whole".

### 6.1 From the path to the type

A gRPC call's `:path` is `/package.Service/Method` (`request.Request.RawURI`, the query cut as in
`grpcMessageRequest`). The policy's schema looks it up exactly, case-sensitive, in a map built at
load. Found: its input type reads every message of the call (a client stream's messages all have
that type). Not found, or the policy has no schema: schema-less, as today, and counted
([§10](#10-observability)). The lookup is once per call, not per message.

### 6.2 Each field by its kind

The walk is `protowire`, as `grpcwire.walker` is: tag, wire type, value, over the bytes as they
come. For each field number the message type knows, by its kind and the wire type it came with:

| Kind | Wire type | Read as |
|---|---|---|
| `STRING` | bytes | Text: as `spaced` today (a control character but tab, CR, LF is a space), whatever its bytes; invalid UTF-8 too, since a proto2 or non-Go application takes it |
| `BYTES` | bytes | Its runs of ≥ 8 readable characters (`runs(v, minBinaryRun)`); never whole as text, never as a message |
| `MESSAGE` | bytes | Its type, one level deeper, and whole as text when printable, as today (so a string declared a message can't split an attack across fields). Bytes that don't parse as a message: that field is read schema-less (`grpcwire.field`), and the message still counts as read whole (a newer application may have made it a string) |
| `GROUP` | start group | Its type, up to the matching end group |
| `VARINT`, `FIXED32`, `FIXED64` | their own | Nothing |
| repeated `VARINT`/`FIXED*` | bytes | Packed: nothing |
| any | another wire type | **Unknown** (next row) |
| a number the type doesn't have | any | **Unknown:** read schema-less, as `grpcwire` reads it today, named under the parent's path by number (`user.7`) |

A wire type that doesn't match the declared kind is what protobuf runtimes themselves treat as an
unknown field (protobuf-go keeps it in the message's unknown fields, which the application can
still read with `ProtoReflect().GetUnknown()`), so the engine reads it as unknown, not as nothing.
That one rule covers a stale schema (the application has field 7, the set doesn't), type
confusion (a `string` sent as a varint, an `int64` sent as bytes) and smuggling text in fields the
schema doesn't list.

- **Every occurrence is read.** A singular field sent twice keeps only the last value in the
  application (merges, for a message); the engine reads both, a superset of what any runtime
  keeps.
- **Oneof:** each member is a field under its own name; several members in one message are all
  read, whichever the application keeps.
- **Maps:** entries are messages `{key, value}`: `labels.key` and `labels.value`. A key is text the
  rules see as a value, never an argument name.
- **`Any`:** `type_url` is text (`payload.type_url`). When its last segment names a message the
  schema kept ([§5.2](#52-the-compiled-schema)), `value` is read as that type, its fields under the
  `Any`'s path (`payload.sku`); otherwise `value` is read schema-less (`payload.value`, `payload.2.1`).
  The application unpacks by the same `type_url`, so an attacker who names another type changes
  the application's reading too.
- **Groups:** both readers read a group like a nested message, by its type when the schema
  describes it, with the same depth and field limits.

### 6.3 Names

- A field is named by its proto name (not its JSON name), the path joined by dots: `user.name`,
  `order.items.sku`. A repeated field has no index: every element of `items` gives `items.sku`, so
  one exclusion covers them all (Coraza's JSON names `json.items.0.sku` need one per index).
- No `json.`-style prefix: the call has no other body. Extensions: `[package.extension]`, as
  protobuf's text format writes them (`ArgumentPattern` allows brackets).
- Unknown fields: numbers under the nearest named parent (`user.7`, `7.1` at the top).
- A path longer than 256 bytes (an exclusion can't name it) keeps its first 256 bytes. Repeated
  names are fine: `ARGS` holds several values per name.
- Names are built in a buffer reused through the walk and copied once per argument, as today's
  `prefix + "." + strconv.Itoa(num)` already allocates once.

### 6.4 What the rules see

As today: each text field is a form argument (`ARGS`, `ARGS_POST`, via
`tx.AddPostRequestArgument` in `pkg/rules/coraza/coraza.go`), `REQUEST_BODY` stays empty, 920420
stays removed, the policy's argument limit (rule 200005) and the 4,096-field limit apply.

- `ARGS_NAMES` carries the names. They come from the schema (identifiers, dots, digits for
  unknown fields), never from the client, so CRS's rules on argument names have nothing to match.
- Events and `inkwallctl explain` show `ARGS:user.name`; the matched variable is already in the
  event (`api/events/v1`), so the event format doesn't change.
- Undescribed methods and unknown fields keep number names: one policy can see both
  (`user.name` and `user.7`).

### 6.5 Per adapter and per stream

Every adapter reaches the same two readers, so the schema works wherever messages are read today:

| Path | Where messages are read | Change |
|---|---|---|
| Buffered body: ext_proc (Envoy Gateway, Istio, raw Envoy), forward-auth (Traefik), SPOE (HAProxy), the reverse proxy | `Pipeline.inspect` → `grpcText` (`pkg/pipeline/grpc.go`) | `grpcText` takes the policy's type for the call's path |
| ext_proc per message (`grpcStreams: PerMessage`, [0006 §2](0006-adapter-protocols.md#grpc-request-streams-message-by-message-v060-315)) | `streams.Splitter.grpcEvent` (`pkg/streams/streams.go`), created in `pkg/adapters/extproc/streams.go` | `streams.New` takes the type; `GRPCStream` (`pkg/pipeline/grpc_streams.go`), chosen with the call's headers, resolves it once |
| gRPC-Web, gRPC-Web text | `grpcText`, after base64 | Same path, same types |

What each proxy sends is unchanged, and so are its limits: HAProxy's buffer (about 15 KiB with
`option http-buffer-request`) cuts long messages, Traefik reads at most 10 MiB + 1, the reverse
proxy `--max-body-bytes`. A cut message is read up to the cut by its schema, then handled by
`body.onOversize`, as today. Only ext_proc reads long streams message by message
([docs/grpc.md](../grpc.md)).

### 6.6 Why not dynamicpb

`dynamicpb` with `proto.Unmarshal` is the obvious decoder, and wrong for a WAF:

- It keeps what the *application* keeps: the last value of a singular field, the last oneof
  member, merged messages. The WAF must see every value sent ([§6.2](#62-each-field-by-its-kind)).
- It fails a whole message on one proto3 string that isn't UTF-8, where an application in another
  language may take it.
- Unknown fields stay raw bytes, which still need `grpcwire` to read.
- It costs more before any rule runs: on the largest message of the set above (a 33 KB
  `FileDescriptorProto`), `proto.Unmarshal` into `dynamicpb` took 912 µs and allocated 603 KB;
  today's schema-less `grpcwire.Strings` on it took 506 µs and 294 KB, with its 2,166 text fields
  (i7-1255U). A walk over `protowire` that reads each field once can only do less than `Strings`.

`protodesc` and `protoreflect` stay where they help: in the operator, to validate and compile, and
in tests, as the reference ([§11](#11-testing)).

## 7. Performance and memory

- **Decode cost.** Target: `grpcwire.Fields` at most 0.8× the time and allocations of `Strings`
  on the inputs of `BenchmarkGRPCMessages` (`pkg/grpcwire/bench_test.go`) with their descriptors,
  gated in `hack/benchgate` as `GRPCMessages` already is. It skips the passes `Strings` makes per
  field (`valid`, `printable`, `between`), reads numbers as nothing, and reads `bytes` once.
- **Field lookup.** Per message type, a dense slice indexed by field number when the largest
  number is under twice the count (the common case), else a binary search over the sorted numbers:
  a few nanoseconds per field, nothing next to building the strings.
- **Engine memory.** About 48 bytes per field plus its name, pointer-light: the 2,518-field set
  about 160 KB; the 65,536-field bound about 4 MiB per schema. Schemas are cached by `id` across
  policies and bundle applies, as evaluators are: a bundle that doesn't change a schema reuses it,
  and ten policies with one set hold it once.
- **Operator.** One compile per distinct ConfigMap value (5.6 ms for 208 KB); peak memory a few
  times the 8 MiB bound, briefly. **Bundle:** under 20 KB compressed for a typical set.

## 8. Failure modes

| What | Result |
|---|---|
| ConfigMap or key missing, or not labelled | `Accepted=False`, `InvalidRef` (as a rule set's `configMapRef`); the policy's previous version stays in the bundle ([0004 §4.5](0004-operator.md#45-resolver): errors fall back); a policy never resolved is left out |
| Not a descriptor set, unresolved import, invalid descriptors, no service, over a bound | `Accepted=False`, new reason `InvalidGRPCSchema` (registered in `operator/reasons`), the message naming the file and what failed; previous version stays |
| A valid set that describes none of the policy's routes' methods | Accepted; `inkwallctl explain policy` and the metric show every call undescribed |
| Bundle over budget with the schema | `BundleTooLarge`, as any policy |
| Engine before 0.7.0 | Reads schema-less; `Enforced=False`, `EnginesOutdated` |
| Compiled schema fails the engine's checks | The bundle is invalid: `Nack`, the engine keeps its bundle |
| Undescribed method | Schema-less reading, never denied for it |
| Field or wire type the schema doesn't have | Read schema-less as unknown |
| Top-level message doesn't parse, too deep (16), over 4,096 fields, cut, compressed other than gzip | Not read whole: `body.onOversize`, as today (`Pipeline.partly`) |
| Panic in the reader | Recovered: not read whole, as `Strings` does |

**Which way a bad schema fails: open, to schema-less, never to "unread".** A schema only ever
removes guesses; without it the engine reads more, not less. The old version staying in force
covers an edit; a first version that fails is visible in `Accepted=False` before it matters.

## 9. Security

**Untrusted descriptors.** Whoever can write a labelled ConfigMap in the policy's namespace can
write the schema, the same trust as a `WAFRuleSet`'s ConfigMap, which can turn rules off
altogether. What a hostile set can do:

- *Cost:* bounded at compile ([§5.4](#54-bounds)) in the operator, behind `recover`, off the
  request path; in the engine only checked integers and short strings.
- *Blind the policy:* the only reading a schema can weaken is a `string` declared `bytes`, which
  then gives runs of 8 or more characters. Declaring it a number or leaving it out makes it
  unknown, read schema-less; declaring it a message reads it whole when printable. That limit is why
  `bytes` keeps its runs instead of being skipped, and why the schema is the user's reviewed file,
  not the application's answer ([§3.2](#32-why-not-server-reflection)).
- *Other policies:* none. A schema is referenced from its namespace only and applies to its
  policy only; the shared cache is keyed by content hash.

**Hostile messages with a schema.** The reader must read everything the application could act on:

- *Oneof and duplicate confusion:* every occurrence and every member is read ([§6.2](#62-each-field-by-its-kind)).
- *Unknown fields and wire-type mismatches:* read schema-less, never dropped, so data can't be
  smuggled past the rules in a field the schema doesn't list.
- *Groups:* read like nested messages.
- *`Any`:* the type the `type_url` names, or schema-less.
- *Depth, size, count:* the limits of today, with `onOversize` past them; recursion in the schema
  doesn't matter since the data bounds the walk.
- *Names:* from the schema, never the client; a client can't make an argument name a rule or an
  exclusion matches.

The property the tests hold the reader to: **every string value that protobuf-go's own parser
gives the application (fields and unknown fields alike) is in what the rules see** ([§11](#11-testing)).

## 10. Observability

- `inkwall_grpc_messages_read_total{schema="described|undescribed"}` and
  `inkwall_grpc_unknown_fields_total` in the engine, with `policy` when `engine.policyMetrics` is
  on. A rising unknown count means the set is older than the application.
- `inkwallctl explain policy` prints the schema's source, method count and compiled size, and
  whether the routes' gRPC paths are described.

## 11. Testing

- **Unit:** table tests of `grpcwire.Fields` for every row of [§6.2](#62-each-field-by-its-kind):
  nested, repeated, packed and unpacked, maps, oneofs with several members, `Any` known and not,
  extensions, groups, unknown numbers, every wire-type mismatch, invalid UTF-8, paths over 256
  bytes; `pkg/grpcschema.Load` against each engine check.
- **Differential fuzz** (`FuzzFields`): from a fuzz seed, generate a random descriptor set
  (random messages, kinds, labels, nesting, recursion, maps, oneofs), compile it as the operator
  does, generate random and mutated messages; assert that every string protobuf-go's `dynamicpb`
  parse yields (field values and unknown fields' text, read the same way) is among `Fields`'
  values, that `Fields` never panics, and that it reports "read whole" only when `proto.Unmarshal`
  succeeds.
- **Fuzz the operator's compiler** with random `FileDescriptorSet` bytes, and `Load` with random
  `GRPCSchema` bytes: an error or a schema `Fields` can run on, never a panic.
- **Corpus:** the descriptors linked into the engine (as 0002 §8.7's measurement uses), gRPC
  health and reflection, a `googleapis` sample, and the `TestGRPCMessagesFalsePositives` inputs.
- **False positives:** re-run `TestGRPCMessagesFalsePositives` with the messages' schemas. Gate:
  no denial from `bytes` fields in 100,000 messages with four random 1–24 byte fields, and still
  none in the real messages.
- **Benchmarks** (`BenchmarkGRPCFields`, in `hack/benchgate`, [§7](#7-performance-and-memory)), and
  **operator** envtests for each row of [§8](#8-failure-modes), the cache and `EnginesOutdated`.
- **e2e, Envoy Gateway** (`hack/kind/envoy-gateway-e2e.sh`, which already routes
  `grpc.health.v1.Health`): a ConfigMap with `grpc/health/v1/health.proto`; an attack in
  `HealthCheckRequest.service` is denied with the event naming `ARGS:service`; an exclusion
  `when: {argument: service}` lets it through; an undescribed method is still read with number
  names; the same with `grpcStreams: PerMessage`. One more buffered adapter (HAProxy's e2e)
  checks the path through `grpcText`.

## 12. Rollout and compatibility

- **API:** one new optional field, an addition under [API compatibility](../api-compatibility.md);
  the `waf.inkwall.dev/rules` label's description widens to schemas. The bundle format is outside
  that policy and gated by engine version ([§4](#4-api)).
- **Names change when a schema is added:** `when: {argument: "2.1"}` no longer matches once that
  field is `user.name`. The webhook warns when a
  policy with `grpcSchema` has an exclusion whose argument is only digits and dots, and the user
  guide says to move the policy to `Detect`, add the schema, read the events, then rewrite
  exclusions. The operator doesn't translate them: the same numbers mean different fields in
  different methods' types.
- **Rolling the operator back below 0.7.0:** it doesn't know `grpcSchema`, and engines read
  schema-less again. Policies keep working, with number names, so name-based exclusions stop
  applying: more is denied, not less. The upgrade guide says so.
- **The CRD:** an older CRD prunes `grpcSchema` from new writes; roll it back last. [gRPC](../grpc.md)
  gains a section on schemas, and 0002 §8.7's "left for later" points here.

## 13. Decisions

| # | Decision | Rejected |
|---|---|---|
| 1 | A user-supplied `FileDescriptorSet` in a labelled ConfigMap in the policy's namespace, raw or gzipped | Server reflection by the operator or engines; a Secret; OCI artifacts (for now) |
| 2 | `spec.body.grpcSchema.configMapRef`, one set per policy, requires `grpcMessages: Inspect` | A schema turning reading on; several sets merged by the operator |
| 3 | The operator validates with `protodesc` and compiles to `GRPCSchema`; engines only check integers | Descriptors parsed in every engine |
| 4 | The schema in the signed bundle, deduplicated, against the 7,200 KiB budget | Its own stream message and Secrets, as the country table |
| 5 | A `protowire` walk by kind: strings as text, `bytes` by runs ≥ 8, numbers skipped, every occurrence read | `dynamicpb`; skipping `bytes` entirely |
| 6 | Unknown numbers and wire-type mismatches read schema-less | Dropping them |
| 7 | Names are proto field paths without indexes or prefix; extensions in brackets; unknown parts by number | JSON names; `json.`-style prefixes; indexes |
| 8 | Undescribed methods read schema-less | Treating them as unread (`onOversize`) |
| 9 | A bad schema keeps the previous version (`InvalidGRPCSchema`); old engines read schema-less (`EnginesOutdated`) | Failing closed on a bad schema |

## 14. Open questions

1. **`inkwallctl grpc schema fetch`**: call a server's reflection from the user's machine and write
   the ConfigMap, for services whose `.proto` files the user doesn't have at hand. The file is then
   reviewed like any other. *Recommendation:* yes, after v0.7.0; it keeps reflection out of the
   cluster's trust path.
2. **Deny undescribed methods** (`grpcSchema.unknownMethods: Deny`, `UNIMPLEMENTED` or
   `PERMISSION_DENIED`): the schema as an allow list of methods. *Recommendation:* later, once
   v0.7.0 shows how complete users' sets are; a stale set would deny new methods.
3. **Per-field overrides** for `bytes` fields an application reads as text (JSON or SQL in a
   `bytes`), e.g. `textFields: [payload]`. *Recommendation:* wait for a user who needs it; runs of 8
   already catch most attacks there.
4. **`grpcMessages: Inspect` by default for described methods.** If the false positive test of
   [§11](#11-testing) shows no binary false positives, a policy with a schema could read messages
   without saying so. *Recommendation:* no for v0.7.0, since a default change is a behaviour change
   on upgrade ([API compatibility](../api-compatibility.md)); revisit for v1 with the measurement.
5. **Standalone engine:** `--grpc-schema file.binpb`, compiled in the engine with the operator's
   compiler. *Recommendation:* yes, cheaply, after the operator path; the engine links protobuf-go
   already, and a local file is the user's own.
6. **Responses** read with the method's output type, through `pkg/streams`' response splitters.
   *Recommendation:* v0.8.0; the format already carries the type.
