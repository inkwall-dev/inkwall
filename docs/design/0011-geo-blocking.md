# 0011 — Geo Blocking

- Status: Draft
- Date: 2026-11-20
- Updated: 2026-11-20
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md),
  [0002 — System Architecture](0002-system-architecture.md),
  [0004 — Kubernetes Operator](0004-operator.md)

Geo blocking lets a policy deny clients by country, or let only some countries in. It belongs to
tier T1 ([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first)),
next to the IP lists: a cheap check on the client IP, before the rules run. This document decides
the `WAFPolicy` API, where the country database comes from and how it reaches engines, how the
engine looks a country up in about 100 ns, what the operator reports, and how it is tested.
**Nothing here is built yet** (#724).

[Terms](../glossary.md) used here:

- **Engine:** `inkwall-engine`, the process that inspects requests and returns verdicts.
- **Policy:** a `WAFPolicy`. **Bundle:** the signed snapshot of all policies that every engine
  enforces.
- **Database:** a [MaxMind DB](https://maxmind.github.io/MaxMind-DB/) (MMDB) file that maps IP
  networks to countries: MaxMind's GeoLite2 or GeoIP2, DB-IP's Lite, or a compatible one.
- **Country table:** what the operator compiles a database into for engines: sorted IP ranges, each
  with a two-letter country code ([§4.2](#42-the-operator-compiles-a-country-table)).
- **Country code:** an [ISO 3166-1 alpha-2](https://www.iso.org/iso-3166-country-codes.html) code,
  upper case (`DE`, `US`).

## Contents

- [1. Goals and scope](#1-goals-and-scope)
- [2. API](#2-api)
  - [2.1 Fields](#21-fields)
  - [2.2 Unknown and private addresses](#22-unknown-and-private-addresses)
  - [2.3 Order with IP lists, skips and rate limits](#23-order-with-ip-lists-skips-and-rate-limits)
  - [2.4 Validation](#24-validation)
  - [2.5 Older engines](#25-older-engines)
- [3. The database](#3-the-database)
  - [3.1 The user provides it](#31-the-user-provides-it)
  - [3.2 Where the operator reads it](#32-where-the-operator-reads-it)
- [4. Distribution](#4-distribution)
  - [4.1 Options](#41-options)
  - [4.2 The operator compiles a country table](#42-the-operator-compiles-a-country-table)
  - [4.3 The bundle pins the table](#43-the-bundle-pins-the-table)
  - [4.4 The stream and the Secrets](#44-the-stream-and-the-secrets)
  - [4.5 Before the table arrives](#45-before-the-table-arrives)
- [5. Engine design](#5-engine-design)
  - [5.1 Lookup](#51-lookup)
  - [5.2 Memory](#52-memory)
  - [5.3 Where in the pipeline](#53-where-in-the-pipeline)
  - [5.4 Bundle and API changes](#54-bundle-and-api-changes)
- [6. Parsing the MMDB](#6-parsing-the-mmdb)
- [7. Operator status](#7-operator-status)
- [8. Observability](#8-observability)
- [9. Client IP](#9-client-ip)
- [10. Testing](#10-testing)
- [11. Decisions](#11-decisions)
- [12. Open questions](#12-open-questions)

## 1. Goals and scope

Many sites serve customers in a few countries, or must not serve some by law. Denying those
countries at the WAF cuts the traffic the rules must inspect, and the noise in the events, for
about 100 ns per request.

**In v0.7.0:**

- `WAFPolicy.spec.geo`: a deny list or an allow list of country codes, per policy ([§2](#2-api)).
- A database the user provides; Inkwall ships none ([§3](#3-the-database)).
- The operator compiles it into a country table, pins its hash in the signed bundle, and sends it to
  engines over the stream they already have. Updates need no restart ([§4](#4-distribution)).
- A lookup of about 100 ns with no allocation ([§5](#5-engine-design)).
- Status on the `InkwallConfig` and the policies, metrics and events with the country
  ([§7](#7-operator-status), [§8](#8-observability)).

**Later, not in v0.7.0:**

- Regions and cities, autonomous systems (ASN), anonymous proxies and VPNs.
- A database the operator downloads from a URL itself ([open question 1](#12-open-questions)).
- Geo blocking in the standalone engine, without the operator.
- Geo blocking in the proxies' own GeoIP features (HAProxy, Envoy).

## 2. API

```yaml
spec:
  mode: Block
  geo:
    deny: [RU, KP]          # or allow: [DE, AT, CH]; not both
    unknown: Allow          # Allow (default) or Deny: a public address with no country
    mode: Detect            # optional: log only, on a Block policy
```

### 2.1 Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `deny` | country codes, ≤ 250, a set | — | Clients in these countries are denied (403, reason `geo-deny`) |
| `allow` | country codes, ≤ 250, a set | — | Only clients in these countries get through; others are denied |
| `unknown` | `Allow` or `Deny` | `Allow` | A public address the database has no country for ([§2.2](#22-unknown-and-private-addresses)) |
| `mode` | `Detect` | the policy's | `Detect` logs instead of denying, on a `Block` policy |

`allow` here does **not** mean what it means in `ipLists.allow`. A client in an IP allow list is
let through uninspected (`pkg/pipeline/pipeline.go`, `ipListed`). A client in an allowed country is
only not denied by geo: its requests still go through the rate limits and the rules. The field
docs, the user guide and `inkwallctl explain policy` say so.

`deny` and `allow` are exclusive. A deny list inside an allow list adds nothing that removing the
country from the allow list doesn't, and two lists invite the question of which wins.

The countries live in the policy, not in a shared object. Rejected: country entries in
`WAFIPList` (`operator/api/v1alpha1/wafiplist_types.go`). An IP list is data many policies share
and the operator resolves by name; a country list is a few codes tied to one application. Putting
countries there would also make the resolver depend on the database to turn a list into CIDRs. A
cluster-wide default belongs to the planned `WAFPolicyDefault`
([0004 §3](0004-operator.md#3-api-wafinkwalldevv1alpha1)).

`mode: Detect` follows the rate limits' design (0009, in review): a policy already in `Block` can
try geo first without moving the whole policy back to `Detect`. A `Block` geo on a `Detect` policy
is refused, since the policy mode exists to keep a policy from blocking.

### 2.2 Unknown and private addresses

A lookup has three outcomes:

| Outcome | When | What geo does |
|---|---|---|
| A country | The database maps the address to a country code | Allow or deny per the list |
| Private | No country, and the address is loopback, link-local, [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918), [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) or [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) (CGNAT) | Nothing: never denied by geo |
| Unknown | No country, and the address is public | Per `unknown` |

A country comes from the record's `country.iso_code`, or else its `registered_country.iso_code`
(MaxMind's own fallback for networks with no located country, such as some anycast and satellite
ranges). A record with neither, such as one with only a continent, is unknown.

**Decision: `unknown: Allow` by default, and private addresses always pass.** Reasons:

- Almost every public address has a country in these databases. The unknown ones are mostly
  unannounced or newly allocated ranges. Denying them by default buys little and breaks traffic
  when a database is behind.
- Private addresses are where a wrong client IP shows up: behind a load balancer that hides the
  client, every request comes from the load balancer's private address
  ([0002 §8.2](0002-system-architecture.md#82-client-ip-correctness)). If those were denied, a
  misconfigured client IP with `allow: [DE]` would take the site down. Instead geo does nothing and
  says so ([§9](#9-client-ip)).
- A user who wants unknown addresses denied sets `unknown: Deny`. A user who wants private ranges
  denied uses an IP deny list, which is the tool for addresses.

A database that maps a private range to a country (a custom one, or the e2e's) is obeyed: a
country found always wins.

Rejected: `unknown: Deny` by default for allow lists ("only DE" read strictly). Safer on paper, but
one database update that drops a range, or one hop that hides the client, denies real users.

### 2.3 Order with IP lists, skips and rate limits

`Pipeline.check` (`pkg/pipeline/pipeline.go`) checks the IP lists first, then the skip list, then
the rest. Geo goes right after the IP lists:

1. IP lists (`ipListed`): deny → 403 `ip-deny`; allow → let through, `ip-allow`.
2. **Geo (new):** a denied country, or an unknown address with `unknown: Deny` → 403 `geo-deny` in
   `Block`; in `Detect`, remember it and go on.
3. T0 skip list (`routes.Decide`).
4. Rate limits (0009).
5. WebSocket handshake rules, `body.grpc: Deny`, then the rules.

| Situation | What happens |
|---|---|
| Client in an IP deny list | Denied with `ip-deny`; geo isn't looked up |
| Client in an IP allow list | Let through uninspected; geo isn't looked up. A partner in a denied country can be let in this way |
| Denied country, path in `skip.paths` | Denied: like an IP deny, geo covers the whole route, skipped paths included |
| Denied country, `Block` | 403, not counted by rate limits, rules not run |
| Denied country, `Detect` (the policy's or `geo.mode`) | Counted, then the request goes on: skip list, rate limits, rules. If nothing else decides, the verdict is `log` with reason `geo-deny`; if a rule matched, its reason wins and the metric still counts the geo match |
| Inspection suspended (`InkwallConfig.spec.suspend`) | No geo: the engine allows every request before any policy (`pkg/policy`, `Set.Check`) |
| A request several policies inspect | Each applies its own geo; the strictest verdict wins, as for the rules |
| `exclusions` | No effect: exclusions turn rules off by ID, and geo is not a rule |

Geo runs before the skip list, as the IP deny list does today, and before the rate limits, so a
denied country never spends a client's tokens nor an evaluation slot. In `Detect` the request goes
on to the rules, like a rate limit in `Detect` and unlike an `ip-deny` in `Detect` (which stops).
A country is a large population, and a user trying geo wants to see what the rules find in the
rest of it.

`BodyLimit` (`pkg/pipeline/pipeline.go`) returns 0 for a client the IP lists decide, so adapters
don't read a body that won't be inspected. It does the same for a geo deny in `Block`.

### 2.4 Validation

Schema and CEL, the first step of [0004 §3.1](0004-operator.md#31-validation):

- Each code: pattern `^[A-Z]{2}$`. Lower case is refused rather than folded, so that `de` and `DE`
  can't both sit in one set.
- `deny` and `allow`: 1 to 250 codes each, `listType=set`; exactly one of them is set
  (`has(self.deny) != has(self.allow)`).
- `unknown`: enum `Allow`, `Deny`. `mode`: enum `Detect`.

**Rejected: an enum of the ISO 3166-1 codes in the CRD.** The databases use codes that aren't
officially assigned (`XK` for Kosovo, a user-assigned code), a custom database may use others
(`XA`–`XZ`, as the e2e does), and the list changes. A changed enum would need a CRD release. So the
validating webhook warns, without refusing, on a code that isn't in its built-in ISO list (with
`XK` added): "`UK` is not an ISO 3166-1 country code; the United Kingdom is `GB`". `UK` and `EU`
are the likely mistakes, and both get their own message.

### 2.5 Older engines

An engine before 0.7.0 ignores `spec.geo` and denies nothing. `requirement` in
`operator/internal/distribution/status.go` gains `spec.geo` with version 0.7.0, so
`enforcedConditions` sets `Enforced=False` with reason `EnginesOutdated` while an older engine runs
the bundle, as for every field before it.

## 3. The database

### 3.1 The user provides it

Inkwall ships no database, and the docs say why:

- **MaxMind GeoLite2 and GeoIP2** are licensed to the user who downloads them, with an account,
  under MaxMind's terms; Inkwall can't redistribute them.
- **DB-IP's IP to Country Lite** is under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/),
  which would allow shipping it. Rejected all the same: a database baked into the image is as old
  as the release, a few weeks to months, and countries' ranges move every week. The user's
  database follows the vendor's schedule instead.

The user chooses a vendor and keeps the database current; the guide shows MaxMind's
[`geoipupdate`](https://github.com/maxmind/geoipupdate) and DB-IP's monthly download, and reminds
the user of the vendor's attribution terms.

Supported: any MMDB whose records have `country.iso_code` (GeoLite2-Country, GeoIP2-Country,
DB-IP Country Lite; the City editions too, since they carry the country). A database with no
`country.iso_code` in any record is refused ([§7](#7-operator-status)). Other schemas (IPinfo's
flat `country_code`) are [open question 3](#12-open-questions).

### 3.2 Where the operator reads it

`InkwallConfig.spec.geo.database`, exactly one of:

```yaml
spec:
  geo:
    database:
      file: /var/lib/inkwall/geo/GeoLite2-Country.mmdb
      # or
      secretRef: {name: geo-db, key: country.mmdb}
```

- **`file`**: a path in the operator's pod, under `/var/lib/inkwall/geo/`, where the Helm chart
  mounts `geo.volume`: any volume (a PVC, an [image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image)
  where the cluster has them, a CSI driver). With `geo.geoipupdate.enabled`, the chart instead runs
  MaxMind's `geoipupdate` as a sidecar of the operator, with the account ID and license key from a
  Secret, writing to a shared `emptyDir` there, and opens the chart's NetworkPolicy egress for it.
  The operator polls the file every minute (size and modification time, then the hash), so an
  atomic replace of any kind is seen. The path must stay under that directory: the webhook refuses
  `..` and anything else, so an `InkwallConfig` can't ship the operator's own token or keys to every
  engine.
- **`secretRef`**: a Secret in the operator's namespace, raw or gzipped (by its magic bytes). A
  Secret holds at most [1 MiB](https://kubernetes.io/docs/concepts/configuration/secret/#restriction-data-size),
  which a full country database (about 9 MB, half that gzipped) doesn't fit. It is for small custom
  databases and the tests. A ConfigMap was rejected as a third kind: the same 1 MiB, no gain.

Only the operator reads the source. The engines never see it, never reach the vendor, and never
need its credentials.

## 4. Distribution

### 4.1 Options

| Option | For | Against |
|---|---|---|
| (a) In the signed bundle | One signature, one version, one channel | A country database is about 9 MB, half that compressed; the bundle's ceiling is 7,200 KiB compressed, shared by up to 5,000 policies (`pkg/bundlesecret`: 8 chunks of 900 KiB; [0004 §8](0004-operator.md#8-scale-targets-v1)). The stream carries the bundle whole ([0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)), so every policy edit would resend it to every engine |
| (b) Its own message on the operator stream, pinned by the bundle | The bundle stays small; the table moves only when it changes; engines keep one connection; no new trust | A second message type to send, cache and report |
| (c) A volume the injected sidecar mounts | No operator work | Engines run in the proxies' namespaces, so each needs its own copy; Secrets and ConfigMaps hold 1 MiB; a PVC must be `ReadWriteMany` across nodes; an image volume changes only with a pod restart; nothing verifies it; each integration's injection changes (`operator/internal/injection/sidecar.go`) |
| (d) The engine downloads it | — | Engines have no egress, by design ([0002 §3.4](0002-system-architecture.md#34-control-plane-optional), D4), and would each need the vendor's credentials |

**Decision: (b).** The operator compiles the database into a country table, the bundle carries the
table's SHA-256, and the table travels as its own message on the stream. The next sections give
each part.

### 4.2 The operator compiles a country table

The engine never parses an MMDB. The operator (leader only, like the bundle builder) reads the
database, walks every network, and writes a **country table**: a new proto,
`inkwall.geo.v1.CountryTable`.

```proto
message CountryTable {
  // IPv4 ranges: starts[i] is the first address of range i, which runs to
  // starts[i+1]-1 (the last to 255.255.255.255). Strictly increasing,
  // starts[0] == 0. codes[i] is range i's country, two bytes 'A'-'Z', or
  // 0x0000: no country.
  repeated fixed32 v4_starts = 1;  // packed
  bytes v4_codes = 2;              // 2 bytes per range
  // IPv6, the same, each start 16 bytes big-endian.
  bytes v6_starts = 3;
  bytes v6_codes = 4;
  // Where it came from, for status and explain.
  string database_type = 5;        // the MMDB's metadata, e.g. GeoLite2-Country
  google.protobuf.Timestamp database_built = 6;
  bytes database_sha256 = 7;       // of the source file
}
```

Why the operator compiles, not the engine:

- **One parser of an untrusted format, off the request path.** MMDB is a binary search tree and a
  pointer-based data section. Parsing it runs once per database change, in the operator, in a
  goroutine with a size limit and `recover` ([§6](#6-parsing-the-mmdb)). The engine only checks a
  table of sorted integers, which a few lines verify completely.
- **Smaller and denser.** Only the country survives. MMDB splits ranges on CIDR boundaries; the
  operator merges neighbours with the same country. A City database (tens of MB) compiles to the
  same table as its country edition.
- **No MMDB library in the engine.** The engine's dependencies stay as they are; only the operator
  links the reader.
- **One answer.** All engines hold the same table, byte for byte, which the bundle pins.

The table's compressed size is reported in the status ([§7](#7-operator-status)). It is bounded:
at most 4 million ranges per family, and 14,400 KiB compressed (16 chunks of 900 KiB,
[§4.4](#44-the-stream-and-the-secrets)). A database over either is refused with reason
`TooLarge`.

### 4.3 The bundle pins the table

`Bundle` gains `GeoTableRef geo_table = 11`: the table's SHA-256 and size. The bundle is signed,
so the hash is signed: an engine uses a table only once it runs a bundle that names the table's
SHA-256. A table that arrives first (on connect, [§4.4](#44-the-stream-and-the-secrets)) waits,
unused, for that bundle, and is dropped if the next bundle names another. No second signature, no second version counter, no second rollback
check: the bundle has all three (D5, [0002 §11](0002-system-architecture.md#11-decisions-adr-log)).

`geo_table` is part of the bundle's content hash, so a new database is a new bundle version. That
costs every engine a bundle apply twice a week (MaxMind's GeoLite2 schedule), which recompiles no
rule set that didn't change. The reference is set only when some policy uses `spec.geo`; a cluster
without geo policies never carries or sends a table.

Rejected: a separately signed table manifest outside the bundle. It would need its own version,
its own monotonic check and its own `Ack`, to save a bundle version twice a week.

### 4.4 The stream and the Secrets

**Stream** (`api/agent/v1`, [0002 §5.2](0002-system-architecture.md#52-engine--operator-bundle-distribution)):

- `WatchResponse` gains `CountryTableMessage geo_table = 3`: the SHA-256 and the gzipped table, in
  one message. Engines already accept messages of up to 65 MiB (`pkg/agent/agent.go`,
  `MaxCallRecvMsgSize`), so no chunking is needed. Field 2 stays reserved for directives.
- `Hello` and `Heartbeat` gain `bytes geo_table_sha256`: the table the engine holds.
- The operator sends the table when the engine's hash differs from the current bundle's: on
  connect, before the bundle, so a new engine applies both at once; after a database update, to
  every engine. Sends share the distribution server's limit of 50 at once
  ([0004 §4.7](0004-operator.md#47-distribution-server-all-replicas)). For 500 engines and a 4 MB
  table that is 2 GB per update, spread over the slots; the scale test measures how long
  ([§10](#10-testing)).
- Once it runs a bundle naming the table, the engine verifies the hash, decodes, checks the table ([§5.1](#51-lookup)), swaps it in
  atomically, writes it to its cache (`/var/run/inkwall/geo.table`, the `emptyDir` beside
  `bundle.pb`), and reports the new hash in its next heartbeat. No restart.
- A table that fails a check is dropped, logged and counted; the engine keeps the one it had, and
  reports that one's hash, so the operator sees it and retries with backoff.

**Secrets.** The leader stores the compressed table as `inkwall-geo-a-0`… (or `-b-`), with a
manifest, through `pkg/bundlesecret` (`Split`, the a/b slots, the SHA-256 check), as the bundle's
chunks are ([0004 §4.6](0004-operator.md#46-bundle-builder-leader-only)). Two uses:

- **Engine cold start.** An engine with no cache and no operator reads the bundle Secret
  (`--bundle-secret`, `pkg/agent/secret.go`). It reads the table's chunks the same way. The
  `inkwall-bundle-reader` Role grants `get` on their names too.
- **Leader change.** A new leader reads the stored table instead of compiling the source again
  before its first bundle.

Cost: about 5 MB in etcd per slot for a country database. Accepted.

### 4.5 Before the table arrives

An engine can run a geo policy without the table: the database isn't configured or is invalid,
the engine just started, or a send failed. Then geo follows the policy's `failureMode`, as any
check that can't run does (`Pipeline.failed`; D8, fail open in `Detect`, closed in `Block`):

| `failureMode` | Geo without a table |
|---|---|
| `Open` | Geo is skipped; the request goes on to the rest of the pipeline. Counted as `no-table` |
| `Closed` | 503 with reason `geo-unavailable`, like a timeout or an overload |

`Open` skips only geo, not the whole pipeline: unlike a timeout, nothing is left half done.

Readiness: an engine whose bundle names a table it doesn't have keeps `/readyz` failing until the
table is loaded, for at most 10 s after the bundle, then turns ready and follows the table above.
With the cache or the stream, the table arrives well within that; the wait only matters on cold
starts, where a `Closed` policy would otherwise answer 503s during them.

When the source becomes invalid later, the operator keeps the last good table in the bundle, so
engines keep enforcing with it, and reports the problem ([§7](#7-operator-status)). Only when no
good table was ever compiled does the bundle carry none.

## 5. Engine design

### 5.1 Lookup

New package `pkg/geo`, built like `pkg/iplist` (sorted, merged ranges and a binary search, about
60 ns at 10,000 prefixes and no allocation: [0002 §4.2](0002-system-architecture.md#42-crds-wafinkwalldevv1alpha1)):

- **Table:** `v4 []uint32` starts with `v4c []uint16` codes, and `v6 []u128` starts with
  `v6c []uint16`. A code is `(c1 << 8) | c2`; 0 is no country.
- **Lookup:** unmap an IPv4-mapped address (as `iplist.Set.Contains` does), pick the family,
  `slices.BinarySearch` for the last start ≤ the address, return its code. 4 million ranges are 22
  steps. 6to4 and Teredo addresses are looked up as they are, not by their embedded IPv4.
- **Per policy:** a 676-bit set (26 × 26, every two-letter code, 88 bytes) for `deny` or `allow`.
  It doesn't depend on the table, so a new table recompiles no policy.
- **Once per request.** The country is looked up at most once, the first time a policy with geo
  (or an event, [§8](#8-observability)) needs it, and kept in the request. Several policies and
  `BodyLimit` reuse it.
- **Check at load:** lengths match, starts strictly increasing, `starts[0]` is zero, codes are 0
  or two letters, counts within the bounds of [§4.2](#42-the-operator-compiles-a-country-table).
  The table is then trusted: a bad table can only give a wrong country, never a crash.
- **Cost target:** ≤ 150 ns per lookup, 0 allocations, gated by the benchmarks of
  [§10](#10-testing). If the benchmark misses it on the IPv4 table, a 65,536-entry index on the
  top 16 bits (256 KiB) narrows the search to one `/16`.

Rejected: no cache across requests. A lookup is already cheaper than a locked map access.

Rejected: looking up in the MMDB per request with the library
([`maxminddb-golang`](https://github.com/oschwald/maxminddb-golang)'s `Lookup` and an
offset-to-country map). It walks up to 128 tree nodes (more steps than the binary search), runs
the third-party parser of an untrusted file on every request, and keeps the whole file, cities
and all, in memory. It stays as the reference in the differential fuzz ([§10](#10-testing)).

### 5.2 Memory

6 bytes per IPv4 range and 18 per IPv6 range, in pointer-free slices, so the garbage collector
never scans them. The exact size is in the status before any engine loads it
([§7](#7-operator-status)), and in the gauge `inkwall_geo_table_bytes`. During a swap the engine
holds the old and the new table for one bundle apply.

The engine's default memory limit is 512 MiB, with `GOMEMLIMIT` at 90% of it
(`operator/internal/injection/sidecar.go`, `internal/memlimit`). The table is on the heap and
counts toward it. Rejected: `mmap` of the cached file. Page cache counts toward the container's
memory limit anyway, the cache volume may be a memory-backed `emptyDir`, a truncated file faults
the process, and the table is small enough to read.

### 5.3 Where in the pipeline

Geo is a policy's, so it runs inside `Pipeline.check` (`pkg/pipeline/pipeline.go`) right after
`ipListed`, in the order of [§2.3](#23-order-with-ip-lists-skips-and-rate-limits). The table is
engine-wide and outlives bundles, like `Evaluators` (`pkg/policy/policy.go`): a pointer swapped
atomically, read once per request.

### 5.4 Bundle and API changes

- **`api/geo/v1/geo.proto`** (new): `CountryTable` ([§4.2](#42-the-operator-compiles-a-country-table)).
- **`api/bundle/v1/bundle.proto`:** `Bundle.geo_table = 11` (`GeoTableRef { sha256, size }`);
  `Policy.geo = 16` (`Geo { repeated string deny; repeated string allow; bool unknown_deny;
  bool detect }`; field 15 is the rate limits' in 0009). Engines before 0.7.0 skip both.
- **`api/agent/v1`:** `WatchResponse.geo_table = 3`; `Hello.geo_table_sha256 = 8`;
  `Heartbeat.geo_table_sha256 = 6`.
- **`api/engine/v1/engine.proto`:** `REASON_GEO_DENY` and `REASON_GEO_UNAVAILABLE`, the next
  free numbers after 0009's `REASON_RATE_LIMIT`; `pkg/pipeline` gains `ReasonGeoDeny` and
  `ReasonGeoUnavailable`, written `geo-deny` and `geo-unavailable`.
- **`api/events/v1/events.proto`:** `SecurityEvent.country = 23` ([§8](#8-observability)).

## 6. Parsing the MMDB

**Library: [`github.com/oschwald/maxminddb-golang/v2`](https://github.com/oschwald/maxminddb-golang),
in the operator only.**

- **License:** [ISC](https://opensource.org/license/isc-license-txt), a permissive license
  compatible with Inkwall's Apache-2.0; its notice goes with the others in the release's SBOM.
- **Dependencies:** `golang.org/x/sys`, already in `go.mod`. Its `go.mod` lists `testify` and a
  `tool` for its own tests and code generation; neither is built into Inkwall.
- **Safety:** it reads from a byte slice (`OpenBytes`) with bounds checks, has a `Verify` that
  checks the tree and the data section, and fuzz targets of its own (`FuzzDatabase`,
  `FuzzNetworks`).

How the operator uses it:

1. Read at most 128 MiB (the source limit; a City database fits), compute the source's SHA-256.
   Skip everything else if it is unchanged.
2. `OpenBytes`, then `Verify`. Refuse what fails, with reason `Invalid`.
3. Walk `Networks()`, decoding only `country.iso_code` and `registered_country.iso_code` into a
   two-field struct. Refuse codes that aren't two ASCII letters; upper-case lower-case ones.
4. Fill the gaps between networks with "no country", merge neighbours, and check the bounds.
5. All of it in a goroutine with `recover` and a deadline of one minute: a crafted file that
   panics or loops makes a `Invalid` condition, never a crashed leader.

The input is the cluster admin's own file, so the threat is a corrupt download more than an
attacker. It is still parsed as untrusted, since a broken file must not stop the operator, which
enforces every other policy too.

Rejected: writing our own MMDB reader. The format is small, but a maintained, fuzzed reader is
less risk than a new one, and only the operator runs it.

## 7. Operator status

**`InkwallConfig`:**

- `spec.geo.database` ([§3.2](#32-where-the-operator-reads-it)).
- A new condition, `GeoDatabaseReady`, set only when `spec.geo` is:

| Status | Reason | When |
|---|---|---|
| True | `Loaded` | Compiled and published; the message gives the type, build date, ranges and table size |
| True | `Stale` | Loaded, but built more than 30 days ago; check the updater |
| False | `NotFound` | The file or the Secret key doesn't exist |
| False | `Invalid` | Not a valid MMDB, a bad country code, or parsing failed or timed out |
| False | `NoCountryData` | No record has `country.iso_code` |
| False | `TooLarge` | Over 128 MiB, 4 million ranges per family, or 14,400 KiB compressed |

  While it is `False` after a good load, engines keep the last good table, and the message says
  which and since when.
- `status.geo`: `sha256`, `databaseType`, `built`, `ranges`, `compressedBytes`, like
  `status.bundle`.

**`WAFPolicy`:** a policy with `spec.geo` is `Enforced=False` with a new reason
`GeoDatabaseUnavailable` when the cluster has no table, or while some engines that run the bundle
don't hold its table yet (they report it in their heartbeats). The message says which: "no country
database: set InkwallConfig spec.geo.database", or "2 of 6 engines don't have the country table
yet (first: …)". `Accepted` stays `True`: the policy is valid, and it will be enforced once the
table arrives. `EnginesOutdated` ([§2.5](#25-older-engines)) takes precedence.

A policy with `spec.geo` but no database configured gets one Warning event, and the webhook warns
when it is applied.

`inkwallctl status` shows the database line: type, build date, how many engines hold it.

## 8. Observability

**Metrics** (engine):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inkwall_requests_total` | counter | (existing) | New reason values `geo-deny` and `geo-unavailable` |
| `inkwall_geo_denied_total` | counter | `action`, `country` | Requests geo denied (`deny`) or would have (`log`), by country, `unknown` for unknown addresses |
| `inkwall_geo_lookups_total` | counter | `result` | Lookups for geo policies: `country`, `private`, `unknown`, `no-table` |
| `inkwall_geo_table_bytes` | gauge | | The table's size in memory |
| `inkwall_geo_table_built_timestamp_seconds` | gauge | | The database's build time |
| `inkwall_geo_table_load_failures_total` | counter | | Tables received that failed a check |

The `country` label is bounded: only codes geo denies get series, at most 676 plus `unknown`; in
practice, the handful a policy lists or the few dozen an allow list leaves out. The operator adds
`inkwall_operator_geo_table_compressed_bytes`.

Two alerts:

- `InkwallGeoDatabaseStale`: the build time is more than 30 days old, for an hour.
- `InkwallGeoClientIPPrivate`: on an engine with geo policies, more than half the lookups are
  `private` for 15 minutes. The client IP is probably the load balancer's ([§9](#9-client-ip)).

**Security events.** Every event gains `country` when the engine has a table: the code, `unknown`,
or empty for private addresses. That is one lookup per event, not per request, and it is what a
SIEM wants next to `client_ip`. Geo denials are events (every verdict that isn't `allow`,
`httpadapter.IsEvent`), and a denied country can be a flood that pushes other events out of the
bounded buffer (`pkg/events`). So geo events are **sampled per (policy, country)**: the first, then
at most one per second, each carrying how many requests it stands for, in the same field the rate
limits' sampled events add (0009 §6). The metrics count every request. The log lines go through
the existing per-(policy, rule, reason) log limiter.

**`inkwallctl explain`** ([0008](0008-assistants.md)):

- `explain request <id>` on a `geo-deny`: the client IP, its country and its source (country or
  registered country), the policy's list, and the cause and fix from the reasons registry
  (`operator/reasons/reasons.go` gains `geo-deny` and `geo-unavailable`).
- `explain policy`: the list, `unknown`, and that `allow` doesn't skip inspection.
- `inkwallctl geo lookup <ip>`: reads the published table from its Secrets, checks it against the
  bundle, and prints the country, so a user can test an address before blocking it.

## 9. Client IP

Geo is only as right as the client IP, and a hard prerequisite. Two ways it goes wrong:

- **Every client looks like the load balancer.** The address is usually private, so geo does
  nothing ([§2.2](#22-unknown-and-private-addresses)). It is surfaced, not hidden: the `private`
  lookups metric and its alert, `explain request` showing the address, and the guide's first step.
  If the load balancer's address is public (some cloud load balancers), every request gets the
  load balancer's country: an allow list then passes or denies everyone, which `Detect` shows
  before it matters.
- **Clients choose their address.** A trusted proxy setting that's too wide lets a client write its
  own `X-Forwarded-For` and pick a country. The webhook already warns of a prefix that trusts every
  address ([0002 §8.2](0002-system-architecture.md#82-client-ip-correctness)).

The user guide for geo starts with [Client IP behind a load balancer](../client-ip.md), and says
to run the policy with `geo.mode: Detect` first and check the `client_ip` and `country` of a few
events. `docs/client-ip.md` lists geo blocking among the features that use the address.

## 10. Testing

| Layer | What | Where |
|---|---|---|
| Unit | The compiler: gaps filled, neighbours merged, `registered_country` fallback, lower case folded, bad codes refused, each bound; the same table from the same database, byte for byte | `operator/internal/geo` |
| Unit | Table checks (each refusal), lookup at range edges, `0.0.0.0` and `255.255.255.255`, `::` and the last IPv6 address, IPv4-mapped IPv6, the bitsets | `pkg/geo` |
| Unit | The order of [§2.3](#23-order-with-ip-lists-skips-and-rate-limits): IP deny and allow before geo, geo before skips and rate limits, `Detect` runs the rules and a rule's reason wins, `geo.mode: Detect`, `unknown`, private addresses, no table with `Open` and `Closed`, `BodyLimit` | `pkg/pipeline`, `pkg/policy` |
| Unit | The agent: table before bundle, a table with the wrong hash dropped, the previous table kept, the cache read at start, the readiness wait | `pkg/agent` |
| Unit | CRD validation (each CEL rule), webhook warnings (`UK`, `EU`, an unassigned code, a path outside the mount), `requirement` returns 0.7.0, `GeoDatabaseReady` reasons, `GeoDatabaseUnavailable` | `operator/api/v1alpha1/validation_test.go`, `operator/webhook`, `operator/internal/distribution`, `operator/internal/controller` |
| Fuzz | `FuzzCompile`: arbitrary bytes, and valid databases with random bytes flipped, into the compiler: an error or a table that passes the engine's checks, never a panic or a timeout | `operator/internal/geo` |
| Fuzz | `FuzzTable`: arbitrary bytes into the engine's decoder and checks | `pkg/geo` |
| Fuzz | Differential: a database built from random networks and codes, then random addresses: the table's answer equals the library's `Lookup` | `operator/internal/geo` |
| Benchmark | `BenchmarkLookup` over a synthetic table of 1 million IPv4 and 1 million IPv6 ranges, random addresses; `BenchmarkCheck` with and without geo. Target ≤ 150 ns and 0 allocs/op, gated by `make bench-compare` (`hack/benchgate`) | `pkg/geo`, `pkg/pipeline` |
| e2e on kind | Per proxy (`hack/kind/e2e.sh` and the other `*-e2e.sh`): the test builds a tiny database mapping one client pod's address to `XA` and the rest of `10.0.0.0/8` to `XB`, and loads it with `secretRef`. `deny: [XA]` denies that pod with 403 `geo-deny` and lets another through; replacing the database flips it with no engine restart (restart counts unchanged); `Detect` logs; no database makes the policy `GeoDatabaseUnavailable` and a `Closed` policy answer 503; an engine before 0.7.0 makes it `EnginesOutdated` (`hack/kind/upgrade.sh`) | `hack/kind` |
| Scale | `operator/test/scale` with a 4 MB table and 500 engines: time until all hold a new table, operator memory | `operator/test/scale` |

**The test database.** Tests write their own MMDBs with a small writer in
`operator/internal/geo/mmdbtest`: a search tree with 24-bit records and a data section of
`{country: {iso_code}}` maps, per the [MaxMind DB spec](https://maxmind.github.io/MaxMind-DB/),
about 200 lines. It also writes broken files on purpose for the fuzz seeds. Rejected: MaxMind's
[`mmdbwriter`](https://github.com/maxmind/mmdbwriter). It is a separate module with its own
dependencies for test use only, and it is built to write valid files, not broken ones. No vendor
database is committed to the repository, for their licenses.

## 11. Decisions

| # | Decision | Rejected |
|---|---|---|
| 1 | `WAFPolicy.spec.geo` with `deny` or `allow` (exclusive), `unknown`, optional `mode: Detect` | Countries in `WAFIPList`; both lists at once |
| 2 | `unknown: Allow` by default; private addresses never denied by geo unless the database maps them | Unknown denied by default for allow lists |
| 3 | After the IP lists, before skips, rate limits and rules; IP allow beats geo; `Detect` goes on to the rules | Geo before the IP lists; geo after skips |
| 4 | Codes checked by pattern; the webhook warns on unassigned ones | An ISO enum in the CRD |
| 5 | The user provides an MMDB; Inkwall ships none | Shipping DB-IP Lite in the image |
| 6 | Source: a file in the operator's pod (any volume, or a `geoipupdate` sidecar) or a small Secret | A ConfigMap; a volume in every sidecar; engines downloading |
| 7 | The operator compiles the MMDB into a country table; the engine never parses MMDB | MMDB lookups in the engine |
| 8 | The table on the operator stream, its SHA-256 pinned in the signed bundle, stored in chunk Secrets for cold start | The table in the bundle; a separately signed manifest |
| 9 | Without a table, geo follows the policy's `failureMode`; readiness waits up to 10 s | Always open; always closed |
| 10 | `pkg/geo`: sorted ranges and a binary search, a country bitset per policy, one lookup per request; ≤ 150 ns, 0 allocs | A per-IP cache; `mmap` |
| 11 | `maxminddb-golang/v2` (ISC) in the operator only, behind `Verify`, `recover` and a deadline | Our own MMDB reader |
| 12 | `GeoDatabaseReady` on the `InkwallConfig`; `Enforced=False`, `GeoDatabaseUnavailable` on policies; `EnginesOutdated` for old engines | `Accepted=False` while the table is missing |
| 13 | Every event carries `country`; geo events sampled per (policy, country) | An event per denied request |

## 12. Open questions

1. **The operator downloads the database itself**, from a URL with credentials from a Secret, as
   [0002 §4.2](0002-system-architecture.md#42-crds-wafinkwalldevv1alpha1) plans for fetched IP
   lists. It would drop the sidecar, but makes the operator a download client for each vendor.
2. **Standalone engine.** Load a table compiled by `inkwallctl geo compile` from a file flag?
3. **Other schemas.** IPinfo's and others' flat fields: a configurable field path, or not at all?
4. **ASN and anonymizers.** The same table with an ASN or a flag instead of a country would give
   `spec.geo.denyASNs` and anonymous-proxy blocking. Worth it after v0.7.0 shows how geo is used.
5. **Geo in the proxy.** HAProxy and Envoy have GeoIP features of their own that would deny before
   the engine is asked, as moving T1 into the proxies
   ([0001 §4](0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first))
   would.
