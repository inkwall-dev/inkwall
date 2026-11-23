# Geo blocking

A policy's `geo` denies clients by country, or lets only some countries in: a denied client gets
`403 Forbidden` (reason `geo-deny`) before the skipped paths, the rate limits and the rules. It
needs a country database, which you provide, and engines 0.7.0 or later.

Geo is only as right as the client IP the engine resolves. Read
[First, the client IP](#first-the-client-ip) before anything else, and run the policy with
`geo.mode: Detect` first.

## Contents

- [First, the client IP](#first-the-client-ip)
- [The database](#the-database)
- [Give the operator the database](#give-the-operator-the-database)
- [A first policy](#a-first-policy)
- [Fields](#fields)
- [Unknown and private addresses](#unknown-and-private-addresses)
- [Where geo runs](#where-geo-runs)
- [Before the country table arrives](#before-the-country-table-arrives)
- [Status](#status)
- [Metrics, alerts and events](#metrics-alerts-and-events)
- [Personal data](#personal-data)
- [Upgrading and rolling back](#upgrading-and-rolling-back)

## First, the client IP

The engine looks up the country of the client IP it resolves ([Client IP behind a load
balancer](client-ip.md)). Two ways it goes wrong:

- **Every client looks like the load balancer.** Its address is usually private, and geo never
  denies a private address, so geo does nothing. The `private` lookups of
  `inkwall_geo_lookups_total` show it, and the `InkwallGeoClientIPPrivate` alert fires when more
  than half the lookups are private for 15 minutes. If the load balancer's address is public,
  every request gets the load balancer's country instead.
- **Clients choose their address.** A trusted proxy prefix that is too wide lets a client send its
  own `X-Forwarded-For` and pick its country. The webhook warns of a prefix that trusts every
  address.

So: set the client IP up as [the guide](client-ip.md) says, apply the policy with
`geo.mode: Detect`, and check the `client_ip` and `country` of a few of its events before you
remove `mode`.

## The database

Inkwall ships no country database. Use a [MaxMind DB](https://maxmind.github.io/MaxMind-DB/)
(MMDB) whose records have `country.iso_code`:

- **MaxMind GeoLite2-Country** (free, with an account) or **GeoIP2-Country**; the City editions
  work too, since they carry the country. MaxMind licenses them to you, under its terms:
  [GeoLite2's EULA](https://www.maxmind.com/en/geolite2/eula) asks you to keep the database up to
  date and, when MaxMind releases an update, to move to it and stop using the old one within 30
  days. Inkwall supports that with the `Stale` reason after 30 days and its alert; engines keep the
  last good table only until a new one comes. The EULA also limits sharing the data with third
  parties: events carry the client's `country`, and go to the control plane when one is connected
  ([Personal data](#personal-data)). Read the terms that apply to you.
- **DB-IP's IP to Country Lite**, under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/):
  it needs attribution where you use it.
- A compatible database of your own, with `country.iso_code` (or `registered_country.iso_code`).

Keep it current: countries' ranges move every week. MaxMind's
[`geoipupdate`](https://github.com/maxmind/geoipupdate) downloads GeoLite2 twice a week; DB-IP
publishes its Lite database monthly.

Only the operator reads the database. It compiles it into a **country table** (sorted address
ranges and their country, about 2 to 3 MB compressed for a country database) and sends it to the
engines on the stream they already have; engines never see the database, nor the vendor's
credentials. A new database reaches every engine without a restart.

## Give the operator the database

`InkwallConfig.spec.geo.database` is one of:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: InkwallConfig
metadata: {name: default}
spec:
  geo:
    database:
      file: /var/lib/inkwall/geo/GeoLite2-Country.mmdb
      # or
      # secretRef: {name: geo-db, key: country.mmdb}
```

- **`file`**: a path under `/var/lib/inkwall/geo/`, in the operator's pod. The operator polls it
  every minute; replace the file by a rename (as `geoipupdate` does), not by writing over it.
  The Helm chart mounts it in one of two ways:
  - `geo.geoipupdate.enabled: true` runs MaxMind's `geoipupdate` beside each operator replica,
    with your account ID and license key from a Secret (`geo.geoipupdate.secretName`, keys
    `account-id` and `license-key`), writing to a volume of that pod. Each replica has its own
    copy. The pod then needs internet egress to MaxMind: the chart's NetworkPolicy opens HTTPS for
    it (`geo.geoipupdate.egressCIDRs`, every IPv4 and IPv6 address by default, since a
    NetworkPolicy can't name a host). The sidecar has its own credentials and reaches two things:
    the geo volume, where it writes the database, and that egress. It doesn't get the operator's
    ServiceAccount token, which can read the bundle signing key's Secret: the pod sets
    `automountServiceAccountToken: false` and mounts the token into the operator's container
    alone. The image is pinned by digest. A NetworkPolicy applies to the whole pod, though: the
    operator's container, which holds that token, can reach `egressCIDRs` on 443 too. Narrow it to
    your egress proxy where you can, or use `geo.volume`.
  - `geo.volume`: any volume you fill from outside the cluster, such as a PVC or an image volume.
    The chart runs two operator replicas, and either can lead: a PVC shared by both needs
    `ReadOnlyMany`.
- **`secretRef`**: a key of a Secret in the operator's namespace, raw or gzipped. A Secret holds at
  most 1 MiB, which a full country database doesn't fit: for small custom databases and tests.

The InkwallConfig's `GeoDatabaseReady` condition says whether it worked ([Status](#status)).

## A first policy

Deny two countries, logging only while you watch it:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: shop, namespace: shop}
spec:
  targetRefs: [{kind: Ingress, name: shop}]
  mode: Block
  geo:
    deny: [RU, KP]
    mode: Detect
```

Its events (reason `geo-deny`, action `log`) and `inkwall_geo_denied_total{action="log"}` show what
`Block` would deny. Remove `mode` to deny.

Or let only some countries in:

```yaml
  geo:
    allow: [DE, AT, CH]
```

## Fields

| Field | Default | Meaning |
|---|---|---|
| `deny` | | Countries whose clients are denied: 1 to 250 codes |
| `allow` | | The only countries whose clients get through geo: 1 to 250 codes |
| `unknown` | `Allow` | A public address the database has no country for: `Allow` or `Deny` |
| `mode` | the policy's | `Detect` logs what geo would deny, on a `Block` policy too |

Exactly one of `deny` and `allow`. Codes are [ISO 3166-1 alpha-2](https://www.iso.org/iso-3166-country-codes.html),
upper case: the United Kingdom is `GB`, not `UK`, and the EU isn't a country. The webhook warns
of a code that isn't assigned (`XK`, Kosovo, is accepted: the databases use it).

`allow` doesn't mean what it means in `ipLists.allow`: a client in an IP allow list skips
inspection, while a client in an allowed country is only not denied by geo, and its requests still
go through the rate limits and the rules.

## Unknown and private addresses

| The client's address | What geo does |
|---|---|
| A country in the database | Denies it or not, per the list |
| Private (loopback, link-local, RFC 1918, RFC 4193, CGNAT `100.64.0.0/10`), unspecified, or no client IP at all | Nothing: never denied by geo |
| Public, no country (`unknown`) | Per `unknown`: allowed by default |

A database that maps a private range to a country is obeyed. A record's country is its
`country.iso_code`, else its `registered_country.iso_code`; `ZZ` means no country. To deny private
ranges, use an IP deny list, the tool for addresses.

## Where geo runs

In a policy's checks, in this order:

1. IP lists: a denied client gets `403 ip-deny`; an allowed one is let through uninspected (geo
   isn't looked up, so a partner in a denied country can be let in this way).
2. **Geo.** In `Block`: `403 geo-deny`, also on the skipped paths. The rate limits don't count the
   request, and the rules don't run.
3. Skipped paths.
4. Rate limits.
5. The rules.

In `Detect`, the request goes on: if nothing else decides, the verdict is `log` with reason
`geo-deny`; if a rule matched, its reason wins (the metric still counts the geo match). On a
skipped path, `Detect` logs `geo-deny` rather than `skipped`, so it shows what `Block` would deny.
A request several policies inspect gets each policy's geo; the strictest verdict wins. Suspending
inspection (`InkwallConfig.spec.suspend`) suspends geo too.

## Before the country table arrives

- **No country table at all** (no database configured, or none compiled yet): geo is skipped,
  whatever the `failureMode`, and the policy says so: `Enforced=False`, reason
  `GeoDatabaseUnavailable`. Applying `spec.geo` before the database is set doesn't take the site
  down.
- **An engine without the table its bundle names** (it just started with no cache, and the operator
  is unreachable): geo follows the policy's `failureMode`. `Open` skips geo (counted as `no-table`);
  `Closed`, the default of a `Block` policy, answers `503` with reason `geo-unavailable`. A
  `Detect` geo always skips.

An engine waits for the table at startup within `--bootstrap-timeout` (10 s), as for its first
bundle, and caches it beside the bundle, so a restart has it. It never turns unready for the table
later. When a new database comes, an engine keeps enforcing with the previous table until the new
one arrives.

## Status

On the InkwallConfig, `GeoDatabaseReady` (only with `spec.geo`):

| Status | Reason | When |
|---|---|---|
| True | `Loaded` | Compiled and published; the message gives the type, build date, ranges and size |
| True | `Stale` | Loaded, but built more than 30 days ago: check the updater |
| False | `NotFound` | The file or the Secret key doesn't exist |
| False | `Invalid` | Not a valid MaxMind DB, or reading it failed or took more than a minute |
| False | `NoCountryData` | No record has `country.iso_code` |
| False | `TooLarge` | Over a bound: 256 MiB of file, 16 MiB from a Secret, a table of 32 MiB |

While it is `False` after a good load, engines keep the last good table. A source older than the
stored table (two replicas' `geoipupdate` copies, right after a leader change) isn't an error: the
stored table stays, and the condition stays `Loaded`. To go back to an older database on purpose,
delete the table's Secrets: `kubectl -n inkwall-system delete secret inkwall-geo`, and
`kubectl -n inkwall-system delete secret -l waf.inkwall.dev/bundle-chunk=inkwall-geo`.

`status.geo` gives the table's hash, database type, build time, ranges and size.

On a policy with `geo`, `Enforced` is `False` with `GeoDatabaseUnavailable` when the cluster has no
table, or while some engines that run the bundle hold none; `EnginesOutdated` when an engine is
older than 0.7.0, which ignores `geo`.
The policy gets a Warning Event when `Enforced` turns `GeoDatabaseUnavailable`.

Removing `spec.geo` from the InkwallConfig turns geo off: the next bundle names no table, the
policies with `geo` say `GeoDatabaseUnavailable`, and the operator deletes the table's Secrets once
that bundle is published.

To see the country the engines give an address, from the table the published bundle names:

```sh
inkwallctl geo lookup 198.51.100.7 2001:db8::1
```

It checks the table against the bundle's hash of it, but doesn't verify the bundle's signature: the
engines verify their own copy. `inkwallctl explain policy` shows a policy's `geo` in a line, and
`inkwallctl explain request` an event's country.

## Metrics, alerts and events

| Metric | Labels | Meaning |
|---|---|---|
| `inkwall_geo_denied_total` | `action`, `country` | Requests geo denied (`deny`) or would have (`log`) |
| `inkwall_geo_lookups_total` | `result` | Lookups: `country`, `private`, `unknown`, `no-table` |
| `inkwall_geo_table_bytes` | | The table's size in an engine's memory |
| `inkwall_geo_table_built_timestamp_seconds` | | The database's build time |
| `inkwall_geo_table_load_failures_total` | | Tables an engine refused |
| `inkwall_operator_geo_table_compressed_bytes` | | The table's size on the operator, compressed |

The alerts `InkwallGeoDatabaseStale` (the database was built more than 30 days ago, for an hour)
and `InkwallGeoClientIPPrivate` (more than half the lookups are private, for 15 minutes) come with
the chart's monitoring kit ([monitoring](monitoring.md)).

Every security event carries `country` when the engine holds a table: the code, `unknown`, or
empty for a private address. Geo's own events are sampled, so a denied country's flood doesn't push
other events out: the first per policy and country, then one a minute, with the count in
`sampled_count`. The metrics count every request.

## Personal data

An event's `country`, next to its `client_ip`, is personal data about the client. Events go to the
control plane when one is connected, and to your SIEMs when you export them: under some vendors'
terms (GeoLite2's among them), that may be sharing the database's data with a third party. Check
yours before connecting.

## Upgrading and rolling back

- Engines before 0.7.0 ignore `geo`: their policies are `EnginesOutdated`, and they get no table.
- Rolling the operator back below 0.7.0 drops geo silently: the older operator builds bundles
  without it. It leaves the `inkwall-geo` Secrets behind; delete them with the lines in
  [Status](#status). Roll the CRD back last: an older CRD drops `spec.geo` from policies written
  after that.
