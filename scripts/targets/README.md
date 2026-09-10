# Target registry seed

The initial `target_id` set for [docs/ontology.md](../../docs/ontology.md) §4,
built from `docs/uniq-hostnames.txt` (citizenlab test-list hostnames), the IM
nettest targets already in `oonipipeline/targets.py`, and the public-resolver
endpoints the dnscheck-style tests probe.

## Files

| File | What |
|---|---|
| `seed_targets.py` | Generator. Re-run after editing its curated blocks. |
| `schema.sql` | ClickHouse DDL for `targets` and `target_hostnames`. |
| `targets_seed.tsv` | ~1490 targets: id, service, role, combination_rule, category, description, source. |
| `target_hostnames_seed.tsv` | ~95 curated matcher rows: exact / pattern / ip / domain → target_id. |
| `public_suffix_list.dat` | PSL snapshot the eTLD+1 fallback uses (2026-08-17). |

## The identity rule

A `target_id` is either **`<service_slug>/<role>`** (curated:
`facebook/website`, `facebook/cdn`, `signal/chat`, `google_dns/resolver`) or a
bare **`<registrable-domain>`** (mechanical, meaning "role not yet curated").
A stamped id is resolved in order:

1. **exact** hostname row in `target_hostnames`
2. **pattern** row (regex), first match
3. **ip** row for IP-literal "hostnames"
4. **domain** row, longest-suffix match — this is what makes a curated
   service total over its namespace: an unseen `www2.facebook.com` still
   stamps `facebook/website` instead of diverging into the fallback. A suffix
   walk rather than a registrable-domain lookup, so `play.googleapis.com`
   reaches `google/api` even though the PSL private section makes it its own
   registrable domain
5. fallback: the hostname's **PSL registrable domain**, which is itself the
   `target_id` (e.g. `www.bbc.co.uk` → `bbc.co.uk`).

Only curated exceptions are stored as matcher rows; the fallback is computed
in code, so every observation gets a deterministic id even for hostnames the
registry has never seen, and curation can lag observation without leaving
nulls behind. The full PSL (including the private section) is used on
purpose: `ooni.github.io` is a distinct censorship subject from `github.io`.

The flagship services (Meta, Google/YouTube, Twitter/X, Wikipedia, Telegram,
Signal, WhatsApp, Proton, Tor, GitHub, Reddit, TikTok, the public resolvers)
get curated ids **at seed time** because that is when it is free: no series
exist yet. Promoting a bare domain to a `service/role` id later is a rename,
i.e. a series break the detector reads as a blocking event — so the long tail
deliberately stays mechanical until a domain earns deliberate promotion.
Curated ids are shared across nettests: a web_connectivity measurement of
`web.telegram.org` lands on the same `telegram/web` series as the telegram
nettest, and `edge-mqtt.facebook.com` on `facebook_messenger/edge` rather
than `facebook/website`.

## Loading

```sh
clickhouse-client -n < schema.sql
clickhouse-client -q "INSERT INTO targets (target_id, service, role, combination_rule, category_code, description, source) SELECT target_id, service, role, combination_rule, category_code, description, source FROM input('target_id String, service String, role String, combination_rule String, category_code String, description String, source String, n_hostnames UInt32') FORMAT TSVWithNames" < targets_seed.tsv
clickhouse-client -q "INSERT INTO target_hostnames (matcher_kind, matcher, target_id, source) FORMAT TSVWithNames" < target_hostnames_seed.tsv
```

## Enriching

Both tables are `ReplacingMergeTree(updated_at)`: to change a row, INSERT it
again with the same key; read with `FINAL`. Three kinds of enrichment, in
increasing order of care required:

- **Metadata** (`service`, `role`, `category_code`, `notes`, `metadata` map):
  edit freely, any time. Resolved at query time, never stamped.
- **New hostname mappings** pointing at an *existing* target (a new CDN
  hostname for `facebook/cdn`): also safe, but only affect observations
  generated after the workers reload the registry; older rows keep the
  mechanical id.
- **Renaming a `target_id`** — which includes promoting a bare domain into a
  new `service/role` id — is a series break the detector reads as a blocking
  event. Do it rarely and deliberately; deprecate and add, like rule ids.

Hostnames not yet in the registry surface via a census query worth running
periodically (inserting `source='census'` stub rows for enrichment):

```sql
INSERT INTO targets (target_id, source)
SELECT DISTINCT target_id, 'census'
FROM obs_web
WHERE target_id NOT IN (SELECT target_id FROM targets FINAL)
```

## Stamping in the observation workflow

`assign_target_ids` in `oonipipeline/targets.py` already mutates observations
after `consume_web_observations`. The intended evolution: a `TargetRegistry`
loaded from these tables at worker start (same lifecycle as `NetinfoDB` in
`tasks/observations.py`), applying the four-step resolution above to every web
observation, with the in-code eTLD+1 fallback guaranteeing totality. The
canary test in `tests/test_transforms.py` keeps failing loudly when a nettest
endpoint resolves to no curated target.
