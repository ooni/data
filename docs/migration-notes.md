# Migration notes

Operations that must be run by hand against a live ClickHouse cluster, in
deploy order. Each entry names the commit that introduced it.

`oonipipeline checkdb --print-diff` reports schema drift for the table models
but does **not** cover the hand-written DDL in `make_create_queries()`, so the
steps below need to be checked manually.

---

## 1. Rebuild `fingerprints_dns` if it is still an `ENGINE = URL` table

**Introduced by:** "Use a single canonical definition for the fingerprint tables"

### Background

`fingerprints_dns` had two conflicting definitions:

- `db/create_tables.py` declared it `ENGINE = URL(...)` over the upstream CSV,
  with every column typed `String`.
- `tasks/updaters/fingerprints_updater.py` declared it `EmbeddedRocksDB` with
  typed enums for `scope` and `pattern_type` and `UInt8` for
  `confidence_no_fp`.

Both used `CREATE TABLE IF NOT EXISTS`, so whichever ran first on a given
deployment won, and the analysis query's join behaviour differed accordingly.
The `EmbeddedRocksDB` definition is now the only one.

A deployment that ended up with the `URL` variant will keep working — the join
still resolves — but every query against it performs a live HTTPS fetch from
raw.githubusercontent.com, and the untyped columns compare differently. It must
be rebuilt.

### Check which variant is deployed

```sql
SHOW CREATE TABLE fingerprints_dns;
```

If the output contains `ENGINE = URL(`, apply the fix. If it contains
`ENGINE = EmbeddedRocksDB`, nothing to do.

### Fix

The updater recreates and repopulates the table, so it is safe to drop. Run
during a window when no analysis job is executing, since the table is briefly
absent.

```sql
DROP TABLE IF EXISTS fingerprints_dns;
```

Then trigger the `update_fingerprints` task in the `updaters` DAG (or run
`update_fingerprints(clickhouse_url)` directly). Confirm:

```sql
SHOW CREATE TABLE fingerprints_dns;
SELECT count() FROM fingerprints_dns;
```

Expect `EmbeddedRocksDB` and a row count between 100 and 50,000 — the updater
asserts this range itself, so a failure there means the upstream CSV is
malformed and the old table should be left in place.

### Note on `fingerprints_http` (part of step 1)

`fingerprints_http` was never declared in `create_tables.py`, only in the
updater, so it has no conflicting variant. It is now also declared in
`make_create_queries()` for consistency; the DDL is identical to what the
updater already used (the `scope` enum keeps the two extra values `injb` and
`prov` that the HTTP fingerprint set uses), so `CREATE TABLE IF NOT EXISTS` is
a no-op on existing deployments.

---

## 2. Add the `top_*_rule_id` columns to `analysis_web_measurement`

**Introduced by:** "Extract the fuzzy-logic rule set into data and record which rule fired"

### Background

Rows now record which scoring rule produced their score, not only the score.
`write_analysis_web_fuzzy_logic` uses a positional `INSERT .. SELECT`, so the
new columns must exist on the table before the next analysis run or the insert
will fail with a column-count mismatch. **Apply this before deploying.**

### Fix

```sql
ALTER TABLE analysis_web_measurement
    ADD COLUMN IF NOT EXISTS `top_dns_rule_id` LowCardinality(String),
    ADD COLUMN IF NOT EXISTS `top_tcp_rule_id` LowCardinality(String),
    ADD COLUMN IF NOT EXISTS `top_tls_rule_id` LowCardinality(String);
```

`ADD COLUMN` appends, which matches where they sit in `make_create_queries()`
and in the query's projection. Do not insert them mid-table: the positional
insert relies on the order agreeing. `tests/test_rules.py` asserts the two
stay in sync, but only for a freshly created table — it cannot see a live
schema that drifted.

Existing rows backfill as `''`, which is distinguishable from the `'none'`
sentinel used when no rule matched.

### Verify

```sql
SELECT top_dns_rule_id, count() FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 1 DAY
GROUP BY top_dns_rule_id ORDER BY count() DESC;
```

This is the distribution that was previously unknowable. Expect
`answer_unmatched` to be a large share of non-zero `dns_blocked` rows — that
catch-all scores 0.75 blocked and is the main suspected false-positive source.
Confirming or refuting that is the point of the column.

### Rollback

The columns are additive and unused by the detector and the API. Reverting the
code without dropping them is safe: the old writer projects fewer columns than
the table has, which `INSERT .. SELECT` rejects — so roll back the DDL too if
reverting.

```sql
ALTER TABLE analysis_web_measurement
    DROP COLUMN IF EXISTS `top_dns_rule_id`,
    DROP COLUMN IF EXISTS `top_tcp_rule_id`,
    DROP COLUMN IF EXISTS `top_tls_rule_id`;
```
