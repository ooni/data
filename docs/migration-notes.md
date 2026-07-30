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

A deployment that ended up with the `URL` variant will keep working, the join
still resolves, but every query against it performs a live HTTPS fetch from
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

Expect `EmbeddedRocksDB` and a row count between 100 and 50,000, the updater
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
stay in sync, but only for a freshly created table. It cannot see a live
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
`answer_unmatched` to be a large share of non-zero `dns_blocked` rows, that
catch-all scores 0.75 blocked and is the main suspected false-positive source.
Confirming or refuting that is the point of the column.

### Rollback

The columns are additive and unused by the detector and the API. Reverting the
code without dropping them is safe: the old writer projects fewer columns than
the table has, which `INSERT .. SELECT` rejects, so roll back the DDL too if
reverting.

```sql
ALTER TABLE analysis_web_measurement
    DROP COLUMN IF EXISTS `top_dns_rule_id`,
    DROP COLUMN IF EXISTS `top_tcp_rule_id`,
    DROP COLUMN IF EXISTS `top_tls_rule_id`;
```

---

## 3. Drop `obs_web_ctrl_rollup` if it was ever created

**Introduced by:** "Revert the control baseline rollup"

### Background

An earlier step created `obs_web_ctrl_rollup`, a precomputed hourly control
baseline, along with a writer task in the hourly DAG and in the CLI `run` loop.
**That work has been reverted in full**: the table is no longer in
`make_create_queries()`, and nothing writes to or reads from it.

It was built to fix a determinism and cost problem in the inline control
derivation. Re-reading the generated SQL showed that problem did not exist:
both control subqueries bind the same `start_time`/`end_time` as the experiment,
so each run already scans exactly its own hour and re-running an hour reproduces
the same control. The real defect is that the window is too *narrow*, which is
being fixed in the rule set instead. See
[implementation-plan.md](implementation-plan.md) §3.3.

### Check whether it exists

The table was only ever created by an explicit run of the step below, or by
`checkdb --create-tables` while the reverted code was deployed. Many
deployments will never have had it.

```sql
EXISTS TABLE obs_web_ctrl_rollup;
```

### Fix

Nothing read the table, so dropping it loses only its own contents. Deploy the
revert **first**, so the DAG and CLI stop referencing the writer, then:

```sql
DROP TABLE IF EXISTS obs_web_ctrl_rollup;
```

If the reverted code is still deployed when you drop it, the hourly
`make_ctrl_rollup` task will fail on the missing table. Order matters.

### Verify

```sql
EXISTS TABLE obs_web_ctrl_rollup;   -- expect 0
```

Confirm the hourly DAG no longer has a `make_ctrl_rollup` task and that
`make_observations` runs straight into `make_analysis`.

### Rollback

To restore it, recover the implementation from commit `b02923b` and re-apply
the create and backfill it documented. Do that only with evidence that a wider
control window improves scoring, per
[implementation-plan.md](implementation-plan.md) §3.3.

---

## 4. Add `probe_id` columns

**Introduced by:** "Extract probe_id from measurements"

### Background

Measurements now carry a top-level `probe_id`: a pseudonymous probe identifier
issued via anonymous credentials, so repeated measurements from one probe can be
linked without identifying it. The pipeline extracts it onto every observation
(via `ProbeMeta`) and carries it through to `analysis_web_measurement`, which is
what lets consumers count distinct probes instead of using `uniq(report_id)` as
a proxy.

Every measurement collected before the scheme shipped omits the key. It
normalises to `''`, which means **unknown**, not "one probe". Queries must
exclude it: `uniqIf(probe_id, probe_id != '')`.

### Fix

Two independent changes. **Apply the `analysis_web_measurement` one before
deploying**, because that writer uses a positional `INSERT .. SELECT` and will
fail on a column-count mismatch.

```sql
-- Observation tables. Inserts name their columns, so these are not
-- order-sensitive and can be applied at any point.
ALTER TABLE obs_web            ADD COLUMN IF NOT EXISTS `probe_id` String;
ALTER TABLE obs_http_middlebox ADD COLUMN IF NOT EXISTS `probe_id` String;

-- Judgment table. Order-sensitive: must be appended last, matching where it
-- sits in make_create_queries() and in the query's projection.
ALTER TABLE analysis_web_measurement ADD COLUMN IF NOT EXISTS `probe_id` String;
```

`obs_web_ctrl` does **not** get the column. It records the test helper's view,
which has no probe, and `WebControlObservation` carries no `ProbeMeta`.

Note the generated DDL places `probe_id` inside the `ProbeMeta` block, in the
middle of the observation tables, while `ADD COLUMN` appends it at the end. That
divergence is harmless because observation inserts name their columns, but a
freshly created table and a migrated one will differ in column order.

### Verify

```sql
SELECT table, name, type FROM system.columns
WHERE database = currentDatabase() AND name = 'probe_id' ORDER BY table;
```

Expect `obs_web`, `obs_http_middlebox` and `analysis_web_measurement`. After the
next analysis run, coverage should start appearing on recent measurements only:

```sql
SELECT toStartOfDay(measurement_start_time) AS d,
       countIf(probe_id != '') AS with_id, count() AS total
FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 7 DAY
GROUP BY d ORDER BY d;
```

Old buckets are legitimately all-empty; only measurements collected after probes
began sending the field will populate it.

### Rollback

Revert the code first, then drop. Reverting the code without dropping leaves the
analysis writer projecting one column fewer than the table has, which
`INSERT .. SELECT` rejects.

```sql
ALTER TABLE obs_web                  DROP COLUMN IF EXISTS `probe_id`;
ALTER TABLE obs_http_middlebox       DROP COLUMN IF EXISTS `probe_id`;
ALTER TABLE analysis_web_measurement DROP COLUMN IF EXISTS `probe_id`;
```
