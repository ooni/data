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
ALTER TABLE analysis_web_measurement ON CLUSTER oonidata_cluster
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
ALTER TABLE analysis_web_measurement ON CLUSTER oonidata_cluster
    DROP COLUMN IF EXISTS `top_dns_rule_id`,
    DROP COLUMN IF EXISTS `top_tcp_rule_id`,
    DROP COLUMN IF EXISTS `top_tls_rule_id`;
```

## 3. Add `probe_id` columns

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
ALTER TABLE obs_web ON CLUSTER oonidata_cluster          ADD COLUMN IF NOT EXISTS `probe_id` FixedString(64);
ALTER TABLE obs_http_middlebox ON CLUSTER oonidata_cluster ADD COLUMN IF NOT EXISTS `probe_id` FixedString(64);

-- Judgment table. Order-sensitive: must be appended last, matching where it
-- sits in make_create_queries() and in the query's projection.
ALTER TABLE analysis_web_measurement ON CLUSTER oonidata_cluster ADD COLUMN IF NOT EXISTS `probe_id` FixedString(64);
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
ALTER TABLE obs_web  ON CLUSTER oonidata_cluster                DROP COLUMN IF EXISTS `probe_id`;
ALTER TABLE obs_http_middlebox ON CLUSTER oonidata_cluster      DROP COLUMN IF EXISTS `probe_id`;
ALTER TABLE analysis_web_measurement ON CLUSTER oonidata_cluster DROP COLUMN IF EXISTS `probe_id`;
```

## 4. Reprocess `top_*_rule_id` for the last 30 days

**Introduced by:** "Rank the top rule on evidence before score"

### Background

`top_*_rule_id` was `argMax(rule_id, blocked)`. On a measurement that is not
blocked the key is 0 on every row, so `argMax` kept whichever row it saw first.
Every web_connectivity measurement carries one row per resolved IP plus one per
redirect hop, and the redirect rows hold only HTTP, so they score `no_*_data`
and were winning that tie. The recorded values are wrong for a large share of
rows, skewed toward the `no_*_data` ids.

No DDL: the columns and their types are unchanged, only the expression filling
them. `analysis_web_measurement` is a `ReplacingMergeTree` keyed on
`(measurement_uid, measurement_start_time, probe_cc, probe_asn)`, so re-running
analysis over a window inserts replacements rather than editing in place.

### Before you start: make the rerun deterministic

Analysis is not a pure function of the measurement. Four things decide what a
rerun writes, and three of them have to be pinned by hand.

**1. The window must match the one that wrote the row.** `make_analysis` derives
its window from the timestamp it is given: `YYYY-MM-DDTHH` scores one hour,
`YYYY-MM-DD` scores twenty-four. That window is also the window the control
aggregates (`ctrl_dns_success_rate`, `ctrl_tls_success_rate` and the rest) are
computed over, so rescoring an hourly bucket as part of a daily one compares
each measurement against 24x more control data and moves the `blocked` scores
themselves — not just the rule id this migration is repairing.

Production writes hourly: `obs_web.bucket_date` reads `2026-08-03T12`, and the
hourly DAG is what fills it. **`oonipipeline run` cannot reproduce that over a
30-day range.** `build_timestamps` collapses whole days into daily buckets, so
`--start-at 2026-07-04 --end-at 2026-08-03` yields 30 daily buckets, and even an
hour-offset range only stays hourly at its two ends:

```
2026-07-04T00 -> 2026-08-03T00   30 buckets, all daily
2026-07-04T01 -> 2026-08-03T01   53 buckets, hourly at each end, daily between
```

Use the Airflow DAG instead, which runs one hour per task instance.

**2. Pause the event detector.** It reads `analysis_web_measurement` and its
state cannot be recomputed, so let it consume rows once, after they settle:

```
airflow variables set enable_event_detector false
```

The `gate_event_detector` ShortCircuitOperator in
`hourly_batch_measurement_processing` reads this. Restore it to `true` when the
backfill and the OPTIMIZE below have finished.

**3. Check the fingerprint table has not moved.** The analysis query joins
`fingerprints_dns` as it stands at run time, with no snapshot pinning, so a
rerun scores against today's corpus rather than the one in force when the row
was written. Only `country_consistent_blockpage` depends on it, but if the
corpus changed mid-window some DNS verdicts will legitimately differ from the
originals. Record the row count before starting so a later diff is explicable:

```sql
SELECT count() FROM fingerprints_dns;
```

Pinning this properly is the versioned-scoring-inputs work, still outstanding.

**4. `top_probe_analysis` and `top_*_failure` will churn regardless.** They are
`anyHeavy`, which is order-dependent: the same four rows in a different order
return a different answer when no value holds a majority. Expect these three
columns to differ after any rerun, on rows whose verdict did not change. Only
`top_*_rule_id` is deterministic today.

### Reprocess

Re-run analysis alone, one hour at a time. Observations are untouched.

Directly, from a host with ClickHouse access, is the faster route: 30 days is
720 hourly buckets, and the Airflow path builds a fresh virtualenv per task
instance at `max_active_tasks=2`.

```python
from datetime import datetime, timedelta
from oonipipeline.settings import config
from oonipipeline.tasks.analysis import MakeAnalysisParams, make_analysis

t, end = datetime(2026, 7, 4), datetime(2026, 8, 3)
while t < end:
    make_analysis(MakeAnalysisParams(
        clickhouse_url=config.clickhouse_url,
        probe_cc=[], test_name=["web_connectivity"],
        timestamp=t.strftime("%Y-%m-%dT%H"),   # hourly, matching production
    ))
    t += timedelta(hours=1)
```

Through Airflow instead, if you want the run recorded. This reruns existing DAG
runs only; the hourly DAG has `catchup=False`, so an hour it never ran will not
be created by a clear:

```bash
airflow tasks clear hourly_batch_measurement_processing --task-regex make_analysis --start-date 2026-07-04 --end-date 2026-08-03 --yes
```

Then collapse the duplicate rows. Until this runs, both the old and the new row
for each measurement are visible and every count below is inflated:

```sql
OPTIMIZE TABLE analysis_web_measurement PARTITION '202607' FINAL;
OPTIMIZE TABLE analysis_web_measurement PARTITION '202608' FINAL;
```

The partition key is `substring(measurement_uid, 1, 6)`, so a 30-day window
spans two partitions in most months. Confirm convergence:

```bash
oonipipeline check-duplicates --start-at 2026-07-04 --end-at 2026-08-03
```

For a single measurement, `write_analysis_web_fuzzy_logic` takes a
`measurement_uid` argument, which is the cheapest way to test the change before
committing to the range.

### Verify

`no_*_data` should now appear only where the measurement genuinely carried no
data at that layer:

```sql
SELECT top_tls_rule_id, count() AS n,
       countIf(greatest(tls_ok_max, tls_blocked_max, tls_down_max) > 0) AS with_verdict
FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 30 DAY
GROUP BY top_tls_rule_id ORDER BY n DESC;
```

Any `no_*_data` row with `with_verdict > 0` means a row carrying no data still
outranked one that did, so the evidence levels in `analysis/rules.py` are wrong.
Run it *after* the OPTIMIZE: before that, unmerged old rows still carry the old
values and the `no_*_data` share will look unchanged.

The verdicts themselves should be stable. If they are not, the cause is one of
the four items above rather than this change:

```sql
SELECT countIf(tls_blocked_max >= 0.5) AS blocked, count() AS total
FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 30 DAY;
```

### Rollback

Revert the code and reprocess again. Both versions write valid ids from the same
vocabulary, so a partially reprocessed range is inconsistent but not corrupt.
