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

---

## 3. Create `obs_web_ctrl_rollup` and backfill it

**Introduced by:** "Precompute the control baseline into an hourly rollup"

### Background

The analysis query derives its control by aggregating a full day of
`obs_web_ctrl` plus a second full-day scan of `obs_web`, on every hourly run.
That is ~24x redundant work, and it makes scoring depend on *when the job ran*:
the 01:00 run sees roughly an hour of control data and the 23:00 run sees
twenty-three, so `ctrl_dns_success_rate > 0.5` is a threshold over very
different sample sizes depending on time of day. Re-running a backfill
therefore produced different scores than the original run, and because
`analysis_web_measurement` is a `ReplacingMergeTree` keyed on
`measurement_uid`, the newer value silently won.

This step adds the rollup table and starts populating it. **The analysis query
does not read it yet** — that is a separate change, gated on comparing the two
paths on real data.

### Apply

The table is created by `make_create_queries()`, so
`oonipipeline checkdb --create-tables` (or the normal deploy path) will add it.
To create it by hand:

```sql
CREATE TABLE IF NOT EXISTS obs_web_ctrl_rollup
(
    `hostname` String,
    `ts_hour` DateTime('UTC'),
    `ip` String,
    `ip_asn` UInt32,
    `dns_success_count` UInt32,
    `dns_failure_count` UInt32,
    `tcp_success_count` UInt32,
    `tcp_failure_count` UInt32,
    `tls_success_count` UInt32,
    `tls_failure_count` UInt32,
    `tls_inconsistent_count` UInt32,
    `tls_consistent_probe_count` UInt32
)
ENGINE = ReplacingMergeTree
ORDER BY (hostname, ts_hour, ip, ip_asn)
PARTITION BY toYYYYMM(ts_hour)
SETTINGS index_granularity = 8192;
```

### Backfill

The rollup only covers windows that have been written. Before anything reads
it, backfill further back than the earliest window you intend to analyse by at
least `DEFAULT_CTRL_LOOKBACK` (see `analysis/ctrl_rollup.py` for the current
value) — a control window that starts before the rollup does will silently see
a partial baseline, which is the failure mode this change exists to remove.
Backfilling further than the minimum is cheap and harmless, so err wide.

Per-hour, via the task:

```bash
python -c "
from oonipipeline.tasks.ctrl_rollup import MakeCtrlRollupParams, make_ctrl_rollup
make_ctrl_rollup(MakeCtrlRollupParams(clickhouse_url='<URL>', timestamp='2026-07-27T13'))
"
```

`write_ctrl_rollup` is idempotent — one row per key per write into a
`ReplacingMergeTree` — so re-running a window replaces it rather than
accumulating. Re-running a backfill is safe.

### Verify

```sql
SELECT toDate(ts_hour) AS d, count() AS rows, uniqExact(hostname) AS hostnames
FROM obs_web_ctrl_rollup FINAL
GROUP BY d ORDER BY d DESC LIMIT 10;
```

Expect one row per (hostname, hour, ip). Query it with `FINAL`: replacement is
applied at merge time, so without it a re-run that has not merged yet is
counted twice.

### Rollback

Nothing reads the table yet, so dropping it only loses the backfill:

```sql
DROP TABLE IF EXISTS obs_web_ctrl_rollup;
```

Also revert the `make_ctrl_rollup` task from the hourly DAG and the CLI `run`
loop, or they will fail on the missing table.
