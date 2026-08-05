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

## 4. Reprocess `top_*_rule_id`

**Introduced by:** "Rank the top rule on evidence before score"

### Background

`top_*_rule_id` was `argMax(rule_id, blocked)`. On a measurement that is not
blocked the key is 0 on every row, so `argMax` kept whichever row it saw first.
Every web_connectivity measurement carries one row per resolved IP plus one per
redirect hop, and the redirect rows hold only HTTP, so they score `no_tls_data`
and were winning that tie. The recorded values are wrong for a large share of
rows, skewed toward the `no_*_data` ids.

No DDL: the columns and their types are unchanged, only the expression filling
them. Nothing reads these columns yet, so the reprocess can run behind the live
pipeline.

### Verify

`no_*_data` should now appear only where the measurement had no data
at that layer:

```sql
SELECT top_tls_rule_id, count() AS n,
       countIf(greatest(tls_ok_max, tls_blocked_max, tls_down_max) > 0) AS with_verdict
FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 1 DAY
GROUP BY top_tls_rule_id ORDER BY n DESC;
```

Any `no_*_data` row with `with_verdict > 0` means a row carrying no data still
outranked one that did, so the evidence levels in `analysis/rules.py` are wrong.

### Rollback

Revert the code. Both versions write valid ids from the same vocabulary.

## 5. Reprocess after the per-endpoint trust change

**Introduced by:** "Gate TCP and TLS on the endpoint, not the DNS verdict"

### Background

DNS scoring was restricted to the system resolver and its window partitioned
without the resolver, so every DNS signal was constant across a measurement. A
row whose address came from another resolver inherited the system resolver's
verdict and was masked with it. `dns_untrusted` is replaced by
`endpoint_untrusted`, which additionally requires that nothing independent
vouches for the address.

No DDL. `RULES_VERSION` goes to 2, and the rule id changes, so rows written
before and after are distinguishable in `top_{dns,tcp,tls}_rule_id`.

### What to expect

Measured over a 10-minute production window (9,731 measurements), rescoring
with the new code against the old:

- **no change to any `*_blocked` score**
- 3 rule-id changes, all `tcp: endpoint_untrusted -> none`

That is the designed outcome: the new condition is strictly narrower than the
one it replaces, so it can only unmask rows, never mask new ones. It is close
to a no-op on today's data because no web_connectivity 0.5 measurements are in
the pipeline yet: every row still comes from the system resolver. The change
matters when 0.5 arrives, and it is safe to land first.

The 3 rows that moved to `none` expose a pre-existing gap rather than a new
one: the TCP cascade has no equivalent of DNS's `failure_no_ctrl`, so a TCP
failure against an endpoint with no control data matches nothing. It was
already reachable whenever `dns_blocked` was 0; it now also catches these.
`none` runs at 0.03% of measurements, so this is a cleanup, not a blocker.

### Reprocess

Same procedure as section 4, including the detector pause and the OPTIMIZE.
Because scores do not move, the detector will see no changepoints from this;
the reprocess is for rule-id attribution only and can run at low priority.

### Refit the calibration afterwards

`Calibration` in the API service's `scoring.py` was fitted against a corpus
scored under `RULES_VERSION = 1`. Scores are unchanged here, so the fit remains
valid and `SCORING_VERSION` does not strictly need to move, but check it
rather than assume: re-run the fit cell in `analysis-evaluation.ipynb` after
reprocessing and confirm INTERCEPT and SLOPE land inside their recorded
intervals. If they do not, the reprocess changed more than this note predicts.

### Verify

`dns_untrusted` should disappear entirely, and no row should carry a DNS
verdict it did not earn:

```sql
SELECT top_tcp_rule_id, top_tls_rule_id, count()
FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 1 DAY
  AND (top_tcp_rule_id = 'dns_untrusted' OR top_tls_rule_id = 'dns_untrusted')
GROUP BY 1, 2;
```

Expect zero rows once the range is fully reprocessed.

### Rollback

Revert the code and reprocess. Both rule sets write valid ids; a partially
reprocessed range carries a mix of `dns_untrusted` and `endpoint_untrusted`,
which is inconsistent but not corrupt, and the `RULES_VERSION` on each row says
which is which.
