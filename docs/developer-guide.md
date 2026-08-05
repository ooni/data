# Developer guide

How to work on this pipeline: getting a local environment, the common change
recipes, and the traps that have actually bitten.

Companion documents: [requirements.md](requirements.md),
[architecture.md](architecture.md),
[ontology.md](ontology.md), [user-guide.md](user-guide.md),
[implementation-plan.md](implementation-plan.md).
Bare ids like `O2` or `V2` cite requirements.md.

---

## 1. Repository layout

```
oonidata/                        library: measurement models + S3 client
  src/oonidata/models/
    nettests/                    per-nettest dataclasses (the wire format)
    observations.py              observation models (these ARE the DB schema)
  src/oonidata/dataclient.py     S3 access, measurement iteration

oonipipeline/                    the pipeline itself
  src/oonipipeline/
    transforms/                  measurement -> observation
      measurement_transformer.py shared machinery (the fiddly part)
      nettests/                  one transformer per nettest
      observations.py            NETTEST_TRANSFORMERS registry
    analysis/
      rules.py                   the scoring rule set (data, not SQL)
      web_analysis.py            the judgment query
      detector.py                CUSUM changepoint detection
      volume.py, time_inconsistencies.py   data-quality checks
    tasks/                       thin wrappers making the above schedulable
    db/create_tables.py          DDL; table models -> schema
    targets.py                   IM platform target registry
  tests/

dags/                            Airflow DAG definitions
docs/                            this documentation

ooni/backend/ooniapi/services/oonimeasuremen/   FastAPI read API: a separate
                                                 repo, deployed independently
```

**Where the schema lives:** for observation tables, the dataclasses in
`oonidata/models/observations.py` generate the DDL. For everything else, the DDL
is hand-written in `db/create_tables.py`. Both are emitted by
`make_create_queries()`.

---

## 2. Local setup

### Environment

```bash
cd oonipipeline && uv sync
```

### ClickHouse

Tests need a ClickHouse. The default path is docker-compose (via
`pytest-docker`, pinned to 25.2). If you do not have Docker, point the suite at
any running instance:

```bash
OONIPIPELINE_TEST_CLICKHOUSE_URL="clickhouse://test:test@127.0.0.1:19000/default" \
    .venv/bin/python -m pytest tests/
```

Without either, every database-backed test *skips* and the suite reports green
while covering none of the SQL. Check the skip count.

To run a server from a Homebrew ClickHouse:

```bash
clickhouse server --config-file=/path/to/config.xml
```

**On ClickHouse older than 25.x, append `?allow_experimental_analyzer=1` to the
URL.** The analysis query aliases an expression to the name of a column it reads
(`dns_answers_contain_bogon`), which the old analyzer rejects with "Different
expressions with the same alias". The compose fixture pins 25.2 where the new
analyzer is default, so this only appears against older local instances.

### Which tests need what

| Suite | Needs a DB | Runtime |
|---|---|---|
| `test_rules.py`, `test_dags.py`, `test_transforms.py`, `test_fingerprints.py` | no | seconds |
| `test_analysis.py`, `test_detector.py`, `test_db.py`, `test_e2e.py`, `test_updaters.py` | yes | minutes to ~40 min |

The offline suites are the fast feedback loop. Keep new logic testable there
where you can. Extracting the rules from SQL into data was motivated as much by
this as by anything else.

---

## 3. Common changes

### 3.1 Adding a scoring rule

Rules are data in `analysis/rules.py`. Add a `Rule` to `DNS_RULES`, `TCP_RULES`
or `TLS_RULES`:

```python
Rule(
    rule_id="descriptive_stable_name",
    condition="<SQL boolean over the analysis query's scope>",
    blocked=0.9, down=0.1, ok=0.0,
    comment="Why this evidence pattern means this.",
),
```

Then:

- **Position matters.** `multiIf` is first-match; a rule only fires when every
  rule above it did not. Adding a rule below `answer_unmatched` in `DNS_RULES`
  makes it unreachable. A test asserts that it stays last.
- **`rule_id` is a public contract.** It is persisted per measurement. Renaming
  one breaks historical rule-distribution analysis.
- **Do not change existing weights casually.** A weight change must be shown
  to be an improvement against the labelled corpus (V2): re-run the fit in
  [analysis-evaluation.ipynb](analysis-evaluation.ipynb) and ship the diff
  with the change. Prefer adding a more specific rule above a general one over
  retuning the general one.
- `pytest tests/test_rules.py` checks ids are unique, weights are in range,
  triples never sum above 1, and the outcome and rule-id cascades agree.

### 3.2 Adding a nettest transformer

1. Add the measurement model under `oonidata/models/nettests/`, register it in
   `SUPPORTED_CLASSES`.
2. Add a transformer under `transforms/nettests/`, register it in
   `NETTEST_TRANSFORMERS` (`transforms/observations.py`).
3. Build observations with `self.make_{dns,tcp,tls,http}_observations(...)` and
   combine with `self.consume_web_observations(...)`.
4. Add a fixture measurement and a test asserting the observation count.

If the nettest probes fixed named endpoints rather than a URL, also register
targets (§3.3).

**Do not split the input to `consume_web_observations` to get per-target rows.**
That call maps DNS/TCP/TLS/HTTP observations to each other by `transaction_id`
and `ip:port` across the whole measurement; splitting changes which rows get
merged, and therefore the row count. Tag afterwards instead. That is why
`assign_target_ids` mutates the returned list.

### 3.3 Adding a target

Add a `Target` to `TARGETS` in `oonipipeline/targets.py` and a hostname mapping
in `_EXACT` or `_PATTERNS`.

Key targets by **service role, not hostname**, and map historical and current
hostnames for the same service to one `target_id`. A target that changes
identity is indistinguishable from a blocking event to the detector.

Set `combination_rule` from the nettest's own spec logic: `any_of` for a
redundant pool, `all_of` for an independently required service.

A canary test fails when any observed endpoint resolves to no known target, so a
platform rename surfaces loudly rather than silently dropping rows.

### 3.4 Changing a table schema

For observation tables, edit the dataclass. For others, edit the DDL in
`db/create_tables.py`. Then:

1. `oonipipeline checkdb --print-diff` reports drift for the *model-generated*
   tables. It does *not* cover hand-written DDL, so check those manually. Both
   recorded schema incidents were in the uncovered half, so extending it is on
   the plan (§3.11); both halves already come from `make_create_queries()`.
2. **Write the migration to `docs/migration-notes.md`.** Live ClickHouse
   clusters are not migrated automatically. Include the check, the fix, the
   verification query, and the rollback.
3. If the table is written by a positional `INSERT .. SELECT`, see §4.1.

### 3.5 Labelling measurements for the corpus

The adjudication tool is [labeler.html](labeler.html): a self-contained page,
open it in a browser. The workflow it implements:

1. **Identify yourself.** Your name goes on every label, so disagreements stay
   attributable and inter-rater checks are possible.
2. **Draw a stratified sample.** The queue is drawn from production at fixed
   per-stratum rates: blocked-leaning rows heavily (`screen_positive`, 1 in 10),
   rows the pipeline calls clean lightly but never zero (`screen_negative`,
   1 in 5,000, which is the only bound on what the pipeline is *missing*), all
   exact fingerprint matches, and known incident windows (1 in 5). Every label
   carries a `sampling_weight` (how many production rows it stands for) and a
   `design_id` derived from the draw specification, which together keep
   production base rates recoverable from an incident-skewed sample.
3. **Adjudicate blinded.** The pipeline's verdict is sealed until you commit, and
   strata are interleaved and never displayed, so you cannot lean on what the
   thing you are evaluating already thinks. The reveal afterwards is how rule
   bugs get found.
4. **Label.** One of `blocked` / `down` / `ok` / `can't call it` / `unusable`,
   judged from what was available at measurement time only. A `blocked` call
   requires **one or more** mechanism paths from the taxonomy in
   [ontology.md](ontology.md) §12: censorship co-occurs (DNS injection next to
   SNI resets is a routine deployment), so each distinct technique the evidence
   supports gets its own path. Any prefix is valid, so specificity is never
   invented; redundant ancestor/descendant pairs collapse to the deeper path.
   Labels use the taxonomy rather than rule ids on purpose: rule-id labels can
   only show a rule reproduces itself, and they rot on every rule split.
   The panel is a stepped keyboard flow (verdict, mechanisms, confidence,
   rationale, commit), so a practised labeller never touches the mouse.
5. **Export.** Labels stay in the browser until exported as JSON, designs and
   weights included, so the draw is reconstructable by someone who was not
   there.

Downstream the labels become per-rule likelihood ratios, clustered per probe so
one chatty probe cannot inflate a rule's label count.

### 3.6 Adding a scheduled job

Add the logic under `analysis/`, a thin params-dataclass wrapper under `tasks/`,
and a `PythonVirtualenvOperator` in `dags/pipeline.py`. Follow the existing
`timestamp`/`ts` convention for window parameters.

---

## 4. Traps

### 4.1 Positional `INSERT .. SELECT`

`write_analysis_web_fuzzy_logic` does `INSERT INTO analysis_web_measurement
SELECT * FROM (...)`. Column *order* must match the table exactly. Add new
columns at the *end* of both the DDL and the projection, which is also where
`ALTER TABLE ADD COLUMN` puts them.

`tests/test_rules.py` asserts the projection's column count matches the table's,
which catches the common one-sided edit, but only for a freshly created table.
It cannot see a live schema that drifted, and it cannot see a same-arity
transposition of type-compatible columns, which would ship wrong per-layer rule
attribution with green tests. The class fix is a named-column insert, planned to
ride the next writer change (plan §3.9); until then, append-only discipline.

### 4.2 Airflow `op_kwargs` are unchecked

They are forwarded as keyword arguments, so a stale key is a `TypeError` at task
runtime, not at DAG parse time. This has shipped before. `tests/test_dags.py`
statically checks every `op_kwargs` key against its callable's signature.

### 4.3 The detector is stateful and path-dependent

`event_detector_cusums` accumulates across runs and cannot be recomputed for a
window in isolation. **Before backfilling, pause the live detector** by setting
the `enable_event_detector` Airflow Variable to `false`. Otherwise the live
task writes rows that deduplicate against your backfill and win.

Nothing enforces this: the invariant is held by the person remembering. That
is the class of safeguard O2 tolerates least: the failure is silent and the
state is not rebuildable from the archive, so O2's exception clause demands a
mechanism here, not a better ritual. The planned end state is stateless
windowed detection (plan §3.10), which removes the protocol rather than
hardening it; until then, treat any backfill as an alerting outage and say so
where alerts are watched.

```bash
CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml python -m oonipipeline.main \
    event-detector --clear-changepoints --truncate-cusums \
    --start-at 2025-01-01 --end-at 2026-01-01
```

### 4.4 `ReplacingMergeTree` deduplicates eventually

A `SELECT` can see both the old and new row until parts merge. Do not write and
immediately read back expecting deduplication. Use `FINAL` or an explicit
`OPTIMIZE` in tests.

### 4.5 Externally-owned reference data changes shape

Fingerprints, test lists and ASN metadata come from repositories we do not
control. The analysis query's fingerprint join is equality-only, implementing
`pattern_type = 'full'`; a new `prefix` or `regexp` DNS fingerprint would simply
never match, and the blockpage rule would silently stop firing for it.

`tests/test_fingerprints.py` fails loudly if upstream introduces a pattern type
the query cannot evaluate. **Follow this pattern for any externally-owned
data**: assert the assumptions your SQL makes, so a silent degradation becomes a
red test.

Also note `Fingerprint.expected_countries` and `.confidence_no_fp` are annotated
`List[str]` / `int` but load from CSV as `str`. And `confidence_no_fp` is a
0–10 self-assessment, not 0–100.

### 4.6 Observation data is not clean

`hostname` may be null (HTTP-only rows) or an IP literal (Telegram). PII
scrubbing can put the literal string `"scrubbed"` where an address belongs.
Handle both before treating either column as structured.

---

## 5. Testing philosophy

**Assert on generated SQL, not just on query results.** Query-formatting
functions return `(sql, params)`; asserting on the string catches structural
mistakes with no database and in milliseconds.

**When refactoring SQL, prove equivalence mechanically.** Extracting the rules
was verified by pulling the generated cascades apart and checking they emitted
the same tuple sequences in the same order as the hand-written originals, not
by reading the diff carefully.

**Check the data before fixing a data bug.** Three defects in the fingerprint
path turned out to be latent rather than active once the actual CSV was
inspected, and one proposed fix (`confidence_no_fp / 100`) would have been wrong
because the scale is 0–10. Cheap to check, expensive to get wrong.

**Verify a new test can fail.** A canary that cannot fire is worse than none.

---

## 6. Tradeoffs in the development model

### 6.1 Rules as data, SQL as generated output

**Buys:** the rule set is unit-testable with no database, reviewable as a table
in a pull request, and machine-readable, which is what allows persisting
`rule_id` and, later, learning weights.

**Costs:** the SQL you debug is not the SQL in the repository. When ClickHouse
reports an error at a character offset, you must generate the query to find it.
Mitigated by keeping the generator dumb: it does string interpolation and
nothing conditional. Committing the generated SQL, with a CI check that
regeneration is clean, would close the gap outright and is worth doing when the
query surface next changes.

**Requirements:** the extraction is what makes rule ids persistable and
weights learnable (E1, E6); the residual cost is developer experience, not a
traded requirement.

### 6.2 Wide fixture-driven transformer tests

Transformer tests assert exact observation counts (33 for Telegram, 137 for
WhatsApp, …) against real archived measurements.

**Buys:** they are precise, fast, offline, and they catch the merge-logic
regressions that matter most. The `target_id` work was validated almost entirely
by these counts staying identical.

**Costs:** brittle in an uninformative way, a legitimate improvement to the
merge logic breaks them with a number, not an explanation. Accept the churn;
the alternative is much weaker coverage of the most bug-prone code.

### 6.3 Database tests are slow and optional

The full suite takes ~40 minutes and skips silently without a database.

**Buys:** the SQL is exercised end to end against real measurements.

**Costs:** slow enough that people skip it, and the silent-skip behaviour means
a green run may mean nothing. The `OONIPIPELINE_TEST_CLICKHOUSE_URL` override
exists to lower the barrier; it fails loudly if set but unreachable, rather than
falling through to skips. The remaining fix is making the pinned-container suite
a *required* CI job, so a skipped-database run can no longer read as green.

**Requirements:** a suite that must be remembered to be meaningful is the
remembered class of safeguard O2 prices as weaker; the required CI job is the
mechanism that retires it.

### 6.4 Manual migrations

**Buys:** no migration framework, and every schema change is reviewed by a human
who understands ClickHouse's constraints, which matter more than usual, since
`ALTER` semantics differ substantially per table engine.

**Costs:** entirely dependent on discipline. A schema change without a
`docs/migration-notes.md` entry is a production incident waiting for the next
deploy. Treat the note as part of the change, not documentation of it.

**Requirements:** exactly the ritual O2 accepts (written, owned, and
checkable after the fact) and prices as weaker than a mechanism. The
migration note *is* the written procedure; extending `checkdb` to the
hand-written DDL (plan §3.11) is the mechanism that shrinks what the ritual
must carry.
