# Implementation plan

Where the pipeline currently stands, and what the next steps are. Each MVP
item names the requirements it serves (bare ids like `E3` cite
[requirements.md](requirements.md)), and §5 states this plan's tradeoffs as
requirement conflicts.

Companion documents: [requirements.md](requirements.md),
[architecture.md](architecture.md),
[ontology.md](ontology.md), [user-guide.md](user-guide.md),
[developer-guide.md](developer-guide.md). Live-cluster migrations are in
[migration-notes.md](migration-notes.md).

---

## 1. Current state

### Built and in production

- **Observation generation** for 13 nettests: `web_connectivity`, `dnscheck`,
  `signal`, `facebook_messenger`, `whatsapp`, `telegram`, `stunreachability`,
  `tor`, `browser_web`, `urlgetter`, `http_header_field_manipulation`,
  `http_invalid_request_line`, `echcheck`.
- **Judgment tier**: `analysis_web_measurement`, `(blocked, down, ok)` per
  DNS/TCP/TLS layer, with the driving rule id persisted.
- **CUSUM changepoint detection** with Slack alerting, gated by an Airflow
  Variable.
- **Data-quality checks**: measurement volume anomalies and clock
  inconsistencies, into `faulty_measurements`.
- **Read API**: FastAPI over observations and analysis.
- **Reference-data updaters**: fingerprints, citizenlab test lists, ASN
  metadata.

### Recently landed

| Commit | Change |
|---|---|
| `11ad937` | Rules extracted from SQL into data (`analysis/rules.py`); `top_{dns,tcp,tls}_rule_id` persisted per measurement. |
| `5f2e704` | IM observations tagged with `target_id`; target registry with `any_of`/`all_of` semantics; drift canary. |
| `12ef656` | `probe_id` extracted end to end: the pseudonymous identifier from OONI's anonymous-credential system, on every observation and analysis row. |
| `84ef8b4` | DNS fingerprint join hardened (multi-country `expected_countries`, `fp` scope gate, `full`-only limitation made explicit, canary test). |
| `7cc188a`, `e6fd4a4`, `4bf2c6c` | One canonical fingerprint DDL; daily-DAG `op_kwargs` fix with a static test; non-Docker test override. |
| `a40fc49` | Control-baseline rollup removed: the inline control is already deterministic, and the real defect (no control vs contrary control) is a rules fix, §3.3. |
| `c555f55`, `62ecf86` | The API's `Calibration` reads the fitted likelihood-ratio table; what-if promotion analysis driven from it, with the deployed threshold read from the service. |
| `5247450`, `d61668f` | Event label grain shipped: editor, incident import, replay harness (`event_eval.py`, `oonipipeline event-eval`), hourly timeseries for setting onset brackets. |
| `57b977c` | TCP/TLS gated on the endpoint rather than the DNS verdict (`endpoint_untrusted`, `RULES_VERSION` 2; migration-notes §5). |
| `74df178`, `fba816d` | Evaluation-notebook fixes; a second adjudicator's measurement labels landed. |

Test state: 111 passed, 2 failed, 2 skipped. Both failures
(`test_e2e.py::test_volume_analysis`,
`test_e2e.py::test_time_inconsistencies_analysis`) predate this work and are
tracked separately; note they are the only tests covering the data-quality jobs.

Both labelling tools are built: [labeler.html](labeler.html) (workflow in
[developer-guide.md](developer-guide.md) §3.5) and
[event-labeler.html](event-labeler.html)
([label-corpus-design.md](label-corpus-design.md)). The first draws exist
under [labels/](labels/): measurement labels from two adjudicators plus an
imported event-label draft. The corpus is still far from the volume targets in
label-corpus-design.md §2.5, and until §3.9 persists the fired-rule sets, the
likelihood-ratio fits remain winner-censored.

### Known gaps

| Gap | Consequence | Violates |
|---|---|---|
| No HTTP layer in the analysis | HTTP blockpage detection, the classic "confirmed" signal, is absent. `fingerprints_http` is refreshed and joined nowhere. | M3, M1 |
| No tier-3 state table | The detector aggregates tier 2 inline with a median, discarding measurement counts. | E5, E2 |
| No `locus` axis | Resolver-side DNS censorship is attributed to `probe_asn` instead of `resolver_asn`, naming the wrong responsible party and making series flip as probes rotate resolvers. | E7, D1 |
| Target is `domain(input)` only | No way to ask "is Facebook blocked?" without assembling a union of domains by hand. | M1 |
| No event entity | A national block emits up to ~1800 uncorrelated changepoints and an unbatched Slack flood. | M4, D4 |
| Only web_connectivity is analysed | All 13 nettests write observations; the analysis keys on the URL's domain, which the IM tests do not have. | M1 |
| Corpus thin, fits winner-censored | First labels are drawn (two adjudicators) and the LR fit runs, but volume is far below the targets that make per-rule LRs informative, and only the *winning* rule is persisted, so fits are conditional on cascade position. | V1, V2 |
| Detector watchlist is narrow | Citizenlab global `GRP` plus `twitter.com`; country-specific news blocking is structurally invisible. | priority 5, D1 |
| `resolver_transport` unused | `dns_engine IN ('getaddrinfo','system')` excludes DoT/DoH/UDP answers from the answer set, so `dnscheck`'s central comparison is dropped. | E1, M1 |
| ~28 spec nettests have no transformer | Notably `openvpn`, actively collected with no analysis path at all. | M1 |
| Reference data is unversioned | Fingerprints and test lists join as of run time; no verdict names the corpus state that produced it, and a rebuild cannot reproduce old output for validation. | P3, A5 |
| Alerts are not reconstructible | Changepoints reference no measurement set, tier-2 rows mutate under them, and the recovery procedure regenerates history under current code. | P5, P4 |
| Late data never reaches detection | The daily DAG has no detector task; the CUSUM never revisits a closed hour. Late uploads correlate with censored networks (C7). | D2 |
| Volume collapse is silent | An empty hour produces no signal, so a shutdown quiets the detector instead of alarming it. | D2 |
| Control admits probe assertions | TLS-consistency trusts a submitter-written boolean; one fabricated row can change every probe's scoring for a hostname. | A4, A2 |
| Data-quality tier is a dead end | The volume and clock checks read the v4 `fastpath` table, and nothing consumes `faulty_measurements`. | E4, O5 |
| No production health signals | Canaries run in CI while the guarded data refreshes hourly; the Slack sink has no delivery monitoring. | O3 |
| Detection record not backed up | Single node; the detector tables are the only state not rebuildable from S3. | P1, O5 |
| Throttling not representable | Timing and volume fields (`tls_handshake_time`, read counts) land in observations, but no vocabulary state or signal reads them; "is this throttled?" cannot be asked. | M7 |

---

## 2. Scope

The plan is deliberately narrow. Richer machinery (Dempster-Shafer verdicts, a
full locus taxonomy, a materialised state tier, a target hierarchy) is recorded
in [ontology.md](ontology.md) Appendix A with the trigger that would revive
each; the rule registry already carries most of the distinctions that machinery
would re-derive (§6.1 there).

| Problem | Addressed by |
|---|---|
| Missing control read as contrary evidence | 3.3 (`answer_no_ctrl`) |
| False positives | 3.1 (quantify `answer_unmatched`), 3.2 (validity) |
| Missing capability | 3.4 (HTTP layer) |
| Alert noise and instability | 3.5 (series key), 3.6 (cell state) |
| Alert volume | 3.7 (events) |
| Unmeasurable changes | 3.8 (corpus and evaluation harness) |
| Poisonable control set | 3.13 (verified control membership) |
| Provenance and reproducibility | 3.9 (versioned scoring inputs) |
| Unreconstructible alerts, late data, backfill hazard | 3.10 (stateless detection) |
| Silent degradation in production | 3.11 (health checks) |

Roughly eight to ten weeks. Everything else is §4.

---

## 3. MVP

Ordered so cheap work that makes later work measurable comes first. Each item is
independently shippable.

### 3.1 Quantify and fix `answer_unmatched`

Any DNS answer matching nothing in the control scores `0.75` blocked. It fires
for legitimately rotating CDN and geo-DNS answers, and is the prime
false-positive suspect.

**This is measurable today**, since `top_dns_rule_id` shipped in `11ad937`:

```sql
SELECT top_dns_rule_id, count() AS n, countIf(dns_blocked > 0.5) AS scored_blocked
FROM analysis_web_measurement
WHERE measurement_start_time > now() - INTERVAL 7 DAY
GROUP BY top_dns_rule_id ORDER BY n DESC;
```

If it dominates `dns_blocked > 0.5`, do 3.3 first and measure again: much of it
is likely to be absent control rather than contrary evidence. Whatever remains
is then split by whether the answer's ASN is plausible for the target, rather
than by lowering the constant blindly.

**Effort:** days. **Depends on:** nothing to measure; 3.3 to interpret.
**Serves:** E4, V2.

### 3.2 Measurement validity

Instrumentation defects currently score as blocking. Reference case in
[ontology.md](ontology.md) §10.

1. **Probe-attribute confound check.** For `(target, layer, failure)`, compare
   how it partitions by `software_version` / `engine_version` / `platform`
   against `probe_asn` / `probe_cc`. Wide network spread with narrow version
   spread is an instrumentation defect. Needs no curation. **Effort:** M.
2. **Corroboration gate on `ssl_` failures.** They earn 0.9; require the failure
   across more than one software version, else cap lower. Changes weights, so
   validate against 3.8 rather than by eye. **Effort:** S.
3. **Known-defect registry** extending `faulty_measurements`, curated by
   investigation. **Effort:** S per entry.

**Serves:** E4, and O5's no-dead-ends rule: the registry only counts once
scoring or publication actually consumes it.

### 3.3 Distinguish "no control" from "control disagrees"

`answer_unmatched` fires when `dns_answer_matches_ctrl = 0`, which is true both
when the control returned **different** addresses and when there is **no
control at all** for that hostname. Those are opposite evidence states, scored
identically at 0.75 blocked.

The control window is the analysis window, one hour: both control subqueries in
`web_analysis.py` bind the same `start_time`/`end_time` as the experiment. So a
hostname the test helper did not happen to resolve in that hour has no control
rows, the `LEFT JOIN` misses, and every answer for it scores 0.75 blocked. This
is the most likely reason `answer_unmatched` dominates.

The failure branch already handles this correctly, which is what makes the fix
obvious: on a join miss `ctrl_dns_success_rate` is `0/0`, so both
`failure_ctrl_ok` and `failure_ctrl_also_failing` fail their comparisons and it
falls through to `failure_no_ctrl` at `(0.5, 0.5, 0)`. The answer branch has no
equivalent.

**Fix:** add `answer_no_ctrl` immediately above `answer_unmatched`, conditioned
on `ctrl_dns_success_count + ctrl_dns_failure_count = 0`, scored as the
`(0, 0, 0)` mask. Roughly ten lines in `analysis/rules.py`.

Then re-measure 3.1: `top_dns_rule_id` shows directly how much of
`answer_unmatched` was really "we had nothing to compare against".

**Effort:** hours. Pure rules change, offline-testable, no migration, no new
table. **Serves:** E3, E4: absence of evidence must mask, not accuse.

**Note:** a separate one-line edge case sits nearby. `measurement_day` is
`toStartOfDay(measurement_start_time)` computed independently on both sides of
the join, so a measurement at exactly midnight joins against control rows from
the following day and finds none. Narrow, but free to fix while in there.

### 3.4 HTTP layer

`http_failure` is selected in the analysis query and never used. There is no
`http_blocked/down/ok`, and `fingerprints_http` is refreshed hourly and joined
nowhere. This is the largest capability gap: HTTP blockpage detection is the
classic `confirmed` signal and the engine cannot currently reproduce it.

1. Add the columns and an `http_outcome` rule set, mirroring the TLS cascade's
   gating so a blocked DNS or TCP verdict masks HTTP.
2. Join `fingerprints_http` on `location_found` against
   `http_response_header_location` / `_server` / `http_response_status_code`.
3. **Body fingerprints need a decision.** `obs_web` stores only
   `http_response_body_sha1` and length, so the majority of fingerprints (1414
   `contains`, 275 `prefix`) cannot be evaluated in ClickHouse. Match at
   observation time using the existing `FingerprintDB.match_http` and persist
   the matches. Those columns existed as `pp_http_*` before v5.0.0-alpha.1.

Note the HTTP fingerprint set uses `prefix`/`contains`/`regexp` patterns and
`fp` scope, so the robustness work in `84ef8b4` is a prerequisite rather than a
tidy-up.

**Effort:** weeks. **Depends on 3.8** for the weights (V2). **Serves:** M3,
M1.

### 3.5 Composite series key for DNS

Keying DNS series on `probe_asn` alone makes a series flip between blocked and
unblocked as probes in one network rotate between resolvers, which is a large
source of detector noise. Key DNS series on the composite
`(probe_cc, probe_asn, resolver_asn)` instead.

Deliberately **not** a substitution of the resolver's AS for the network key.
On-path injection, the dominant national-scale DNS technique, answers for
whatever resolver was addressed, so substitution would attribute a middlebox in
the probe's country to Google or Cloudflare. The composite key stabilises
series without deciding attribution; naming the resolver's AS as responsible
additionally requires evidence the same resolver misbehaves for probes in other
networks, which is future work ([ontology.md](ontology.md) §11).

**Effort:** days. **Serves:** D1, E7. **Note:** the `dns_isp.*` / `dns_other.*`
labels the aggregation API returns need a mapping, since they have no direct
successor (M6: deprecate by mapping, never silently).

### 3.6 Cell state as a rule histogram

Replace the detector's inline `quantile(0.5)` with a per-cell, per-layer rule
histogram (canonical query in [architecture.md](architecture.md) §3.1; semantics
in [ontology.md](ontology.md) §9). Consensus, sample size and ambiguity all fall
out of it, no new formalism required. The specifics that matter:

- **Per layer**, the verdict is the dominant **outcome class**, not the dominant
  rule id: the vocabulary is fine-grained on the blocked side, so a raw-id mode
  splits the blocked vote. All three layers' histograms are carried, since the
  detector needs `tcp_blocked` and `tls_blocked` too.
- **Masked rows are excluded** from detector signals, or DNS-blocking onset
  reads as TCP/TLS *unblocking*.
- Carry `n_probes` (`uniqIf(probe_id, probe_id != '')`), `n_sessions`,
  `n_measurements` and `uniq(resolver_asn)`; weight detection by established
  credentialed probes (A3): identities are cheap to mint, but the attested
  age and history that make a probe *established* are not.
- Carry an arrival-lag column (derivable from `bucket_date`) so "few
  measurements existed" and "few had arrived yet" stop being the same cell.
- **The evidence floor applies to alerting**: no changepoint from a series whose
  cells would all render "not enough data".

Build as a view first; if materialised later, a scheduled rebuild per closed
window, never an insert-time materialized view (architecture §3.1 says why).

**Effort:** days. **Depends on:** 3.5 for the grain. **Serves:** E5, E2, D4;
the arrival-lag column is D2's minimum form.

### 3.7 Correlate changepoints into events

Cluster changepoints within a time window by `(cc, target)` and `(cc, asn)`
before alerting, with `n_asns`, `n_domains`, `layers`, `first_ts` and a
severity. Alert on events; cap volume per run, and record what the cap dropped.

Semantics that must be specified up front, not discovered in code review:
clusters are per direction (a mixed +1/-1 cluster during ISP-by-ISP rollout is
two events, not one); events can extend as they roll out across ISPs over days;
and when the two cluster keys disagree, the larger event subsumes the smaller.
Build the interface as **events subsume their member changepoints**, so richer
detection can replace the internals later without a schema change.

Cross-ASN agreement is a filter, not a guarantee: the pipeline's own false
positives (CDN reconfigurations, probe-release defects, fingerprint and rule
deploys) are common-cause and present with exactly the same simultaneity. Before
grading an event by ASN spread, check the contrast the data already holds: did
the same target move in *other* countries in the same hour, and did the control
degrade too? Carrying the ruleset and fingerprint-snapshot versions (3.9) on
analysis rows is what makes a deploy distinguishable from a coordinated block.

**Effort:** a week. **Serves:** M4, D4, D5. **Do before** widening the
detector watchlist, or the noise gets worse. Note the watchlist itself needs
review: the hardcoded `twitter.com` predates the rename to x.com (D1).

### 3.8 Labelled corpus and evaluation harness

The yardstick every scoring and detection change is measured against. Two label
grains, curated in one pass:

**Per-measurement labels**, produced with the adjudication tool
([labeler.html](labeler.html); workflow in
[developer-guide.md](developer-guide.md) §3.5). The design decisions that make
the corpus a valid yardstick are built into the tool:

- **A stratified draw with an explicit negative class.** Blocked-leaning rows
  are sampled heavily, but clean-scoring production rows are drawn too (1 in
  5,000): they are the only bound on what the pipeline is *missing*, and the
  honest denominator for false-positive rates. Weights and a derived `design_id`
  keep production base rates recoverable from the incident-skewed sample.
- **Blinded adjudication.** The pipeline's verdict is sealed until the label is
  committed, so the corpus measures the pipeline rather than echoing it.
- **Labels use the mechanism taxonomy, not rule ids**
  ([ontology.md](ontology.md) §12): any prefix of a taxonomy path is a valid
  label, scoring is hierarchical, and the corpus survives rule splits. Rule-id
  labels could only show a rule reproduces itself.
- **Per-probe clustering.** Label counts are deduplicated by `probe_id` (or
  `report_id` for pre-credential rows) when fitting, so one chatty probe cannot
  inflate a rule's evidence.

What the labels become: **per-rule likelihood ratios**, not posteriors. The
corpus oversamples positives by construction, so `P(blocked | rule)` is not
estimable from it; the likelihood ratio is invariant to the sampling rate and is
the forensic reporting standard. "This evidence pattern is 40x more likely under
blocking than not, per corpus vN" replaces "0.9 means the author felt strongly".

**Per-event labels**: implemented end to end, comprising the editor
([event-labeler.html](event-labeler.html)), the incident import, and the
replay harness (`event_eval.py`, `oonipipeline event-eval`) that reconstructs
cell state and reports event recall, detection latency, false alerts per
quiet series-week, and alerts per true event. The record itself is specified
in [label-corpus-design.md](label-corpus-design.md) §1.2: scope with explicit
unknowns, onset and resolution as intervals, mechanisms from the same
taxonomy, `true_event` vs `false_positive_event`, and `scoreable` to keep
recall honest. What remains is curation toward the 50–150 row target. Without
that corpus, 3.5, 3.6 and 3.7 change what alerts fire with no measurement,
which is the same mistake as shipping weight changes without labels.

**Effort:** the tooling is built; what remains is curation volume. Nothing
that alters weights (3.2's gate, 3.4's rule set) lands without the
per-measurement half; no detector change lands without the per-event half
(V2). **Serves:** V1, V2, V3, E6.

### 3.9 Versioned scoring inputs

Scoring is a function of the rules, the reference data and the window; today
only the window is pinned. Fingerprints and test lists join as of run time,
and no verdict can name the corpus state that produced it. Re-scoring history
against *newer* fingerprints is desirable: a blockpage discovered today
should fire on last year's measurements, but it must be a visible, named
operation, with the old inputs still resolvable so any past output can be
reproduced for validation (P3, P4). Today it is neither: it happens silently
on every rebuild, and nothing records what the original run saw.

- Updaters record the fetched commit SHA and append content-hashed snapshots to
  small history tables (the corpora are 100 to 50k rows; history backfills from
  upstream git for free).
- Analysis resolves the snapshot as of the *window*, not the run, and persists
  `ruleset_version` and `fp_snapshot` on every row.
- A CI test replays a fixture window twice with pinned inputs and asserts
  identical output, so newly introduced nondeterminism becomes a red test
  rather than an aspiration.

While touching the writer, two riders that are much cheaper together: switch
the positional `INSERT .. SELECT` to **named columns** (removing the
transposition trap outright), and persist the **full fired-rule set** per layer
(`{layer}_rules_fired`, every condition that holds rather than only the first
match). The fired set is what makes recalibration an actual join (a rule split
or reorder currently orphans history), removes winner-censoring from any future
calibration, and quantifies how often corroborating rules co-fire, which is the
measurement the deferred log-odds combiner is gated on.

**Effort:** about a week. **Do before** 3.8 curation starts and before 3.1's
rule split, or both are confounded by cascade position. **Serves:** P2, P3,
E1, A5.

### 3.10 Stateless detection and an append-only alert log

Detection state is the one tier that cannot be recomputed, and everything
painful about operating it follows: the pause-before-backfill protocol held by
memory, alerts that cannot be reconstructed after re-analysis, late
measurements silently bypassing a forward-only accumulator.

Redefine detection as a pure function over a trailing window of cell state
(3.6): recompute per closed hour over the last W days, emit changepoints as
idempotent upserts keyed `(series, signal, cp_hour)`, and only alert on keys
not seen before, recorded in an **append-only alert log** with
`first_detected_at` and the window bounds consumed. Only series with new rows
since the last run need re-evaluating.

What this buys: backfills stop interacting with live detection at all; every
alert is reproducible on demand; late-arriving data is absorbed on the next run
instead of never; and the detector finally meets the same determinism standard
as every other tier. The alert log is load-bearing, not a nicety: it is the
durable record of what was detected when, surviving re-analysis, and the
detection tables become disposable like every other tier. One doctrine must be
written before cutover: what a changepoint near the trailing edge shifting or
vanishing means for an already-sent alert.

Migrate by running shadow alongside the live CUSUM for a few weeks and
comparing emitted changepoints.

**Effort:** 2 to 3 weeks, riding 3.6/3.7 (which rewrite the detector's input
and output anyway). Preserving the stateful accumulator through that rewrite
would entrench the one component that violates the determinism principle.
**Serves:** P5, O4, D2, and it retires the O2-exception hazard documented in
[developer-guide.md](developer-guide.md) §4.3.

### 3.11 Production health checks

The canary tests guard upstream data assumptions at CI time, while the guarded
data refreshes in production every 30 to 60 minutes. Run the same assertions as
a scheduled job writing to a metric: fingerprint join match rate, rule-firing
distribution drift, updater staleness, DAG failure alerting, and a liveness
check on the Slack sink itself (today "no events" and "no delivery" are
indistinguishable). Extend `checkdb` to the hand-written DDL, including an
assertion that `fingerprints_dns` is `EmbeddedRocksDB` and not the legacy
live-URL engine.

Cheapest useful form of a second opinion: a weekly digest comparing a
judgment-free failure-rate signal computed straight from `obs_web` against
tier-2 detection, with a named owner. A raw shift with no judgment-tier
detection is a scoring blind spot; a judgment-tier detection with no raw
support is a rule or fingerprint defect. This is also the only interim signal
for the paths scoring does not cover yet (HTTP, the unanalysed nettests).

**Effort:** days for the checks; the digest needs an owner more than it needs
code (O1). **Serves:** O3, A5, D2 (the sink liveness check).

### 3.12 Carry web_connectivity 0.5's structural tags into observations

Scoring now gates on the address rather than the measurement, so 0.5's
multi-resolver endpoints are analysable ([ontology.md](ontology.md) §6.2). What
is still dropped is the structure the spec attaches to each operation:
`obs_web` has no `classic`, `depth` or `fetch_body` column, and
`transaction_id` is NULL on every row in production.

Each matters for a different reason:

- **`fetch_body=false`** marks the extra TLS handshakes 0.5 performs on
  `http://` URLs purely to check whether resolved addresses are valid
  (extension E001). Those are address-validation probes, not statements about
  whether a user could reach the site. Feeding them into `tls_blocked` would
  manufacture TLS blocking on plain-HTTP targets. They are, however, exactly
  the evidence `ip_trusted` wants, which is what E001 exists to produce, so
  the tag is what lets us use them for one purpose and not the other.
- **`depth=N`** separates the requested URL from redirect targets. Today a
  redirect chain flattens: a measurement of `https://www.4chan.org/` that
  redirects to `4chan.org` yields HTTP-only rows for both hostnames with
  nothing recording which came first, so blocking of the target and blocking of
  a redirect hop are indistinguishable.
- **`classic`** marks what the probe's own `blocking`/`accessible` keys were
  computed from, which is what makes `probe_analysis` comparable to pipeline
  output rather than merely adjacent to it.
- **`transaction_id`** is the spec's intended join key: one per DNS lookup, one
  per endpoint per redirect depth. `consume_web_observations` already prefers
  it and falls back to matching on IP, but since it is universally NULL the
  fallback is all that runs. Under 0.5 that fallback becomes actively wrong:
  several resolvers can return the same address, and the TCP observation goes
  to whichever DNS observation reaches it first: order-dependent, the same
  class of defect as the pre-`Evidence` `argMax`.

Additive: new columns and a transformer change, no rescoring of existing rows.
Worth doing before 0.5 measurements arrive in volume, since rows written
without the tags cannot be repaired without reprocessing observations.

**Effort:** days. **Serves:** E1, E4. **Note:** no 0.5 measurements are
reaching the pipeline yet (production is 0.0.1 through 0.4.3 and `dns_engine`
is always `system`), so this is not yet urgent, but it is a precondition for
0.5 being analysable rather than merely ingested.

### 3.13 Verified control membership

The TLS-consistency control admits any address on which *any* probe asserted a
valid handshake: a submitter-written boolean, never revalidated centrally
([ontology.md](ontology.md) §5). A poisoned entry rewrites the scoring of
every other probe's measurements of that hostname, which is why A4 gives
controls the strictest admission standard in the system.

1. **Admission floor.** An address counts as TLS-consistent only when asserted
   by at least k distinct established credentialed probes
   (`uniqIf(probe_id, …)` weighted by attested standing, A3), from more than
   one network where coverage allows. Pre-credential history cannot meet the
   floor; scoring it keeps the current behaviour, and the A2 caveat prices the
   residual exposure.
2. **Address sanity.** Geolocation and anycast checks on the asserted address:
   an anycast answer that "validates" from one vantage point, or an address
   whose location is implausible for the target, is exactly the case the floor
   exists to catch.
3. **Central revalidation** is the durable fix, blocked on a storage decision:
   `peer_certificates` is currently decoded, used and discarded
   ([ontology.md](ontology.md) Appendix A.5 records the trigger).

**Effort:** days for the floor and sanity checks; revalidation waits on the
certificate-storage decision. **Serves:** A4, A2.

---

## 4. Later

Not scheduled. Each is either lower value per unit effort than the above, or
blocked on it.

| Item | Why deferred, and what would revive it |
|---|---|
| Per-rule likelihood-ratio calibration (E6) | Underway rather than deferred: the fit lives in [analysis-evaluation.ipynb](analysis-evaluation.ipynb) and the API's `Calibration` reads its output (migration-notes §5). Full promotion needs 3.9's fired sets, or the LRs stay conditional on "fired **and won**", a cascade-position-dependent quantity. |
| Run-versioned, append-only judgment tier (P4) | Score history under a candidate ruleset as a named run, diff against production, promote atomically. Revive at the first corpus-driven reweight, which otherwise overwrites published history. |
| Log-odds rule combination | The cascade discards corroboration by design. Revive only if 3.9's fired sets show co-firing is common (>10-20% of blocked-leaning rows); otherwise calibrated LRs on the cascade capture most of the value. |
| Corpus-fitted presentation thresholds (E6, V2) | Replace the provisional state cutoffs with quantiles fitted on the corpus, published as "error rates on the calibration corpus", never as guarantees. After 3.8. |
| Shrinkage for thin cells (E5) | Dirichlet smoothing toward the parent grain, artefact-backed rules exempt. After 3.6; winner's-curse bias on modal shares is the trigger. |
| Two-level (country + ASN) detection (M4) | Weak simultaneous shifts across many ASNs stay under per-series thresholds, so 3.7 has nothing to cluster precisely in low-probe countries. Revive when the 3.8 event harness shows missed national events; phase 1 is one extra pooled series. |
| Detector-statistic bake-off (V2) | 3.10 fixes the execution model, not the statistic. Candidate statistics (windowed CUSUM, beta-binomial rate comparison, regime models) compete on 3.8's event scorecard. Revive when the scorecard shows the incumbent missing adjudicated events or paging on quiet series. |
| Event-time lateness ledger (D2) | Measure first: one query over `bucket_date - measurement_start_time` stratified by censored-country ASNs. Revive if >1-2% of a typical hour arrives after the run, or at the first missed event traced to late uploads. |
| Parquet observation tier on S3 | Only if 3.4's body-fingerprint backfill is decided to be full-history: capture that one expensive pass as Parquet rather than discarding it. Forward-only 3.4 means skip. |
| SQL models framework (SQLMesh/dbt) | After the MVP grows the SQL DAG to ~5 stages. The frameworkless pieces (committed generated SQL, named-column inserts, required DB CI job) are already in 3.9/3.11. |
| v5-native data-quality checks (E4, O5) | The volume and clock checks read v4's `fastpath` and feed a table nothing consumes. Replace when v4 retires, and either wire `faulty_measurements` into scoring or drop it. |
| Endpoint-grain tier 2 (D1) | Tier 2 collapses endpoints with `max`, so scores drift with a target's answer-set size. Recomputable from tier 1 without S3. Revive at the first changepoint traced to CDN growth rather than policy. |
| Throttling signals (M7) | The evidence is already stored (E1): `tls_handshake_time`, `tls_read_count` and related timing and volume fields land in observations. Missing are a vocabulary state, series definitions, and ground truth to validate against. Design the cell-state grain so a rate or latency signal can be added without a regrain; revive at the first adjudicated throttling event, which also seeds the corpus rows to score it by. |
| Full `locus` axis with inference (E7) | 3.5 stabilises series; naming *who* is responsible needs cross-network resolver checks that do not exist. Blockpage-fingerprint `scope` already attributes what it matches, and the planned middlebox and transit detectors widen that set. See [ontology.md](ontology.md) A.2. |
| Dempster-Shafer verdicts / pipeline-side mechanism inference / target hierarchy / cert store | Ontology Appendix A, each with its trigger. (The mechanism *taxonomy* was promoted into ontology §12; what stays deferred is the pipeline emitting mechanism labels as output.) |
| Widening the detector watchlist (priority 5) | Needs 3.7 first, and the stale hardcoded entry fixed (D1). |
| Coverage of ~28 unsupported nettests | `openvpn` first (actively collected, no analysis path); then the low-level probes, which map onto existing observation shapes. |

---

## 5. Tradeoffs in this plan

Stated as requirement conflicts; bare ids cite
[requirements.md](requirements.md).

**Fixing measurement before adding capability.** The priority order's rule of
1 over 5. 3.1, 3.2 and 3.8 improve nothing a user can see, and the
alternative (shipping the HTTP layer first, the most visible gap) would put
hand-set weights on a new layer with no way to meet V2.

**A rule histogram instead of a probabilistic state model.** Meets E5, three
uncertainties kept distinguishable, with one cheap structure that composes
with what is already shipped. The cost, partial belief within a single
measurement, is one the requirements decline to buy (the Dempster–Shafer row
of the non-requirements table). If that trigger fires, Appendix A.1 is the
upgrade path, and the histogram is not wasted work.

**A view instead of a table for cell state.** O1 against read cost: nothing
new to operate or backfill while the grain is still being learned, paid for on
every query. The materialisation trigger is recorded (X1), and the promotion
path avoids the insert-time materialized view that would corrupt the counts E2
depends on (architecture §3.1).

**Deferring locus.** E7 is honoured (no attribution without attribution
evidence) at the cost of not answering "who is responsible", the
highest-value distinction for end users ("this site refuses your country"
versus "your ISP blocks it"). Fingerprint `scope` narrows the deferral:
matched blockpages already carry an adjudicated scope worth surfacing. The
rest waits on cross-network resolver evidence, trigger recorded. Still the
deferral most likely to be regretted.

**Curated labels rather than crowdsourced.** V1's quality bar over coverage.
Recall measured on known incidents is structurally blind to what was never
detected, and labels cluster by incident, so the effective sample size is the
number of incidents, not of measurements. The stratified negative class
bounds the false-positive side honestly (V3); the false-negative side stays
an estimate, and is reported as such.

**Stateless recomputation over durable detector state.** Buys P5, O4 and D2's
late-data absorption. Costs recomputing a window every run rather than
updating an accumulator, a bounded horizon beyond which changepoints are
immutable, and an alert-revision doctrine that must be written rather than
inherited. The accumulator is not kept-and-guarded instead because its
failure mode sits in O2's exception: silent, and unrecoverable from the
archive. The compute is small at the current watchlist; the doctrine is the
real work.
