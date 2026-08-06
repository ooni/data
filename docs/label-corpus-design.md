# Label Corpus Design

Three label grains, one curation workflow. This is the machinery behind
requirements V1–V3 ([requirements.md](requirements.md)): ground truth
independent of the rules it evaluates, no unmeasured changes, and a corpus
whose own health is watched.

**Why three.** The per-measurement corpus calibrates *scoring*: it is what the
per-rule likelihood ratios in [analysis-evaluation.ipynb](analysis-evaluation.ipynb)
are fitted from. It is structurally incapable of evaluating the *detector*:
time-to-detect, missed events, false-alarm density and alert-flood size are
properties of a time series that no per-measurement metric can express. That is
what the event grain is for.

The event grain in turn cannot express a *rate*. It is curated, so recall over
it is a coverage statement about a hand-built set, and there is no denominator
in it: nothing defines quiet time, and quiet time can only be counted if it was
sampled from a frame. That is what the interval grain is for. It is the mirror
image of the event grain — sampled rather than curated, weighted rather than
enumerated, negative rather than positive.

They share sourcing. An analyst working an incident produces the first two in
one pass: the event row (when it started, where, against what) and a sample of
measurement rows drawn from inside and around it. The third is drawn, not
found, which is the point of it.

**Neither grain is stored server-side.** Labels live in the browser and leave by
copy-paste, which is why there is no write endpoint, no auth surface and no
migration. The schemas below are the shape of the exported JSON. Persisting them
into ClickHouse is a later decision, and the shapes are chosen so it stays open.

---

## Part 1: Schemas

### 1.1 Measurement labels: implemented

Emitted by [labeler.html](labeler.html). One object per adjudication, append-only:
a re-adjudication writes a new row and sets `superseded_by` on the old one.

```jsonc
{
  "label_id":           "uuid",
  "measurement_uid":    "20260722184232.178120_CN_webconnectivity_09960fae",
  "observed_at":        "2026-07-22T18:42:21",

  // denormalised selection keys, so a stratum can be audited without a join
  "probe_cc": "CN", "probe_asn": 9808, "resolver_asn": 0,
  "target":   "b9vhe.com", "test_name": "web_connectivity",

  // the judgment
  "label":            "blocked",      // blocked | down | ok | unadjudicated | unusable
  "label_confidence": "uncertain",    // certain | probable | uncertain
  "mechanisms":       ["tls.reset.other"],   // empty unless label = blocked
  "mechanism_taxonomy": "v1",
  "label_source":     "analyst",
  "adjudicator":      "arturo",
  "adjudicated_at":   "2026-08-03T16:46:31.058Z",
  "rationale":        "…",            // required for label_source = analyst

  // sampling design — unrecoverable if omitted, see §1.5
  "sampling_stratum":   "screen_negative",
  "sampling_weight":    2207987.8,
  "sampling_design_id": "d2241318a47",
  "screen_kind":        "fastpath_proxy",

  "blinded":          true,           // pipeline verdict was hidden at judgment time
  "superseded_by":    null,
  "supersede_reason": null
}
```

**Fields worth explaining.**

`label` carries `unusable` as well as `unadjudicated`. `unadjudicated` means
"not yet looked at"; `unusable` means "looked at, and this row cannot be judged":
malformed measurement, missing control, probe clock nonsense. Collapsing them
destroys the denominator: a stratum with 40% unusable rows is telling you
something about the pipeline, not about blocking.

`label_confidence` is *not* a likelihood ratio. It records adjudicator certainty
on this row. Fit LRs on `certain` + `probable` and report the sensitivity of each
to dropping `probable`; a rule whose LR moves a lot is judgment-dependent and
should be flagged as such.

`mechanisms` is an array under taxonomy v1 ([ontology.md](ontology.md) §12).
Multiple entries mean co-occurring techniques, one per technique. This is what
makes the corpus survive a rule-set refactor: a label keyed to a rule id ages
badly, a label recording "this was an SNI reset" does not.

`screen_kind` records *how* the stratum was screened: `fastpath_proxy`,
`loni_layer_proxy`, `fingerprint`, `incident_scope`. Different screens have
different, unmeasured coverage, so a later refit can drop or separate them.

`blinded` records that the pipeline's verdict was hidden when the call was made
(§3.4). A corpus mixing blinded and unblinded labels cannot be pooled.

**Not implemented, and why it matters.** There is no `probe_id`,
`scored_rules`, `pipeline_version` or `event_id` on a label today.

- `probe_id` exists in the pipeline but is empty for measurements predating the
  anonymous-credential scheme, so LR bootstraps currently resample
  *measurements* rather than *probes*. That understates the interval whenever one
  probe dominates a stratum.
- `scored_rules` (the full fired set) needs the persistence work in
  [implementation-plan.md](implementation-plan.md) §3.9. Until then LRs are
  conditional on "fired **and won**", a cascade-position-dependent quantity.
  The evaluation notebook joins `top_*_rule_id` from
  `analysis_web_measurement` at fit time instead of snapshotting it.
- `event_id` is deliberately absent rather than merely unbuilt: see §1.2.

### 1.2 Event labels: implemented

Emitted by [event-labeler.html](event-labeler.html), seeded from OONI's published
incidents by [incidents_to_events.py](../scripts/incidents_to_events.py).

```jsonc
{
  "event_id":    "uuid5 of the incident id, so re-import is idempotent",
  "incident_id": "348668101300",        // provenance when imported
  "slug": "…", "title": "…",

  // scope
  "probe_cc":        "ES",
  "asn_scope":       [3352, 6739],
  "asn_scope_kind":  "listed",          // all | listed | unknown
  "target_set":      ["www.womenonweb.org"],
  "target_set_kind": "enumerated",      // enumerated | category | unknown

  // how, in the same taxonomy as the measurement labels
  "mechanisms": ["dns.injection.bogon", "tls.reset.sni"],
  "mechanism_taxonomy": "v1",

  // when, as intervals: published reports date events coarsely
  "onset_earliest": "2020-02-01T00:00:00",
  "onset_latest":   "2020-02-02T00:00:00",
  "resolution_earliest": null,          // null = ongoing
  "resolution_latest":   null,

  // grading
  "event_class": "true_event",          // true_event | false_positive_event | disputed
  "scoreable":   "yes",                 // yes | no_coverage | unknown
  "confidence":  "probable",            // certain | probable | uncertain

  // evidence
  "source": "ooni_report",              // ooni_report | partner | press | operator
                                        // | court_order | internal_analysis
  "source_urls": ["…"], "corroborators": [], "test_names": ["web_connectivity"],

  "adjudicator": "arturo", "adjudicated_at": "…", "rationale": "…",
  "added_at": "…", "superseded_by": null, "supersede_reason": null,
  "import_source": "incidents.json",
  "needs_review": []                    // import-time flags, cleared on save
}
```

**Derived, never stored.** A stored `ongoing = true` next to a non-null
`resolution_earliest` is not extra information, it is a bug that renders as
data. The editor shows these read-only as they resolve, which is also how a
scope entry error becomes visible immediately:

```
ongoing   = resolution_earliest is null
layers    = distinct first path segment of each mechanism
size_band = asn_scope_kind = 'all'      -> national
            asn_scope_kind = 'unknown'  -> unknown
            len(asn_scope) > 1          -> multi_asn
            target_set_kind = 'enumerated' and len(target_set) = 1 -> micro
                                        -> single_asn
```

Recall is still reported stratified by `size_band`: adjudicated events skew
large and famous, so unstratified recall is optimistic. The band just stops
being something an analyst can enter wrongly.

**`scoreable` is what makes recall honest.** An event on networks where OONI had
no probes during the window cannot be detected by any detector, and counting it
as a miss makes recall meaninglessly pessimistic. It is the event-level
counterpart of `unusable`. The editor resolves it with a one-click coverage
query rather than a guess, and the harness reports the excluded count alongside
recall so the exclusion stays visible.

**`false_positive_event` is first-class.** An adjudicated false alarm is gold
negatives for the measurement corpus and a must-not-fire regression test for the
detector. The harness inverts the pass condition for these rows.

**No sampling columns.** Events are curated, not sampled: there is no frame to
draw from and no weight to carry. This is the one structural difference between
the grains, and it is why event recall is a coverage statement about a
hand-built set rather than an estimate of a population.

**No `event_id` on measurement labels.** Linking the grains would invite
propagating an incident-grain adjudication to every measurement in the window,
which mislabels the unaffected ones: the single most damaging corpus defect
available. Measurements drawn from inside an event carry
`sampling_stratum = incident_window` and are judged on their own evidence.

### 1.3 Interval labels: implemented

Emitted by [interval-labeler](https://docs.ooni.org/tools/interval-labeler),
drawn from `GET /api/v1/labeling/interval_sample`. One row per adjudicated
cell-week, append-only in the same way as the measurement grain.

The unit is the detector's own unit — `event_detector_cusums` keys on
`(probe_cc, probe_asn, domain)` ([architecture.md](architecture.md)
§"Storage") — because anything coarser would estimate a rate over a different
population than the one the detector runs on:

```jsonc
{
  "interval_id": "uuid",
  "probe_cc": "TZ", "probe_asn": 33765, "domain": "telegram.org",
  "window_start": "2026-03-02T00:00:00", "window_end": "2026-03-09T00:00:00",

  "verdict": "quiet_observed",   // quiet_observed | blocked_throughout
                                 // | event_present | uncertain | unusable
  "confidence": "probable",
  "rationale": "…",

  "sampling_stratum": "random_covered",   // | detector_alerted | near_miss
  "screen_kind": "volume_stratified_random",
  "sampling_weight": 41022.5,
  "sample_population": 820450, "sample_rows": 20,
  "sampling_design_id": "…",

  "volume_band": "high",                  // derived from the count
  "measurements_in_window": 3184,         // from the frame query, not a guess

  "event_overlap": [],                    // null = no corpus was cross-checked
  "blinded": true,
  "adjudicator": "…", "adjudicated_at": "…",
  "superseded_by": null, "supersede_reason": null
}
```

**`quiet_observed`, never `quiet`.** The week is judged from the same OONI data
the detector reads, so an unmeasured block is indistinguishable from calm. The
name caps the claim at "no interference visible in OONI's data", which is the
honest ceiling and also the fair one: a better candidate that finds subtle real
events must not be charged a false alarm for finding them.

**The verdict answers "did it change", not "was it blocked".** The detector is a
changepoint detector, so a transition is the only thing it can be right or wrong
about, and state and change come apart on a common case: a week inside a
long-running block. It has no transition in it, so the detector should stay
silent and an alert there is a false alarm — but the cell is not quiet.
`blocked_throughout` is that week. Without it the two available labels are both
wrong: `quiet_observed` asserts "no interference visible" about a blocked week
and puts it in the pool later mined as clean negatives, while `event_present`
credits a detection nobody earned — the real onset was weeks earlier — *and*
removes the week from the false-alarm denominator, so a detector that re-fires
throughout a long block scores clean on both metrics. A six-month event
corrupted all twenty-six of its weeks that way.

How the estimator reads the five:

```
false-alarm denominator   quiet_observed + blocked_throughout
recall / latency          event_present only
clean negatives           quiet_observed only
excluded, and counted     uncertain, unusable
```

A mechanism shift inside an ongoing block (injected DNS answers giving way to
TLS resets) is a transition and stays `event_present`, as does a recovery, with
the direction named in the rationale. If direction needs to become machine
readable, the next move is a separate `onset_direction` field rather than more
verdict values.

**This grain carries weights, and the event grain does not.** Events are
curated: no frame, no weight, and none can be invented later. Intervals are
sampled precisely so a rate exists, which makes §1.5 apply to them in full. The
event grain is the exception among the three, not this one.

**The strata partition the frame.** `detector_alerted` is the cell-weeks the
deployed detector fired in, `near_miss` those that scored blocked-leaning
without firing, `random_covered` everything else. Each cell-week belongs to
exactly one, so it has one selection probability and one correct weight;
`random_covered` is resolved as the complement of whatever else is being drawn,
and the resolved predicate is part of the design spec.

`detector_alerted` alone would be circular — it estimates the incumbent's
precision *given that it fired*, and a candidate's alerts in cells the
incumbent never flagged would land on weeks nobody adjudicated, making its
false alarms structurally invisible. As a stratum with a recorded screen and a
weight it is not, because the weight states how much of the frame it stands
for. Note this uses the historical alert log as a screen, which §4's "it does
not replay the incumbent" does not forbid.

**The frame is bounded, and says so.** Cell-weeks below a volume floor are
excluded, because a uniform draw over all of them is dominated by cells too
thin for any detector to fire in and every detector then scores well. Frames
snap to whole ISO weeks, since a partial week is a shorter observation window
rather than a smaller one. The default domain set is the one the detector
actually runs on. All three are in the design spec, so all three are in the
design id.

**Derived, never stored.** `volume_band` follows the `ongoing` / `size_band`
rule: the harness re-derives it from `measurements_in_window` rather than
trusting the stored value, which a merge or a hand edit can contradict.

**`uncertain` is first-class and counted**, as `unusable` is in §1.1. Ambiguous
cells that get quietly skipped leave the easy negatives behind, and the rate
improves for a reason that appears in no number.

### 1.4 Sampling designs: implemented

Not a separate table. Every export carries the designs its labels were drawn
under, keyed by `design_id`, so weights are reconstructable from the export
alone:

```jsonc
"sampling_designs": {
  "d2241318a47": {
    "design_id": "d2241318a47", "replicate": 1,
    "spec":      { /* the content-addressed input: strata, frame, scope */ },
    "drawn_at":  "2026-08-03T16:37:32.021Z",
    "frame_start": "…", "frame_end": "…",
    "strata": {
      "screen_negative": {
        "predicate": "confirmed = 'f' AND anomaly = 'f' AND msm_failure = 'f'",
        "table": "fastpath", "screen_kind": "fastpath_proxy",
        "population_estimate": 44159756, "drawn": 20,
        "frame_start": "…", "frame_end": "…", "scope": { … }
      }
    }
  }
}
```

`design_id` is a content hash of `spec`, so the same parameters always produce
the same id and the same queue, and no two different parameter sets can share
one. `replicate` is part of the spec: increment it for an independent draw from
the same population.

**`corpus_version` is not implemented.** Fits currently name the export file
they read. A version cut is a small addition when it is needed; the shape that
matters is that membership is derived (`added_at <= cut_at` and not superseded
as of that timestamp) rather than stamped on the row, so a revised adjudication
does not retroactively change a published figure.

### 1.5 Why `sampling_stratum` / `sampling_weight` cannot be added later

These are the only fields in the sampled schemas that are **unrecoverable
retroactively**. Everything else can be backfilled by re-reading the
measurement. But "what was this row's probability of being selected into the
corpus" is a fact about a process that has already finished running. Start
curation without them and you have a pile of interesting examples with no way to
compute a rate from it; the only repair is re-doing the sampling.

This is why the interval grain (§1.3) was built as a *draw* rather than as a
collection of quiet weeks somebody noticed. A pile of intervals without weights
would look like a corpus and support no rate at all.

Implemented measurement strata, from `labeling.py`:

| stratum | screen | purpose |
|---|---|---|
| `screen_positive` | `anomaly AND NOT confirmed` | LR numerator, precision |
| `screen_negative` | `NOT anomaly AND NOT confirmed` | false-negative bound, base rate |
| `screen_dns` | `dns_blocked >= t` | DNS-attributed positives |
| `screen_tcp` | `tcp_blocked >= t`, DNS quiet | TCP-attributed positives |
| `screen_tls` | `tls_blocked >= t`, DNS and TCP quiet | TLS-attributed positives |
| `fingerprint_match` | `confirmed` | census, high-precision positives |
| `incident_window` | inside an event scope | positives, mechanism coverage |

The layer strata exist because a uniform draw from `anomaly` oversamples
whichever mechanism dominates globally (in practice TLS resets), so a corpus
built from it calibrates one layer and starves the others. They read the
pipeline's own scores, so they oversample what it can already see;
`screen_negative` remains the only stratum that can discover what it misses,
which is why its share must never be cut. `t` is
`scoring.BLOCKING_THRESHOLD`, so a threshold change redefines these strata and
labels drawn either side are not one population.

`control_agreement` is specified but **not implemented**: it needs an
`obs_web_ctrl` join with per-layer agreement predicates, and a negative stratum
with a wrong predicate is worse than an absent one, because it silently deflates
every LR denominator.

Implemented interval strata, from the same module:

| stratum | screen | purpose |
|---|---|---|
| `detector_alerted` | a positive changepoint in the week | precision of the incumbent's alerts |
| `near_miss` | no alert, but `greatest(*_blocked) >= t` in the week | importance sampling: where disagreement lives |
| `random_covered` | the complement of the above, in frame | the denominator |

These differ from the measurement strata in one structural way: they are a
*partition*, resolved against the strata actually being drawn. Two draws over
overlapping populations would give a cell-week two selection probabilities and
no correct weight, and unlike the measurement strata — where the layer
predicates are disjoint by construction — an alerted cell-week is otherwise
also a member of the random population.

---

## Part 2: How an analyst should think about it

### 2.1 The one-sentence version

You are not deciding whether a *site* is blocked in a *country*; you are
deciding what a *single measurement* shows, using only what was available at the
time it was taken.

### 2.2 The three questions, in order

**Q1. Is this row judgeable at all?** Missing control, malformed response,
truncated capture, probe clock skew → `unusable`. Do this first and ruthlessly;
every minute agonising over a broken row is a minute not spent on a real one.

**Q2. Did the connection fail, and how?** Separate *failure* from
*interference*. A timeout with a control that also timed out is `down`. A reset
against a working control is interference. This is where most disagreement
lives, so it is where the rubric needs the most worked examples.

**Q3. Is the interference deliberate?** Blockpage, injected DNS answer,
consistent-across-probes RST at a specific byte offset → `blocked`. Transient,
one probe, no pattern → probably `down` with `label_confidence = uncertain`.

### 2.3 Rules that must be internalised

- **Judge the measurement, not the incident.** A measurement taken inside a
  known incident window on an unaffected ASN, or before the block landed, or
  from a probe using an offshore resolver, is `ok`. These rows are the most
  valuable in the corpus and the easiest to get wrong. Labelling `blocked`
  because the incident report says the country was blocking is incident
  adjudication wearing a measurement's clothes.
- **`unadjudicated` is a legitimate outcome.** Forcing a call on an
  ambiguous row poisons the calibration exactly where it matters most.
- **Do not look at the pipeline's verdict first.** See §3.4.
- **Write the rationale.** One sentence naming the specific evidence: "control
  returned 3 AWS A-records, probe got a single RIPE-registered in-country IP
  hosting a known ISP notice page". This is what makes a disagreement resolvable.
- **You are allowed to be wrong.** Two adjudicators, an overlap set, a published
  [Cohen's κ](https://en.wikipedia.org/wiki/Cohen%27s_kappa) (the standard
  measure of inter-rater agreement, correcting for chance). The disagreement
  rate per rule is the ceiling on any accuracy claim the project later makes;
  measuring it is more valuable than avoiding it.

### 2.4 On the interval grain, the question is different

Not "what does this measurement show" but "did anything change in this cell
during this week". Three things follow that catch people out.

- **A uniformly blocked week is not quiet.** Nothing changes inside it, so its
  own shape says nothing. Judge the week, but look at the fortnight either
  side; the labeller pads the chart for exactly this reason.
- **Boring is the expected answer.** Most cell-weeks are quiet, and that is the
  product: a rate needs its denominator counted, not curated. A session that
  produced forty quiet rows and no interesting finding did its job.
- **A known event inside the window is `event_present`, not a skip.** Dropping
  the row shrinks the denominator with nothing on the record to say why, which
  is worse than the contamination it was meant to avoid — contamination biases
  the rate upward, the safe direction.

### 2.5 Where to start

`answer_unmatched`. It scores `(0.75, 0, 0.25)` for any DNS answer matching
nothing in the control, fires routinely on legitimately rotating CDN and geo-DNS
answers, and is the documented prime false-positive suspect. It is also the rule
uniform sampling reaches slowest, roughly 12% of DNS-blocked traffic, so it is
the strongest candidate for a rule-targeted draw.

### 2.6 Volume expectations

A few hundred adjudicated measurements gives informative LRs for the top 5–10
rules per layer; the tail honestly stays at prior and should be shown as such
rather than given a number. Per-country stratification needs thousands and
should wait. For events, 50–150 rows is the working target.

For intervals the binding constraint is not rows but *country-weeks*: the
bootstrap clusters on them, because cell-weeks correlate across ASNs within a
country and across adjacent weeks. Below ten clusters the harness prints no
interval at all rather than an arbitrary one, so aim to spread a session over
many countries and weeks instead of deepening a few. Intervals are also much
faster to judge than measurements — a flat chart is a few seconds — so a
couple of hundred is a realistic sitting.

---

## Part 3: UI

### 3.1 The adjudication queue: implemented

[labeler.html](labeler.html). One row at a time, drawn from a stratum,
keyboard-first, with the pipeline's verdict hidden until commit.

| Panel | Content |
|---|---|
| Request | target, timestamp, probe cc / asn / resolver_asn |
| Observation | what the probe got: DNS answers per resolver, TCP, TLS handshake, HTTP |
| Control | the same fields from the control, side by side, diffed |
| Context | other measurements of this target from this ASN ±6h |

The side-by-side diff against control is the whole product. An analyst who
can see "control: 4 answers, all Cloudflare; probe: 1 answer, in-country ASN" in
one glance judges in seconds; one who has to reconstruct that from JSON does not
build a corpus of any size.

Controls: `B` blocked, `D` down, `O` ok, `U` can't call it, `X` unusable, then
confidence, mechanism chips, and a rationale field. Commit advances.

### 3.2 The event editor: implemented

[event-labeler.html](event-labeler.html). A form over the event schema, four
inputs and nothing else; everything derivable is derived.

- **Onset as a bracket.** Two pickers, "no earlier than" / "no later than",
  defaulting to what the cited source supports. An analyst made to enter a
  single onset invents precision that is not there, and the harness then scores
  latency against a fiction. The editor refuses an inverted bracket.
- **Scope builder with an explicit "unknown".** `asn_scope_kind` and
  `target_set_kind` exist so "national, but we do not know which ASNs" is
  representable. Without it, analysts either guess or omit the event.
- **Mechanisms from the same taxonomy as the measurement queue.** Multi-select,
  prefixes selectable, so one event carries both `dns.injection.bogon` and
  `tls.reset.sni`. A `true_event` cannot be saved without at least one.
- **Coverage check next to `scoreable`.** One click queries
  `/api/v1/aggregation/analysis` (an existing endpoint, no new API), broken
  down by ASN, and sets `scoreable` from the answer. Traffic in the country but
  none on the listed ASNs correctly reads as `no_coverage`.

Import merges by `event_id` and leaves already-adjudicated rows alone, so a
refreshed draft can be re-imported without losing work.

### 3.3 The quiet-interval queue: implemented

[interval-labeler](https://docs.ooni.org/tools/interval-labeler). Closer to the
measurement queue than to the event editor: a drawn queue, one cell-week at a
time, blinded until commit, `Q` quiet, `B` blocked throughout, `E` event
present, `U` can't call it, `X` unusable, plus confidence and a rationale.

- **The observation timeline, padded.** The same stacked failure-mix chart the
  event editor plots, over the adjudicated week with a settable margin either
  side. The margin is not context, it is the evidence for the `Q` / `B`
  distinction: a week inside a long-running block and a week where nothing is
  wrong are both flat from inside the band, and only the fortnight either side
  tells them apart.
- **Failure strings, not scores**, for the same reason as §3.2: an interval
  judged from the pipeline's opinion of blocking is judged by the thing being
  evaluated, and here one of the strata *is* the detector's output.
- **Event-corpus cross-check.** Importing an event export flags cell-weeks a
  known event overlaps, and the flagged ids are carried on the label. The flag
  says which verdict the overlap implies — `event_present` when the event
  starts or ends inside the week, `blocked_throughout` when it merely covers
  it — because steering every overlap to `event_present` is exactly the error
  §1.3 describes. This is external ground truth rather than detector output, so
  showing it before commit is not unblinding.
- **The reveal shows the alert log, the stratum and the scores.** After commit:
  the changepoints in the window drawn on the chart, which stratum the row was
  drawn from with its weight, and a second chart of what the pipeline concluded
  — blocking probability, per-layer scores, and which outcome carried each
  bucket — on the same time axis. The per-layer values are drawn as independent
  lines, never stacked: they are componentwise maxima and routinely sum above
  one ([user-guide.md](user-guide.md) §3.5).

### 3.4 The blinding rule: implemented

**The pipeline's verdict, the winning rules and the LoNI triple stay hidden
until the analyst commits.** Then reveal, with a supersede path for "this
changed my mind".

This is not fussiness; it is requirements V1. The corpus exists to evaluate
the pipeline; an analyst who sees `blocked, country_consistent_blockpage, 0.9`
before judging is anchored, and every LR fitted from those labels is inflated
by an unmeasurable amount. Blinding costs one UI state and removes an entire
class of circularity. The post-commit reveal is useful too: it is how
analysts find rule bugs.

On the interval grain the rule is stronger, not merely inherited. There, one
stratum is the detector's own alert log, so an unblinded alert state does not
nudge the analyst towards an answer — it *is* the answer to the question being
asked. The sampler's candidate path returns no changepoints, no CUSUM state and
no scores; all of it lives behind `interval_reveal`.

### 3.5 Corpus health dashboard: not implemented

The evaluation notebook covers per-rule label counts and the unusable rate. Not
covered: inter-adjudicator κ, probe concentration, and per-stratum shortfall
against a design target.

---

## Part 4: Workflows

| | Workflow | Status |
|---|---|---|
| W1 | Fired-rule persistence | **not done**: only the winning rule per layer is stored, so LRs are conditional on "fired and won" ([implementation-plan.md](implementation-plan.md) §3.9) |
| W2 | The sampler | **done**: `GET /api/v1/labeling/sample`, records predicate and population before drawing |
| W3 | Auto-label ingestion | **not done**: `fingerprint_match` stratum exists; control-agreement negatives do not |
| W4 | Overlap assignment | **not done**: a fixed replicate drawn by two adjudicators approximates it |
| W5 | Supersede | **done**: the labeller writes a new row and links the old |
| W6 | Version cut | **not done**: fits name the export file |
| W7 | The LR fit | **done**: [analysis-evaluation.ipynb](analysis-evaluation.ipynb) §5, conditioned per layer, [Jeffreys-smoothed](https://en.wikipedia.org/wiki/Jeffreys_prior), bootstrap CIs. Not done: beta-binomial shrinkage, probe clustering |
| W8 | LR diff report | **partial**: §7 prices a promotion; no automatic diff on refit |
| W9 | Event replay harness | **done**: [detector-evaluation.ipynb](detector-evaluation.ipynb) §4 |
| W11 | The interval sampler | **done**: `GET /api/v1/labeling/interval_sample`, cell-weeks drawn from a snapped, volume-floored frame under a resolved partition |
| W12 | The false-alarm estimate | **done**: [detector-evaluation.ipynb](detector-evaluation.ipynb) §5, Horvitz–Thompson per volume band with a cluster bootstrap |
| W10 | Privacy review before `probe_id` | **outstanding**: probe-level linkage across time and target is a correlation surface the project has historically avoided creating; requirements PR1 makes the review a precondition, deciding retention, access and an aggregation floor before the field is threaded through the corpus |

### The harness (W9, W12)

[detector-evaluation.ipynb](detector-evaluation.ipynb) replays the detector over
both corpora and reports: event recall stratified by `size_band`, median
detection latency, alerts per detected true event, and — from the interval
corpus — the weighted false-alarm rate per silent series-week with a
cluster-bootstrap interval.

It is a notebook rather than a CLI subcommand for the same reason
[analysis-evaluation.ipynb](analysis-evaluation.ipynb) is. A scorecard tells you
a configuration's number; the question actually being asked is which
configuration to ship, and that needs the intermediate frames on screen — which
events were missed and what their series looked like, which silent weeks
carried the rate, what happens to both as `edd` moves. §7 sweeps the parameters and
plots recall against false alarms, fetching observations once and replaying them
per setting; a single-configuration command could not do that at all.

Four things it does not do, all deliberate:

**It does not replay the incumbent.** The deployed CUSUM is online and its output
depends on the order measurements arrived in, which the pipeline does not
record. Every replay starts cold, so it scores stateless candidates exactly and
the incumbent only approximately. That asymmetry is itself an argument for
making detection stateless.

**It does not score unadjudicated events.** Rows without `scoreable = yes` or
without mechanisms are excluded and counted, not silently treated as misses.

**It does not count alarms over event lead-ins.** That was the old CLI harness's
false-alarm proxy: quiet time over "whatever cells happen to surround an
adjudicated event", a population nothing sampled and one concentrated in exactly
the countries and networks where quiet time is least typical. The interval
corpus replaces it with an estimate over a frame, so the proxy is gone rather
than printed alongside.

**It does not gate a deploy.** The CLI command exited non-zero on a failed
event, which was usable in CI; a notebook is not. What replaces it is a rule
rather than an exit code — a promotion needs the frontier in §7, compared
against the incumbent's *interval* rather than its point estimate, and the
export files it read named in the commit message. If detector gating in CI is
wanted later, it should run this notebook (`jupyter nbconvert --execute`) rather
than reintroduce a second implementation of the same arithmetic.

Latency is measured from `onset_earliest` and can be negative: reports are
day-granular and usually lag the block, so firing before the bracket opens is a
good outcome, not a sign error.

### What makes the false-alarm number an estimate (W12)

Four choices, all in §5 of the notebook.

**Its denominator is silence, not calm.** Both `quiet_observed` and
`blocked_throughout` weeks belong in it: neither contains a transition, so the
detector should fire in neither, and an alert in either is a false alarm. The
rate is reported over the two together and split between them, because they
fail differently — alerts in quiet weeks are noise, and alerts inside ongoing
blocks are duplicate pages on something already known.

**It weights.** The queue oversamples alerted and near-miss weeks on purpose, so
counting alarms over the rows would describe the queue. Each row is weighted by
`population / n_labelled` for its pooled stratum group — recomputed from the
design records rather than read off the row, exactly as the measurement notebook
recomputes label weights, because the stored weight assumes the whole queue was
worked.

**It clusters.** The bootstrap resamples `(probe_cc, ISO week)` blocks within
stratum group, because a national event or a probe-fleet outage moves many ASNs
at once and treating cell-weeks as independent reports an interval narrower than
the evidence supports. Below ten clusters it reports no interval rather than an
arbitrary one.

**It warms up.** Each replay starts a fortnight before the window and counts
only what fires inside it: a cold CUSUM's first threshold crossing establishes
state silently, so replaying the bare week would swallow the alarms being
counted.

---

## Part 5: The failure modes to watch

| Failure | Symptom | Guard |
|---|---|---|
| Incident-grain leakage | Every row in a window labelled `blocked` | No `event_id` on labels; audit the `ok` rate inside `incident_window`: a zero rate means the analyst is adjudicating the incident |
| Anchoring | Analyst labels track pipeline verdicts near-perfectly | §3.4 blinding, recorded per label; monitor agreement as a *diagnostic*, not a target |
| Pseudo-replication | One chatty probe dominates a stratum | Needs `probe_id` (W10); currently unguarded |
| Negative-class starvation | `screen_negative` count flat | Treat as a release blocker for any published LR |
| Silent design drift | Sampling rate changed without a new design id | `design_id` is a content hash of the spec, so it cannot happen silently |
| Threshold drift | Layer strata redefined under the same design | `scoring_version` and `blocking_threshold` recorded in every design spec |
| Version soup | Published figures with no reproducible input | Weakest link today: fits name an export file, not a cut (W6) |
| Circular quiet time | False-alarm rate estimated only over weeks the incumbent alerted in | `random_covered` is the denominator and the strata partition the frame; a draw without it estimates precision-given-firing and says so |
| Frame flattery | Every detector scores well on quiet time | Volume floor, whole ISO weeks, detector's own domain set — all three in the design spec, so a change to any of them changes the design id |
| Absence read as calm | A block on an unmeasured network scores as a false alarm against a better detector | The verdict is `quiet_observed`, never `quiet`; the claim is capped at what OONI's data shows |
| Ongoing block read as a detection | A detector re-firing through a long block scores perfect recall and no false alarms, because every week of it was labelled `event_present` | `blocked_throughout` (§1.3): a week with no transition stays in the false-alarm denominator whether or not the cell is blocked |
| Differential effort | Ambiguous cell-weeks quietly skipped, leaving the easy negatives | `uncertain` is first-class and the harness counts exclusions by reason |
| Independence assumed | A false-alarm interval far too narrow | Cluster bootstrap on `(probe_cc, week)`; no interval below ten clusters |
