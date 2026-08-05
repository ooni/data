# Requirements

What the pipeline must achieve, stated independently of how. The companion
documents describe *approaches*; this document is what those
approaches are assessed against.

The system under requirement: OONI turns measurements submitted by volunteer
probes on the open internet into evidence about network interference. That
evidence takes three forms (per-measurement verdicts, aggregates, event
alerts) and reaches four audiences: Explorer end users, journalists and
advocates, researchers, and legal and policy consumers. The pipeline is
everything between the raw measurement archive and those surfaces, plus the
evaluation machinery (label corpora, replay harnesses) that gates changes to
any of it.

Companions: [architecture.md](architecture.md) (how it runs),
[ontology.md](ontology.md) (what the entities mean),
[user-guide.md](user-guide.md) (consuming it),
[developer-guide.md](developer-guide.md) (working on it),
[implementation-plan.md](implementation-plan.md) (current state and next
steps).

**How to use this document**

- Requirement ids (`E3`, `A2`, …) are stable, and are what other documents
  cite when explaining a design decision or a tradeoff.
- Requirements are timeless. Where the system currently falls short is tracked
  in the implementation plan rather than annotated here.
- A design decision is assessed against a requirement as one of: **meets**;
  **partially meets**, naming the missing piece; or **trades**, naming what was
  bought and which requirement paid for it. An accepted shortfall carries
  either a mitigation or the trigger for revisiting it. A shortfall with
  neither is a gap.
- Two rules to keep the assessment honest are:
  - A safeguard that rests on someone remembering is assessed as **weaker than a mechanism** 
    and recorded as such, rather than counted as solved (O2).
  - If something's been deferred and nobody wrote down what would bring it back, that's not a
    decision, but rather a drift (X1).
- When requirements conflict, §11 decides which wins.

---

## 1. The environment

Constraints are facts the system lives in. A design is not asked to change
them, only to account for them; a design that assumes one of them away fails
assessment regardless of its other merits.

| id | Constraint |
|---|---|
| C1 | **Input is adversarial.** Measurements are submitted from the open internet, and any field a probe reports (network, country, software version, results) may be forged. Credentialed probes carry a pseudonymous, network-local `probe_id` from the anonymous-credential scheme. It provides [unforgeable metadata](https://ooni.org/post/2025-announcing-ooni-new-anonymous-credential-system/) (probe age, measurement count, trust status) attested without revealing the raw values, plus Sybil resistance that raises the cost of manufacturing many *trusted* identities. Everything collected before the scheme, and any probe omitting it, is unauthenticated forever. |
| C2 | **The S3 archive is the only durable given.** Everything else is derived. Anything that cannot be derived from it must be explicitly named and separately protected, or it does not survive. |
| C3 | **Reference data is community-owned.** Blockpage fingerprints, test lists and network metadata live in external repositories that include additional maintainers and consumers, their own cadence, and change underneath the pipeline. |
| C4 | **The team is small.** A handful of engineers. Standing human attention is the scarcest resource in the design space. |
| C5 | **Production exists.** ClickHouse and the S3 layout are in production and working. The API, Explorer, and the published `confirmed` / `anomaly` vocabulary have consumers which make coordinating a migration very complicated. |
| C6 | **Errors are asymmetric.** OONI output is cited in litigation, press and policy. A false blocking claim is ammunition against OONI's credibility everywhere and forever; a missed event is invisible. Both are failures, priced differently. |
| C7 | **Data arrives late, correlated with censorship.** Probes on interfered networks upload late or never, often *because of* the event being measured. Designs should not assumes prompt arrival of data. |
| C8 | **Coverage is uneven and uncontrolled.** The probe population is volunteer, with orders-of-magnitude differences between countries and networks. While it's possible to [prioritize the testing](https://docs.ooni.org/backend/ooniapi/services/#prioritization) of certain targets in specific geographies, if no volunteers exist in the region the coverage will remain scarse. Building additional coverage and capacity in a region is costly. |

---

## 2. Product requirements

**M1. One question, every resolution.** The system answers *"does blocking of
kind K, in location X, affecting target Y, over time contour Z, exist?"* at
every step of each ladder: endpoint → network → country; URL → domain →
service; hour → arbitrary window. Each step gets a coherent answer and its
evidence. Moving along a ladder changes the scope of the answer, never its
meaning.

**M2. Three states, not a flag.** Output distinguishes **blocked** (a
restriction is in place) from **down** (unavailable, without signs of
blocking) from **ok**, with an explicit **insufficient** below the evidence
floor (E3). Separating unavailability from censorship is the hard problem this
system exists to work on; collapsing back to a binary anomaly flag is a
regression, whatever else a design buys.

**M3. Mechanism at the evidence's specificity.** Where interference is found,
the output says *how* it is implemented (DNS injection, SNI-triggered reset, a
served blockpage) at whatever specificity the evidence supports, without
inventing precision. "TLS interference, trigger unidentified" is a complete
answer when the evidence stops there.

**M4. Events, onsets and endings.** The system detects the onset and
resolution of blocking and notifies humans at **event grain**: one real-world
event maps to approximately one notification carrying its scope (networks,
targets, layers), rather than one alert per affected series. Event semantics
are specified rather than emergent from implementation, including direction,
extension while an event rolls out across networks, and subsumption between
overlapping clusters.

**M5. Four readers, one substrate.** The same data serves end users
(plain-language states), journalists and advocates (artefact-led narratives
with checkable counts), researchers (raw observations and reproducible
queries), and legal or policy consumers (a provenance chain from claim to
evidence). Deeper surfaces may say more; no surface may contradict another.

**M6. Continuity by mapping.** Existing published vocabulary evolves by
explicit mapping and deprecation, never by silently changing meaning under a
consumer (X2). This covers the `confirmed` / `anomaly` flags, API outcome
labels, and persisted rule ids.

**M7. Slowness is a form of interference.** Interference that
slows a connection rather than breaking it must be expressible in the
vocabulary and computable from what probes already record: TLS handshake
duration, read counts, and the other timing and volume fields on observations.
This is not implemented yet, and is stated here so it gets designed for rather
than discovered later. A vocabulary that can only express reach or no-reach
answers "no" to "is this throttled?" when the honest answer is "the schema
cannot represent the question".

---

## 3. Evidence and honesty

**E1. Facts before conclusions.** What happened is recorded separately from
what it means, and conclusions are recomputable from the recorded facts.
Concretely: a change of interpretation (reweighted rules, a split rule, a newly
discovered blockpage fingerprint) must be applicable to history without
reprocessing the raw archive, for every evidence class the pipeline chose to
store. Where evidence is discarded at ingest and reinterpretation therefore
requires a full reprocess, that loss is a named, deliberate decision rather
than a discovery made later.

**E2. Every claim ships its evidence.** A published aggregate carries its
witness (which cell or measurement produced the extreme), the sample size and
denominator behind it, and its independence count: distinct credentialed
probes where available, client-chosen identifiers only as labelled upper
bounds (A3). Published counts are exact under routine operation, so storage
and read semantics such as deduplication lag and scheduled double-writes must
not allow a correct query to return an inflated number.

**E3. Weak evidence changes the statement, not a footnote.** Below the
evidence floor the published state is *insufficient*, never a strong label
with a low confidence attached, because readers keep labels and discard
qualifiers. Insufficient is not ok, is not an error, and is the honest state
for most cells. The floor applies to every surface: API, UI, exports, and
alerts (D4).

**E4. No manufactured findings.** Defects of the instrument (probe bugs, stale
trust stores, enrichment confused by anycast or geolocation error) must be
separable from network interference, and the separation must fail toward
*insufficient* rather than toward *blocked*, because folding instrument
defects into blocking manufactures censorship findings. Measurement validity
is an axis orthogonal to network state. A validity signal that exists must be
consumed by the scoring or publication path; a check that feeds nothing is
assessed as absent (O5).

**E5. Uncertainty stays decomposed.** "How much do we know" is at least three
quantities: per-measurement ambiguity, sample size and independence, and
consensus among conclusive measurements. Each demands a different response (a
better rule, more data, an investigation), so they stay distinguishable
through aggregation. Aggregation also preserves the question's type. An
existential answer, a prevalence, and a state label are different results with
different operators, and a statistic that lets a fragmented minority
under-call real blocking, or lets a widened selection manufacture certainty,
violates this.

**E6. Numbers that look like probabilities are calibrated.** Any figure a
reader will read as a probability is either calibrated against ground truth
and cites the corpus version it was calibrated on, or it is not published.
Internal uncalibrated weights are legitimate machinery; publication is the
boundary. Calibration claims state what they were measured on and never use
guarantee language the sampling assumptions cannot support.

**E7. Attribution only with attribution evidence.** Naming a responsible party
(an ISP, a resolver operator, a government, the site itself) is a distinct
claim requiring distinct evidence beyond locating interference at a layer.
Some evidence does carry it: a matched blockpage fingerprint has a `scope`
saying whether the block is ISP-level, national, institutional or
provider-side, and that is publishable because a human adjudicated it
upstream. Where the evidence does not separate the candidates (on-path
injection versus resolver behaviour; server-side geoblocking versus network
blocking), the output says "unknown" rather than defaulting to any party, and
no key, column name or label smuggles an attribution the evidence does not
carry.

---

## 4. Provenance and reproducibility

**P1. Rebuildable, with named exceptions.** All pipeline state is recomputable
from the S3 archive plus pinned reference snapshots. The exceptions are the
record of what was detected and published when, the label corpora, and
operational metadata. They are enumerated in one place, backed up, and
restore-tested (O5).

**P2. Deterministic recomputation.** Re-running any tier over a window with
pinned inputs yields identical output, and CI proves it rather than aspiring
to it. Window semantics are explicit per tier: which time axis selects rows,
what happens to late arrivals, when a window is final. "Deterministic because
the window's incompleteness got frozen" is acceptable only as a stated policy
with its consequences owned (D2), never as an accident.

**P3. Versioned scoring inputs.** Every verdict names what produced it: the
ruleset version and the reference-data snapshots, resolved as of the
*measurement's* window rather than the run's wall clock. While it's 
desirable to re-score usinng newly discovered fingerprints, it should be 
possible to also re-score using historical inputs for validation purposes.

**P4. Published history does not silently mutate.** What was relied upon,
meaning verdicts served and alerts sent, remains reconstructible after
re-analysis. Re-scoring is a visible, auditable operation: a new version that
can be reconstructed, even when it has been superseeded, never an in-place 
overwrite that leaves no possibility to rebuild what the world previously saw.

**P5. Alerts are evidence-grade.** For any emitted alert, the inputs it
consumed are identifiable and its statistic recomputable, at any later date.
"The database now returns something different and we cannot explain why" is a
failed assessment in a litigation setting. The provenance standard achieved at
the judgment tier applies with at least equal force to every tier that
publishes more loudly than it.

---

## 5. Adversarial robustness

**A1. A stated threat model.** The design documents a threat model for
submitted data, and every published aggregate and every detection statistic is
assessed against *"what could a submitter make this say?"* in both directions:
manufacturing a finding that is not there, and suppressing one that is.

**A2. Single-submitter bounds.** No single unauthenticated submitter, at
trivial cost, may flip a reader-facing headline state, poison a control or
baseline so as to change how *other* probes' measurements score, or suppress
or displace an alert (including by flooding a volume cap). Where residual
exposure is accepted, as it must be for pre-credential history (C1), the
published claim carries the caveat that prices it.

**A3. Independence counted on attested identities.** Corroboration counts
backing published claims use `probe_id`, whose attested metadata (probe age,
measurement count, trust status) and Sybil resistance make a population of
*established* probes expensive to fake. 
Reader-facing floors therefore key on established credentialed probes rather 
than on raw distinct ids. Client-chosen identifiers such as report ids and 
session counts may appear only as labelled upper bounds on independence.

**A4. Controls are verified, not asserted.** Membership in any control or
baseline set requires evidence the pipeline itself validated: central
revalidation, corroboration by k distinct credentialed observers, geolocation
and anycast sanity of the address. A single submitter-asserted boolean is
never sufficient. A poisoned control rewrites the scoring of everyone else's
measurements, so controls carry the strictest admission standard in the
system.

**A5. Reference data is guarded by content, beyond shape.** A content change
in an externally-owned corpus must not silently change published verdicts:
fetched revisions are recorded (P3), diffs are observable, and a *fall* in
match rate alerts (O3). One accepted upstream pull request must not be able to
retire a confirmed finding, or manufacture one, with nothing noticing.

---

## 6. Privacy

**PR1. No new exposure without discussion and disclosure.** The privacy
posture users were promised is the one they keep. Linkability and the
anonymity set today sit at the **network level**: measurements from one
network are linkable to each other, and a probe is anonymous within its
network's population. `probe_id` is network-local by design precisely to
preserve that boundary rather than sharpen it. Any change that would expose
more than is already collected, or resolve identity more finely than the
network, is a decision taken deliberately, discussed before it ships, and
disclosed to users. That covers new uses of `probe_id` in corpora, exports and
APIs, each of which settles retention, access and an aggregation floor first.

**PR2. Private by design, starting on the probe.** Redaction happens as far
upstream as it can, on the probe and before submission, so that data arriving
at OONI is already minimal. What reaches the pipeline is then treated as
redacted for good: every derived tier and export respects it, and no
enrichment step reconstructs what scrubbing removed.

---

## 7. Detection and alerting

**D1. Signals track policy, not infrastructure weather.** Series identity and
detection statistics are stable under changes that are not policy changes: a
CDN widening its rotation, probes rotating between resolvers, a platform
renaming its domain, a test-list edit. A changepoint must mean the network's
behaviour changed, not that the internet reorganised underneath the series key
or the statistic.

**D2. Severity must not silence.** The severest events (volume collapse,
shutdowns, interfered networks uploading late) must strengthen the detection
signal, or at minimum still reach detection when the data arrives (C7). An
empty hour is a signal rather than a no-op, and a measurement arriving after
its window's first evaluation is eventually evaluated rather than permanently
skipped. "No alert" must also be distinguishable from both "no data arrived"
and "alert delivery is broken" (O3).

**D3. Latency is modest, and stated.** Detection operates on the scale of
minutes to hours. An alert within roughly two hours of a promptly-uploaded
measurement meets the requirement. There is no streaming requirement, and
nothing may trade determinism (P2) for freshness beyond this bar.

**D4. Alerts meet the evidence floor, and floods cannot displace events.** No
alert fires from a series whose every cell would publish as *insufficient*
(E3). Alert volume per run is bounded, and what a bound drops is prioritised
and recorded, so that tripping many low-value alerts cannot silently push a
real event out of the delivered set (A2).

**D5. Distinguish the world changing from the pipeline changing.** The
pipeline's own artefacts (rule and fingerprint deploys, reference-data
refreshes, probe releases, collector hiccups) are common-cause and present
with exactly the signature of coordinated blocking: simultaneous,
cross-network. Detection and event grading must therefore consult the
discriminating contrasts the data already holds, which are input versions on
the rows (P3), the same target's behaviour in other countries, control-side
degradation, and probe-attribute confounds (E4). Cross-network simultaneity
alone is never sufficient corroboration.

---

## 8. Validation

**V1. Ground truth independent of the thing evaluated.** Labels use a
vocabulary independent of the prediction vocabulary, meaning a mechanism
taxonomy rather than rule ids, so evaluation cannot collapse into the pipeline
grading its own echo. Adjudication is blinded to the pipeline's verdict.
Sampling designs are recorded well enough that production rates are estimable
from the corpus, and the negative class is drawn by design rather than
incidentally.

**V2. No unmeasured changes.** Nothing that changes what is published ships
without measurement at the right grain. Scoring changes are measured against
the per-measurement corpus. Detector changes (statistic, thresholds, series
keys, watchlist) are measured against the event-grain scorecard: recall by
event size, detection latency, false alarms per quiet series-week, alerts per
true event. Presentation thresholds are fitted and versioned rather than
eyeballed. A tier without a baseline cannot claim improvement.

**V3. The corpus itself is monitored.** Negative-class share,
inter-adjudicator agreement, per-probe concentration, per-stratum shortfall. A
starved negative class is a release blocker for any published error rate,
because the negative class is the only bound on what the pipeline is missing.

---

## 9. Operations

**O1. Runs on the team we have.** No new standing service, datastore, or
recurring human ritual without a fired trigger written down in advance.
Anything that needs recurring human attention has a named owner, or it is
assessed as not existing (C4).

**O2. Mechanism, not discipline.** Enforce correctness invariants with
interlocks, schema, or CI wherever practical. A documented, owned procedure is
an acceptable substitute at this team size (C4), but counts as weaker and is 
recorded as such, not as solved. Exception: where a violation would fail 
silently and the damage is unrecoverable, a mechanism is required, not a
procedure.

**O3. Production health is observable.** Scoring health (fingerprint-join
match rates, rule-distribution drift), pipeline liveness (task failures,
updater staleness, window-coverage holes), and the alert path itself are
monitored in production. That means the same assertions CI makes, run where
the data actually changes, on the cadence at which it changes (A5). The alert
sink is itself alive-checked, so "no events" and "no delivery" are different
observations (D2).

**O4. Routine operations are safe by construction.** Backfill, reprocess,
catch-up and deploy cannot corrupt detection state, double-count published
numbers, or silently rewrite history (P4). The operator question "is it safe
to run this now?" must have the standing answer "yes".

**O5. No dead ends, no unprotected state.** Every produced table has a
consumer or a retirement plan, every check feeds a decision, and the
non-rebuildable state (P1) is backed up with a tested restore. A quality flag
nothing reads and a published detection record living on one disk are both
assessed as absent.

**O6. Documentation for mixed expertise.** Each document is readable on its
own by a team member who does not hold the whole system in their head: terms
defined where used, the status of every capability explicit (built, in flight,
deferred), cross-references a convenience rather than a prerequisite.
Complexity beyond the current delivery lives in a future-work document rather
than inline. The documents agree with each other, and a contradiction between
two documents is a defect in both.

---

## 10. Evolution

**X1. Deferral with a trigger.** Anything cut, deferred or parked is recorded
with the concrete condition that would revive it. The trigger is what makes
"not now" a decision instead of drift; its absence is assessed as a gap.

**X2. Public contracts are append-only.** Rule ids, taxonomy nodes, API
labels, and schema columns that consumers read: add and deprecate, never
re-point, rename in place, or silently redefine (M6).

**X3. Additive extension paths.** New nettests, rules, targets, and label
strata are additions to registries rather than redesigns. The cost of the next
capability is proportional to the capability, not to the age of the system.

**X4. Scale is not foreclosed.** Designs need not pre-build for a wider
watchlist, more layers, or richer detection, but must not embed decisions that
make growth a rewrite. Interfaces are drawn where internals will churn: an
event subsumes its member changepoints, so the detector's internals can change
without a schema break.

---

## 11. Priorities

Ordered. When requirements conflict, the higher wins; a design may spend a
lower requirement to protect a higher one, and must say that it is doing so.

1. **Published claims are true and defensible** (E-group; P4, P5; A2). The
   product is credibility (C6). When honesty conflicts with coverage or
   sensitivity, publish less, honestly.
2. **Provenance** (P-group). A claim that cannot be reconstructed should not
   have been published. Sophistication never outranks explainability at a
   published surface.
3. **Detection that cannot be silenced** (D2 first, then D1, D4, D5). Missing
   the largest events is mission failure in the other direction. It ranks
   below 1 and 2 only because a wrong alert spends the credibility that makes
   true alerts worth anything.
4. **Operability** (O-group). A safeguard the team cannot operate does not
   exist. At this team size (C4), simplicity is a correctness feature rather
   than an aesthetic.
5. **Coverage and capability** (M3 depth, more layers, more nettests, wider
   watchlists). Grown last, on top of the above. The history of this project's
   false positives is the history of capability outrunning validation.

Three standing rules for resolving the common conflicts:

- **Honest-and-narrow beats broad-and-wrong** (1 over 5). The system's reach
  grows only as fast as its ability to be right about what it reaches.
- **Explainable beats optimal** (2). At every published surface a traceable
  method beats a better-scoring opaque one. Opaque methods may rank work for
  humans internally; they never decide what is published.
- **Deterministic beats fresh** (2 over D3). Hourly batch is acceptable
  forever; irreproducible speed is not acceptable ever.

---

## 12. Non-requirements

Explicitly out of scope, each with the trigger that would change that, which
is X1 applied to the requirements themselves. A design is not criticised for
omitting these; it would be criticised for building them now.

| Not required | Why | Trigger to revisit |
|---|---|---|
| Streaming or sub-hourly detection | The collector delivers hourly; consumers act on hours-to-days timescales (D3) | A consumer with a demonstrated need to act in minutes |
| High availability of the read path | Durability (P1, O5) is required; uptime is not mission-critical | The API becoming load-bearing for a partner, or Explorer SLOs |
| Attribution *in the general case*, every interference traced to a party | Fingerprint `scope` already attributes matched blockpages, and the planned middlebox and transit detectors will extend that. What stays out of scope is inferring a party where no such evidence exists (E7) | Those detectors landing, which widens the attributable set rather than lifting the evidence standard |
| Per-measurement belief fusion (Dempster–Shafer and kin) | The rule vocabulary already carries the distinctions categorically | A measurement needing partial belief that no rule split can express |
| Learned models deciding published verdicts | Violates priority 2; permitted as firewalled triage feeding human curation | Never, for the published verdict itself. The firewalled-triage form has its own trigger: a blockpage family the corpus missed for days |
| Crowdsourced labelling | Ground-truth quality over volume (V1) | The curated corpus demonstrably too small for the top rules, with adjudication capacity the binding constraint |
| Ingesting other observatories' data into the pipeline | Corroboration happens at analysis and reporting time rather than at ingestion | A formal data-sharing agreement with aligned schemas |
