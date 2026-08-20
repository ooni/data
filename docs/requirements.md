# Requirements

The design goals of the data pipeline. Companian documents specify approaches to
this.

Problem statement:

OONI turns measurements submitted by volunteer probes on the open internet into
evidence about network interference.

That evidence takes three forms:
- per-measurement verdicts
- aggregates
- event alerts

Evidence reaches these audiences:
- OONI Explorer end users
- journalists and advocates
- researchers 
- legal and policy consumers

The OONI data pipeline is everything between the raw measurement archive and
those surfaces, plus the evaluation machinery (label corpora, replay harnesses)

## C. Constraints

These are constraints we need to account for due to external factors which are
generally outside of our control.

| id | Constraint |
|---|---|
| C1 | **Input is adversarial.** Measurements are submitted from the open internet, and any field a probe reports (network, country, software version, test_keys) may be forged. Credentialed probes carry a pseudonymous, network-local `probe_id` from the anonymous-credential scheme. It provides [unforgeable metadata](https://ooni.org/post/2025-announcing-ooni-new-anonymous-credential-system/) (probe age, measurement count, trust status) attested without revealing the raw values, plus Sybil resistance that raises the cost of manufacturing many *trusted* identities. Everything collected before the scheme, and any probe omitting it, is unauthenticated forever. |
| C2 | **The S3 archive is the only durable given.** Everything else is derived. Anything that cannot be derived from it must be explicitly named and separately protected. |
| C3 | **Reference data is community-owned.** Blockpage fingerprints, test lists and network metadata live in external repositories that include additional maintainers and consumers, their own cadence, and change underneath the pipeline. |
| C4 | **The team is small.** A handful of engineers spread across many different software components. Human attention is the scarcest resource. |
| C5 | **Production exists.** ClickHouse and the S3 layout are in production and working. The API, Explorer, and the published `confirmed` / `anomaly` vocabulary have consumers that have been trained on them. Migrating to a different vocabulary carries with it a cost. |
| C6 | **Errors are asymmetric.** OONI output is cited in litigation, press and policy. If we publish that something is blocked with high confidence and it turns out to be inaccurate, this can be used to discredit OONI. If we miss an event that's invisible. They are both failures, but have a different impact. |
| C7 | **Data arrives late, correlated with censorship.** Probes on interfered networks upload late or never, often *because of* the event being measured. Designs should not assumes prompt arrival of data. |
| C8 | **Coverage is uneven and uncontrolled.** The probe population is volunteer, with orders-of-magnitude differences between countries and networks. It's possible to [prioritize the testing](https://docs.ooni.org/backend/ooniapi/services/#prioritization) of certain targets in specific probe_cc, probe_asn pairs, however if no volunteers exist in the region the coverage will remain scarse. Building additional coverage and capacity in a region is costly. |

---

## R. Product requirements

**R1. One question, every resolution.** The system answers *"does blocking of
kind K, in location X, affecting target Y, over time contour Z, exist?"* at
every step of each ladder: endpoint → network → country; URL → domain →
service; hour → arbitrary window. Each step should have a coherent answer and
evidence in support of it.

**R2. Three states** Output distinguishes **blocked** (a
restriction is in place) from **down** (unavailable, without signs of
blocking) from **ok**, with an explicit **insufficient** below the evidence
floor (E3). Separating unavailability from censorship is the hard problem
which motivated the creation of this new pipeline iteration.
In order to preserve backward compatibility, these 3 states should map cleanly
to the `anomaly`/`confirmed` view.

**R3. Mechanism at the evidence's specificity.** Where interference is found,
the output says *how* it is implemented (DNS injection, SNI-triggered reset, a
served blockpage) based on whatever is visibile in the data.
Examples include:
- "TLS RST interference, trigger unidentified"
- "TLS timeout interference, triggered by SNI"

**R4. Events, onsets and endings.** The system detects the onset and
resolution of blocking and notifies humans at **event grain**: one real-world
event maps to approximately one notification carrying its scope (networks,
targets, layers). 

**R5. Four readers, one substrate.** The same data serves end users
(plain-language states), journalists and advocates (artefact-led narratives
with checkable counts), researchers (raw observations and reproducible
queries), and legal or policy consumers (a provenance chain from claim to
evidence). Surfaces should not contradict each other.

**R6. Continuity by mapping.** Existing published vocabulary evolves by
explicit mapping and deprecation. 
This covers the `confirmed` / `anomaly` flags, API outcome
labels, and persisted rule ids.

**R7. Slowness is a form of interference.** Interference that
slows a connection rather than breaking it must be expressible in the
vocabulary and computable from what probes already record: TLS handshake
duration, read counts, and the other timing and volume fields on observations.

---

## E. Evidence

**E1. Facts before conclusions.** What happened (`observations`) is recorded
separately from what it means (`analysis`), and conclusions are recomputable
from the recorded facts.
A change of interpretation (reweighted rules, a split rule, a newly
discovered blockpage fingerprint) must be applicable to history without
reprocessing the raw archive, for every evidence class the pipeline chose to
store.

**E2. Every claim ships its evidence.** A published aggregate carries its
witness (which cell or measurement produced the extreme), the sample size and
denominator behind it, and its independence count: distinct credentialed
probes where available, client-chosen identifiers only as labelled upper
bounds (A3).

---

## P. Provenance and reproducibility

**P1. Rebuildable, with named exceptions.** All pipeline state is recomputable
from the S3 archive plus external resources.

**P2. Versioned scoring inputs.** Every verdict names what produced it: the
ruleset version and the reference-data snapshots. While it's desirable to
re-score usinng newly discovered fingerprints, it should be possible to also
re-score using historical inputs for validation purposes.

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

**PR2. Private by design.** Redaction happens as far
upstream as it can, on the probe and before submission, so that data arriving
at OONI is already minimal. What reaches the pipeline is then treated as
redacted for good: every derived tier and export respects it, and no
enrichment step reconstructs what scrubbing removed.

---

## D. Detection and alerting

**D1. Signals track policy, not infrastructure weather.** Series identity and
detection statistics should be stable under changes that are not internet filtering 
policy changes: probes using different resolvers, a platform renaming its domain, 
a test-list edit. A changepoint must mean the network's behaviour changed, not
that the thing we are measuring changed.

**D2. Severity must not silence.** The severest events (volume collapse,
shutdowns, interfered networks uploading late) must strengthen the detection
signal, or at minimum still reach detection when the data arrives (C7).

**D3. Distinguish the world changing from the pipeline changing.** The
pipeline's own artefacts (rule and fingerprint deploys, reference-data
refreshes, probe releases, collector hiccups) might present a signal similar
to coordinated blocking. Detection should account for this and consider
approaches such as looking at across different networks or countries to
control for it.

## NR. Non-requirements

Explicitly out of scope, each with the trigger that would change that, which
is X1 applied to the requirements themselves. A design is not criticised for
omitting these; it would be criticised for building them now.

| Not required | Why | Trigger to revisit |
|---|---|---|
| Streaming or sub-hourly detection | The collector delivers hourly; consumers act on hours-to-days timescales | A consumer with a demonstrated need to act in minutes |
| High availability of the read path | Durability is required; uptime of measurement API is not mission-critical | The API becoming load-bearing for a partner, or Explorer SLOs |
| Attribution *in the general case*, every interference traced to a party | Fingerprint `scope` already attributes matched blockpages, and the planned middlebox and transit detectors will extend that. What stays out of scope is inferring a party where no such evidence exists | Those detectors landing, which widens the attributable set rather than lifting the evidence standard |
