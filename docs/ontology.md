# Ontology

What the entities mean and what the numbers claim. Read this before
interpreting any output or adding any field.

Companions: [requirements.md](requirements.md) (what it must achieve),
[architecture.md](architecture.md) (how it runs),
[user-guide.md](user-guide.md) (consuming it),
[developer-guide.md](developer-guide.md) (working on it),
[implementation-plan.md](implementation-plan.md) (what happens next).
Bare ids like `E3` or `A4` cite requirements.md.

**Status markers**, used throughout:

| Marker | Meaning |
|---|---|
| **[built]** | In production. Unmarked text describes built behaviour. |
| **[mvp]** | In the current delivery scope. |
| **[later]** | Deferred. Appendix A records the trigger that would revive it. |

---

## 1. Measurement

One nettest run, against one input, by one probe, at one time. Keyed by
`measurement_uid`; grouped into a `report_id` (one probe session) and a
`bucket_date` (the S3 partition it arrived in).

A measurement is raw evidence with the probe's own verdict attached
(`test_keys.blocking`). The pipeline keeps that as `probe_analysis` but does not
trust it. Recomputing centrally is a founding goal (E1), since probe-side
analysis cannot be improved retroactively and varies by probe version.

## 2. Observation

> A timestamped statement about a network condition seen by one vantage point.

The atomic fact: "the TLS handshake to `8.8.4.4:443` with SNI `dns.google`
failed with `connection_reset`". An observation says **what happened**, never
what it means.

One measurement becomes many observations. That decomposition is what makes
ad-hoc research possible: you can ask "every TLS handshake to this address
across all nettests" without the test's designer having anticipated it.

**`obs_web`** holds one row per (measurement, endpoint), merging the DNS answer,
TCP connect, TLS handshake and HTTP transaction for the same address. Merging is
by `transaction_id`, falling back to `ip:port`; anything unmergeable gets its own
row with the other layers null.

Fields worth knowing:

- `hostname` may be **null** (HTTP-only rows) or an IP literal (Telegram
  addresses its datacentres numerically).
- `ip` may be the literal string `"scrubbed"`, from upstream PII redaction.
- `ip_asn`, `ip_cc`, `ip_is_bogon` are enriched as of the measurement's
  timestamp, not today's.
- `resolver_asn`, `resolver_as_cc` record which resolver answered.
- `dns_engine` records transport: `system`, `getaddrinfo`, `udp`, `dot`, `doh`.

**`obs_web_ctrl`** is the web_connectivity test helper's view of the same
hostname. **Only web_connectivity produces it**, which is the main reason
analysis does not extend to other nettests.

**`obs_http_middlebox`** holds HIRL/HFM results. No target and no three-state
verdict, so it is a separate table: shape, not subject matter, is the right
reason to split one.

## 3. Layer

`dns | tcp | tls | http`. **Observed, not inferred**: the DNS query either
failed or it did not.

This is why verdicts are keyed by layer rather than by censorship mechanism. You
are routinely certain about the layer and uncertain about everything else, so
layer is the one dimension that never demands an attribution you cannot make.

One qualifier matters today: whether `resolver_asn == probe_asn`. It is
currently re-derived independently in `detector.py` and in the aggregation API,
which is two definitions of one concept free to drift. **[mvp]** makes it a
stored column.

A known defect: the analysis query restricts the DNS answer set to
`dns_engine IN ('getaddrinfo','system')`, so DoT and DoH answers are silently
excluded from scoring, which discards the entire point of `dnscheck`.

## 4. Target

The subject being assessed.

**Today [built]:** web tests key on `domain(input)`. The four instant-messaging
transformers additionally set `target_id` (`signal/chat`, `telegram/dc_pool`),
because those tests have no per-measurement input at all and would otherwise
collapse into one empty-domain group.

**The rule for what a `target_id` may be:** a stable *name*, never an address.
Endpoints rotate; a target keyed on one would mint a new series at every CDN
change, which is indistinguishable from a blocking event to a changepoint
detector. The same reasoning is why IM targets key on **service role** rather
than hostname: Signal's chat endpoint maps to `signal/chat` whether the archive
calls it `textsecure-service.whispersystems.org` or `chat.signal.org`.

IP:port stays an observation attribute, reachable through the argmax of a query
(§8), never a series key.

**Grouping [mvp]:** "is Facebook blocked?" should be one question rather than a
union the user assembles from domains they would have to already know. The
minimal form is a checked-in config listing group members, expanded to an
`IN (...)` at query time. No hierarchy table and no target-type enum until
something needs them (Appendix A.4).

`combination_rule` is recorded per IM target and describes how endpoint outcomes
combine: `any_of` for redundant pools (WhatsApp's 16 hosts, Telegram's
datacentres), `all_of` for independently required services (Signal's chat,
directory, CDN, SFU, storage). Populated; **no scorer reads it yet**.

## 5. Control

What the same target looks like from somewhere the censor is not.

Two sources, both **[built]**:

1. `obs_web_ctrl`, the test helper's resolution and connection results.
2. Addresses on which *any* probe completed a TLS handshake with a valid
   certificate. Strong evidence an address is genuine, and needs no test helper.

Source 2 trusts a probe-asserted boolean: `tls_is_certificate_valid` is written
by whoever submitted the measurement, and certificates are not revalidated
centrally (§10). A single fabricated measurement can therefore insert an address
into the control and change how every other probe's measurements of that
hostname score. **[mvp]**: an address counts as TLS-consistent only when
asserted by at least k distinct established credentialed probes (§8.4; A4),
and central revalidation is the durable fix
([implementation-plan.md](implementation-plan.md) §3.13).

The control window **is** the analysis window: both subqueries bind the same
bounds as the experiment. That is deterministic and cheap, but narrow. A
hostname the test helper did not resolve in that hour has no control at all, and
the DNS cascade currently cannot distinguish that from a control that disagreed.
Fixing that distinction is **[mvp]**.

Widening that window would need a precomputed aggregate, since scanning a
trailing 24h or 7d of raw `obs_web_ctrl` on every hourly run is not
affordable. Whether it is worth it is a question to settle after the rule fix
above, not before. **[later]**

Not available, and the prerequisite for extending analysis to helper-less
nettests: cross-network baselines ("this hostname resolves fine in 40 other
ASNs"), per-resolver baselines, and historical baselines. All computable from
`obs_web` alone. **[later]**

## 6. Verdict

Per layer, a `(blocked, down, ok)` triple in `[0,1]`, plus the id of the rule
that produced it.

The three-state decomposition is the load-bearing idea in the system.
Separating *unavailable* from *censored* is the hard problem in this field, and
most measurement systems dodge it with a binary anomaly flag.

- **ok**: no filtering detected; the target is reachable.
- **down**: unavailable, but not because of blocking.
- **blocked**: some restriction is in place.

### 6.1 The rule id is the real vocabulary

The numbers are uncalibrated hand-set constants. The **rule id is the more
informative field**, and it is what makes output explainable, re-scorable and
learnable. Several distinctions people reach for a richer numeric model to
express are already carried by the rule vocabulary:

| Rule | Expresses |
|---|---|
| `no_dns_data` | no evidence at this layer |
| `endpoint_untrusted` | evidence exists, but about an address we cannot vouch for |
| `failure_no_ctrl` `(0.5, 0.5, 0)` | not OK, cause undetermined |
| `country_consistent_blockpage` | determinate blocking, with an artefact |
| `bogon_not_in_ctrl` | determinate blocking, and *how* |

Ambiguity is a **property of the rule**, looked up in the registry, not a
quantity that has to be tracked per measurement. This is why the elaborate
uncertainty representation in Appendix A.1 is deferred rather than needed.

### 6.2 Semantics you must respect

- **The triples are not probability distributions.** Most sum to 1;
  `answer_matches_ctrl` sums to 0.9; the no-data rules sum to 0. Do not apply
  probabilistic or possibilistic combination rules to them.
- **`(0, 0, 0)` is an overloaded mask.** It means "no observation at this
  layer", is indistinguishable from "observed and inconclusive", and is *also*
  what a layer scores when an earlier layer already failed. Never read
  `blocked == 0` as evidence of absence. Each rule carries an `Evidence` level
  (`NONE`, `DISCARDED`, `SCORED`) saying which of the three it means; read that
  instead. It is not persisted yet, only computed inside the analysis query.
- **Sample size is invisible** in the triple. Always carry a count.
- **Layers gate each other, per address and not per measurement.** A result is
  uninterpretable when the *address it was obtained against* is not a real
  address for the target: connecting to a censor's blockpage says nothing about
  whether the target is reachable. So TCP and TLS are masked when the address
  came from a lookup that looks poisoned **and** nothing independent vouches for
  it: the control returned it too, or somebody completed a valid handshake for
  the expected name on it (`ip_trusted` in the analysis query).

  This used to key on the measurement's DNS verdict instead, which was the same
  thing only while every address came from one resolver. web_connectivity 0.5
  tests addresses obtained from DNS-over-UDP, DoH and the test helper, so a
  poisoned system lookup no longer implies every address tested was poisoned,
  and "DNS is blocked but the site was reachable via other addresses" became a
  state worth reporting rather than a contradiction.
- **Scores drift with answer-set size.** DNS is scored per answer and the layers
  collapse with `max`, so the more addresses a target returns, the more chances
  one misses the control. A CDN widening its rotation can shift a series with no
  policy change behind it, which is the same false-changepoint hazard the
  target-naming rule in §4 exists to prevent, re-entering through the statistic.

### 6.3 Presentation states **[mvp]**

The triple belongs in the API and in exports. It should not be a headline: three
uncalibrated numbers that do not sum to 1 will be read as probabilities by
everyone who did not write them.

| State | Renders as | Condition |
|---|---|---|
| `blocked` | Blocked | determinate rule **and** a distinctive artefact |
| `likely_blocked` | Consistent with blocking | determinate rule, no artefact |
| `impaired` | Not working, cause unclear | ambiguous rule dominant |
| `down` | Not working, no sign of blocking | down-leaning rule dominant |
| `ok` | Reachable | ok rule dominant |
| `insufficient` | Not enough data | below the evidence floor |

`blocked` versus `likely_blocked` is separated by *evidence kind*, not score.
The artefact is a fingerprint match, a bogon inside the provider's own range, a
certificate issued to a middlebox name: something that settles it alone. This
preserves the `confirmed` / `anomaly` distinction OONI already publishes.

Continuity with the existing flags: `confirmed` → `blocked`; `anomaly` splits
into `likely_blocked` / `impaired` / `down`; `ok` → `ok`; `insufficient` is new.
**`msm_failure` stays on a separate axis** (§10). Measurement validity is not a
network state.

**The rule that makes this rigorous (E3):** below the evidence floor the state
becomes `insufficient`. It never becomes `blocked` with a low confidence
attached. Readers keep labels and discard qualifiers, so weak evidence must
change *what is said*, not footnote it.

Two corollaries: `insufficient` is **not** `ok` (an empty cell rendering as
reachable is the most damaging default available, and happens by accident
whenever a chart plots a rate and `n=0` evaluates to 0); and `insufficient` is
not an error, it is the common and honest state for most cells.

Thresholds are **provisional** until fitted on the labelled corpus (V2). Keep
them in one module and mark them unvalidated in the UI.

## 7. Rule

One branch of a layer's scoring cascade, living in `analysis/rules.py` as data,
with the SQL generated from it.

**Ordering is significant.** `multiIf` takes the first match, so a rule fires
only when everything above it did not. This is a decision tree with hand-set
leaves; the conditions are not mutually exclusive on their own.

Each rule has a stable `rule_id`, persisted per measurement as
`top_{dns,tcp,tls}_rule_id`. Rule ids are a **public contract**: renaming one
breaks historical analysis.

Known weak rule: **`answer_unmatched`** scores `(0.75, 0, 0.25)` for any DNS
answer that matched nothing in the control. It fires routinely for legitimately
rotating CDN and geo-DNS answers, and is the prime false-positive suspect.
Quantifying and fixing it is the first **[mvp]** item.

## 8. Aggregation

The system answers one question at whatever resolution is asked:

> Does blocking of kind K, in location X, affecting target Y, over time contour
> Z, exist?

Location, target and time are each a ladder you can move along.

### 8.1 `max` is right, for a proposition

The question is existential, and `max` is the aggregator for `∃` over a graded
truth value. One blocked address among eight means blocking exists; the answer
is not diluted by the seven that worked.

It is also why free zooming is cheap: `max` is associative, commutative and
idempotent, so max-over-IPs → max-over-measurements → max-over-hours →
max-over-ASNs composes in any order, at any level, with no precomputed rollups.

### 8.2 Never aggregate the triple componentwise

`max` applies to **one proposition**. The triple is a distribution over three
states of **one subject**. Componentwise `max` produces three independent
existential answers in a slot typed as a single state:

```
max(blocked)=1, max(down)=0, max(ok)=1   →  (1, 0, 1)
```

The values are individually true (something is blocked, something else is fine).
The container is wrong. Aggregation must return a **profile**, never a triple:

```
any_blocked   max(blocked)                 the ∃ answer
n_blocked     countIf(blocked > θ)         prevalence
n_total       count()                      denominator
argmax_*      argMax(x, blocked)           which cell, which rule, which failure
```

Three distinct operations are involved and they have different result types:

| Operation | Question | Operator |
|---|---|---|
| Existential | Does blocking exist here? | `max` over one component |
| Prevalence | How much is blocked? | counts |
| Aggregate state | What is the state of this set? | see below |

For a heterogeneous selection the honest aggregate state is "blocked on some
networks, reachable on others". Report it as counts (`3 of 41`) rather than as a
state label.

### 8.3 `max` is monotone in selection size

Widening a query can only raise the answer. A country-wide `max` over a large
country approaches 1 for almost any target and means little alone: widening
manufactures certainty.

So a max must **always** ship with its selection size, the count above
threshold, and its **argmax**: which cell produced it, via which rule. An
existential claim without its witness is an assertion with the evidence deleted.

### 8.4 Aggregation under adversarial input

Measurements arrive from the open internet, so every aggregate must be read
against the question "what could a submitter make this say?" (A1). Two
regimes:

- **Credentialed measurements** carry `probe_id`, issued through OONI's
  [anonymous credential system](https://ooni.org/post/2025-announcing-ooni-new-anonymous-credential-system/):
  a pseudonymous, network-local identifier whose credential attests metadata
  about the probe (age, measurement count, trust status) without revealing the
  raw values. Minting one identity is cheap; what the scheme's Sybil
  resistance makes expensive is a *population* of established identities with
  real age and history. `uniqIf(probe_id, probe_id != '')` therefore counts
  distinct credentialed probes, and any published threshold should further
  weight by the attested standing of those probes rather than treat every id
  equally (A3).

Three consequences for published claims:

- **`max` has a breakdown point of one.** A single fabricated row sets
  `any_blocked = 1` for a whole country-week, and no volume of honest data
  dilutes it. `max` resists the dilution attack and is defenceless against the
  injection one; counts behave the opposite way. Publish both.
- **The argmax is a witness to verify, not proof.** `argMax(x, blocked)`
  returns the most extreme row in the selection, which under contamination is
  the injected one. Open the witness measurement before quoting it.
- **The reporting floor**: a headline claim should be corroborated by at least
  k distinct established credentialed probes (A2, A3), with the witness
  checked by hand. For pre-credential history that standard is unreachable,
  and the honest phrasing is "reported by up to N sessions", which a reader
  can discount.

## 9. Cell state **[mvp]**

The unit the detector and the presentation layer should both read: one
`(target, network, layer, hour)` cell, summarising the measurements in it.

**Store a histogram of rule firings, not a pooled score.**

```
rule_counts   Map(LowCardinality(String), UInt32)
n_measurements
n_probes      uniqIf(probe_id, probe_id != '')   -- "" is unknown, not a probe
```

Everything needed falls out of it, which is why the machinery in Appendix A.1 is
not required:

| Derived | From |
|---|---|
| Verdict | the dominant **outcome class**, not the dominant rule |
| Mechanism | the dominant rule within that class |
| Consensus | the class's share of measurements |
| Sample size | the sum |
| Ambiguity | a property of the dominant rule, from the registry |
| Confidence interval | binomial on the class share |

The class grouping (each rule maps to blocked / down / ok in the registry) is
load-bearing, not cosmetic. The vocabulary is fine-grained on the blocked side
and near-singular on the ok side, so a plurality over raw rule ids splits the
blocked vote: a cell at 40% `answer_matches_ctrl`, 35% `failure_ctrl_ok`, 25%
`answer_unmatched` is 60% blocked-leaning yet its modal rule is the ok one.
Classify first, then take the mode; keep the rule histogram for mechanism. Note
also that a small-n modal share is biased upward by winner's curse, so thin
cells need shrinkage before their share is quoted.

### 9.1 Three uncertainties, not one

The mistake worth avoiding is treating "how much evidence" as a single number.

| Kind | Question | Read from |
|---|---|---|
| **Ambiguity** | Is each measurement individually conclusive? | which rule dominates |
| **Sample size** | How many independent observations? | `n_probes` |
| **Consensus** | Do the conclusive ones agree with each other? | modal share |

| Cell | Ambiguity | Sample | Consensus |
|---|---|---|---|
| 500 measurements, all `failure_no_ctrl` | high | fine | high |
| 2 measurements, both blockpage-matched | low | thin | high |
| 50 measurements, 25 reset / 25 timeout | low | fine | **low** |

Each needs a different response (a better rule, more measurements, an
investigation), so collapsing them loses the information that says which.

### 9.2 Consensus is measured on the rule axis

This is the case that averaging scores gets backwards. Ten measurements at 0.75
average to 0.75; five at 0.75 plus five at 0.80 average to **0.775**, a higher
number from weaker evidence, because the network is behaving inconsistently.

Averaging discards *what produced* the mass, and two rules landing on similar
scores are not the same evidence. A deliberately configured block applies
consistently; a cell splitting between timeouts and resets looks more like
unstable infrastructure, or two differently-configured middleboxes, than policy.
A rule histogram makes this visible for free.

Disagreement discounts the *mechanism* claim hard, and the *blocking* claim only
mildly, since disagreeing rules usually still agree it is blocked. How mild is a
calibration question, not a guess.

### 9.3 Counting independent observers

"37 of 42 measurements" is a weak statement if it is one probe measuring 42
times. What matters is how many *distinct probes* agreed.

`probe_id` **[built]** is the credential-scheme identifier from §8.4. It is on
every observation and on `analysis_web_measurement`, so a guarded `uniqIf`
over it is the count to use.

Two caveats that decide how to write the query:

- **`""` means unknown, not one probe.** Every measurement collected before the
  scheme shipped omits the key. Counting `''` as a probe would collapse an
  entire archive's worth of distinct probes into one. Exclude it:
  `uniqIf(probe_id, probe_id != '')`.
- **Fall back to `uniq(report_id)`** where coverage is thin, which it will be
  for historical windows. A report is one probe session, so it over-counts a
  probe that measured across several sessions and under-counts nothing.

Carry both. Reader-facing thresholds key on the probe count where it is
available and otherwise treat the session count as the upper bound §8.4 says
it is (A3).

### 9.4 Build it as a view, not a table

Start as a `GROUP BY` at query time: over the detector's watchlist the scan is
small, and a view keeps the grain revisable while it is still being learned.

If it is later materialised, it must be a scheduled rebuild per closed window,
never an insert-time materialized view;
[architecture.md](architecture.md) §3.1 explains why the insert-time form
double-counts every re-scored measurement.

## 10. Measurement validity **[mvp]**

A failure string records **what the probe's stack concluded**, not what the
network did.

The reference case: Signal rotated its pinned root CA, and probe versions
carrying the old trust store reported `ssl_invalid_certificate` against valid
certificates. Those score 0.9 blocked (the highest weight in the TLS cascade,
because SSL errors are normally the most suspicious class), and
`top_tls_failure` reports "invalid certificate" as though it described the
network. **The control cannot help**: the defect is in the instrument, not on
the path, so the helper succeeds and the divergence reads as blocking.

This is not exotic. `unknown_failure_map` in `measurement_transformer.py` is
already a hand-maintained list of ~40 platform- and locale-specific error
strings, including Windows messages in four languages.

**The discriminator**, which needs no curation:

> If a failure for a target correlates with **probe attributes** rather than
> **network attributes**, it is an instrumentation defect.

`ssl_invalid_certificate` across 40 unrelated ASNs in 12 countries but only on
`software_version <= 3.15` is a probe bug. The same string on every version but
one ASN is the network. `software_name`, `software_version`, `engine_version`
and `platform` are already stored.

Validity is **orthogonal** to network state (E4), exactly as `msm_failure`
already is. Folding instrument defects into `blocked` has a predictable
direction: it manufactures censorship findings rather than hiding them.

The discriminator has a limit worth stating: it keys on self-reported fields.
`software_version`, `platform` and the network attributes are all supplied by
the submitter, so forged version diversity can dress real interference up as an
instrument defect. Weight the check by credentialed probes (§8.4) rather than
raw rows, and treat it as triage rather than adjudication.

Where the pipeline controls the trust decision it should make it centrally, and
for one nettest it does: `SignalTransformer` passes a `TLSCertStore` holding
both the old and new roots and revalidates itself. Generalising that is blocked
by a storage gap: `peer_certificates` is decoded, used, and discarded, so a
trust-store bug found later cannot be fixed without reprocessing from S3
(Appendix A.5).

## 11. Detection entities

**Series**: currently `(probe_cc, probe_asn, domain)`.

**[mvp] change:** key DNS series on the composite `(probe_asn, resolver_asn)`.
Keying on `probe_asn` alone makes a series flip between blocked and unblocked as
probes in one network rotate between resolvers; the composite key stabilises the
series (D1) without deciding who is responsible.

That last clause is deliberate. Substituting the resolver's AS for the network
key would attribute **on-path injection**, the dominant technique for
national-scale DNS censorship, to the resolver's operator: an injecting
middlebox answers for whatever resolver was addressed, so a probe querying
`8.8.8.8` across it would pin the event on Google's AS. Attributing a series to
the resolver's AS additionally requires evidence that the same resolver behaves
the same way for probes in *other* networks, which is a cross-network check the
pipeline does not yet compute. Until it does, series are stable and attribution
stays with the probe's network (E7).

**Signal**: one of `dns_isp_blocked`, `dns_other_blocked`, `tcp_blocked`,
`tls_blocked`. Each is currently the hourly **median** LoNI across the series, a
statistic of a statistic that discards both spread and count. §9 replaces it.

**CUSUM state** (`event_detector_cusums`): `current_state`, `s_pos`, `s_neg`,
`last_ts` per series and signal. **Path-dependent**: it cannot be recomputed for
a window without replaying from a known-good point, which is why backfilling
requires pausing the live detector. Two further limits: an empty hour produces
no signal, so volume collapse, the severest event in the field, silences the
detector rather than alarming it; and `(0,0,0)`-masked rows must be excluded
from the per-layer signals, or DNS-blocking onset floods the TCP and TLS series
with structural zeros and reads as *unblocking*. The evidence floor of §6.3
applies to alerting too: a changepoint from a series whose every cell would
render "not enough data" should not page anyone.

**Changepoint** (`event_detector_changepoints`): an emitted transition, with
direction, accumulators and the threshold crossed. It carries no reference to
the measurements consumed, and tier-2 rows mutate under it on re-analysis, so an
emitted alert is not currently reconstructible after the fact. The stateless
detector and append-only alert log in the MVP exist to fix exactly this.

**Event [mvp]**: a cluster of correlated changepoints. Does not exist. A
national blocking event currently emits one changepoint per
`(cc, asn, domain, signal)` with no deduplication: up to 1800 rows and an
unbatched Slack flood. Cross-ASN agreement is also the best available
false-positive filter (one ASN is noise, eight simultaneously is an event) and
there is nowhere to compute it.

## 12. Mechanism taxonomy **[mvp]**

*How* interference is implemented, as opposed to *whether* it is happening. This
exists because **ground truth needs a label vocabulary that is independent of
the thing being evaluated** (V1).

### 12.1 Why not just label with rule ids

Rule ids (§7) are the pipeline's *prediction* vocabulary. Using them as the
*label* vocabulary would make evaluation circular: you cannot measure whether a
rule is right using a label that is defined as "the rule fired". Three concrete
problems:

- **Circularity.** A corpus labelled `bogon_not_in_ctrl` can only tell you the
  rule reproduces itself.
- **Rot.** Rule ids are a public contract but they still change as rules split.
  Splitting `failure_ctrl_ok` by failure class is already scheduled
  ([implementation-plan.md](implementation-plan.md) §3.3), and every label
  referencing it would need re-adjudicating.
- **Register.** A human looking at a measurement says "DNS injection returning
  an address in the ISP's own range", not `bogon_not_in_ctrl`.

So: **labels use the taxonomy, predictions use rule ids, and evaluation is a
mapping between them** (§12.6). The taxonomy also outlives any particular
scoring engine, which is what lets a corpus stay useful across a rewrite.

### 12.2 Structure

Nodes are dot-separated paths, `<layer>.<action>.<qualifier>`:

- **layer** is where the interference *manifested*, matching §3. Observed, not
  inferred.
- **action** is what was done: `injection`, `reset`, `mitm`, `throttle`, or a
  bare failure mode such as `timeout`.
- **qualifier** is a per-action detail whose meaning depends on the action: the
  trigger for `reset`/`throttle`, the payload for `injection`, the certificate
  class for `mitm`. It is a taxonomy, not a grammar; do not assume the third
  segment means the same thing everywhere.

Every prefix is itself a valid node. `tls.mitm` is a legitimate label; so is
bare `tls`.

### 12.3 Vocabulary, v1

Internal nodes are marked. Anything not marked is a leaf.

```
dns                                    (internal)
dns.injection                          (internal)
dns.injection.blockpage                answer is a known blockpage address
dns.injection.bogon                    answer is a bogon or provider-internal address
dns.injection.other                    answer is injected but is neither of the above
dns.nxdomain                           NXDOMAIN for a name that resolves elsewhere
dns.refused                            REFUSED
dns.timeout                            no answer

tcp                                    (internal)
tcp.reset                              RST during connection establishment
tcp.timeout                            SYN unanswered
tcp.refused                            RST in response to SYN

tls                                    (internal)
tls.reset                              (internal)
tls.reset.sni                          RST after ClientHello, triggered by the server name
tls.reset.other                        RST during handshake, trigger unidentified
tls.timeout                            handshake stalls
tls.mitm                               (internal)
tls.mitm.self_signed                   presented certificate is self-signed
tls.mitm.ca_signed                     validly signed but for an unexpected name or issuer
tls.throttle.sni                       [unmeasurable today]

http                                   (internal)
http.blockpage                         a block page is served
http.redirect                          redirect to a block page
http.error                             status-code refusal (403 and similar)
http.reset.host                        RST after the request line or Host header
http.timeout                           no response
http.throttle.host                     [unmeasurable today]

ip                                     (internal)
ip.unreachable                         ICMP unreachable or no route
ip.prefix_null_route                   [needs co-affected evidence]
```

Three deliberate choices, each of which resolves an ambiguity a labeller would
otherwise hit:

**Reset lives at the layer where it manifested.** An earlier sketch had both
`tcp.reset.sni` and `tls.reset.sni`, which is ambiguous: the RST is a TCP event
but the trigger is TLS content. The rule is the one already in §3: layer is
where it *manifested*. A reset during connection establishment is `tcp.reset`; a
reset after the ClientHello is `tls.reset.sni`; a reset after the Host header is
`http.reset.host`.

**`throttle` is an action, not a family.** `tls.throttle.sni` sits alongside
`tls.reset.sni`, which makes reset-versus-throttle-under-the-same-trigger
genuine alternatives inside one frame rather than artificially split across two.

**There is no `access_denied.geo`.** Geoblocking is an ordinary technique
(`http.error`, `http.redirect`) attributable to the server rather than the
network. That attribution belongs on the locus field (§12.5), not in the
technique path. **No value may appear on two axes.**

Nodes marked `[unmeasurable today]` are reserved deliberately. `web_connectivity`
measures reachability, not throughput, so nothing can currently produce them.
Reserving the path is better than minting one under deadline later; treat their
absence from a corpus as "never measured", not "never happened".

### 12.4 Label the deepest node the evidence supports

The central rule, and the reason for a hierarchy rather than a flat enum.

A labeller who sees a reset but cannot tell what triggered it labels
`tls.reset`, not `tls.reset.sni`. A labeller who sees a failed handshake but has
no certificate to inspect labels `tls`, not `tls.mitm`.

**Internal nodes are the common case, not a fallback.** Most evidence does not
reach a leaf, and forcing a leaf choice manufactures precision the measurement
does not contain. A label of `tls.mitm` is a complete, correct label.

### 12.5 The label record

A ground-truth label is not a single string. Verdict and mechanism are separate
axes, and mechanisms are multi-label.

| Field | Meaning |
|---|---|
| `measurement_uid` | What is being labelled |
| `verdict` | `ok` / `down` / `blocked` / `unknown` |
| `mechanisms` | Set of taxonomy nodes. Empty unless `verdict = blocked` |
| `locus` | Per mechanism: `network` / `server_side` / `unknown` |
| `evidence` | Free text: what the labeller saw that decided it |
| `labeller`, `labelled_at` | Provenance |
| `taxonomy_version` | Which vocabulary the nodes come from |

Four properties this has to have:

- **Verdict and mechanism are separate.** An outage has a verdict of `down` and
  no mechanism. Mechanism describes how interference is implemented; if there is
  no interference there is nothing to describe.
- **Mechanisms are a set.** Networks routinely run DNS injection and SNI
  filtering at once. `{dns.injection.bogon, tls.reset.sni}` is a normal label.
- **Exclusive within a family.** Two nodes from the same top-level branch should
  not both appear for one measurement. If the evidence seems to demand it, the
  right label is their common ancestor.
- **`locus` is recorded even though the pipeline cannot infer it** (it is
  deferred, Appendix A.2). This is a feature: ground truth should record what is
  true, not what the current engine can compute. Labels where a human could tell
  server-side refusal from network blocking are exactly the evidence for whether
  building that inference is worth it.

### 12.6 Evaluation is hierarchical, not exact-match

A prediction of `tls.mitm` against a truth of `tls.mitm.self_signed` is
**correct but imprecise**, not wrong. Scoring it as a miss would penalise the
engine for the honesty §12.4 requires.

Use hierarchical precision and recall: expand both prediction and truth to
include all their ancestors, then compare as sets.

```
hP = |anc(pred) ∩ anc(truth)| / |anc(pred)|
hR = |anc(pred) ∩ anc(truth)| / |anc(truth)|
```

Under-specific predictions lose recall and keep precision; over-specific ones
lose precision and keep recall. That asymmetry is what you want, because
over-claiming a mechanism is the more damaging error.

Report three numbers separately, since they call for different fixes:

| Outcome | Means | Fix |
|---|---|---|
| Exact | leaf agreed | none |
| Under-specific | predicted an ancestor of truth | a rule needs more evidence plumbed in |
| Over-specific or sibling | predicted a descendant, or a different branch | a rule is wrong |

The mapping from rule id to node is maintained alongside the rules, since it is
what evaluation joins on. Some rules map to an internal node by nature, and some
map conditionally on the failure string:

| Rule | Node |
|---|---|
| `dns/country_consistent_blockpage` | `dns.injection.blockpage` |
| `dns/bogon_not_in_ctrl` | `dns.injection.bogon` |
| `dns/tls_inconsistent_not_in_ctrl` | `dns.injection` *(internal)* |
| `dns/answer_unmatched` | `dns.injection` *(internal, weak)* |
| `dns/failure_ctrl_ok` | `dns.nxdomain` / `dns.timeout` / `dns.refused`, by failure |
| `tcp/failure_ctrl_ok` | `tcp.reset` / `tcp.timeout`, by failure |
| `tls/failure_ctrl_ok_ssl` | `tls.mitm` *(internal)* |
| `tls/failure_ctrl_ok_reset` | `tls.reset.sni` |
| `tls/failure_ctrl_ok_other` | `tls` *(internal)* |

That table is also a to-do list: every internal-node entry marks a place where
the evidence to reach a leaf usually exists but no rule reads it. Going from
`tls.mitm` to `tls.mitm.self_signed` needs the certificate issuer, which
`obs_web` already stores.

### 12.7 Versioning

- `taxonomy_version` on every label, so a corpus stays interpretable after the
  vocabulary moves.
- **Node ids are append-only** (X2). Adding a leaf under an existing internal node is
  backward compatible: old labels at the parent stay valid, just less specific.
- **Never re-point an existing id.** Deprecate and add rather than redefine; a
  silently redefined node invalidates every label using it, with no way to tell
  which.
- Renaming requires re-adjudication, so treat the paths as permanent.

Align outward where it is free (pipeline v5, ICLab, RFC 7754 filtering terms)
and inward to the dot-separated `outcome_label` values the aggregation API
already returns, which is not optional if those consumers are to keep working.

### 12.8 The event label record

The second label grain: whole incidents rather than single measurements, used
by the replay harness to score the detector (event recall, detection latency,
false alerts per quiet series-week). Fifty to 150 rows, hand-curated from
adjudicated incidents. This grain is **implemented**: the full field list,
export format and storage model live in
[label-corpus-design.md](label-corpus-design.md) §1.2, and the editor is
[event-labeler.html](event-labeler.html). What matters semantically:

- **Scope is explicit about ignorance.** `asn_scope_kind` and
  `target_set_kind` carry `unknown`, so "national, but we do not know which
  ASNs" is representable without guessing.
- **Timing is an interval, not an instant.** Onset and resolution each carry
  an earliest/latest bracket, because published reports date events coarsely
  and the harness scores onsets with tolerance windows. Null resolution
  bounds mean not known to have ended.
- **Mechanisms are a set here too** (§12.5), from the same taxonomy as the
  measurement labels, and a per-event mechanism is usually *less* specific
  than a per-measurement one: an incident report that says "DNS blocking"
  labels `dns`, not a leaf.
- **`false_positive_event` is first-class.** An adjudicated false alarm (the
  Signal-CA class) is the negative half of the corpus and a must-not-fire
  regression test for the detector.
- **`scoreable` keeps recall honest.** An event on networks where OONI had no
  probes cannot be detected by any detector; the harness excludes and counts
  those rows rather than scoring them as misses.
- **An event spanning countries is one row per `probe_cc`**, sharing sources
  and rationale. The harness replays per-country series, so a multi-row event
  falls out naturally; do not invent a regional grain for a hand-curated
  corpus.
- **Supersede, never overwrite:** a re-adjudication writes a new row and links
  the old one.

Everything a consumer might want beyond that (`ongoing`, the affected layers,
the size band) is derived, never stored, so a curator cannot enter a
contradiction as data.

## 13. Tradeoffs

Stated as requirement conflicts, in the assessment vocabulary of
[requirements.md](requirements.md).

### 13.1 Three states rather than a binary flag

**Buys** M2: the distinction users actually need, and the one OONI is uniquely
positioned to make. **Costs** a rule set that must apportion across three
states even when the evidence only separates one from the other two. No
requirement is traded; the price is paid in rule-design effort.

### 13.2 Verdicts keyed by layer

**Buys** a primary key that is observed rather than inferred, so no row
demands an attribution the evidence cannot make (E7). **Costs** the ability to
answer "what mechanism" directly; the rule id supplies it instead, at whatever
specificity the evidence supported, which is exactly M3's standard.

### 13.3 Graded confidence rather than a discrete label

**Buys** honesty about uncertainty and lets consumers pick a threshold.
**Costs** false precision: an uncalibrated 0.75 published bare invites the
probability reading E6 forbids. §6.3 is the mitigation, collapsing to states
at the presentation boundary (E3) and keeping the numbers internal until the
corpus calibrates them.

### 13.4 Hand-authored rules rather than a learned model

**Buys** verdicts that trace to a named rule with a stated condition: the
"explainable beats optimal" priority rule, and the provenance chain M5's legal
reader needs. OONI's output is cited in litigation and press; "the model said
so" is not a defensible provenance chain. **Costs** uncalibrated weights
(repaired through the corpus: E6, V2) and a cascade that discards
corroboration, since first match wins and two independent weak signals never
combine. The intended fix keeps the structure and learns the leaves, which
with rule ids and a corpus is counting with a prior.

### 13.5 Existential `max` as the default

**Buys** the right answer to M1's question, and a monoid structure that makes
free zooming cheap and order-independent. **Costs** monotonicity in selection
size, mitigated by the E2 discipline (always ship size, prevalence and argmax)
rather than by the schema, a remembered rule, which O2 prices as weaker than
a mechanism; and a breakdown point of one under fabricated input (§8.4), which
is why headline claims carry the established-probe floor A2 and A3 demand.

### 13.6 Rule histogram rather than a pooled probabilistic state

**Buys** E5 whole: consensus, sample size and ambiguity from one cheap
structure, with no new formalism, composing with everything already shipped.
**Costs** the ability to express partial belief *within* a single measurement,
a cost the requirements decline to buy (the Dempster–Shafer row of the
non-requirements table). If the trigger fires, Appendix A.1 is the upgrade
path.

---

# Appendix A: deferred elaborations

Each of these was designed, then cut as more machinery than the problem
currently justifies. Recorded with the trigger that would revive it (X1), so
picking one back up is a decision rather than drift.

### A.1 Mass over subsets (Dempster-Shafer)

Represent verdicts as a mass function over subsets of `{ok, down, blocked}`,
with `m(Θ)` for ignorance and `m({down, blocked})` for "not OK, cause
undetermined", reporting `[Bel, Pl]` intervals.

**Why cut:** the rule vocabulary already carries these distinctions
categorically (§6.1). `no_dns_data` *is* `m(Θ)=1`; `failure_no_ctrl` *is*
`m({down,blocked})`. The formalism re-derives from numbers what the rule id
states directly.

**Trigger:** a single measurement needing partial belief across states
in a way no rule split can capture, or a requirement to fuse independent
evidence sources per measurement.

### A.2 Locus as a first-class axis

`resolver | isp_middlebox | transit | server_side | unknown`, inferred from
cross-network and cross-transport evidence, with attribution following it.

**Why cut:** the concrete win is alert stability, and §11's `resolver_asn`
regrain delivers that for one `GROUP BY`. The full axis additionally needs
cross-vantage-point inference that does not exist.

**Trigger:** needing to publish *who* is responsible (`server_side` versus ISP
is the high-value case for end users), or false positives traceable to
server-side refusal being reported as network blocking.

### A.3 Hierarchical mechanism taxonomy (promoted, see §12)

Previously deferred on the grounds that rule ids already act as mechanism labels
at the granularity the evidence supports.

**The trigger fired:** ground-truth labelling needs a vocabulary independent of
the rules being evaluated, or the corpus is circular and rots on every rule
split. Specified in §12.

What remains deferred is *pipeline-side inference* of mechanism: emitting
mechanism labels as pipeline output, with beliefs attached. The rule-id mapping
in §12.6 is sufficient for evaluation and needs no new output.

### A.4 Target hierarchy as data

A `target_type` enum, a `target_hierarchy` edge table, groups and categories as
first-class queryable rungs.

**Why cut:** a checked-in group config expanded to `IN (...)` at query time
answers "is Facebook blocked?" without a schema.

**Trigger:** group membership needing to vary by country or over time, or
consumers other than the UI needing to resolve groups.

### A.5 Content-addressed certificate store

A `certificates` table keyed by chain fingerprint, written once per unique
chain, so trust-store bugs are corrected by re-scoring rather than reprocessing
from S3.

**Why cut:** a real gap, but the §10 confound check catches the same class of
defect without new storage.

**Trigger:** a second Signal-CA-class incident, or a need to re-run certificate
validation historically.

### A.6 Tier 3 as a materialised table

`analysis_target_state` with pooled state, credible intervals and provenance.

**Why cut:** row-count analysis suggests it may be larger than the tier it
summarises (§9.4).

**Trigger:** measurement showing the view is too slow for the detector or the
API at production volume.
