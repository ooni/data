# User guide

How to consume the datasets this pipeline produces, and what the numbers can and
cannot support.

Read [ontology.md](ontology.md) first if you intend to interpret any verdict.
The semantics have sharp edges that are easy to get wrong.

Companions: [requirements.md](requirements.md) (the obligations these caveats
enforce), [architecture.md](architecture.md),
[developer-guide.md](developer-guide.md),
[implementation-plan.md](implementation-plan.md).

**Status markers**: unmarked is built and queryable today; **[mvp]** is in the
current delivery scope; **[later]** is deferred.

---

## 1. Which dataset answers which question

The system answers one question at whatever resolution you choose:

> **Does blocking of kind K, in location X, affecting target Y, over time
> contour Z, exist?**

Each coordinate is a ladder you can move along: location from endpoint to ASN to
country, target from URL to domain to platform group, time from hour to
arbitrary window. §3.4 explains why that works and what it costs.

| Question | Where to look |
|---|---|
| What exactly did a probe see? | `obs_web`: raw observations, no interpretation |
| What did the test helper see? | `obs_web_ctrl` (web_connectivity only) |
| Is this target blocked, down, or fine? | `analysis_web_measurement` |
| *Why* do we think so? | `analysis_web_measurement.top_*_rule_id` |
| Which platform endpoint was measured? | `obs_web.target_id` |
| When did blocking start or stop? | `event_detector_changepoints` |
| Which domains are in which category? | `citizenlab` |
| Which measurements look untrustworthy? | `faulty_measurements` |

Access is by direct ClickHouse query or the HTTP API (§4). SQL is more capable;
the API is stable and convenient.

---

## 2. Reading a verdict

Each row of `analysis_web_measurement` is one measurement against one target,
with a `(blocked, down, ok)` triple per layer.

```sql
SELECT measurement_start_time, probe_cc, probe_asn, domain,
       dns_blocked, dns_down, dns_ok, top_dns_failure, top_dns_rule_id,
       tcp_blocked, tls_blocked
FROM analysis_web_measurement
WHERE domain = 'x.com' AND probe_cc = 'TR'
  AND measurement_start_time > now() - INTERVAL 7 DAY
ORDER BY measurement_start_time DESC
LIMIT 50;
```

`dns_blocked = 0.9` reads as "strong evidence of DNS-layer interference for this
measurement". It is *not* a calibrated probability.

### Rule ids are the field to lead with

`top_dns_rule_id` names the rule that produced the score, and carries more
information than the number does:

| Rule id | Means |
|---|---|
| `country_consistent_blockpage` | Matched a known blockpage fingerprint for this country |
| `bogon_not_in_ctrl` | A bogon address the control never returned |
| `tls_inconsistent_not_in_ctrl` | Certificates fail for this answer and the control never returned it |
| `failure_ctrl_ok` | Resolution failed here but succeeded in the control |
| `answer_unmatched` | Matched nothing in the control. **Weak, see §3.2** |
| `answer_matches_ctrl` / `tls_consistent_answer` | Evidence the answer is genuine |

Full set with weights and rationale in `analysis/rules.py`.

### Getting back to the evidence

Every analysis row carries `measurement_uid`:

```sql
SELECT hostname, ip, ip_asn, ip_is_bogon, dns_failure, dns_answer,
       tcp_failure, tls_failure, tls_is_certificate_valid,
       tls_end_entity_certificate_issuer_common_name
FROM obs_web
WHERE measurement_uid = '<uid>';
```

`https://explorer.ooni.org/m/<measurement_uid>` renders the original.

**Lead with the artefact.** "DNS returned `10.10.34.36`, an address inside the
provider's own network that does not host this site" is more persuasive than any
score, and it is what survives contact with an ISP's press office.

---

## 3. Caveats you must respect

Each of these will produce a wrong conclusion if ignored.

### 3.1 The scores are uncalibrated expert judgment

Weights are hand-assigned and have never been validated against labelled data.
`0.9` means "whoever wrote the rule considered this strong evidence", not "90%
of such cases are blocking". Quote rule ids and artefacts; be careful quoting
the decimals as probabilities.

### 3.2 `answer_unmatched` is weak and common

Any DNS answer matching nothing in the control scores `0.75` blocked. It fires
routinely for legitimately rotating CDN and geo-DNS answers. **Treat it as a
lead, not a finding**, and check whether the answer's ASN is plausible for the
target.

### 3.3 Zero does not mean "not blocked"

`(0, 0, 0)` is a mask meaning "no observation at this layer". It is
indistinguishable from "observed and inconclusive", and it is *also* what a
layer scores when an earlier layer already failed: if DNS is blocked, TCP and
TLS for that row are deliberately zeroed, because addresses from an
untrustworthy resolver cannot be assessed.

Filter on `dns_ok > 0 OR dns_blocked > 0 OR dns_down > 0` rather than assuming
`blocked = 0` means healthy.

### 3.4 `max` answers an existential question

Scores aggregate by `max`, deliberately. The question is existential and `max`
is the aggregator for `∃`: one blocked address among eight means blocking
exists, undiluted by the seven that worked. It is also why you can zoom freely,
since `max` is associative, commutative and idempotent.

**The catch: `max` is monotone non-decreasing in selection size.** Widening a
query can only raise the answer, so a country-wide max approaches 1 for almost
any target and means little alone.

Never quote a max alone. Always carry the selection size, the count above
threshold, and the **argmax**:

```sql
SELECT
    probe_cc,
    max(dns_blocked)                      AS any_blocked,   -- the ∃ answer
    countIf(dns_blocked > 0.5)            AS n_blocked,     -- prevalence
    count()                               AS n_total,
    argMax(probe_asn, dns_blocked)        AS worst_asn,     -- the argmax
    argMax(top_dns_rule_id, dns_blocked)  AS worst_rule
FROM analysis_web_measurement
WHERE domain = 'x.com' AND measurement_start_time > now() - INTERVAL 1 DAY
GROUP BY probe_cc
HAVING n_total > 20;
```

"Something here is blocked" is only usable alongside "specifically, this one".

**The argmax is a witness to check, not proof.** Measurements are submitted from
the open internet, and `argMax(x, blocked)` returns the most extreme row in the
selection, which under fabricated input is the fabricated one. A single injected
row sets `any_blocked = 1` for a whole country-week. Before publishing: open the
witness measurement, and require the finding to be corroborated by several
distinct established credentialed probes (§3.8). See
[ontology.md](ontology.md) §8.4.

### 3.5 Never aggregate the triple componentwise

```sql
-- WRONG: three existential answers wearing a state vector
SELECT max(dns_blocked), max(dns_down), max(dns_ok) FROM ...
```

This can return `(1, 0, 1)`, incoherent as a state. The values are individually
true (something is blocked, something else is fine); the container is wrong.
`max` applies to one *proposition*; the triple is a distribution over three
states of one *subject*. Use the profile shape above instead.

For a heterogeneous selection, report counts ("blocked on 3 of 41 networks")
rather than a single state label.

### 3.6 `top_*_failure` and `top_*_rule_id` may describe different rows

`top_dns_failure` is `anyHeavy` (modal) while `top_dns_rule_id` is
`argMax(..., dns_blocked)`. Different orderings, so **the failure string does not
necessarily come from the row that produced the score**. When you need the
failure that explains a score, take it with the same ordering, as
`argmax_failure` does above.

### 3.7 A failure string describes the probe, not always the network

`tls_failure = 'ssl_invalid_certificate'` records what the probe's TLS stack
concluded. Signal rotated its pinned root CA, and probe versions carrying the
old bundle reported invalid certificates against valid chains. Those score 0.9
blocked, and the control cannot help because the defect is in the instrument
rather than on the path.

Before attributing an `ssl_` failure to a network, check whether it partitions
by probe attributes or network attributes:

```sql
SELECT software_version, count() AS n, uniq(probe_asn) AS asns, uniq(probe_cc) AS ccs
FROM analysis_web_measurement AS a
JOIN obs_web AS o USING (measurement_uid)
WHERE a.domain = '<target>' AND o.tls_failure LIKE 'ssl_%'
GROUP BY software_version ORDER BY n DESC;
```

Wide ASN spread with narrow version spread is an instrumentation defect. Narrow
ASN spread across all versions is the network. See
[ontology.md](ontology.md) §10.

### 3.8 Sample size is invisible

A score from one measurement is byte-identical to one from five hundred. Carry a
`count()` alongside any aggregate and discount thin cells.

What matters is how many *distinct probes* agreed, not how many measurements
there were: 42 measurements may be one probe measuring 42 times. `probe_id` is a
pseudonymous probe identifier issued via [anonymous
credentials](https://ooni.org/post/2025-announcing-ooni-new-anonymous-credential-system/),
carried on observations and on `analysis_web_measurement`. Its credential
attests each probe's age, measurement count and trust status without revealing
them, so while minting a single identity is cheap, a population of
*established* probes is expensive to fake. `n_probes` is the count that holds
up under adversarial submission, and it holds up best restricted to
established probes. `report_id` is client-chosen and free to mint, so
`n_sessions` is an upper bound on independence, not a count of observers.

**Exclude the empty string when counting.** It means "collected before the
scheme shipped", not "one probe", and counting it would collapse a whole archive
into a single observer:

```sql
SELECT domain,
       uniqIf(probe_id, probe_id != '') AS n_probes,
       count()                          AS n_measurements
FROM analysis_web_measurement
WHERE probe_cc = 'IT' AND measurement_start_time > now() - INTERVAL 7 DAY
GROUP BY domain;
```

### 3.9 A missing control looks like a contrary control

The control is built from the same hour as the measurements being scored. If the
test helper did not resolve a hostname in that hour there is no control for it,
and the DNS cascade cannot tell "the control returned something different" from
"there was nothing to compare against". Both land on `answer_unmatched` at 0.75
blocked.

So a `answer_unmatched` verdict on a rarely-measured hostname is weak evidence
twice over. Check whether control data exists for that hostname and hour before
treating it as a finding. Fixing this is **[mvp]**.

### 3.9a Counts can read double right after a run

The hourly and the nightly DAG both process every window into a
`ReplacingMergeTree`, and deduplication is eventual, so until parts merge a
count query can return up to twice the real number. "84 of 84 measurements"
minutes after the nightly run may be 42. For any count you intend to publish,
read with `FINAL`:

```sql
SELECT count() FROM analysis_web_measurement FINAL
WHERE domain = '<target>' AND probe_cc = '<cc>'
  AND measurement_start_time > now() - INTERVAL 1 DAY;
```

`max`-based statistics are immune (duplicates cannot raise a max); counts and
averages are not.

### 3.10 Only web_connectivity is meaningfully analysed

All 13 transformers write observations, but the analysis keys on the URL's
domain, which the IM tests do not have. Their observations *are* usable:
`obs_web.target_id` identifies which platform endpoint was measured, so query
`obs_web` directly for those.

### 3.11 The detector watches a narrow domain list

Citizenlab global `GRP` plus a hardcoded `twitter.com`: social media and
messaging. Country-specific news blocking is structurally invisible to
changepoint detection today. Note the hardcoded entry predates the domain's
rename to x.com, so the flagship platform is plausibly unmonitored; treat the
watchlist as needing review, not as a statement of coverage.

### 3.12 There is no HTTP-layer verdict

`http_blocked` does not exist. HTTP blockpage detection, the classic
"confirmed" signal, is not implemented. Plaintext HTTP blocking, content
injection and 302-to-blockpage are invisible here. **[mvp]**

---

## 4. HTTP API

| Endpoint | Returns |
|---|---|
| `GET /api/v1/aggregation/analysis` | Aggregated verdicts with outcome labels |
| `GET /api/v1/measurements` | Per-measurement analysis rows |
| `GET /api/v2/observations` | Raw observations |
| `GET /api/v2/aggregation/observations` | Aggregated observations by failure etc. |

The analysis aggregation returns dot-separated `outcome_label` values:
`dns_isp.blocked.<failure>`, `dns_other.blocked.<failure>`,
`tcp.blocked.<failure>`, `tls.blocked.<failure>`, with an `outcome_value`. The
`dns_isp` / `dns_other` split is by whether the probe used its ISP's resolver.

Two warnings:

- **It is derived in the API layer, not stored**, and the same derivation exists
  independently in the detector. It does not correspond to a stored column.
- **`dns_other` is attributed to the wrong network.** When a non-ISP resolver
  censors, the interference belongs to the *resolver's* AS, but the row is keyed
  on `probe_asn`. So `dns_other` under one `probe_asn` mixes every resolver its
  probes happened to use, and a series can flip between blocked and unblocked
  purely because probes rotated resolvers. Group by `resolver_asn` yourself:

```sql
SELECT resolver_asn, resolver_as_cc,
       max(dns_blocked) AS any_blocked, count() AS n
FROM analysis_web_measurement
WHERE domain = '<target>' AND measurement_start_time > now() - INTERVAL 7 DAY
GROUP BY resolver_asn, resolver_as_cc
HAVING n > 10 ORDER BY any_blocked DESC;
```

Making this the detector's default grain is **[mvp]**.

---

## 5. Changepoints

`event_detector_changepoints` records transitions, one row per
`(probe_cc, probe_asn, domain, block_type)` with `change_dir` (`+1` blocked,
`-1` unblocked).

```sql
SELECT ts, probe_cc, probe_asn, domain, block_type, change_dir
FROM event_detector_changepoints
WHERE ts > now() - INTERVAL 30 DAY AND change_dir = 1
ORDER BY ts DESC;
```

Three caveats:

- **There is no event entity.** A national block emits one changepoint per
  `(cc, asn, domain, layer)`, potentially ~1800 rows for one event. Cluster them
  yourself by `(cc, domain, ts)` before drawing conclusions. **[mvp]**
- **Detector state is path-dependent.** Backfilling analysis without pausing the
  detector corrupts its accumulators.
- **Cross-network agreement is a filter, not a guarantee.** A changepoint on one
  network is noise; the same one on eight simultaneously is *usually* an event,
  but the pipeline's own false positives (a CDN reconfiguration, a probe-release
  defect, a fingerprint update) are common-cause and present with exactly the
  same signature. Check whether the same target moved in other countries in the
  same hour before treating simultaneity as confirmation.
- **Alerting only fires on step changes in promptly-arriving data.** Measurements
  arriving after their hour's run update the tables but never reach detection,
  and an hour with no measurements produces no signal at all: a total shutdown
  silences the detector rather than alarming it. Absence of a changepoint is not
  absence of an event; check the analysis tables for the window you care about.

---

## 6. Reporting guidance

**Never aggregate method to a country by majority vote.** Method varies by ISP
within a country and that variation *is* the finding. Eleven Spanish ASNs, one
doing TLS interception, is a better story than a national label. Country-level
statements should read "at least one network was observed doing X", and the
default view should be an ASN × method matrix.

**Distinguish server-side refusal from network blocking.** "This site refuses
connections from your country" and "your ISP blocks this site" are different
claims that read identically to users. The pipeline does not label this axis, so
check manually: an origin 403 or geo-redirect is not censorship by the user's
network.

**Distinguish collateral from targeted blocking, by hand.** A domain caught by
an IP block aimed elsewhere should not be reported like a deliberate block.
Check whether unrelated domains on the same address went dark simultaneously.
This will not be automated: it is a claim about *other* targets and about
intent, and needs investigatory work.

**Prefer counts to averaged scores.** "37 of 42 measurements from AS12345 showed
a bogon DNS answer" is checkable and hard to dispute. "Average blocking score
0.71" is neither.

**Do not attribute DNS interference seen through an external resolver to
anyone without more evidence.** On-path injection answers for whatever
resolver was addressed, so divergent answers through `8.8.8.8` do not
implicate Google, nor, on their own, the ISP. Check whether the same resolver
behaves the same way for probes in *other* networks before naming either;
until then, write "the resolver used by this probe".

**Say what granularity you queried at.** Because `max` only rises as a selection
widens (§3.4), "blocking of X exists in country Y" is weaker than it sounds
unless you also say how many networks and measurements were behind it, and which
one produced the answer.

---

## 7. Presenting findings to end users **[mvp]**

The design for the non-specialist surface. State vocabulary in
[ontology.md](ontology.md) §6.3; an interactive version of these sketches is in
[explorer-mockup.html](explorer-mockup.html).

### 7.1 Layered disclosure

| Layer | Content | Reader |
|---|---|---|
| 1 Finding | The observable fact, in one sentence | Anyone |
| 2 State + basis | One of the six states, plus the counts behind it | Anyone |
| 3 Method | The rule that fired, and the evidence artefact | Journalist, advocate |
| 4 Raw | Triple, `rule_id`, measurement links, query | Researcher, lawyer |

The ordering is the inverse of how the pipeline computes. Internally the verdict
comes first and the mechanism refines it; for a reader the mechanism is more
persuasive, because a distinctive artefact settles the question on its own. Lead
with what you can show.

### 7.2 Lead with the artefact

Not `x.com  BLOCKED  confidence 0.78`, but:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  ▲  Blocked                                    AS12345 · IT  │
  │                                                              │
  │  DNS resolution for x.com returned 10.10.34.36, an address   │
  │  inside your provider's own network that does not host the   │
  │  site.                                                       │
  │                                                              │
  │  Seen in 37 of 42 measurements from this network             │
  │  over the last 7 days.                                       │
  │                                                              │
  │  What this means for you                                     │
  │  Your provider's DNS is returning a false address. A         │
  │  different resolver, or encrypted DNS, may reach the site.   │
  │                                                              │
  │  Method  bogon_not_in_ctrl                    [ evidence ▾ ] │
  └──────────────────────────────────────────────────────────────┘
```

The state label is present but subordinate. The sentence a reader repeats to
someone else is the artefact sentence.

### 7.3 Confidence is a count, not a percentage

Show "seen in 37 of 42 measurements", never "Blocked (42% confidence)". Readers
keep labels and discard qualifiers, so below the evidence floor the **state
itself** changes to "Not enough data".

Build that sentence on the number of distinct probes
(`uniqIf(probe_id, probe_id != '')`) rather than the raw measurement count.
"Seen by 9 probes on this network" is a stronger claim than "seen 42 times",
and it is the one a reader will assume you meant.

### 7.4 Colour is redundant, never load-bearing

- **Never colour-only.** Every state needs a text label and a distinct glyph.
- **Avoid a red/green primary axis.** Red-green deficiency is the common one.
- **Do not use a single hue ramp.** "Not working, no sign of blocking" is not
  halfway between reachable and blocked; it is a different axis.

| State | Glyph | Note |
|---|---|---|
| Reachable | `●` | |
| Not enough data | `▨` | **hatched, neutral**; must not read as positive |
| Not working, no sign of blocking | `○` | |
| Not working, cause unclear | `◐` | |
| Consistent with blocking | `△` | |
| Blocked | `▲` | reserved for artefact-backed |

The hatched treatment matters most: rendering an empty cell as pale green
happens by accident whenever a chart plots a rate and `n=0` evaluates to 0.

### 7.5 Time series must show how much data is behind them

A line at 0.8 from three measurements cannot look like one from three hundred.
Three rules: gaps in coverage are drawn as gaps and never interpolated across;
`n` is always visible as a strip under the axis; and changepoints are marked on
the series with their cause, not filed in a separate list.

### 7.6 The query surface

The three coordinates from §1 become three granularity controls, so a reader can
move along each ladder and get a coherent answer at every rung.

```
  Location  [ Country ▾ ] Italy          Target [ Group ▾ ] Facebook (7)
  Time      [ Range ▾   ] 1–14 Mar 2026

   ▲  Yes, on 3 of 41 networks measured

   Strongest case: AS12345 (Example Telecom), where m.facebook.com
   returned an address inside the provider's own network in 37 of 42
   measurements.                                              [ → ]

   Based on 1,204 measurements from 41 networks.
   6 networks had too little data to assess.
```

Four assertions in that sketch: the headline answers the existential question
**and immediately qualifies it** with a denominator; the **argmax is offered
first**, because an existential claim without its witness has the evidence
deleted; networks that could not be assessed are **counted separately** rather
than folded into either side; and a multi-network selection defaults to a
**per-network matrix**, because collapsing to one national label destroys the
finding.

### 7.7 Before this ships

- **Thresholds are provisional** until the labelled corpus exists. Keep them in
  one module and mark them unvalidated in the UI.
- **Name a responsible party only on attribution evidence.** A blockpage
  fingerprint's `scope` (ISP-level, national, institutional, provider-side)
  was adjudicated by a human upstream and is citable. Absent that, do not name
  a resolver operator or an ISP; phrase it as "the resolver used by this
  probe" until resolver attribution lands (§4).
- **Artefacts are attacker-controlled.** Blockpage bodies and certificate names
  are chosen by whoever is blocking. Escape on output, prefer structured
  exemplars over body text, never render an artefact as page chrome.
