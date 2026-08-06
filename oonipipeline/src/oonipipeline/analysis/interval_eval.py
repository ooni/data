"""Estimate a detector's false-alarm rate over adjudicated quiet intervals.

`event_eval.py` answers "does it find things". It cannot answer "how often does
it shout when nothing is there", because that is a *rate* and the event corpus
has no denominator in it: it is curated, so there is no frame, no weights, and
no way to say what population a count of false alarms is a count over. Its
`false_alarms_per_quiet_series_week` uses each event's own lead-in as a stand-in
for quiet time, which is a proxy over whatever cells happen to surround
adjudicated events — not an estimate over anything.

This is the estimate. It reads the interval corpus (one adjudicated label per
`(probe_cc, probe_asn, domain)` x ISO week, drawn from a recorded frame),
replays the detector over each labelled cell-week, and reports what fraction of
observed-quiet time it alerts in.

## What makes it an estimate rather than a count

Every row carries the design it was drawn under. The queue deliberately
oversamples the interesting strata — weeks the incumbent alerted in, weeks that
scored blocked-leaning without alerting — because a uniform draw is almost all
trivially quiet cells and costs analyst time to learn nothing. Counting alarms
over those rows would therefore describe the queue. Weighting each row by
`population / drawn` for its stratum
([Horvitz-Thompson](https://en.wikipedia.org/wiki/Horvitz%E2%80%93Thompson_estimator))
describes the frame.

Two consequences worth stating plainly:

- A corpus whose rows lack `sampling_weight` cannot be repaired. It is the one
  field that is unrecoverable after the fact (label-corpus-design.md §1.5), so
  rows without it are excluded and counted, never defaulted to 1.
- Intervals are not independent. Cell-weeks autocorrelate in time and correlate
  across ASNs within a country during the same week, so the interval is a
  cluster bootstrap over `(probe_cc, iso_week)` rather than a binomial one,
  which would be narrow by a factor nobody can see.

## What it does not do

It does not replay the incumbent, for the same reason `event_eval` does not:
the deployed CUSUM is online and its state depends on arrival order, which the
pipeline does not record. The `detector_alerted` stratum uses the historical
alert log as a *screen* — which is a use of the log, not a replay of the
detector — and what gets scored here is always a cold-start replay of the
configuration under test.

It does not treat `quiet_observed` as `quiet`. The verdict is what an analyst
could see in OONI's data, so an unmeasured block reads as calm and this number
is an upper bound on quality, not a certificate. Contamination of that kind
biases the rate *upward*, which is the safe direction.
"""

import json
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from clickhouse_driver import Client as ClickhouseClient

from .detector import LastCusum, detect_changepoints, get_observations

log = logging.getLogger(__name__)

# Bands are derived from the measurement count, never read off the row: the
# labeller stores what it drew, and a corpus that has been merged, re-exported
# or hand-edited can carry a band that disagrees with its own count. Edges match
# `labeling.VOLUME_BAND_EDGES` in the API service; they are part of what a
# per-band rate means, so a change here is a change to the reported quantity.
VOLUME_BAND_EDGES: Tuple[Tuple[Optional[int], str], ...] = (
    (100, "low"),
    (1000, "medium"),
    (None, "high"),
)


def volume_band(n: int) -> str:
    for edge, name in VOLUME_BAND_EDGES:
        if edge is None or n < edge:
            return name
    return VOLUME_BAND_EDGES[-1][1]


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    return datetime.fromisoformat(str(ts).replace("Z", "").split("+")[0])


def _naive(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


@dataclass
class IntervalResult:
    """One replayed cell-week."""

    probe_cc: str
    probe_asn: int
    domain: str
    window_start: datetime
    verdict: str
    stratum: str
    weight: float
    volume_band: str
    measurements: int
    alerts: int

    @property
    def cluster(self) -> Tuple[str, str]:
        """Cell-weeks are resampled in country-week blocks, not individually:
        a national event, a routing change or a probe-fleet outage moves many
        ASNs in one country at once, so treating them as independent draws
        would report an interval narrower than the evidence supports."""
        return (self.probe_cc, self.window_start.strftime("%G-W%V"))


def _ht_ratio(rows: Iterable[IntervalResult], numerator) -> Optional[float]:
    """Weighted mean of `numerator` over rows. The denominator is the weighted
    count of cell-weeks, so the unit is "per series-week" — the same unit the
    event scorecard prints, now with a population behind it."""
    num = 0.0
    den = 0.0
    for r in rows:
        num += r.weight * numerator(r)
        den += r.weight
    return num / den if den else None


def _cluster_bootstrap(
    rows: List[IntervalResult], numerator, resamples: int, seed: int
) -> Optional[Tuple[float, float]]:
    """Percentile interval, resampling `(probe_cc, iso_week)` clusters.

    Returns None below ten clusters. An interval computed from four blocks is
    not a wide interval, it is an arbitrary one, and printing it invites the
    reader to treat noise as a measurement.
    """
    clusters: Dict[Tuple[str, str], List[IntervalResult]] = {}
    for r in rows:
        clusters.setdefault(r.cluster, []).append(r)
    keys = list(clusters)
    if len(keys) < 10:
        return None

    rng = random.Random(seed)
    draws: List[float] = []
    for _ in range(resamples):
        sample: List[IntervalResult] = []
        for _ in keys:
            sample.extend(clusters[keys[rng.randrange(len(keys))]])
        v = _ht_ratio(sample, numerator)
        if v is not None:
            draws.append(v)
    if not draws:
        return None
    draws.sort()
    lo = draws[int(0.025 * (len(draws) - 1))]
    hi = draws[int(0.975 * (len(draws) - 1))]
    return lo, hi


@dataclass
class IntervalCard:
    excluded: Dict[str, int] = field(default_factory=dict)
    results: List[IntervalResult] = field(default_factory=list)
    ci: Optional[Tuple[float, float]] = None

    @property
    def quiet(self) -> List[IntervalResult]:
        return [r for r in self.results if r.verdict == "quiet_observed"]

    @property
    def with_event(self) -> List[IntervalResult]:
        return [r for r in self.results if r.verdict == "event_present"]

    @property
    def false_alarms_per_quiet_series_week(self) -> Optional[float]:
        return _ht_ratio(self.quiet, lambda r: r.alerts)

    @property
    def quiet_weeks_alarm_free(self) -> Optional[float]:
        """The paging-load reading of the same corpus. A configuration that
        fires eight times in one week and never again has a bad rate and a fine
        alarm-free share; one that fires once a week everywhere has the
        reverse. Which one is tolerable is an operational choice, so both are
        printed rather than blended."""
        return _ht_ratio(self.quiet, lambda r: 1.0 if r.alerts == 0 else 0.0)

    @property
    def interval_detection_rate(self) -> Optional[float]:
        """P(detector fires | an event was present), estimated over the frame.

        Not the same quantity as event recall: that is coverage over a curated
        set of known events, this is a weighted rate over sampled cell-weeks
        that turned out to contain one. When the two disagree, the curated set
        is the optimistic one — it skews large and famous by construction."""
        return _ht_ratio(self.with_event, lambda r: 1.0 if r.alerts > 0 else 0.0)

    def by_band(self, rows: List[IntervalResult]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for _, band in VOLUME_BAND_EDGES:
            in_band = [r for r in rows if r.volume_band == band]
            if not in_band:
                continue
            rate = _ht_ratio(in_band, lambda r: r.alerts)
            out[band] = f"{rate:.3f} (n={len(in_band)})" if rate is not None else "n/a"
        return out

    def format(self) -> str:
        def num(v, dp=3):
            return "n/a" if v is None else f"{v:.{dp}f}"

        quiet = self.quiet
        clusters = {r.cluster for r in quiet}
        lines = [
            f"scored {len(self.results)} intervals "
            f"({len(quiet)} observed-quiet, {len(self.with_event)} with an event)"
            + (f", excluded {sum(self.excluded.values())} ({self.excluded})"
               if self.excluded else ""),
            f"  false alerts / quiet series-wk  {num(self.false_alarms_per_quiet_series_week)}"
            + (f"   95% CI [{self.ci[0]:.3f}, {self.ci[1]:.3f}]" if self.ci else
               "   (CI needs 10+ country-weeks)"),
            f"    by volume band                {self.by_band(quiet)}",
            f"  quiet weeks with no alert       "
            f"{num(self.quiet_weeks_alarm_free, 2)}",
            f"  fires when an event is present  "
            f"{num(self.interval_detection_rate, 2)}"
            f"   (weighted, {len(self.with_event)} intervals)",
            f"  weighted quiet time             "
            f"{sum(r.weight for r in quiet):,.0f} cell-weeks, "
            f"{len(clusters)} country-weeks sampled",
        ]
        if quiet:
            # Which rows drive the number. A rate carried by three heavy rows
            # is a different claim from the same rate spread over two hundred,
            # and the difference does not show up in the point estimate.
            heaviest = sorted(quiet, key=lambda r: -r.weight * r.alerts)[:5]
            noisy = [r for r in heaviest if r.alerts]
            if noisy:
                lines.append("  loudest quiet intervals:")
                for r in noisy:
                    lines.append(
                        f"    {r.probe_cc} AS{r.probe_asn} {r.domain[:34]:<34} "
                        f"{r.window_start:%Y-%m-%d} {r.alerts} alert(s) "
                        f"w={r.weight:,.0f}"
                    )
        return "\n".join(lines)


def score_interval(
    db: ClickhouseClient,
    label: Dict[str, Any],
    lead: timedelta = timedelta(days=14),
    **detector_kwargs: Any,
) -> Optional[IntervalResult]:
    """Replay the detector across one cell-week and count what it emitted.

    The replay starts `lead` before the window and only alerts inside the
    window are counted. That lead is not context, it is warm-up: a cold CUSUM
    starts in the `unk` state and its first threshold crossing establishes
    state *silently*, so a replay of the bare week would swallow exactly the
    alarms this is meant to count.
    """
    start = _parse(label.get("window_start"))
    end = _parse(label.get("window_end"))
    if start is None or end is None or not label.get("domain"):
        return None

    observations = list(get_observations(
        db,
        start_time=start - lead,
        end_time=end,
        domains=[label["domain"]],
        probe_cc=[label["probe_cc"]] if label.get("probe_cc") else None,
    ))
    asn = int(label.get("probe_asn") or 0)
    observations = [o for o in observations if int(o["probe_asn"]) == asn]
    if not observations:
        return None

    observations.sort(key=lambda o: (o["probe_cc"], o["probe_asn"], o["domain"], o["ts"]))
    cusum_map: Dict[str, LastCusum] = {}
    changepoints, _, _ = detect_changepoints(
        observations, cusum_map, edd=detector_kwargs.pop("edd", 10), **detector_kwargs
    )
    alerts = sum(
        1
        for c in changepoints
        if c["change_dir"] > 0 and start <= _naive(c["ts"]) < end
    )

    n = int(label.get("measurements_in_window") or 0)
    return IntervalResult(
        probe_cc=label.get("probe_cc") or "",
        probe_asn=asn,
        domain=label["domain"],
        window_start=start,
        verdict=label.get("verdict") or "",
        stratum=label.get("sampling_stratum") or "",
        weight=float(label["sampling_weight"]),
        volume_band=volume_band(n),
        measurements=n,
        alerts=alerts,
    )


def load_intervals(path: str) -> List[Dict[str, Any]]:
    """Live rows from an interval export, or a bare array of them."""
    data = json.loads(open(path).read())
    rows = data if isinstance(data, list) else data.get("intervals", [])
    return [r for r in rows if not r.get("superseded_by")]


def run_interval_harness(
    clickhouse_url: str,
    intervals_path: str,
    lead_days: int = 14,
    bootstrap: int = 400,
    seed: int = 0,
    **detector_kwargs: Any,
) -> IntervalCard:
    labels = load_intervals(intervals_path)
    db = ClickhouseClient.from_url(clickhouse_url)
    card = IntervalCard()

    def exclude(reason: str) -> None:
        card.excluded[reason] = card.excluded.get(reason, 0) + 1

    for label in labels:
        verdict = label.get("verdict")
        if verdict not in ("quiet_observed", "event_present"):
            # `uncertain` and `unusable` are counted, not dropped. A corpus
            # that quietly loses its ambiguous rows keeps only the easy
            # negatives, and the rate improves for a reason that appears in no
            # number on this card.
            exclude(verdict or "unadjudicated")
            continue
        if not label.get("sampling_weight"):
            exclude("no_weight")
            continue
        r = score_interval(
            db, label, lead=timedelta(days=lead_days), **detector_kwargs
        )
        if r is None:
            # No series at all in a cell-week that was drawn *because* it had
            # measurements in it. Either the frame and the replay disagree
            # about the cell, or the data moved under the corpus.
            exclude("no_series")
            continue
        card.results.append(r)

    if card.quiet:
        card.ci = _cluster_bootstrap(
            card.quiet, lambda r: r.alerts, resamples=bootstrap, seed=seed
        )
    return card


def gate(card: IntervalCard, budget: float) -> Tuple[bool, str]:
    """Decide whether a configuration passes a false-alarm budget.

    The comparison is against the *lower* end of the interval, so a change
    fails only when the corpus can actually tell the rate apart from the
    budget. Gating on the point estimate makes small corpora fail at random,
    and a gate that fails at random gets switched off.
    """
    rate = card.false_alarms_per_quiet_series_week
    if rate is None:
        return True, "no observed-quiet intervals — nothing to gate on"
    if card.ci is None:
        return rate <= budget, (
            f"rate {rate:.3f} vs budget {budget:.3f} (point estimate: too few "
            f"country-weeks for an interval)"
        )
    lo, _ = card.ci
    return lo <= budget, f"95% CI lower bound {lo:.3f} vs budget {budget:.3f}"
