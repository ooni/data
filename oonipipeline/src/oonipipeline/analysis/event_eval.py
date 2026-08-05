"""Score a detector configuration against the adjudicated event corpus.

Per-measurement labels calibrate *scoring*; they cannot say anything about
*detection*. Time-to-detect, missed events, false-alarm density and alert-flood
size are properties of a time series, and this is the harness that measures
them.

## What it does

For each event: pull the cell series for its scope, replay the detector over a
window that starts before the onset bracket, and ask three things.

- Did a positive changepoint land inside the onset bracket widened by
  `tolerance`? That is a hit, and its offset from `onset_earliest` is the
  detection latency.
- How many changepoints fired in the quiet lead-in *before* the bracket? Those
  are false alarms, and the lead-in length gives the per-week rate. Using each
  event's own lead-in avoids a second pass over the whole corpus.
- How many fired in total inside the bracket? That is the alert flood: one
  event that emits forty alerts is a paging problem even when recall is
  perfect.

`false_positive_event` rows invert the test: any changepoint in the window is a
failure, so an adjudicated false alarm becomes a must-not-fire regression.

## What it deliberately does not do

**It does not replay the incumbent.** The deployed CUSUM is online and its
output depends on the order measurements arrived in, which the pipeline does
not record. The harness starts every cell from a cold accumulator, so it scores
stateless replays exactly and the incumbent only approximately. That asymmetry
is real and is itself an argument for making detection stateless.

**It does not score events with no coverage.** An event on networks OONI never
measured cannot be detected by anything, and counting it as a miss makes recall
meaninglessly pessimistic. Rows are scored only when `scoreable == "yes"`; the
rest are counted and reported separately so the exclusion stays visible.
"""

import json
import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from clickhouse_driver import Client as ClickhouseClient

from .detector import LastCusum, detect_changepoints, get_observations

log = logging.getLogger(__name__)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    return datetime.fromisoformat(str(ts).replace("Z", "").split("+")[0])


def _naive(dt: datetime) -> datetime:
    """Drop tzinfo. The analysis columns are DateTime64(_, 'UTC') so ClickHouse
    hands back aware datetimes, while label timestamps are naive UTC strings.
    Everything here is UTC; comparing the two forms is what breaks."""
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


@dataclass
class EventResult:
    event_id: str
    title: str
    probe_cc: str
    size_band: str
    event_class: str
    detected: bool
    latency_hours: Optional[float]
    alerts_in_window: int
    false_alarms_in_lead: int
    lead_weeks: float
    series_count: int

    @property
    def passed(self) -> bool:
        """A true event should be detected; a false-positive event should not."""
        if self.event_class == "false_positive_event":
            return self.alerts_in_window == 0
        return self.detected


@dataclass
class Scorecard:
    scored: int = 0
    excluded: Dict[str, int] = field(default_factory=dict)
    results: List[EventResult] = field(default_factory=list)

    @property
    def true_events(self) -> List[EventResult]:
        return [r for r in self.results if r.event_class == "true_event"]

    @property
    def recall(self) -> Optional[float]:
        t = self.true_events
        return sum(r.detected for r in t) / len(t) if t else None

    @property
    def median_latency_hours(self) -> Optional[float]:
        v = [r.latency_hours for r in self.true_events if r.latency_hours is not None]
        return statistics.median(v) if v else None

    @property
    def false_alarms_per_quiet_series_week(self) -> Optional[float]:
        weeks = sum(r.lead_weeks * max(r.series_count, 1) for r in self.results)
        alarms = sum(r.false_alarms_in_lead for r in self.results)
        return alarms / weeks if weeks else None

    @property
    def alerts_per_true_event(self) -> Optional[float]:
        hit = [r for r in self.true_events if r.detected]
        return statistics.mean([r.alerts_in_window for r in hit]) if hit else None

    def recall_by_band(self) -> Dict[str, str]:
        """Adjudicated events skew large and famous, so a single recall number
        is optimistic. Stratify it."""
        out: Dict[str, str] = {}
        for band in sorted({r.size_band for r in self.true_events}):
            rows = [r for r in self.true_events if r.size_band == band]
            out[band] = f"{sum(r.detected for r in rows)}/{len(rows)}"
        return out

    def format(self) -> str:
        def pct(v):
            return "n/a" if v is None else f"{v:.0%}"

        def num(v, unit="", dp=1):
            return "n/a" if v is None else f"{v:.{dp}f}{unit}"

        lines = [
            f"scored {self.scored} events"
            + (f", excluded {sum(self.excluded.values())} ({self.excluded})"
               if self.excluded else ""),
            f"  event recall                    {pct(self.recall)}"
            f"   {self.recall_by_band()}",
            # Negative latency means the detector fired before onset_earliest,
            # inside the tolerance. Reports are day-granular and usually lag the
            # block, so detecting early is a good outcome, not a sign error.
            f"  median detection latency        {num(self.median_latency_hours, 'h')}"
            f"   (negative = fired before the bracket opened)",
            # Per series-week, so it is small by construction: three digits or
            # every configuration reads as 0.0.
            f"  false alerts / quiet series-wk  "
            f"{num(self.false_alarms_per_quiet_series_week, dp=3)}",
            f"  alerts per detected true event  {num(self.alerts_per_true_event)}",
        ]
        failed = [r for r in self.results if not r.passed]
        if failed:
            lines.append(f"  {len(failed)} events failed:")
            for r in sorted(failed, key=lambda r: r.probe_cc)[:15]:
                why = ("fired when it should not"
                       if r.event_class == "false_positive_event" else "missed")
                lines.append(f"    {r.probe_cc} {r.title[:52]:<52} {why}")
        return "\n".join(lines)


def size_band(ev: Dict[str, Any]) -> str:
    """Derived, never stored — see label-corpus-design.md §1.2."""
    if ev.get("asn_scope_kind") == "all":
        return "national"
    if ev.get("asn_scope_kind") == "unknown":
        return "unknown"
    if len(ev.get("asn_scope") or []) > 1:
        return "multi_asn"
    if ev.get("target_set_kind") == "enumerated" and len(ev.get("target_set") or []) == 1:
        return "micro"
    return "single_asn"


def score_event(
    db: ClickhouseClient,
    ev: Dict[str, Any],
    tolerance: timedelta = timedelta(hours=24),
    lead: timedelta = timedelta(days=14),
    **detector_kwargs: Any,
) -> Optional[EventResult]:
    targets = ev.get("target_set") or []
    if ev.get("target_set_kind") != "enumerated" or not targets:
        return None  # nothing to query a series for

    onset_lo = _parse(ev.get("onset_earliest"))
    onset_hi = _parse(ev.get("onset_latest")) or onset_lo
    if onset_lo is None:
        return None
    resolved = _parse(ev.get("resolution_latest"))

    window_start = onset_lo - lead
    window_end = (resolved or onset_hi) + tolerance

    observations = list(get_observations(
        db, start_time=window_start, end_time=window_end,
        domains=targets, probe_cc=[ev["probe_cc"]] if ev.get("probe_cc") else None,
    ))
    # Restrict to the listed ASNs, when the event names them.
    wanted = set(ev.get("asn_scope") or [])
    if ev.get("asn_scope_kind") == "listed" and wanted:
        observations = [o for o in observations if o["probe_asn"] in wanted]
    if not observations:
        return None

    series = {(o["probe_cc"], o["probe_asn"], o["domain"]) for o in observations}
    observations.sort(key=lambda o: (o["probe_cc"], o["probe_asn"], o["domain"], o["ts"]))

    # Cold start per replay: no carried state, hence stateless-only scoring.
    cusum_map: Dict[str, LastCusum] = {}
    changepoints, _, _ = detect_changepoints(
        observations, cusum_map, edd=detector_kwargs.pop("edd", 10), **detector_kwargs
    )

    onsets = [(_naive(c["ts"]), c) for c in changepoints if c["change_dir"] > 0]
    lo, hi = onset_lo - tolerance, onset_hi + tolerance
    in_window = [c for t, c in onsets if lo <= t <= (resolved or hi)]
    in_bracket = [t for t, _ in onsets if lo <= t <= hi]
    in_lead = [c for t, c in onsets if t < lo]

    latency = None
    if in_bracket:
        latency = (min(in_bracket) - onset_lo).total_seconds() / 3600.0

    return EventResult(
        event_id=ev["event_id"],
        title=ev.get("title") or ev["event_id"],
        probe_cc=ev.get("probe_cc") or "",
        size_band=size_band(ev),
        event_class=ev.get("event_class") or "true_event",
        detected=bool(in_bracket),
        latency_hours=latency,
        alerts_in_window=len(in_window),
        false_alarms_in_lead=len(in_lead),
        lead_weeks=lead.total_seconds() / (7 * 86400),
        series_count=len(series),
    )


def run_harness(
    clickhouse_url: str,
    events_path: str,
    tolerance_hours: int = 24,
    lead_days: int = 14,
    **detector_kwargs: Any,
) -> Scorecard:
    events = json.loads(open(events_path).read())["events"]
    db = ClickhouseClient.from_url(clickhouse_url)
    card = Scorecard()

    for ev in events:
        if ev.get("superseded_by"):
            continue
        if ev.get("scoreable") != "yes":
            card.excluded[ev.get("scoreable") or "unknown"] = (
                card.excluded.get(ev.get("scoreable") or "unknown", 0) + 1)
            continue
        if not (ev.get("mechanisms") or []):
            # An event with no mechanism has not been adjudicated, only imported.
            card.excluded["no_mechanism"] = card.excluded.get("no_mechanism", 0) + 1
            continue
        r = score_event(
            db, ev, tolerance=timedelta(hours=tolerance_hours),
            lead=timedelta(days=lead_days), **detector_kwargs,
        )
        if r is None:
            card.excluded["no_series"] = card.excluded.get("no_series", 0) + 1
            continue
        card.results.append(r)
        card.scored += 1
    return card
