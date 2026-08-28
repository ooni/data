from enum import StrEnum
import logging
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Mapping, Iterable
from time import time

from clickhouse_driver import Client as ClickhouseClient

from .rules import Evidence, OutcomeClass, get_layer, get_rule

log = logging.getLogger(__name__)


@dataclass()
class Cell:
    domain: str
    probe_cc: str
    probe_asn: str
    resolver_asn: str
    ts_hour: datetime  # hour
    n_measurements: int
    n_probes: int
    dns_rule_counts: Mapping[str, int]  # sumMap([top_dns_rule_id], [toUInt32(1)])
    tcp_rule_counts: Mapping[str, int]  # sumMap([top_tcp_rule_id], [toUInt32(1)])
    tls_rule_counts: Mapping[str, int]  # sumMap([top_tls_rule_id], [toUInt32(1)])
    # layer -> amount of blocked measurements in that layer
    k_blocked: Mapping[str, int]  # layer -> |Blocked measurements|
    n_ok: Mapping[str, int]  # layer -> |Ok measurements|
    discarded: Mapping[str, int]  # layer -> |Ignored rules|

class State(StrEnum):

    UNKNOWN = 'UNK'
    OK = 'OK'
    BLOCK = 'BLOCK'

@dataclass
class ChangePoint:
    domain: str
    probe_cc: str
    probe_asn: str
    resolver_asn: str
    ts_hour: datetime
    s_neg: float
    s_pos: float
    h: float
    state: State # Acquired in this hour


def get_cells(
    clickhouse: ClickhouseClient,
    domains: list[str],
    start_time: datetime,
    end_time: datetime,
    probe_cc: str | None = None,
) -> Iterable[Cell]:
    query = f"""
    SELECT
        domain, probe_cc, probe_asn,
        -- Kept as its own key column for DNS series, never substituted for
        -- probe_asn: on-path injection answers for whatever resolver was
        -- addressed, so folding the resolver into the network key would attribute
        -- a middlebox to the resolver operator's AS. See ontology §11.
        resolver_asn,
        toStartOfHour(measurement_start_time)      AS ts_hour,
        sumMap([top_dns_rule_id], [toUInt32(1)])   AS dns_rule_counts,
        sumMap([top_tcp_rule_id], [toUInt32(1)])   AS tcp_rule_counts,
        sumMap([top_tls_rule_id], [toUInt32(1)])   AS tls_rule_counts,
        count()                                    AS n_measurements,
        uniqIf(probe_id, probe_id != '')           AS n_probes
    FROM analysis_web_measurement
    WHERE
        domain IN %(domains)s
        AND ts_hour >= %(start_time)s
        AND ts_hour <= %(end_time)s
        {"AND probe_cc=%(probe_cc)s" if probe_cc else ""}
    GROUP BY domain, probe_cc, probe_asn, resolver_asn, ts_hour
    ORDER BY domain, probe_cc, probe_asn, resolver_asn, ts_hour
    SETTINGS
    max_bytes_before_external_group_by=201001000,
    max_bytes_before_external_sort=201001000
    """

    params = {"domains": domains, "start_time": start_time, "end_time": end_time}
    if probe_cc:
        params["probe_cc"] = probe_cc

    result = clickhouse.execute_iter(
        query,
        params=params,
        with_column_types=True,
        chunk_size=1000,
    )
    first_chunk = next(result)
    col_names = [t[0] for t in first_chunk[0]]

    # chunk_size > 1 returns a list per iteration, this iterator flattens
    # that structure
    def _iter_rows():
        # first chunk has column definitions on position 0
        yield from first_chunk[1:]
        for chunk in result:
            yield from chunk

    rows = (dict(zip(col_names, r)) for r in _iter_rows())

    rule_maps = ["dns_rule_counts", "tcp_rule_counts", "tls_rule_counts"]
    for row in rows:
        row["k_blocked"] = defaultdict(int)
        row["n_ok"] = defaultdict(int)
        row["discarded"] = defaultdict(int)
        for rule_map in rule_maps:
            if not row.get(rule_map):
                continue

            rule_ids, counts = row[rule_map]
            # convert mapping to a format easier to use
            row[rule_map] = dict(zip(rule_ids, counts))  # TODO not sure if useful

            for rule_id, count in row[rule_map].items():
                try:
                    rule = get_rule(rule_id)
                except ValueError as e:
                    # old entries can have old rule names, ignore those
                    log.warning(str(e))
                    continue
                # See: https://docs.ooni.org/data/pipeline-implementation-plan ,
                # section 3.6
                layer = get_layer(rule_id)
                if (
                    rule.evidence == Evidence.SCORED
                    and rule.outcome_class == OutcomeClass.BLOCKED
                ):
                    row["k_blocked"][layer] += count
                elif (
                    rule.evidence == Evidence.SCORED
                    and rule.outcome_class == OutcomeClass.OK
                ):
                    row["n_ok"][layer] += count
                else:
                    row["discarded"][layer] += count
        yield Cell(**row)

# TODO warmup and run it for every relevant (domain,probe_cc,probe_asn, resolver_asn)
class Detector:
    def __init__(self, debug: bool = False):
        self.s_pos = self.s_neg = 0
        self.state = State.UNKNOWN  # UNK | OK | BLOCK
        self.debug = debug
        self.series = [] # List of (s_neg, s_pos) values per step


    def compute_changepoints(
        self,
        series: list[Cell],
        layer: str,
        p0: float = 0.05,
        p1: float = 0.50,
        # TODO choose a better value for h depending on labeled corpus
        # (implementation plan section 3.8)
        h: float = 30,
        warmup: bool = False,
    ) -> list[ChangePoint]:
        """
        Assumes the input list has the following properties:
            - Sorted by time, one entry per hour
            - All cells are from the same (probe_cc, probe_asn, resolver_asn, domain)

        TODO: Definition of p1 and p0 is unclear

        "warmup" runs the detector without generating any new changepoint, it
        only updates internal state
        """
        results = []
        w_block = math.log(p1 / p0)
        w_clear = math.log((1.0 - p1) / (1.0 - p0))

        for cell in series:
            cp = self.step(cell, w_block, w_clear, layer, h)
            if cp and not warmup:
                results.append(cp)
            if self.debug:
                self.series.append((self.s_neg, self.s_pos, self.state))

        return results

    def compute_llr_series(
        self,
        series: list[Cell],
        layer: str,
        p0: float = 0.1,
        p1: float = 0.9,
    ) -> list[float]:
        """
        The raw per-cell log-likelihood-ratio (llr = k*w_block + (n-k)*w_clear)
        for each cell in series.

        Useful for inspecting the evidence a given hour contributed on its own.
        """
        w_block = math.log(p1 / p0)
        w_clear = math.log((1.0 - p1) / (1.0 - p0))

        llrs = []
        for cell in series:
            k = cell.k_blocked[layer]
            n = cell.n_ok[layer] + k  # total scored firings, ok or not
            llrs.append(k * w_block + (n - k) * w_clear)
        return llrs

    def step(self, cell : Cell, w_block : float, w_clear : float, layer : str, h : float) -> ChangePoint | None:
        # original state is unknown, run both series in parallel to discover
        # current state
        k = cell.k_blocked[layer]
        n = cell.n_ok[layer] + k # total scored firings, ok or not
        llr = k * w_block + (n - k) * w_clear

        def make_cp(s: State) -> ChangePoint:
            return ChangePoint(
                domain = cell.domain,
                probe_cc = cell.probe_cc,
                probe_asn = cell.probe_asn,
                resolver_asn = cell.resolver_asn,
                s_neg = self.s_neg,
                s_pos = self.s_pos,
                state = s,
                h = h,
                ts_hour = cell.ts_hour
            )

        if self.state == State.UNKNOWN:
            # s_pos = max(0.0, s_pos + k * w_blocked + (n - k) * w_clear)
            self.s_pos = max(0, self.s_pos + llr)
            self.s_neg = max(0, self.s_neg - llr)

            if self.s_pos > h:
                self.state = State.BLOCK
                self.s_pos = self.s_neg = 0
            elif self.s_neg > h:
                self.state = State.OK
                self.s_pos = self.s_neg = 0
            # Don't return a changepoint: this is the initial state
        elif self.state == State.BLOCK:
            # Run s_neg accumulator: we wan't to see if the blocking signal
            # goes down
            self.s_neg = max(0, self.s_neg - llr)
            self.s_pos = 0
            if self.s_neg > h:
                cp = make_cp(State.OK)
                self.state = State.OK
                return cp
        elif self.state == State.OK:
            # Run s_pos accumulator: we wan't to see if the blocking signal
            # goes up
            self.s_pos = max(0, self.s_pos + llr)
            self.s_neg = 0
            if self.s_pos > h:
                cp = make_cp(State.BLOCK)
                self.state = State.BLOCK
                return cp

        # TODO: Reset to unknown after long periouds without data
        return None

# ----< Charts >---------------------------------------------------------------
LAYERS = ["dns", "tcp", "tls"]

OUTCOME_COLORS = {
    "blocked": "#d62728",  # red
    "ok": "#2ca02c",  # green
    "discarded": "#7f7f7f",  # gray
}


def _full_hour_range(cells: list[Cell]):
    """
    get_cells only ever returns a row for an hour with >=1 measurement — a
    silent hour (zero measurements) never appears in `cells` at all. This
    reconstructs the full hourly index between the first and last observed
    cell so charts can make those gaps explicit instead of silently
    stretching/compressing the time axis around them.
    """
    import pandas as pd

    hours = [cell.ts_hour for cell in cells]
    return pd.date_range(min(hours), max(hours), freq="h")


def _cusum_overlay_df(cells: list[Cell], detector: "Detector"):
    """
    Zips a debug-run Detector's recorded (s_neg, s_pos) steps back onto the
    same cells list it was run over — Detector.series has no timestamp of
    its own, it's positional, one entry per cell in the order step() saw
    them, which is exactly the order/length of the cells list passed to
    compute_changepoints.
    """
    import pandas as pd

    n = min(len(cells), len(detector.series))
    if n < len(cells) or n < len(detector.series):
        log.warning(
            "cells (%d) and detector.series (%d) length mismatch; "
            "overlay truncated to %d — did you run the detector over a "
            "different cells list than the one being charted?",
            len(cells), len(detector.series), n,
        )
    return pd.DataFrame(
        [
            {
                "ts_hour": cells[i].ts_hour,
                "s_neg": detector.series[i][0],
                "s_pos": detector.series[i][1],
            }
            for i in range(n)
        ]
    )


CUSUM_COLORS = {
    "s+": "#1f77b4",  # blue
    "s-": "#f1c40f",  # yellow
}

STATE_BAND_COLORS = {
    "UNK": "#ffe066",    # yellow
    "OK": "#2ca02c",     # green
    "BLOCK": "#d62728",  # red
}


def _state_bands_df(cells: list[Cell], detector: "Detector"):
    """
    Collapses a debug-run Detector's per-step state into contiguous-run
    bands (state_start, state_end, state), one row per unbroken stretch of
    the same state — same idea as v1 detector.py's state background bands.
    """
    import pandas as pd

    n = min(len(cells), len(detector.series))
    if n == 0:
        return pd.DataFrame(columns=["state_start", "state_end", "state"])

    states = [str(detector.series[i][2]) for i in range(n)]
    hours = [cells[i].ts_hour for i in range(n)]

    bands = []
    run_start = 0
    for i in range(1, n + 1):
        if i == n or states[i] != states[run_start]:
            bands.append(
                {
                    "state_start": hours[run_start],
                    # extend to the start of the next hour so the band
                    # covers the full width of the last bar in the run
                    "state_end": hours[i] if i < n else hours[i - 1] + timedelta(hours=1),
                    "state": states[run_start],
                }
            )
            run_start = i
    return pd.DataFrame(bands)


def _make_state_bands_chart(bands_df):
    import altair as alt

    return (
        alt.Chart(bands_df)
        .mark_rect(opacity=0.25)
        .encode(
            x=alt.X("state_start:T"),
            x2=alt.X2("state_end:T"),
            color=alt.Color(
                "state:N",
                scale=alt.Scale(
                    domain=list(STATE_BAND_COLORS.keys()),
                    range=list(STATE_BAND_COLORS.values()),
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("state:N"),
                alt.Tooltip("state_start:T"),
                alt.Tooltip("state_end:T"),
            ],
        )
    )


def _make_cusum_overlay_chart(df_overlay, show_legend: bool, selection, h: float | None = None):
    """
    Melts (s_pos, s_neg) into one color-encoded line series (rather than two
    statically-colored marks + a fake legend swatch) so the CUSUM legend is
    real and click-bindable: click "s+"/"s-" to isolate that line, same as
    the Outcome legend already does for the bars. `selection` is shared
    across all layer subplots (created once by the caller); the legend (and
    the click-binding) is only attached on the subplot where show_legend is
    True.

    h: the detector's threshold — drawn as a green dashed reference line at
    that value on the CUSUM axis (matching the original detector's chart),
    since h is a level s_pos/s_neg cross, not a point in time.
    """
    import altair as alt
    import pandas as pd

    long_df = df_overlay.melt(
        id_vars=["ts_hour"],
        value_vars=["s_pos", "s_neg"],
        var_name="component",
        value_name="value",
    )
    long_df["series"] = long_df["component"].map({"s_pos": "s+", "s_neg": "s-"})

    axis = alt.Axis(title="CUSUM statistic", orient="right")
    line = (
        alt.Chart(long_df)
        .mark_line()
        .encode(
            x=alt.X("ts_hour:T"),
            y=alt.Y("value:Q", axis=axis),
            color=alt.Color(
                "series:N",
                scale=alt.Scale(
                    domain=list(CUSUM_COLORS.keys()),
                    range=list(CUSUM_COLORS.values()),
                ),
                legend=alt.Legend(title="CUSUM") if show_legend else None,
            ),
            opacity=alt.condition(selection, alt.value(1.0), alt.value(0.05)),
            tooltip=[
                alt.Tooltip("ts_hour:T"),
                alt.Tooltip("series:N"),
                alt.Tooltip("value:Q"),
            ],
        )
    )
    if show_legend:
        line = line.add_selection(selection)

    if h is None:
        return line

    threshold = (
        alt.Chart(pd.DataFrame({"h": [h]}))
        .mark_rule(color="green", strokeDash=[4, 4])
        .encode(y=alt.Y("h:Q", axis=axis))
    )
    return line + threshold


def make_cells_histogram_chart(
    cells: list[Cell], detectors: Mapping[str, "Detector"] | None = None
):
    """
    One stacked-bar histogram per layer (dns, tcp, tls): x is the cell hour,
    y is measurement count, stacked by outcome (blocked/ok/discarded). Cells
    sharing the same hour are summed together, so pass in cells already
    scoped to whatever series you want plotted (domain/probe_cc/probe_asn).

    detectors: optional {layer: Detector} of debug-run (debug=True) detectors
    for that same cells list — when given, the layer's s_pos/s_neg series is
    overlaid as lines on an independent right-hand y-axis.
    """
    import altair as alt
    import pandas as pd

    records = [
        {
            "ts_hour": cell.ts_hour,
            "layer": layer,
            "outcome": outcome,
            "count": counts.get(layer, 0),
        }
        for cell in cells
        for layer in LAYERS
        for outcome, counts in (
            ("blocked", cell.k_blocked),
            ("ok", cell.n_ok),
            ("discarded", cell.discarded),
        )
    ]
    df = pd.DataFrame(records)
    df = df.groupby(["ts_hour", "layer", "outcome"], as_index=False)["count"].sum()

    # Make silent hours (no cell at all, i.e. zero measurements) explicit
    # zero-height bars instead of missing rows, so the x-axis spacing and
    # bar width reflect the real hourly cadence rather than compressing
    # around the gaps.
    full_hours = _full_hour_range(cells)
    # A fixed chart width divided across many more hourly bars (now that
    # silent hours are included) can make bars wider than their per-hour
    # pixel slot, causing them to visually overlap their neighbors — scale
    # width with the number of hours instead of leaving it fixed.
    chart_width = max(900, len(full_hours) * 6)
    skeleton = pd.DataFrame(
        [
            (ts_hour, layer, outcome)
            for ts_hour in full_hours
            for layer in LAYERS
            for outcome in OUTCOME_COLORS
        ],
        columns=["ts_hour", "layer", "outcome"],
    )
    df = skeleton.merge(df, on=["ts_hour", "layer", "outcome"], how="left")
    df["count"] = df["count"].fillna(0)

    # Shared across all three layer subplots: click an entry in the Outcome
    # legend (shown only on the last subplot) to isolate that outcome across
    # every subplot; shift-click to select more than one. An empty selection
    # (nothing clicked yet) means "show everything", same as today.
    outcome_selection = alt.selection_multi(fields=["outcome"], bind="legend")
    # Same idea for the CUSUM legend: click "s+"/"s-" to isolate that line
    # across every subplot, and dim the bars too so the line stands out.
    cusum_selection = alt.selection_multi(fields=["series"], bind="legend")

    def make_layer_chart(layer: str, show_x_axis: bool):
        bar_chart = (
            alt.Chart(df[df["layer"] == layer])
            .mark_bar(stroke="black", strokeWidth=1)
            .encode(
                x=alt.X(
                    "ts_hour:T",
                    title=None,
                    axis=alt.Axis(labels=show_x_axis, ticks=show_x_axis),
                ),
                y=alt.Y("count:Q", stack="zero", title="count"),
                color=alt.Color(
                    "outcome:N",
                    scale=alt.Scale(
                        domain=list(OUTCOME_COLORS.keys()),
                        range=list(OUTCOME_COLORS.values()),
                    ),
                    legend=alt.Legend(title="Outcome") if layer == LAYERS[-1] else None,
                ),
                opacity=alt.condition(
                    outcome_selection & cusum_selection, alt.value(0.6), alt.value(0.05)
                ),
                tooltip=["ts_hour:T", "outcome:N", "count:Q"],
            )
        )
        if layer == LAYERS[-1]:
            bar_chart = bar_chart.add_selection(outcome_selection)

        chart = bar_chart
        if detectors and layer in detectors:
            detector = detectors[layer]
            bands_df = _state_bands_df(cells, detector)
            overlay_df = _cusum_overlay_df(cells, detector)
            overlay_chart = _make_cusum_overlay_chart(
                overlay_df,
                show_legend=(layer == LAYERS[-1]),
                selection=cusum_selection,
                h=getattr(detector, "h", None),
            )
            layers = []
            if not bands_df.empty:
                layers.append(_make_state_bands_chart(bands_df))
            layers += [bar_chart, overlay_chart]
            chart = alt.layer(*layers).resolve_scale(
                y="independent", color="independent", opacity="independent"
            )

        return chart.properties(
            width=chart_width,
            height=150,
            title=alt.TitleParams(
                text=layer,
                fontSize=11,
                fontWeight="normal",
                color="gray",
                anchor="start",
                dy=-4,
                offset=2,
            ),
        )

    charts = [
        make_layer_chart(layer, show_x_axis=(layer == LAYERS[-1])) for layer in LAYERS
    ]
    return (
        alt.vconcat(*charts, spacing=10)
        .resolve_scale(x="shared", color="shared")
        .properties(title="Cell outcome histogram")
    )


RULE_COUNT_FIELDS = {
    "dns": "dns_rule_counts",
    "tcp": "tcp_rule_counts",
    "tls": "tls_rule_counts",
}


def _classify_rule_id_for_chart(rule_id: str) -> str:
    """
    blocked/ok/discarded per docs.ooni.org/data/pipeline-implementation-plan
    section 3.6, mirroring get_cells' classification for display purposes.
    """
    try:
        rule = get_rule(rule_id)
    except ValueError as e:
        log.warning(str(e))
        return "discarded"
    if rule.evidence == Evidence.SCORED and rule.outcome_class == OutcomeClass.BLOCKED:
        return "blocked"
    elif rule.outcome_class == OutcomeClass.OK:
        return "ok"
    return "discarded"


def make_rule_histogram_chart(
    cells: list[Cell], detectors: Mapping[str, "Detector"] | None = None
):
    """
    One stacked-bar histogram per layer, same x/y axes and blocked=red /
    ok=green / discarded=gray coloring as make_cells_histogram_chart, but
    each bar is stacked by individual rule id rather than by outcome class.
    There isn't room to label each segment, so the rule id and its count
    are shown in the tooltip on hover instead.

    detectors: optional {layer: Detector} of debug-run (debug=True) detectors
    for that same cells list — when given, the layer's s_pos/s_neg series is
    overlaid as lines on an independent right-hand y-axis.
    """
    import altair as alt
    import pandas as pd

    records = [
        {
            "ts_hour": cell.ts_hour,
            "layer": layer,
            "rule_id": rule_id,
            "outcome": _classify_rule_id_for_chart(rule_id),
            "count": count,
        }
        for cell in cells
        for layer, field in RULE_COUNT_FIELDS.items()
        for rule_id, count in getattr(cell, field).items()
    ]
    df = pd.DataFrame(records)
    df = df.groupby(["ts_hour", "layer", "rule_id", "outcome"], as_index=False)[
        "count"
    ].sum()

    # Make silent hours (no cell at all, i.e. zero measurements) explicit
    # instead of missing rows, so the x-axis spacing reflects the real
    # hourly cadence. Unlike the outcome histogram, there's no fixed rule-id
    # set to cross-join against (that would wrongly claim every rule "fired
    # 0 times" every hour) — just add one zero-height placeholder row per
    # (hour, layer) that has no data at all.
    full_hours = _full_hour_range(cells)
    existing_hour_layer = set(zip(df["ts_hour"], df["layer"]))
    missing_rows = [
        {"ts_hour": ts_hour, "layer": layer, "rule_id": "(no data)", "outcome": "discarded", "count": 0}
        for ts_hour in full_hours
        for layer in LAYERS
        if (ts_hour, layer) not in existing_hour_layer
    ]
    if missing_rows:
        df = pd.concat([df, pd.DataFrame(missing_rows)], ignore_index=True)

    # A fixed chart width divided across many more hourly bars (now that
    # silent hours are included) can make bars wider than their per-hour
    # pixel slot, causing them to visually overlap their neighbors — scale
    # width with the number of hours instead of leaving it fixed.
    chart_width = max(900, len(full_hours) * 6)

    # Shared across all three layer subplots: click an entry in the Outcome
    # legend (shown only on the last subplot) to isolate that outcome across
    # every subplot; shift-click to select more than one. An empty selection
    # (nothing clicked yet) means "show everything", same as today.
    outcome_selection = alt.selection_multi(fields=["outcome"], bind="legend")
    # Same idea for the CUSUM legend: click "s+"/"s-" to isolate that line
    # across every subplot, and dim the bars too so the line stands out.
    cusum_selection = alt.selection_multi(fields=["series"], bind="legend")

    def make_layer_chart(layer: str, show_x_axis: bool):
        bar_chart = (
            alt.Chart(df[df["layer"] == layer])
            # A stroke around each stacked segment, since same-outcome rules
            # share a fill color and would otherwise merge into one blob —
            # the outline is what makes "how many rules contributed" readable
            # at a glance.
            .mark_bar(stroke="black", strokeWidth=1)
            .encode(
                x=alt.X(
                    "ts_hour:T",
                    title=None,
                    axis=alt.Axis(labels=show_x_axis, ticks=show_x_axis),
                ),
                y=alt.Y("count:Q", stack="zero", title="count"),
                color=alt.Color(
                    "outcome:N",
                    scale=alt.Scale(
                        domain=list(OUTCOME_COLORS.keys()),
                        range=list(OUTCOME_COLORS.values()),
                    ),
                    legend=alt.Legend(title="Outcome") if layer == LAYERS[-1] else None,
                ),
                opacity=alt.condition(
                    outcome_selection & cusum_selection, alt.value(0.6), alt.value(0.05)
                ),
                order=alt.Order("rule_id:N"),
                tooltip=[
                    alt.Tooltip("ts_hour:T"),
                    alt.Tooltip("rule_id:N", title="rule"),
                    alt.Tooltip("outcome:N"),
                    alt.Tooltip("count:Q"),
                ],
            )
        )
        if layer == LAYERS[-1]:
            bar_chart = bar_chart.add_selection(outcome_selection)

        chart = bar_chart
        if detectors and layer in detectors:
            detector = detectors[layer]
            bands_df = _state_bands_df(cells, detector)
            overlay_df = _cusum_overlay_df(cells, detector)
            overlay_chart = _make_cusum_overlay_chart(
                overlay_df,
                show_legend=(layer == LAYERS[-1]),
                selection=cusum_selection,
                h=getattr(detector, "h", None),
            )
            layers = []
            if not bands_df.empty:
                layers.append(_make_state_bands_chart(bands_df))
            layers += [bar_chart, overlay_chart]
            chart = alt.layer(*layers).resolve_scale(
                y="independent", color="independent", opacity="independent"
            )

        return chart.properties(
            width=chart_width,
            height=150,
            title=alt.TitleParams(
                text=layer,
                fontSize=11,
                fontWeight="normal",
                color="gray",
                anchor="start",
                dy=-4,
                offset=2,
            ),
        )

    charts = [
        make_layer_chart(layer, show_x_axis=(layer == LAYERS[-1])) for layer in LAYERS
    ]
    return (
        alt.vconcat(*charts, spacing=10)
        .resolve_scale(x="shared", color="shared")
        .properties(title="Rule histogram")
    )
