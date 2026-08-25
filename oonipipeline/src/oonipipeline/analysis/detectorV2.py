from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping
from .rules import get_layer, get_rule, Evidence, OutcomeClass
from clickhouse_driver import Client as ClickhouseClient
import logging

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
    k_blocked: Mapping[str, int] # layer -> |Blocked measurements|
    n_ok: Mapping[str, int] # layer -> |Ok measurements|
    discarded: Mapping[str, int] # layer -> |Ignored rules|


@dataclass
class ChangePoints:
    domain: str
    probe_cc: str
    probe_asn: str
    resolver_asn: str
    ts: datetime
    s: float
    h: float


def get_cells(
    clickhouse: ClickhouseClient,
    domains: list[str],
    start_time: datetime,
    end_time: datetime,
    probe_cc: str | None = None,
) -> list[Cell]:
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
    GROUP BY domain, probe_cc, probe_asn, resolver_asn, ts_hour;
    """

    params = {
        "domains": domains,
        "start_time": start_time,
        "end_time": end_time
    }
    if probe_cc:
        params["probe_cc"] = probe_cc

    result = clickhouse.execute_iter(
        query,
        params=params,
        with_column_types=True,
    )
    col_names = [t[0] for t in next(result)]
    rows = [dict(zip(col_names, r)) for r in result]

    rule_maps = ["dns_rule_counts", "tcp_rule_counts", "tls_rule_counts"]
    for row in rows:
        row['k_blocked'] = defaultdict(int)
        row['n_ok'] = defaultdict(int)
        row['discarded'] = defaultdict(int)
        for rule_map in rule_maps:

            if not row.get(rule_map):
                continue

            rule_ids, counts = row[rule_map]
            # convert mapping to a format easier to use
            row[rule_map] = dict(zip(rule_ids, counts)) # TODO not sure if useful

            for (rule_id, count) in row[rule_map].items():
                try:
                    rule = get_rule(rule_id)
                except ValueError as e:
                    # old entries can have old rule names, ignore those
                    log.warning(str(e))
                    continue
                # See: https://docs.ooni.org/data/pipeline-implementation-plan ,
                # section 3.6
                layer = get_layer(rule_id)
                if rule.evidence == Evidence.SCORED and rule.outcome_class == OutcomeClass.BLOCKED:
                    row['k_blocked'][layer] += count
                elif rule.outcome_class == OutcomeClass.OK:
                    row['n_ok'][layer] += count
                else:
                    row['discarded'][layer] += count

    return [Cell(**row) for row in rows]


def run_detector(
    series: list[Cell], p_block: float = 0.1, p_ok: float = 0.9, edd: int = 1
) -> list[ChangePoints]:
    return []


# Charts
LAYERS = ["dns", "tcp", "tls"]

OUTCOME_COLORS = {
    "blocked": "#d62728",   # red
    "ok": "#2ca02c",        # green
    "discarded": "#7f7f7f", # gray
}


def make_cells_histogram_chart(cells: list[Cell]):
    """
    One stacked-bar histogram per layer (dns, tcp, tls): x is the cell hour,
    y is measurement count, stacked by outcome (blocked/ok/discarded). Cells
    sharing the same hour are summed together, so pass in cells already
    scoped to whatever series you want plotted (domain/probe_cc/probe_asn).
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

    def make_layer_chart(layer: str, show_x_axis: bool):
        return (
            alt.Chart(df[df["layer"] == layer])
            .mark_bar()
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
                tooltip=["ts_hour:T", "outcome:N", "count:Q"],
            )
            .properties(
                width=900,
                height=150,
                title=alt.TitleParams(
                    text=layer, fontSize=11, fontWeight="normal", color="gray",
                    anchor="start", dy=-4, offset=2,
                ),
            )
        )

    charts = [
        make_layer_chart(layer, show_x_axis=(layer == LAYERS[-1]))
        for layer in LAYERS
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


def make_rule_histogram_chart(cells: list[Cell]):
    """
    One stacked-bar histogram per layer, same x/y axes and blocked=red /
    ok=green / discarded=gray coloring as make_cells_histogram_chart, but
    each bar is stacked by individual rule id rather than by outcome class.
    There isn't room to label each segment, so the rule id and its count
    are shown in the tooltip on hover instead.
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
    df = df.groupby(
        ["ts_hour", "layer", "rule_id", "outcome"], as_index=False
    )["count"].sum()

    def make_layer_chart(layer: str, show_x_axis: bool):
        return (
            alt.Chart(df[df["layer"] == layer])
            .mark_bar()
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
                order=alt.Order("rule_id:N"),
                tooltip=[
                    alt.Tooltip("ts_hour:T"),
                    alt.Tooltip("rule_id:N", title="rule"),
                    alt.Tooltip("outcome:N"),
                    alt.Tooltip("count:Q"),
                ],
            )
            .properties(
                width=900,
                height=150,
                title=alt.TitleParams(
                    text=layer, fontSize=11, fontWeight="normal", color="gray",
                    anchor="start", dy=-4, offset=2,
                ),
            )
        )

    charts = [
        make_layer_chart(layer, show_x_axis=(layer == LAYERS[-1]))
        for layer in LAYERS
    ]
    return (
        alt.vconcat(*charts, spacing=10)
        .resolve_scale(x="shared", color="shared")
        .properties(title="Rule histogram")
    )
