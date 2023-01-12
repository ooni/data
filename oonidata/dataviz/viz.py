# This is currently enabled due to: https://github.com/altair-viz/altair/pull/2681
# type: ignore

import numpy as np
import pandas as pd
import altair as alt

from .theme import OONI_COLOR_SCHEME
from .utils import click_query

from urllib.parse import urlparse
import requests

world_100m = requests.get(
    "https://cdn.jsdelivr.net/npm/vega-datasets@v1.29.0/data/world-110m.json"
).json()
alt_data_world_110m = alt.Data(
    values=world_100m, format={"type": "topojson", "feature": "countries"}
)

country_centers = pd.read_csv(
    "https://raw.githubusercontent.com/albertyw/avenews/master/old/data/average-latitude-longitude-countries.csv"
)
country_centers = country_centers[
    ["ISO 3166 Country Code", "Latitude", "Longitude"]
].set_index("ISO 3166 Country Code")

country_meta = pd.read_json(
    "https://raw.githubusercontent.com/ooni/country-util/master/data/country-list.json"
)
country_meta = country_meta[["name", "iso3166_alpha2", "iso3166_num"]].set_index(
    "iso3166_alpha2"
)

citizenlab_global_tl = pd.read_csv(
    "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/global.csv"
)
citizenlab_global_tl["domain_name"] = citizenlab_global_tl["url"].apply(
    lambda x: urlparse(x).netloc
)


def get_df_blocking_of_domain_by_asn(
    domain_name, probe_cc, start_time="2022-11-03", end_time="2022-12-03"
):
    q_args = {
        "domain_name": domain_name,
        "probe_cc": probe_cc,
        "start_time": start_time,
        "end_time": end_time,
    }

    df = click_query(
        """
        SELECT 
        domain_name,
        probe_cc,
        probe_asn,
        probe_as_org_name,
        any(max_blocked) as max_blocked,
        any(max_blocked_label) as blocked_label,
        any(max_down) as max_down,
        any(max_down_label) as down_label,
        any(max_ok) as max_ok,

        (max_blocked / (max_ok + max_down + max_blocked)) as blocked,
        (max_down / (max_ok + max_down + max_blocked)) as down,
        (max_ok / (max_ok + max_down + max_blocked)) as ok,
        SUM(cnt) as count
        FROM (
            SELECT
            domain_name,
            probe_cc,
            probe_asn,
            probe_as_org_name,
            max(ema_avg_blocked) OVER (PARTITION BY probe_cc, probe_asn, domain_name) as max_blocked,
            any(outcome_label) OVER (PARTITION BY probe_cc, probe_asn, domain_name ORDER BY ema_avg_blocked DESC) as max_blocked_label,
            max(ema_avg_down) OVER (PARTITION BY probe_cc, probe_asn, domain_name) as max_down,
            any(outcome_label) OVER (PARTITION BY probe_cc, probe_asn, domain_name ORDER BY ema_avg_down DESC) as max_down_label,
            max(ema_avg_down) OVER (PARTITION BY probe_cc, probe_asn, domain_name) as max_down,
            max(IF(outcome_category == 'http' OR outcome_category == 'https', ema_avg_ok, 0)) OVER (PARTITION BY probe_cc, probe_asn, domain_name) as max_ok,
            cnt
            FROM (
                SELECT 
                domain_name,
                probe_cc,
                probe_asn,
                probe_as_org_name,
                outcome_category,
                outcome_detail,
                outcome_label,
                avgWeighted(ema_blocked, cnt) OVER (PARTITION BY probe_cc, probe_asn, domain_name, outcome_category) as ema_avg_blocked,
                avgWeighted(ema_down, cnt) OVER (PARTITION BY probe_cc, probe_asn, domain_name, outcome_category) as ema_avg_down,
                avgWeighted(ema_ok, cnt) OVER (PARTITION BY probe_cc, probe_asn, domain_name, outcome_category) as ema_avg_ok,
                cnt
                FROM (
                    SELECT
                    domain_name,
                    probe_cc,
                    probe_asn,
                    probe_as_org_name,
                    outcome_category,
                    outcome_detail,
                    IF(outcome_category = 'ok', 'ok', concat(outcome_category, '.', outcome_detail)) as outcome_label,
                    exponentialMovingAverage(1)(blocked_score, t) as ema_blocked,
                    exponentialMovingAverage(1)(down_score, t) as ema_down,
                    exponentialMovingAverage(1)(ok_score, t) as ema_ok,
                    toFloat64(Count()) as cnt
                    FROM (
                        SELECT
                        domain_name,
                        probe_cc,
                        probe_asn,
                        probe_as_org_name,
                        outcome_category,
                        IF(startsWith(outcome_detail, 'failure.unknown_failure') OR startsWith(outcome_detail, 'unknown_failure'), 
                            'failure.unknown', 
                            outcome_detail
                        ) as outcome_detail,
                        blocked_score,
                        ok_score,
                        down_score,
                        row_number() OVER (PARTITION BY domain_name, probe_asn, outcome_category, outcome_detail) as t
                        FROM experiment_result 
                        WHERE timestamp > %(start_time)s AND timestamp < %(end_time)s
                        AND domain_name = %(domain_name)s AND probe_cc = %(probe_cc)s
                    ) GROUP BY probe_cc, probe_asn, probe_as_org_name, domain_name, outcome_category, outcome_detail
                )
            )
        ) GROUP BY probe_cc, probe_asn, probe_as_org_name, domain_name
    """,
        **q_args,
    )
    return df[
        [
            "domain_name",
            "probe_cc",
            "probe_asn",
            "probe_as_org_name",
            "blocked_label",
            "down_label",
            "count",
            "ok",
            "blocked",
            "down",
        ]
    ].melt(
        [
            "domain_name",
            "probe_cc",
            "probe_asn",
            "probe_as_org_name",
            "blocked_label",
            "down_label",
            "count",
        ],
        var_name="stat",
        value_name="stat_value",
    )


def plot_blocking_of_domain_by_asn(
    df=None,
    domain_name=None,
    probe_cc=None,
    start_time="2022-11-03",
    end_time="2022-12-03",
):
    if df is None:
        df = get_df_blocking_of_domain_by_asn(
            domain_name, probe_cc, start_time=start_time, end_time=end_time
        )

    color_scale = alt.Scale(
        domain=["blocked", "down", "ok"],
        range=[
            OONI_COLOR_SCHEME["red7"],
            OONI_COLOR_SCHEME["orange6"],
            OONI_COLOR_SCHEME["green8"],
        ],
    )

    base_chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            y=alt.Y("probe_asn:O", axis=alt.Axis(labels=False, title=None)),
        )
    )

    bars = base_chart.encode(
        x="stat_value:Q",
        color=alt.Color("stat", scale=color_scale, title="status"),
        tooltip=[
            alt.Tooltip("probe_as_org_name:N", title="Network name"),
            alt.Tooltip("probe_asn:N", title="ASN"),
            alt.Tooltip("stat_value:Q", title="value"),
            alt.Tooltip("blocked_label:N", title="blocked_label"),
            alt.Tooltip("down_label:N", title="down_label"),
            alt.Tooltip("count:Q", title="count"),
        ],
        order=alt.Order("stat_value", sort="descending"),
    )

    text = (
        base_chart.mark_text(
            align="center",
        )
        .transform_filter(
            "indexof(datum.blocked_label, 'ok') == -1 & datum.stat == 'blocked'"
        )
        .encode(color=alt.value(OONI_COLOR_SCHEME["gray9"]), text="blocked_label:N")
    )

    bar_count = base_chart.encode(
        y=alt.Y("probe_asn:O", axis=alt.Axis(labels=True, title="ASN")),
        x="count:Q",
    ).properties(width=30)

    return alt.hconcat(bar_count, (bars + text)).properties(
        title=f"Blocking of {domain_name} in {probe_cc} by ASN"
    )


def get_df_blocking_of_domain_in_asn(
    domain_name,
    probe_cc,
    probe_asn,
    start_time="2022-11-03",
    end_time="2022-12-03",
):
    q_args = {
        "domain_name": domain_name,
        "probe_cc": probe_cc,
        "probe_asn": probe_asn,
        "start_time": start_time,
        "end_time": end_time,
    }
    return click_query(
        """
        SELECT
        domain_name,
        probe_cc,
        probe_asn,
        probe_as_org_name,
        outcome_category,
        outcome_detail,
        IF(outcome_category = 'ok', 'ok', concat(outcome_category, '.', outcome_detail)) as outcome_label,
        exponentialMovingAverage(1)(blocked_score, t) as ema_blocked,
        exponentialMovingAverage(1)(down_score, t) as ema_down,
        exponentialMovingAverage(1)(ok_score, t) as ema_ok,
        toFloat64(Count()) as cnt
        FROM (
            SELECT
            domain_name,
            probe_cc,
            probe_asn,
            probe_as_org_name,
            outcome_category,
            IF(startsWith(outcome_detail, 'failure.unknown_failure') OR startsWith(outcome_detail, 'unknown_failure'), 
                'failure.unknown', 
                outcome_detail
            ) as outcome_detail,
            blocked_score,
            ok_score,
            down_score,
            row_number() OVER (PARTITION BY domain_name, probe_asn, outcome_category, outcome_detail) as t
            FROM experiment_result 
            WHERE timestamp > %(start_time)s AND timestamp < %(end_time)s
            AND domain_name = %(domain_name)s AND probe_cc = %(probe_cc)s
            AND probe_asn = %(probe_asn)d
        ) GROUP BY probe_cc, probe_asn, probe_as_org_name, domain_name, outcome_category, outcome_detail
    """,
        **q_args,
    )


def plot_blocking_of_domain_in_asn(
    df=None,
    domain_name=None,
    probe_cc=None,
    probe_asn=None,
    start_time="2022-11-03",
    end_time="2022-12-03",
):
    if df is None:
        df = get_df_blocking_of_domain_in_asn(
            domain_name=domain_name,
            probe_cc=probe_cc,
            probe_asn=probe_asn,
            start_time=start_time,
            end_time=end_time,
        )

    return (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("outcome_detail:O", title=None),
            y=alt.Y("cnt:Q", title="Count"),
            color=alt.Color(
                "ema_blocked:Q", scale=alt.Scale(scheme="redyellowgreen", reverse=True)
            ),
            tooltip=[
                alt.Tooltip("cnt:N", title="Measurement count"),
                alt.Tooltip("outcome_label:N", title="Outcome"),
                alt.Tooltip("ema_blocked:Q", title="Blocked EMA"),
                alt.Tooltip("ema_ok:Q", title="OK EMA"),
                alt.Tooltip("ema_down:Q", title="Down EMA"),
            ],
        )
        .properties(height=250)
        .facet(
            column=alt.Column(
                "outcome_category:N",
                sort=["dns", "tcp", "tls", "https", "http"],
                title=None,
            ),
        )
        .resolve_scale(x="independent")
        .properties(
            title=f"{domain_name} in AS{probe_asn} ({probe_cc}) from {start_time} to {end_time}"
        )
    )


def get_df_blocking_world_map(blocking_threshold=0.7):
    q_args = {"blocking_threshold": blocking_threshold}
    df = click_query(
        """SELECT
    probe_cc,
    CountIf(max_blocked > %(blocking_threshold)f) as blocked_asns,
    CountIf(max_ok > 0.5) as ok_asns,
    domain_name 
    FROM (
        SELECT 
        domain_name,
        probe_cc,
        probe_asn,
        any(max_blocked) as max_blocked,
        any(max_blocked_label) as max_blocked_label,
        any(max_down) as max_down,
        any(max_down_label) as max_down_label,
        arrayMax([0, 1 - max_blocked - max_down]) as max_ok,
        COUNT()
        FROM (
            SELECT
            domain_name,
            probe_cc,
            probe_asn,
            max(ema_avg_blocked) OVER (PARTITION BY probe_cc, probe_asn, domain_name) as max_blocked,
            any(outcome_label) OVER (PARTITION BY probe_cc, probe_asn, domain_name ORDER BY ema_avg_blocked DESC) as max_blocked_label,
            max(ema_avg_down) OVER (PARTITION BY probe_cc, probe_asn, domain_name) as max_down,
            any(outcome_label) OVER (PARTITION BY probe_cc, probe_asn, domain_name ORDER BY ema_avg_down DESC) as max_down_label
            FROM (
                SELECT 
                domain_name,
                probe_cc,
                probe_asn,
                outcome_category,
                outcome_detail,
                outcome_label,
                avgWeighted(ema_blocked, cnt) OVER (PARTITION BY probe_cc, probe_asn, domain_name, outcome_category) as ema_avg_blocked,
                avgWeighted(ema_down, cnt) OVER (PARTITION BY probe_cc, probe_asn, domain_name, outcome_category) as ema_avg_down,
                avgWeighted(ema_ok, cnt) OVER (PARTITION BY probe_cc, probe_asn, domain_name, outcome_category) as ema_avg_ok
                FROM (
                    SELECT
                    domain_name,
                    probe_cc,
                    probe_asn,
                    outcome_category,
                    outcome_detail,
                    IF(outcome_category = 'ok', 'ok', concat(outcome_category, '.', outcome_detail)) as outcome_label,
                    exponentialMovingAverage(1)(blocked_score, t) as ema_blocked,
                    exponentialMovingAverage(1)(down_score, t) as ema_down,
                    exponentialMovingAverage(1)(ok_score, t) as ema_ok,
                    toFloat64(Count()) as cnt
                    FROM (
                        SELECT
                        domain_name,
                        probe_cc,
                        probe_asn,
                        outcome_category,
                        IF(startsWith(outcome_detail, 'failure.unknown_failure') OR startsWith(outcome_detail, 'unknown_failure'), 
                            'failure.unknown', 
                            outcome_detail
                        ) as outcome_detail,
                        blocked_score,
                        ok_score,
                        down_score,
                        row_number() OVER (PARTITION BY domain_name, probe_asn, outcome_category, outcome_detail) as t
                        FROM experiment_result 
                        WHERE timestamp > '2022-11-03' AND timestamp < '2022-12-03'
                    ) GROUP BY probe_cc, probe_asn, domain_name, outcome_category, outcome_detail
                )
            )
        ) GROUP BY probe_cc, probe_asn, domain_name
    ) GROUP BY probe_cc, domain_name
    """,
        **q_args,
    )
    df_blocked_cat = df[df["blocked_asns"] > 0].merge(
        citizenlab_global_tl[["category_code", "category_description", "domain_name"]],
        how="left",
        on="domain_name",
    )
    df_final = (
        df_blocked_cat[(~df_blocked_cat["category_code"].isnull())]
        .join(country_centers, on="probe_cc")
        .join(country_meta, on="probe_cc")
    )
    df_final.loc[:, "asn_blocking_perc"] = df_final["blocked_asns"] / (
        df_final["blocked_asns"] + df_final["ok_asns"]
    )
    return df_final


def plot_blocking_world_map(df=None, blocking_threshold=0.7):
    if df is None:
        df = get_df_blocking_world_map(blocking_threshold=blocking_threshold)

    world_background = alt.Chart(alt_data_world_110m).mark_geoshape(
        fill="lightgray", stroke="white"
    )

    world_foreground = (
        alt.Chart(df)
        .transform_filter((alt.datum.asn_blocking_perc > 0.2))
        .transform_aggregate(
            blocked_sites_in_cat="distinct(domain_name)",
            groupby=[
                "probe_cc",
                "category_code",
                "name",
                "Latitude",
                "Longitude",
                "iso3166_num",
            ],
        )
        .transform_joinaggregate(
            blocked_sites="sum(blocked_sites_in_cat)",
            blocked_categories="count()",
            blocked_category_array="values(category_code)",
            groupby=["probe_cc"],
        )
        .transform_calculate(
            blocked_category_names="pluck(datum.blocked_category_array, 'category_code')",
        )
        .transform_lookup(
            lookup="iso3166_num",
            from_=alt.LookupData(alt_data_world_110m, "id"),
            as_="geom",
            default="Other",
        )
        .transform_calculate(geometry="datum.geom.geometry", type="datum.geom.type")
        .mark_geoshape()
        .encode(
            color=alt.Color(
                "blocked_categories:Q",
                scale=alt.Scale(scheme="reds"),
            ),
            tooltip=[
                alt.Tooltip("name:N", title="Country"),
                alt.Tooltip("blocked_categories:Q", title="blocked_categories"),
                alt.Tooltip("blocked_sites:Q", title="blocked_sites"),
                alt.Tooltip("blocked_category_names:N", title="blocked_category_names"),
            ],
        )
    )

    circles = (
        alt.Chart(df)
        .transform_filter((alt.datum.asn_blocking_perc > 0.2))
        .transform_aggregate(
            blocked_sites_in_cat="distinct(domain_name)",
            groupby=["probe_cc", "category_code", "name", "Latitude", "Longitude"],
        )
        .transform_joinaggregate(
            blocked_sites="sum(blocked_sites_in_cat)",
            blocked_categories="count()",
            blocked_category_array="values(category_code)",
            groupby=["probe_cc"],
        )
        .transform_calculate(
            blocked_category_names="pluck(datum.blocked_category_array, 'category_code')",
        )
        .mark_circle()
        .encode(
            latitude="Latitude:Q",
            longitude="Longitude:Q",
            size=alt.Size("blocked_sites:Q", title="blocked_sites"),
            tooltip=[
                alt.Tooltip("name:N", title="Country"),
                alt.Tooltip("blocked_categories:Q", title="blocked_categories"),
                alt.Tooltip("blocked_sites:Q", title="blocked_sites"),
                alt.Tooltip("blocked_category_names:N", title="blocked_category_names"),
            ],
        )
    )

    return (
        (world_background + world_foreground + circles)
        .configure_view(strokeWidth=0)
        .properties(width=900, height=600)
        .project("naturalEarth1")
    )
