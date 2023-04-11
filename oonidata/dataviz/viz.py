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


def get_df_dns_analysis_raw(
    measurement_uid, start_day="2023-01-01", end_day="2023-01-02"
):
    params = {
        "start_day": start_day,
        "end_day": end_day,
        "measurement_uid": measurement_uid,
    }
    q = """
    SELECT * FROM (
    SELECT 
        report_id,
        input,
        measurement_uid,
        probe_cc,
        probe_asn,
        probe_as_org_name,
        measurement_start_time,
        resolver_ip,
        resolver_asn,
        resolver_cc, 
        resolver_as_org_name,
        resolver_as_cc,
        resolver_is_scrubbed,
        resolver_asn_probe,
        resolver_as_org_name_probe,
        dns_engine_resolver_address,
        dns_engine,
        dns_query_type,
        hostname,
        any(dns_failure) as exp_dns_failure,
        any(ip_is_bogon) OR 0 as exp_answer_contains_bogon,
        any(ip_as_cc = probe_cc) OR 0 as exp_answer_contains_matching_probe_cc,
        any(dns_answer_asn = probe_asn) OR 0 as exp_answer_contains_matching_probe_asn,
        any(lower(ip_as_org_name) = lower(probe_as_org_name)) OR 0 as exp_answer_contains_matching_probe_as_org_name,
        groupArrayIf(
            tuple(dns_answer, dns_answer_asn, dns_answer_as_org_name, ip_as_cc), 
            dns_answer IS NOT NULL
        ) as dns_answers
    FROM obs_web
    WHERE
    measurement_start_time > %(start_day)s
    AND measurement_start_time < %(end_day)s
    AND measurement_uid = %(measurement_uid)s
    AND test_name = 'web_connectivity'
    AND (dns_answer IS NOT NULL OR dns_failure IS NOT NULL)
    GROUP BY report_id,
        input,
        measurement_uid,
        probe_cc,
        probe_asn,
        probe_as_org_name,
        measurement_start_time,
        resolver_ip,
        resolver_asn,
        resolver_cc, 
        resolver_as_org_name,
        resolver_as_cc,
        resolver_is_scrubbed,
        resolver_asn_probe,
        resolver_as_org_name_probe,
        dns_engine_resolver_address,
        dns_engine, hostname, dns_query_type
) as exp
LEFT JOIN (
    SELECT 
        hostname,
        answers,
        failure_asns,
        nxdomain_asns,
        ok_asns,
        ctrl_answers,
        ctrl_failures
    FROM (
        SELECT 
        hostname,

        groupArrayIf(tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns), dns_answer IS NOT NULL) as answers,

        anyIf(failure_asns, dns_answer IS NULL) as failure_asns,

        anyIf(nxdomain_asns, dns_answer IS NULL) as nxdomain_asns,

        arrayReduce('groupUniqArray', arrayFlatten(groupUniqArray(answer_asns))) as ok_asns
        FROM (
            SELECT 
            hostname,
            dns_answer,
            ip_as_org_name,
            ip_asn,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), tls_is_certificate_valid = 1) as tls_consistent_asns,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), dns_failure IS NULL) as answer_asns,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), dns_failure IS NOT NULL) as failure_asns,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), dns_failure = 'dns_nxdomain_error') as nxdomain_asns
            FROM obs_web
            WHERE
            measurement_start_time > %(start_day)s
            AND measurement_start_time < %(end_day)s
            AND (dns_answer IS NOT NULL OR dns_failure IS NOT NULL)
            GROUP BY hostname, dns_answer, ip_as_org_name, ip_asn
        ) GROUP BY hostname
    ) as obs
    FULL OUTER JOIN (
        SELECT 
        hostname,
        groupUniqArrayIf(tuple(ip, ip_count), dns_failure IS NULL) as ctrl_answers,
        groupArrayIf(tuple(dns_failure, failure_count), dns_failure IS NOT NULL) as ctrl_failures
        FROM (
            SELECT
            hostname,
            ip,
            COUNT() as ip_count,
            dns_failure,
            COUNT() as failure_count
            FROM obs_web_ctrl
            WHERE 
            measurement_start_time > %(start_day)s
            AND measurement_start_time < %(end_day)s
            AND (
                dns_success = 1
                OR dns_failure IS NOT NULL
            )
            GROUP BY hostname, ip, dns_failure
        ) GROUP BY hostname
    ) as ctrl
    USING hostname
) as dns_gt
USING hostname 
    """
    return click_query(q, **params)


def get_df_dns_analysis(start_day="2023-01-01", end_day="2023-01-02", limit=100):
    params = {"start_day": start_day, "end_day": end_day}
    q = """WITH
arrayDistinct(arrayMap(x -> x.1, exp.dns_answers)) as exp_dns_answers_ips,
arrayDistinct(arrayMap(x -> x.2, exp.dns_answers)) as exp_dns_answers_asns,
arrayDistinct(arrayMap(x -> lower(x.3), exp.dns_answers)) as exp_dns_answers_as_org_names,

-- tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns)
flatten(arrayMap(
    asn -> arrayFilter(
        y -> y.3 IS NOT NULL AND asn IS NOT NULL AND assumeNotNull(y.3) = assumeNotNull(asn),
        dns_gt.answers
    ),
    exp_dns_answers_asns
)) as dns_answers_asn_match,

-- tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns)
arrayMap(
    x -> tuple(
        x.1,
        x.2,
        x.3,
        -- all answers_asns, except probe_asn
        arrayFilter(
            y -> y.1 != exp.probe_cc OR y.2 != exp.probe_asn,
            x.4
        ),
        -- all tls_consistent_asns, except probe_asn
        arrayFilter(
            y -> y.1 != exp.probe_cc OR y.2 != exp.probe_asn,
            x.5
        )
    ),
    dns_answers_asn_match
) as dns_answers_asn_match_no_asn,

arrayMap(
    x -> tuple(
        x.2,
        x.3,
        length(x.4),
        length(x.5)
    ), dns_answers_asn_match_no_asn
) as dns_answers_asn_match_no_asn_counts_tup,

-- dns_answers in the ground_truth that match the AS ORG name of the answers in the experiment
-- tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns)
flatten(arrayMap(
    asorgname -> arrayFilter(
        y -> y.2 IS NOT NULL AND asorgname IS NOT NULL AND lower(assumeNotNull(y.2)) = lower(assumeNotNull(asorgname)),
        dns_gt.answers
    ),
    exp_dns_answers_as_org_names
)) as dns_answers_as_org_name_match,

-- filter the sub-lists in the answers to exclude the ones from the VP of the probe
-- tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns)
arrayMap(
    x -> tuple(
        x.1, -- dns_answer
        x.2, -- ip_as_org_name
        x.3, -- ip_asn
        -- all answers_asns, except probe_asn
        arrayFilter(
            y -> y.1 != exp.probe_cc OR y.2 != exp.probe_asn,
            x.4
        ),
        -- all tls_consistent_asns, except probe_asn
        arrayFilter(
            y -> y.1 != exp.probe_cc OR y.2 != exp.probe_asn,
            x.5
        )
    ),
    dns_answers_as_org_name_match
) as dns_answers_as_org_name_match_no_asn,

-- tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns)
arrayMap(
    ip -> arrayFirst(
        y -> y.1 IS NOT NULL AND ip IS NOT NULL AND assumeNotNull(y.1) = assumeNotNull(ip),
        dns_gt.answers
    ),
    exp_dns_answers_ips
) as dns_answers_match,

-- tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns)
arrayMap(
    x -> tuple(
        x.1, -- dns_answer
        x.2, -- ip_as_org_name
        x.3, -- ip_asn
        -- all answers_asns, except probe_asn
        arrayFilter(
            y -> y.1 != exp.probe_cc OR y.2 != exp.probe_asn,
            x.4
        ),
        -- all tls_consistent_asns, except probe_asn
        arrayFilter(
            y -> y.1 != exp.probe_cc OR y.2 != exp.probe_asn,
            x.5
        )
    ),
    dns_answers_match
) as dns_answers_match_no_asn,

arrayMap(
    x -> tuple(
        x.2, -- ip_as_org_name
        x.3, -- ip_asn
        length(x.4), -- all_answers
        length(x.5) -- tls_consistent
    ), dns_answers_match_no_asn
) as dns_answers_match_no_asn_counts_tup,

arrayFilter(
    x -> indexOf(exp_dns_answers_asns, x.2) != 0,
    dns_answers_asn_match_no_asn_counts_tup
) as dns_answer_matching_asn,

arrayFilter(
    x -> indexOf(exp_dns_answers_as_org_names, lower(x.1)) != 0,
    dns_answers_as_org_name_match_no_asn_counts_tup
) as dns_answer_matching_as_org_name,

arrayMap(
    x -> tuple(
        x.2, -- ip_as_org_name
        x.3, -- ip_asn
        length(x.4),
        length(x.5)
    ), dns_answers_as_org_name_match_no_asn
) as dns_answers_as_org_name_match_no_asn_counts_tup


SELECT
    exp.report_id,
    exp.input,
    exp.measurement_uid,
    exp.probe_cc,
    exp.probe_asn,
    exp.measurement_start_time,
    exp.resolver_ip,
    exp.resolver_asn,
    exp.resolver_cc, 
    exp.resolver_as_org_name,
    exp.resolver_as_cc,
    exp.resolver_is_scrubbed,
    exp.resolver_asn_probe,
    exp.resolver_as_org_name_probe,
    exp.dns_engine_resolver_address,
    exp.dns_engine,
    exp.hostname,
    exp.exp_dns_failure,

    -- tuple(dns_answer, dns_answer_asn, dns_answer_as_org_name)
    exp.dns_answers as exp_dns_answers,
    
    length(exp_dns_answers) as exp_dns_answers_count,
    exp.exp_answer_contains_bogon,
    
    exp.exp_answer_contains_matching_probe_cc,
    exp.exp_answer_contains_matching_probe_asn,
    exp.exp_answer_contains_matching_probe_as_org_name,

    arraySum(arrayMap(x -> length(x.4), dns_gt.answers)) as dns_answers_all_asn_count,

    arraySum(
        arrayMap(
            x -> x.3,
            dns_answers_match_no_asn_counts_tup
        )
    ) as dns_answers_ip_match_all_count,

    --dns_answers_asn_match_tls_consistent_include_probe_count,
    --dns_answers_as_org_name_match_tls_consistent_include_probe_count,

    arraySum(
        arrayMap(
            x -> x.4,
            dns_answers_match_no_asn_counts_tup
        )
    ) as dns_answers_ip_match_tls_consistent_count,

    arraySum(
        arrayMap(
            x -> length(x.5),
            dns_answers_match
        )
    ) as dns_answers_ip_match_tls_consistent_include_probe_count,

    arraySum(
        arrayMap(
            x -> x.2,
            arrayFilter(
                x -> indexOf(exp_dns_answers_ips, x.1) != 0,
                dns_gt.ctrl_answers
            )
        )
    ) as dns_answers_ip_match_ctrl_count,

    arraySum(
        arrayMap(
            x -> x.3,
            dns_answer_matching_asn
        )
    ) as dns_answers_asn_match_all_count,

    arraySum(
        arrayMap(
            x -> x.4,
            dns_answer_matching_asn
        )
    ) as dns_answers_asn_match_tls_consistent_count,

    arraySum(
        arrayMap(
            x -> x.3,
            dns_answer_matching_as_org_name
        )
    ) as dns_answers_as_org_name_match_all_count,

    arraySum(
        arrayMap(
            x -> x.4,
            dns_answer_matching_as_org_name
        )
    ) as dns_answers_as_org_name_match_tls_consistent_count,

    -- tuple(probe_cc, probe_asn)
    --dns_gt.failure_asns,

    length(arrayFilter(
        x -> x.1 != exp.probe_cc OR x.2 != exp.probe_asn, 
        dns_gt.failure_asns
    )) as failure_asn_count,

    -- tuple(probe_cc, probe_asn)
    --dns_gt.nxdomain_asns,
    
    -- All ASNS with NXDOMAIN != (probe_cc, probe_asn)
    length(arrayFilter(
        x -> x.1 != exp.probe_cc OR x.2 != exp.probe_asn, 
        dns_gt.nxdomain_asns
    )) as nxdomain_asn_count,

    -- tuple(probe_cc, probe_asn)
    --dns_gt.ok_asns,

    -- All ASNS with NXDOMAIN != (probe_cc, probe_asn)
    length(arrayFilter(
        x -> x.1 != exp.probe_cc OR x.2 != exp.probe_asn, 
        dns_gt.ok_asns
    )) as ok_asn_count,

    -- tuple(ip, ip_count)
    --dns_gt.ctrl_answers,

    -- tuple(dns_failure, failure_count)
    --dns_gt.ctrl_failures,

    --dns_answers_ip_match_ctrl_count,
    --ctrl_failures_count


    arraySum(
        arrayMap(
            x -> x.2,
            arrayFilter(
                x -> exp_dns_failure IS NOT NULL AND x.1 = exp_dns_failure,
                dns_gt.ctrl_failures
            )
        )
    ) as ctrl_matching_failures_count,

    arraySum(
        arrayMap(
            x -> x.2,
            arrayFilter(
                x -> x.1 IS NOT NULL,
                dns_gt.ctrl_failures
            )
        )
    ) as ctrl_failure_count

FROM (
    SELECT 
        report_id,
        input,
        measurement_uid,
        probe_cc,
        probe_asn,
        probe_as_org_name,
        measurement_start_time,
        resolver_ip,
        resolver_asn,
        resolver_cc, 
        resolver_as_org_name,
        resolver_as_cc,
        resolver_is_scrubbed,
        resolver_asn_probe,
        resolver_as_org_name_probe,
        dns_engine_resolver_address,
        dns_engine,
        dns_query_type,
        hostname,
        any(dns_failure) as exp_dns_failure,
        any(ip_is_bogon) OR 0 as exp_answer_contains_bogon,
        any(ip_as_cc = probe_cc) OR 0 as exp_answer_contains_matching_probe_cc,
        any(dns_answer_asn = probe_asn) OR 0 as exp_answer_contains_matching_probe_asn,
        any(lower(ip_as_org_name) = lower(probe_as_org_name)) OR 0 as exp_answer_contains_matching_probe_as_org_name,
        groupArrayIf(
            tuple(dns_answer, dns_answer_asn, dns_answer_as_org_name, ip_as_cc), 
            dns_answer IS NOT NULL
        ) as dns_answers
    FROM obs_web
    WHERE
    measurement_start_time > %(start_day)s
    AND measurement_start_time < %(end_day)s
    AND test_name = 'web_connectivity'
    AND (dns_answer IS NOT NULL OR dns_failure IS NOT NULL)
    GROUP BY report_id,
        input,
        measurement_uid,
        probe_cc,
        probe_asn,
        probe_as_org_name,
        measurement_start_time,
        resolver_ip,
        resolver_asn,
        resolver_cc, 
        resolver_as_org_name,
        resolver_as_cc,
        resolver_is_scrubbed,
        resolver_asn_probe,
        resolver_as_org_name_probe,
        dns_engine_resolver_address,
        dns_engine, hostname, dns_query_type
) as exp
LEFT JOIN (
    SELECT 
        hostname,
        answers,
        failure_asns,
        nxdomain_asns,
        ok_asns,
        ctrl_answers,
        ctrl_failures
    FROM (
        SELECT 
        hostname,

        groupArrayIf(tuple(dns_answer, ip_as_org_name, ip_asn, answer_asns, tls_consistent_asns), dns_answer IS NOT NULL) as answers,

        anyIf(failure_asns, dns_answer IS NULL) as failure_asns,

        anyIf(nxdomain_asns, dns_answer IS NULL) as nxdomain_asns,

        arrayReduce('groupUniqArray', arrayFlatten(groupUniqArray(answer_asns))) as ok_asns
        FROM (
            SELECT 
            hostname,
            dns_answer,
            ip_as_org_name,
            ip_asn,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), tls_is_certificate_valid = 1) as tls_consistent_asns,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), dns_failure IS NULL) as answer_asns,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), dns_failure IS NOT NULL) as failure_asns,
            groupUniqArrayIf(tuple(probe_cc, probe_asn), dns_failure = 'dns_nxdomain_error') as nxdomain_asns
            FROM obs_web
            WHERE
            measurement_start_time > %(start_day)s
            AND measurement_start_time < %(end_day)s
            AND (dns_answer IS NOT NULL OR dns_failure IS NOT NULL)
            GROUP BY hostname, dns_answer, ip_as_org_name, ip_asn
        ) GROUP BY hostname
    ) as obs
    FULL OUTER JOIN (
        SELECT 
        hostname,
        groupUniqArrayIf(tuple(ip, ip_count), dns_failure IS NULL) as ctrl_answers,
        groupArrayIf(tuple(dns_failure, failure_count), dns_failure IS NOT NULL) as ctrl_failures
        FROM (
            SELECT
            hostname,
            ip,
            COUNT() as ip_count,
            dns_failure,
            COUNT() as failure_count
            FROM obs_web_ctrl
            WHERE 
            measurement_start_time > %(start_day)s
            AND measurement_start_time < %(end_day)s
            AND (
                dns_success = 1
                OR dns_failure IS NOT NULL
            )
            GROUP BY hostname, ip, dns_failure
        ) GROUP BY hostname
    ) as ctrl
    USING hostname
) as dns_gt
USING hostname 
    """
    if limit > 0:
        params["limit"] = limit
        q += "LIMIT %(limit)d"

    return click_query(q, **params)


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
    data_name=None,
    domain_name=None,
    probe_cc=None,
    probe_asn=None,
    start_time="2022-11-03",
    end_time="2022-12-03",
):
    if df is None and data_name:
        df = alt.NamedData(data_name)

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


def plot_blocking_world_map(df=None, data_name=None, blocking_threshold=0.7):
    if df is None and data_name:
        df = alt.NamedData(data_name)

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
