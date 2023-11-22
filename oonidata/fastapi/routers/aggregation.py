from datetime import date, datetime, timedelta, timezone
from typing import List, Literal, Optional, Union, Dict
from typing_extensions import Annotated
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from oonidata.datautils import PerfTimer

from ..dependencies import ClickhouseClient, get_clickhouse_client
from .measurements import (
    OONI_DATA_COLS_REMAP,
    OONI_DATA_COLS_REMAP_INV,
    SinceUntil,
    test_name_to_group,
    utc_30_days_ago,
    utc_today,
)

import logging

log = logging.getLogger(__name__)

router = APIRouter()

AggregationKeys = Literal[
    "measurement_start_day",
    "domain",
    "probe_cc",
    "probe_asn",
    "test_name",
]

TimeGrains = Literal["hour", "day", "week", "month", "year", "auto"]


class DBStats(BaseModel):
    bytes: int
    elapsed_seconds: float
    row_count: int
    total_row_count: int


class AggregationEntry(BaseModel):
    anomaly_count: int
    confirmed_count: int
    failure_count: int
    ok_count: int
    measurement_count: int

    observation_count: int
    vantage_point_count: int
    measurement_start_day: date
    loni_down_map: Dict[str, float]
    loni_down_value: float
    loni_blocked_map: Dict[str, float]
    loni_blocked_value: float
    # loni_ok_map: Dict[str, float]
    loni_ok_value: float

    domain: Optional[str] = None
    probe_cc: Optional[str] = None
    probe_asn: Optional[int] = None
    test_name: Optional[str] = None


class AggregationResponse(BaseModel):
    # TODO(arturo): these keys are inconsistent with the other APIs
    db_stats: DBStats
    dimension_count: int
    result: List[AggregationEntry]


def get_measurement_start_day_agg(time_grain: TimeGrains):
    if time_grain == "hour":
        return "toStartOfHour(timeofday)"
    if time_grain == "day":
        return "toStartOfDay(timeofday)"
    if time_grain == "week":
        return "toStartOfWeek(timeofday)"
    if time_grain == "month":
        return "toStartOfMonth(timeofday)"
    # TODO(arturo): do we care to keep the auto option?
    return "toStartOfDay(timeofday)"


@router.get("/aggregation", tags=["aggregation"])
async def get_aggregation(
    db: Annotated[ClickhouseClient, Depends(get_clickhouse_client)],
    axis_x: Annotated[AggregationKeys, Query()] = "measurement_start_day",
    axis_y: Annotated[Optional[AggregationKeys], Query()] = None,
    category_code: Annotated[Optional[str], Query()] = None,
    test_name: Annotated[Optional[str], Query()] = None,
    domain: Annotated[Optional[str], Query()] = None,
    input: Annotated[Optional[str], Query()] = None,
    probe_asn: Annotated[Union[int, str, None], Query()] = None,
    probe_cc: Annotated[Optional[str], Query(min_length=2, max_length=2)] = None,
    ooni_run_link_id: Annotated[Optional[str], Query()] = None,
    since: SinceUntil = utc_30_days_ago(),
    until: SinceUntil = utc_today(),
    time_grain: Annotated[TimeGrains, Query()] = "day",
    anomaly_sensitivity: Annotated[float, Query()] = 0.7,
    format: Annotated[Literal["JSON", "CSV"], Query()] = "JSON",
    download: Annotated[bool, Query()] = False,
):
    q_args = {}
    and_clauses = []
    extra_cols = {}
    dimension_count = 1
    if axis_x == "measurement_start_day":
        # TODO(arturo): wouldn't it be nicer if we dropped the time_grain
        # argument and instead used axis_x IN (measurement_start_day,
        # measurement_start_hour, ..)?
        extra_cols[
            "measurement_start_day"
        ] = f"{get_measurement_start_day_agg(time_grain)} as measurement_start_day"
    elif axis_x:
        col = OONI_DATA_COLS_REMAP.get(axis_x)
        extra_cols[axis_x] = f"{col} as {axis_x}"

    if probe_asn is not None:
        if isinstance(probe_asn, str) and probe_asn.startswith("AS"):
            probe_asn = int(probe_asn[2:])
        q_args["probe_asn"] = probe_asn
        and_clauses.append("location_network_asn = %(probe_asn)d")
        extra_cols["probe_asn"] = "location_network_asn as probe_asn"
    if probe_cc is not None:
        q_args["probe_cc"] = probe_cc
        and_clauses.append("location_network_cc = %(probe_cc)s")
        extra_cols["probe_cc"] = "location_network_cc as probe_cc"
    if test_name is not None:
        q_args["test_name"] = test_name_to_group(test_name)
        and_clauses.append("target_nettest_group = %(test_name)s")
        extra_cols["test_name"] = "target_nettest_group as test_name"
    if category_code is not None:
        q_args["category_code"] = category_code
        and_clauses.append("target_category_code = %(category_code)s")
        extra_cols["category_code"] = "target_category_code as category_code"
    if domain is not None:
        q_args["domain"] = domain
        and_clauses.append("target_domain_name = %(domain)s")
        extra_cols["domain"] = "target_domain_name as domain"
    if input is not None:
        # XXX
        pass

    if axis_y:
        dimension_count += 1
        if axis_y == "measurement_start_day":
            # TODO(arturo): wouldn't it be nicer if we dropped the time_grain
            # argument and instead used axis_x IN (measurement_start_day,
            # measurement_start_hour, ..)?
            extra_cols[
                "measurement_start_day"
            ] = f"{get_measurement_start_day_agg(time_grain)} as measurement_start_day"
        else:
            col = OONI_DATA_COLS_REMAP_INV.get(axis_y)
            extra_cols[axis_y] = f"{col} as {axis_y}"

    if since is not None:
        q_args["since"] = since
        and_clauses.append("timeofday >= %(since)s")
    if until is not None:
        and_clauses.append("timeofday <= %(until)s")
        q_args["until"] = until

    q_args["anomaly_sensitivity"] = anomaly_sensitivity

    """
    if anomaly is True:
        and_clauses.append("arraySum(loni_blocked_values) > 0.5")
    elif anomaly is False:
        and_clauses.append("arraySum(loni_blocked_values) <= 0.5")

    if confirmed is True:
        and_clauses.append("arraySum(loni_blocked_values) == 1.0")

    if failure is False:
        # TODO(arturo): how do we map this onto failure?
        pass
    """

    where = ""
    if len(and_clauses) > 0:
        where += " WHERE "
        where += " AND ".join(and_clauses)

    base_cols = [
        "loni_down_map",
        "loni_down_value",
        "loni_blocked_map",
        "loni_blocked_value",
        "loni_ok_value",
        "measurement_count",
        "observation_count",
        "vantage_point_count",
        "confirmed_count",
        "anomaly_count",
    ]

    q = f"""
    WITH
    loni_blocked_weight_avg_map as loni_blocked_map,
    loni_down_weight_avg_map as loni_down_map,
    arraySum(mapValues(loni_blocked_map)) as loni_blocked_value_avg,
    arraySum(mapValues(loni_down_map)) as loni_down_value_avg,
    loni_ok_weight_avg_value as loni_ok_value_avg,

    loni_ok_value_avg +  loni_down_value_avg + loni_blocked_value_avg as loni_total

    SELECT

    loni_down_map,
    loni_blocked_map,

    -- TODO(arturo): this is a bit ghetto
    loni_ok_value_avg / loni_total as loni_ok_value,
    loni_down_value_avg / loni_total as loni_down_value,
    loni_blocked_value_avg / loni_total as loni_blocked_value,

    measurement_count_agg as measurement_count,
    observation_count_agg as observation_count,
    vantage_point_count,

    confirmed_count,
    anomaly_count,

    -- Extra columns
    {", ".join(extra_cols.keys())}

    FROM (
        WITH
        CAST((loni_down_keys, loni_down_values), 'Map(String, Float64)') as loni_down_map,
        CAST((loni_blocked_keys, loni_blocked_values), 'Map(String, Float64)') as loni_blocked_map
        SELECT 

        sumMap(loni_down_map) as loni_down_sum,
        countMap(loni_down_map) as loni_down_cnt,
        arraySum(mapValues(loni_down_cnt)) as loni_down_cnt_total,
        arraySum(mapValues(loni_down_sum)) as loni_down_value_total,
        mapApply(
            (k, v) -> (
                k,
                if(
                    loni_down_cnt_total == 0 or loni_down_cnt[k] == 0, 0,
                    toFloat64(v) / toFloat64(loni_down_value_total)  * toFloat64(loni_down_cnt[k])/toFloat64(loni_down_cnt_total)
                )
            ),
            loni_down_sum
        ) as loni_down_weight_avg_map,
        
        sumMap(loni_blocked_map) as loni_blocked_sum,
        countMap(loni_blocked_map) as loni_blocked_cnt,
        arraySum(mapValues(loni_blocked_cnt)) as loni_blocked_cnt_total,
        arraySum(mapValues(loni_blocked_sum)) as loni_blocked_value_total,
        mapApply(
            (k, v) -> (
                k,
                if(
                    loni_blocked_cnt_total == 0 or loni_blocked_cnt[k] == 0, 0,
                    toFloat64(v) / toFloat64(loni_blocked_value_total) * toFloat64(loni_blocked_cnt[k]) / toFloat64(loni_blocked_cnt_total)
                )
            ),
            loni_blocked_sum
        ) as loni_blocked_weight_avg_map,
        
        sum(loni_ok_value) as loni_ok_total,
        COUNT() as loni_ok_cnt,
        loni_ok_total/loni_ok_cnt as loni_ok_weight_avg_value,

        SUM(measurement_count) as measurement_count_agg,
        SUM(observation_count) as observation_count_agg,
        COUNT(DISTINCT 
            location_network_type,
            location_network_asn,
            location_network_cc,
            location_resolver_asn
        ) as vantage_point_count,

        sumIf(measurement_count, arraySum(loni_blocked_values) == 1) as confirmed_count,
        sumIf(measurement_count, arraySum(loni_blocked_values) >= %(anomaly_sensitivity)f) as anomaly_count,

        -- Extra columns
        {", ".join(extra_cols.values())}

        FROM measurement_experiment_result
        {where}
        GROUP BY {", ".join(extra_cols.keys())}
        ORDER BY {", ".join(extra_cols.keys())}
    )
    """

    cols = base_cols + list(extra_cols.keys())
    t = PerfTimer()
    log.info(f"running query {q} with {q_args}")
    rows = db.execute(q, q_args)

    results: List[AggregationEntry] = []
    if rows and isinstance(rows, list):
        for row in rows:
            d = dict(zip(cols, row))
            d["failure_count"] = 0
            d["ok_count"] = d["measurement_count"] - d["anomaly_count"]
            log.info(f"adding {d}")
            results.append(AggregationEntry(**d))
    return {
        "db_stats": {
            "bytes": -1,
            "elapsed_seconds": t.s,
            "row_count": len(results),
            "total_row_count": len(results),
        },
        "dimension_count": dimension_count,
        # TODO(arturo): it's annoying that this is result instead of results
        "result": results,
    }
