from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Tuple
from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import create_queries

from temporalio import activity


@dataclass
class ClickhouseParams:
    clickhouse_url: str


@activity.defn
def optimize_all_tables(params: ClickhouseParams):
    with ClickhouseConnection(params.clickhouse_url) as db:
        for _, table_name in create_queries:
            db.execute(f"OPTIMIZE TABLE {table_name}")


@dataclass
class ObsCountParams:
    clickhouse_url: str
    # TODO(art): we should also be using test_name here
    # test_name: List[str]
    start_day: str
    end_day: str
    table_name: str = "obs_web"


@activity.defn
def get_obs_count_by_cc(
    params: ObsCountParams,
) -> Dict[str, int]:
    with ClickhouseConnection(params.clickhouse_url) as db:
        q = f"""
        SELECT 
        probe_cc, COUNT()
        FROM {params.table_name} 
        WHERE measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s 
        GROUP BY probe_cc
        """
        cc_list: List[Tuple[str, int]] = db.execute(
            q, {"start_day": params.start_day, "end_day": params.end_day}
        )  # type: ignore
        assert isinstance(cc_list, list)
    return dict(cc_list)
