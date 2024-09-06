import pathlib
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Dict, List, Tuple
from concurrent.futures import ProcessPoolExecutor

from threading import Lock

from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import make_create_queries

from oonipipeline.netinfo import NetinfoDB
from oonipipeline.temporal.common import wait_for_mutations
from temporalio import activity

DATETIME_UTC_FORMAT = "%Y-%m-%dT%H:%M%SZ"

log = activity.logger


process_pool_executor = ProcessPoolExecutor()

@dataclass
class ClickhouseParams:
    clickhouse_url: str


@activity.defn
def optimize_all_tables(params: ClickhouseParams):
    with ClickhouseConnection(params.clickhouse_url) as db:
        table_names = [table_name for _, table_name in make_create_queries()]
        # We first flush the buffer_ tables and then the non-buffer tables
        for table_name in filter(lambda x: x.startswith("buffer_"), table_names):
            db.execute(f"OPTIMIZE TABLE {table_name}")
        for table_name in filter(lambda x: not x.startswith("buffer_"), table_names):
            db.execute(f"OPTIMIZE TABLE {table_name}")


@dataclass
class OptimizeTablesParams:
    clickhouse: str
    table_names: List[str]


@activity.defn
def optimize_tables(params: OptimizeTablesParams):
    with ClickhouseConnection(params.clickhouse) as db:
        for table_name in params.table_names:
            # Wait for mutation to complete so that we don't run into out of
            # space issues while doing the batch inserts
            wait_for_mutations(db, table_name=table_name)
            log.info(f"waiting for mutations to finish on {table_name}")
            db.execute(f"OPTIMIZE TABLE {table_name}")


def update_assets(
    data_dir: str,
    refresh_hours: int = 10,
    force_update: bool = False,
):
    last_updated_at = datetime(1984, 1, 1).replace(tzinfo=timezone.utc)
    datadir = pathlib.Path(data_dir)

    last_updated_path = datadir / "last_updated.txt"

    try:
        last_updated_at = datetime.strptime(
            last_updated_path.read_text(), DATETIME_UTC_FORMAT
        ).replace(tzinfo=timezone.utc)
    except FileNotFoundError:
        pass
    now = datetime.now(timezone.utc)

    last_updated_delta = now - last_updated_at
    if last_updated_delta > timedelta(hours=refresh_hours) or force_update:
        lock = Lock()
        with lock:
            log.info("triggering update of netinfodb")
            NetinfoDB(datadir=datadir, download=True)
            last_updated_path.write_text(now.strftime(DATETIME_UTC_FORMAT))
    else:
        log.info(
            f"skipping updating netinfodb because {last_updated_delta} < {refresh_hours}h"
        )


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
