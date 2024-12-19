import pathlib
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Dict, List, Tuple
from concurrent.futures import ProcessPoolExecutor

from threading import Lock

from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import make_create_queries

from oonipipeline.netinfo import NetinfoDB
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
        for tn in table_names:
            db.execute(f"OPTIMIZE TABLE {tn}")


@dataclass
class OptimizeTablesParams:
    clickhouse: str
    table_names: List[str]
    partition_str: str


@activity.defn
def optimize_tables(params: OptimizeTablesParams):
    with ClickhouseConnection(params.clickhouse) as db:
        for table_name in params.table_names:
            log.info(f"OPTIMIZING {table_name} for partition {params.partition_str}")
            db.execute(
                f"OPTIMIZE TABLE {table_name} PARTITION '{params.partition_str}'"
            )


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
