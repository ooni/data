import pathlib
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Dict, List, Tuple

import fasteners

from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import make_create_queries

from oonipipeline.netinfo import NetinfoDB
from temporalio import activity

DATETIME_UTC_FORMAT = "%Y-%m-%dT%H:%M%SZ"

log = activity.logger


@dataclass
class ClickhouseParams:
    clickhouse_url: str


@activity.defn
def optimize_all_tables(params: ClickhouseParams):
    with ClickhouseConnection(params.clickhouse_url) as db:
        for _, table_name in make_create_queries():
            if table_name.startswith("buffer_"):
                continue
            db.execute(f"OPTIMIZE TABLE {table_name}")


@dataclass
class UpdateAssetsParams:
    data_dir: str
    refresh_hours: int = 10
    force_update: bool = False


@activity.defn
def update_assets(params: UpdateAssetsParams):
    last_updated_at = datetime(1984, 1, 1).replace(tzinfo=timezone.utc)
    datadir = pathlib.Path(params.data_dir)

    last_updated_path = datadir / "last_updated.txt"

    try:
        last_updated_at = datetime.strptime(
            last_updated_path.read_text(), DATETIME_UTC_FORMAT
        ).replace(tzinfo=timezone.utc)
    except FileNotFoundError:
        pass
    now = datetime.now(timezone.utc)

    last_updated_delta = now - last_updated_at
    if (
        last_updated_delta > timedelta(hours=params.refresh_hours)
        or params.force_update
    ):
        lock = fasteners.InterProcessLock(datadir / "last_updated.lock")
        with lock:
            log.info("triggering update of netinfodb")
            NetinfoDB(datadir=datadir, download=True)
            last_updated_path.write_text(now.strftime(DATETIME_UTC_FORMAT))
    else:
        log.info(
            f"skipping updating netinfodb because {last_updated_delta} < {params.refresh_hours}h"
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
