from dataclasses import dataclass
import pathlib
import logging

from datetime import datetime

from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver

    from oonidata.datautils import PerfTimer
    from ...analysis.control import WebGroundTruthDB, iter_web_ground_truths
    from ...netinfo import NetinfoDB
    from ...db.connections import (
        ClickhouseConnection,
    )

log = activity.logger


@dataclass
class MakeGroundTruthsParams:
    clickhouse: str
    data_dir: str
    day: str
    force_rebuild: bool = False


def get_ground_truth_db_path(data_dir: str, day: str):
    ground_truth_dir = pathlib.Path(data_dir) / "ground_truths"
    ground_truth_dir.mkdir(exist_ok=True)
    return ground_truth_dir / f"web-{day}.sqlite3"


@activity.defn
def make_ground_truths_in_day(params: MakeGroundTruthsParams):
    clickhouse = params.clickhouse

    db = ClickhouseConnection(clickhouse)
    netinfodb = NetinfoDB(datadir=pathlib.Path(params.data_dir), download=False)

    dst_path = get_ground_truth_db_path(data_dir=params.data_dir, day=params.day)

    if dst_path.exists() and params.force_rebuild:
        dst_path.unlink()
    elif dst_path.exists():
        return

    t = PerfTimer()
    day = datetime.strptime(params.day, "%Y-%m-%d").date()
    log.info(f"building ground truth DB for {day}")
    web_ground_truth_db = WebGroundTruthDB(connect_str=str(dst_path.absolute()))
    web_ground_truth_db.build_from_rows(
        rows=iter_web_ground_truths(db=db, measurement_day=day, netinfodb=netinfodb)
    )
    web_ground_truth_db.close()
    log.info(f"built ground truth DB {day} in {t.pretty}")
