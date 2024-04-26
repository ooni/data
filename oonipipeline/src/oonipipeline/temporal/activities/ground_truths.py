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


@activity.defn
def make_ground_truths_in_day(params: MakeGroundTruthsParams):
    clickhouse = params.clickhouse
    day = datetime.strptime(params.day, "%Y-%m-%d").date()
    data_dir = pathlib.Path(params.data_dir)

    db = ClickhouseConnection(clickhouse)
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    ground_truth_dir = data_dir / "ground_truths"
    ground_truth_dir.mkdir(exist_ok=True)
    dst_path = ground_truth_dir / f"web-{day.strftime('%Y-%m-%d')}.sqlite3"

    if dst_path.exists():
        dst_path.unlink()

    t = PerfTimer()
    log.info(f"building ground truth DB for {day}")
    web_ground_truth_db = WebGroundTruthDB(connect_str=str(dst_path.absolute()))
    web_ground_truth_db.build_from_rows(
        rows=iter_web_ground_truths(db=db, measurement_day=day, netinfodb=netinfodb)
    )
    log.info(f"built ground truth DB {day} in {t.pretty}")
