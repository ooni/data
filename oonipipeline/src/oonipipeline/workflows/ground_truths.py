import asyncio
from dataclasses import dataclass
import pathlib
import logging

from datetime import datetime, timedelta

from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver

    from oonidata.dataclient import date_interval
    from oonidata.datautils import PerfTimer
    from ..analysis.control import WebGroundTruthDB, iter_web_ground_truths
    from ..netinfo import NetinfoDB
    from ..db.connections import (
        ClickhouseConnection,
    )

log = logging.getLogger("oonidata.processing")


@dataclass
class GroundTruthsWorkflowParams:
    start_day: str
    end_day: str
    clickhouse: str
    data_dir: str


@dataclass
class MakeGroundTruthsParams:
    clickhouse: str
    data_dir: str
    day: str
    rebuild_ground_truths: bool


@activity.defn
def make_ground_truths_in_day(params: MakeGroundTruthsParams):
    clickhouse = params.clickhouse
    day = datetime.strptime(params.day, "%Y-%m-%d").date()
    data_dir = pathlib.Path(params.data_dir)
    rebuild_ground_truths = params.rebuild_ground_truths

    db = ClickhouseConnection(clickhouse)
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    ground_truth_dir = data_dir / "ground_truths"
    ground_truth_dir.mkdir(exist_ok=True)
    dst_path = ground_truth_dir / f"web-{day.strftime('%Y-%m-%d')}.sqlite3"
    if not dst_path.exists() or rebuild_ground_truths != False:
        if dst_path.exists():
            dst_path.unlink()

        t = PerfTimer()
        log.info(f"building ground truth DB for {day}")
        web_ground_truth_db = WebGroundTruthDB(connect_str=str(dst_path.absolute()))
        web_ground_truth_db.build_from_rows(
            rows=iter_web_ground_truths(db=db, measurement_day=day, netinfodb=netinfodb)
        )
        log.info(f"built ground truth DB {day} in {t.pretty}")


@workflow.defn
class GroundTruthsWorkflow:
    @workflow.run
    async def run(
        self,
        params: GroundTruthsWorkflowParams,
    ):
        task_list = []
        start_day = datetime.strptime(params.start_day, "%Y-%m-%d").date()
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d").date()

        async with asyncio.TaskGroup() as tg:
            for day in date_interval(start_day, end_day):
                task = tg.create_task(
                    workflow.execute_activity(
                        make_ground_truths_in_day,
                        MakeGroundTruthsParams(
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            day=day.strftime("%Y-%m-%d"),
                            rebuild_ground_truths=True,
                        ),
                        start_to_close_timeout=timedelta(minutes=30),
                    )
                )
                task_list.append(task)
