from dataclasses import dataclass
import logging
from typing import List
from oonidata.dataclient import date_interval
from oonidata.datautils import PerfTimer
from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.temporal.activities.analysis import (
    AnalysisWorkflowParams,
    MakeAnalysisParams,
    log,
    make_analysis_in_a_day,
    make_cc_batches,
)
from oonipipeline.temporal.common import get_obs_count_by_cc, optimize_all_tables
from oonipipeline.temporal.activities.observations import (
    MakeObservationsParams,
    make_observation_in_day,
)


from temporalio import workflow


import asyncio
from datetime import datetime, timedelta

from oonipipeline.temporal.activities.ground_truths import (
    GroundTruthsWorkflowParams,
    MakeGroundTruthsParams,
    make_ground_truths_in_day,
)

log = logging.getLogger("oonidata.processing")

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver


@dataclass
class ObservationsWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    start_day: str
    end_day: str
    clickhouse: str
    data_dir: str
    fast_fail: bool
    log_level: int = logging.INFO


@workflow.defn
class ObservationsWorkflow:
    @workflow.run
    async def run(self, params: ObservationsWorkflowParams) -> dict:
        log.info("Optimizing all tables")
        optimize_all_tables(params.clickhouse)

        t_total = PerfTimer()
        log.info(
            f"Starting observation making on {params.probe_cc} ({params.start_day} - {params.end_day})"
        )
        task_list = []
        start_day = datetime.strptime(params.start_day, "%Y-%m-%d").date()
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d").date()

        async with asyncio.TaskGroup() as tg:
            for day in date_interval(start_day, end_day):
                task = tg.create_task(
                    workflow.execute_activity(
                        make_observation_in_day,
                        MakeObservationsParams(
                            probe_cc=params.probe_cc,
                            test_name=params.test_name,
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            fast_fail=params.fast_fail,
                            bucket_date=day.strftime("%Y-%m-%d"),
                        ),
                        start_to_close_timeout=timedelta(minutes=30),
                    )
                )
                task_list.append(task)

        t = PerfTimer()
        # size, msmt_count =
        total_size, total_msmt_count = 0, 0
        for task in task_list:
            res = task.result()

            total_size += res["size"]
            total_msmt_count += res["measurement_count"]

        # This needs to be adjusted once we get the the per entry concurrency working
        # mb_per_sec = round(total_size / t.s / 10**6, 1)
        # msmt_per_sec = round(total_msmt_count / t.s)
        # log.info(
        #     f"finished processing {day} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
        # )

        # with ClickhouseConnection(params.clickhouse) as db:
        #     db.execute(
        #         "INSERT INTO oonidata_processing_logs (key, timestamp, runtime_ms, bytes, msmt_count, comment) VALUES",
        #         [
        #             [
        #                 "oonidata.bucket_processed",
        #                 datetime.now(timezone.utc).replace(tzinfo=None),
        #                 int(t.ms),
        #                 total_size,
        #                 total_msmt_count,
        #                 day.strftime("%Y-%m-%d"),
        #             ]
        #         ],
        #     )

        mb_per_sec = round(total_size / t_total.s / 10**6, 1)
        msmt_per_sec = round(total_msmt_count / t_total.s)
        log.info(
            f"finished processing {params.start_day} - {params.end_day} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
        )
        log.info(
            f"{round(total_size/10**9, 2)}GB {total_msmt_count} msmts in {t_total.pretty}"
        )
        return {"size": total_size, "measurement_count": total_msmt_count}


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


@workflow.defn(sandboxed=False)
class AnalysisWorkflow:
    @workflow.run
    async def run(self, params: AnalysisWorkflowParams) -> dict:
        t_total = PerfTimer()

        t = PerfTimer()
        start_day = datetime.strptime(params.start_day, "%Y-%m-%d").date()
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d").date()

        log.info("building ground truth databases")

        async with asyncio.TaskGroup() as tg:
            for day in date_interval(start_day, end_day):
                tg.create_task(
                    workflow.execute_activity(
                        make_ground_truths_in_day,
                        MakeGroundTruthsParams(
                            day=day.strftime("%Y-%m-%d"),
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            rebuild_ground_truths=params.rebuild_ground_truths,
                        ),
                        start_to_close_timeout=timedelta(minutes=2),
                    )
                )
            log.info(f"built ground truth db in {t.pretty}")

        with ClickhouseConnection(params.clickhouse) as db:
            cnt_by_cc = get_obs_count_by_cc(
                db, start_day=start_day, end_day=end_day, test_name=params.test_name
            )
        cc_batches = make_cc_batches(
            cnt_by_cc=cnt_by_cc,
            probe_cc=params.probe_cc,
            parallelism=params.parallelism,
        )
        log.info(
            f"starting processing of {len(cc_batches)} batches over {(end_day - start_day).days} days (parallelism = {params.parallelism})"
        )
        log.info(f"({cc_batches} from {start_day} to {end_day}")

        task_list = []
        async with asyncio.TaskGroup() as tg:
            for probe_cc in cc_batches:
                for day in date_interval(start_day, end_day):
                    task = tg.create_task(
                        workflow.execute_activity(
                            make_analysis_in_a_day,
                            MakeAnalysisParams(
                                probe_cc=probe_cc,
                                test_name=params.test_name,
                                clickhouse=params.clickhouse,
                                data_dir=params.data_dir,
                                fast_fail=params.fast_fail,
                                day=day.strftime("%Y-%m-%d"),
                            ),
                            start_to_close_timeout=timedelta(minutes=30),
                        )
                    )
                    task_list.append(task)

        t = PerfTimer()
        # size, msmt_count =
        total_obs_count = 0
        for task in task_list:
            res = task.result()

            total_obs_count += res["count"]

        log.info(f"produces a total of {total_obs_count} analysis")
        obs_per_sec = round(total_obs_count / t_total.s)
        log.info(
            f"finished processing {start_day} - {end_day} speed: {obs_per_sec}obs/s)"
        )
        log.info(f"{total_obs_count} msmts in {t_total.pretty}")
        return {"total_obs_count": total_obs_count}
