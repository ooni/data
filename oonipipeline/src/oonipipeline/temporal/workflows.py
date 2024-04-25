from dataclasses import dataclass
from typing import List, Optional

import logging
import multiprocessing
import concurrent.futures
import asyncio
from datetime import datetime, timedelta, timezone

from temporalio import workflow
from temporalio.common import SearchAttributeKey
from temporalio.worker import Worker, SharedStateManager
from temporalio.client import (
    Client as TemporalClient,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
)

from oonipipeline.temporal.activities.common import (
    optimize_all_tables,
    ClickhouseParams,
)


# Handle temporal sandbox violations related to calls to self.processName =
# mp.current_process().name in logger, see:
# https://github.com/python/cpython/blob/1316692e8c7c1e1f3b6639e51804f9db5ed892ea/Lib/logging/__init__.py#L362
logging.logMultiprocessing = False

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver

    from tqdm import tqdm
    from oonidata.dataclient import date_interval
    from oonidata.datautils import PerfTimer
    from oonipipeline.db.connections import ClickhouseConnection
    from oonipipeline.temporal.activities.analysis import (
        MakeAnalysisParams,
        log,
        make_analysis_in_a_day,
        make_cc_batches,
    )
    from oonipipeline.temporal.activities.common import (
        get_obs_count_by_cc,
        ObsCountParams,
    )
    from oonipipeline.temporal.activities.observations import (
        MakeObservationsParams,
        make_observation_in_day,
    )

    from oonipipeline.temporal.activities.ground_truths import (
        MakeGroundTruthsParams,
        make_ground_truths_in_day,
    )

log = logging.getLogger("oonidata.processing")


TASK_QUEUE_NAME = "oonipipeline-task-queue"
OBSERVATION_WORKFLOW_ID = "oonipipeline-observations"


def make_worker(client: TemporalClient, parallelism: int) -> Worker:
    return Worker(
        client,
        task_queue=TASK_QUEUE_NAME,
        workflows=[
            ObservationsWorkflow,
            GroundTruthsWorkflow,
            AnalysisWorkflow,
            ObservationsBackfillWorkflow,
            AnalysisBackfillWorkflow,
        ],
        activities=[
            make_observation_in_day,
            make_ground_truths_in_day,
            make_analysis_in_a_day,
            optimize_all_tables,
            get_obs_count_by_cc,
        ],
        activity_executor=concurrent.futures.ProcessPoolExecutor(parallelism + 2),
        max_concurrent_activities=parallelism,
        shared_state_manager=SharedStateManager.create_from_multiprocessing(
            multiprocessing.Manager()
        ),
    )


def get_workflow_start_time() -> datetime:
    workflow_start_time = workflow.info().typed_search_attributes.get(
        SearchAttributeKey.for_datetime("TemporalScheduledStartTime")
    )
    assert workflow_start_time is not None, "TemporalScheduledStartTime not set"
    return workflow_start_time


@dataclass
class ObservationsWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    fast_fail: bool
    log_level: int = logging.INFO
    bucket_date: Optional[str] = None


@workflow.defn
class ObservationsWorkflow:
    @workflow.run
    async def run(self, params: ObservationsWorkflowParams) -> dict:
        if params.bucket_date is None:
            params.bucket_date = (
                get_workflow_start_time() - timedelta(days=1)
            ).strftime("%Y-%m-%d")

        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
        )

        log.info(
            f"Starting observation making with probe_cc={params.probe_cc},test_name={params.test_name} bucket_date={params.bucket_date}"
        )

        res = await workflow.execute_activity(
            make_observation_in_day,
            MakeObservationsParams(
                probe_cc=params.probe_cc,
                test_name=params.test_name,
                clickhouse=params.clickhouse,
                data_dir=params.data_dir,
                fast_fail=params.fast_fail,
                bucket_date=params.bucket_date,
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )
        res["bucket_date"] = params.bucket_date
        return res


@dataclass
class BackfillWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    start_day: str
    end_day: str
    clickhouse: str
    data_dir: str
    fast_fail: bool
    log_level: int = logging.INFO


@workflow.defn
class ObservationsBackfillWorkflow:
    @workflow.run
    async def run(self, params: BackfillWorkflowParams) -> dict:
        start_day = datetime.strptime(params.start_day, "%Y-%m-%d")
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d")

        t = PerfTimer(unstoppable=True)
        task_list = []
        for day in date_interval(start_day, end_day):
            task_list.append(
                workflow.execute_child_workflow(
                    ObservationsWorkflow.run,
                    ObservationsWorkflowParams(
                        bucket_date=day.strftime("%Y-%m-%d"),
                        probe_cc=params.probe_cc,
                        test_name=params.test_name,
                        clickhouse=params.clickhouse,
                        data_dir=params.data_dir,
                        fast_fail=params.fast_fail,
                        log_level=params.log_level,
                    ),
                )
            )

        total_size = 0
        total_measurement_count = 0

        for task in asyncio.as_completed(task_list):
            res = await task
            bucket_date = res["bucket_date"]
            total_size += res["size"]
            total_measurement_count += res["measurement_count"]

            mb_per_sec = round(total_size / t.s / 10**6, 1)
            msmt_per_sec = round(total_measurement_count / t.s)
            log.info(
                f"finished processing {bucket_date} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
            )

        mb_per_sec = round(total_size / t.s / 10**6, 1)
        msmt_per_sec = round(total_measurement_count / t.s)
        log.info(
            f"finished processing {params.start_day} - {params.end_day} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
        )

        return {
            "size": total_size,
            "measurement_count": total_measurement_count,
            "runtime_ms": t.ms,
            "mb_per_sec": mb_per_sec,
            "msmt_per_sec": msmt_per_sec,
            "start_day": params.start_day,
            "end_day": params.start_day,
        }


OBSERVATIONS_SCHEDULE_ID = "oonipipeline-observations-schedule-id"


def gen_observation_schedule_id(params: ObservationsWorkflowParams) -> str:
    probe_cc_key = "ALLCCS"
    if len(params.probe_cc) > 0:
        probe_cc_key = ".".join(map(lambda x: x.lower(), sorted(params.probe_cc)))
    test_name_key = "ALLTNS"
    if len(params.test_name) > 0:
        test_name_key = ".".join(map(lambda x: x.lower(), sorted(params.test_name)))

    return f"oonipipeline-observations-{probe_cc_key}-{test_name_key}"


async def schedule_observations(
    client: TemporalClient, params: ObservationsWorkflowParams
):
    schedule_id = gen_observation_schedule_id(params)

    await client.create_schedule(
        schedule_id,
        Schedule(
            action=ScheduleActionStartWorkflow(
                ObservationsWorkflow.run,
                params,
                id=OBSERVATION_WORKFLOW_ID,
                task_queue=TASK_QUEUE_NAME,
                execution_timeout=timedelta(minutes=30),
                task_timeout=timedelta(minutes=30),
                run_timeout=timedelta(minutes=30),
            ),
            spec=ScheduleSpec(
                intervals=[
                    ScheduleIntervalSpec(
                        every=timedelta(days=1), offset=timedelta(hours=2)
                    )
                ],
            ),
            state=ScheduleState(
                note="Run the observations workflow every day with an offset of 2 hours to ensure the files have been written to s3"
            ),
        ),
    )


@dataclass
class GroundTruthsWorkflowParams:
    start_day: str
    end_day: str
    clickhouse: str
    data_dir: str


@workflow.defn
class GroundTruthsWorkflow:
    @workflow.run
    async def run(
        self,
        params: GroundTruthsWorkflowParams,
    ):
        start_day = datetime.strptime(params.start_day, "%Y-%m-%d").date()
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d").date()

        async with asyncio.TaskGroup() as tg:
            for day in date_interval(start_day, end_day):
                tg.create_task(
                    workflow.execute_activity(
                        make_ground_truths_in_day,
                        MakeGroundTruthsParams(
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            day=day.strftime("%Y-%m-%d"),
                        ),
                        start_to_close_timeout=timedelta(minutes=30),
                    )
                )


@dataclass
class AnalysisWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    day: str
    clickhouse: str
    data_dir: str
    parallelism: int
    fast_fail: bool
    rebuild_ground_truths: bool
    log_level: int = logging.INFO


@workflow.defn(sandboxed=False)
class AnalysisWorkflow:
    @workflow.run
    async def run(self, params: AnalysisWorkflowParams) -> dict:
        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
        )

        log.info("building ground truth databases")
        t = PerfTimer()
        if params.rebuild_ground_truths:
            await workflow.execute_activity(
                make_ground_truths_in_day,
                MakeGroundTruthsParams(
                    clickhouse=params.clickhouse,
                    data_dir=params.data_dir,
                    day=params.day,
                ),
                start_to_close_timeout=timedelta(minutes=30),
            )
            log.info(f"built ground truth db in {t.pretty}")

        start_day = datetime.strptime(params.day, "%Y-%m-%d").date()
        cnt_by_cc = await workflow.execute_activity(
            get_obs_count_by_cc,
            ObsCountParams(
                clickhouse_url=params.clickhouse,
                start_day=start_day.strftime("%Y-%m-%d"),
                end_day=(start_day + timedelta(days=1)).strftime("%Y-%m-%d"),
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )

        cc_batches = make_cc_batches(
            cnt_by_cc=cnt_by_cc,
            probe_cc=params.probe_cc,
            parallelism=params.parallelism,
        )

        log.info(
            f"starting processing of {len(cc_batches)} batches for {params.day} days (parallelism = {params.parallelism})"
        )
        log.info(f"({cc_batches})")

        task_list = []
        async with asyncio.TaskGroup() as tg:
            for probe_cc in cc_batches:
                task = tg.create_task(
                    workflow.execute_activity(
                        make_analysis_in_a_day,
                        MakeAnalysisParams(
                            probe_cc=probe_cc,
                            test_name=params.test_name,
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            fast_fail=params.fast_fail,
                            day=params.day,
                        ),
                        start_to_close_timeout=timedelta(minutes=30),
                    )
                )
                task_list.append(task)

        total_obs_count = sum(map(lambda x: x.result()["count"], task_list))
        return {"obs_count": total_obs_count, "day": params.day}


@workflow.defn
class AnalysisBackfillWorkflow:
    @workflow.run
    async def run(self, params: BackfillWorkflowParams) -> dict:
        start_day = datetime.strptime(params.start_day, "%Y-%m-%d")
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d")

        t = PerfTimer(unstoppable=True)
        task_list = []
        for day in date_interval(start_day, end_day):
            task_list.append(
                workflow.execute_child_workflow(
                    AnalysisWorkflow.run,
                    AnalysisWorkflowParams(
                        day=day.strftime("%Y-%m-%d"),
                        probe_cc=params.probe_cc,
                        test_name=params.test_name,
                        clickhouse=params.clickhouse,
                        data_dir=params.data_dir,
                        fast_fail=params.fast_fail,
                        log_level=params.log_level,
                        parallelism=10,
                        rebuild_ground_truths=True,
                    ),
                )
            )

        total_obs_count = 0

        for task in asyncio.as_completed(task_list):
            res = await task
            day = res["day"]
            total_obs_count += res["obs_count"]

            obs_per_sec = round(total_obs_count / t.s / 10**6, 1)
            log.info(
                f"finished processing {day} speed: {total_obs_count} obs ({obs_per_sec}obs/s)"
            )

        obs_per_sec = round(total_obs_count / t.s / 10**6, 1)
        log.info(
            f"finished processing {day} speed: {total_obs_count} obs ({obs_per_sec}obs/s)"
        )

        return {
            "observation_count": total_obs_count,
            "runtime_ms": t.ms,
            "obs_per_sec": obs_per_sec,
            "start_day": params.start_day,
            "end_day": params.start_day,
        }
