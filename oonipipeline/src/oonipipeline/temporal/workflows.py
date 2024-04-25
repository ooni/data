from dataclasses import dataclass
from typing import List

import logging
import multiprocessing
import concurrent.futures
import asyncio
from datetime import datetime, timedelta, timezone

from temporalio import workflow
from temporalio.worker import Worker, SharedStateManager
from temporalio.client import (
    Client as TemporalClient,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
)


# Handle temporal sandbox violations related to calls to self.processName =
# mp.current_process().name in logger, see:
# https://github.com/python/cpython/blob/1316692e8c7c1e1f3b6639e51804f9db5ed892ea/Lib/logging/__init__.py#L362
logging.logMultiprocessing = False

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver

    from oonidata.dataclient import date_interval
    from oonidata.datautils import PerfTimer
    from oonipipeline.db.connections import ClickhouseConnection
    from oonipipeline.temporal.activities.analysis import (
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
        ],
        activities=[
            make_observation_in_day,
            make_ground_truths_in_day,
            make_analysis_in_a_day,
        ],
        activity_executor=concurrent.futures.ProcessPoolExecutor(parallelism + 2),
        max_concurrent_activities=parallelism,
        shared_state_manager=SharedStateManager.create_from_multiprocessing(
            multiprocessing.Manager()
        ),
    )


@dataclass
class ObservationsWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    fast_fail: bool
    log_level: int = logging.INFO


@workflow.defn
class ObservationsWorkflow:
    @workflow.run
    async def run(self, params: ObservationsWorkflowParams) -> dict:
        # TODO(art): wrap this a coroutine call
        optimize_all_tables(params.clickhouse)

        workflow_id = workflow.info().workflow_id

        # TODO(art): this is quite sketchy. Waiting on temporal slack question:
        # https://temporalio.slack.com/archives/CTT84RS0P/p1714040382186429
        run_ts = datetime.strptime(
            "-".join(workflow_id.split("-")[-3:]),
            "%Y-%m-%dT%H:%M:%SZ",
        )
        bucket_date = (run_ts - timedelta(days=1)).strftime("%Y-%m-%d")

        # read_time = workflow_info.start_time - timedelta(days=1)
        # log.info(f"workflow.info().start_time={workflow.info().start_time} ")
        # log.info(f"workflow.info().cron_schedule={workflow.info().cron_schedule} ")
        # log.info(f"workflow_info.workflow_id={workflow_info.workflow_id} ")
        # log.info(f"workflow_info.run_id={workflow_info.run_id} ")
        # log.info(f"workflow.now()={workflow.now()}")
        # print(workflow)
        # bucket_date = f"{read_time.year}-{read_time.month:02}-{read_time.day:02}"

        t = PerfTimer()
        log.info(
            f"Starting observation making with probe_cc={params.probe_cc},test_name={params.test_name} bucket_date={bucket_date}"
        )

        res = await workflow.execute_activity(
            make_observation_in_day,
            MakeObservationsParams(
                probe_cc=params.probe_cc,
                test_name=params.test_name,
                clickhouse=params.clickhouse,
                data_dir=params.data_dir,
                fast_fail=params.fast_fail,
                bucket_date=bucket_date,
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )

        total_size = res["size"]
        total_measurement_count = res["measurement_count"]

        # This needs to be adjusted once we get the the per entry concurrency working
        mb_per_sec = round(total_size / t.s / 10**6, 1)
        msmt_per_sec = round(total_measurement_count / t.s)
        log.info(
            f"finished processing {bucket_date} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
        )

        # with ClickhouseConnection(params.clickhouse) as db:
        #     db.execute(
        #         "INSERT INTO oonidata_processing_logs (key, timestamp, runtime_ms, bytes, msmt_count, comment) VALUES",
        #         [
        #             [
        #                 "oonidata.bucket_processed",
        #                 datetime.now(timezone.utc).replace(tzinfo=None),
        #                 int(t.ms),
        #                 total_size,
        #                 total_measurement_count,
        #                 bucket_date,
        #             ]
        #         ],
        #     )

        return {
            "size": total_size,
            "measurement_count": total_measurement_count,
            "runtime_ms": t.ms,
            "mb_per_sec": mb_per_sec,
            "msmt_per_sec": msmt_per_sec,
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


@dataclass
class AnalysisWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    start_day: str
    end_day: str
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
