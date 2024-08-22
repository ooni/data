from dataclasses import dataclass
from typing import List, Optional

import logging
import asyncio
from datetime import datetime, timedelta, timezone


from temporalio import workflow
from temporalio.common import (
    SearchAttributeKey,
)
from temporalio.client import (
    Client as TemporalClient,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
    SchedulePolicy,
    ScheduleOverlapPolicy,
)


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
    from oonipipeline.temporal.activities.common import (
        get_obs_count_by_cc,
        ObsCountParams,
        update_assets,
        UpdateAssetsParams,
    )
    from oonipipeline.temporal.activities.observations import (
        MakeObservationsParams,
        make_observation_in_day,
    )

    from oonipipeline.temporal.activities.ground_truths import (
        MakeGroundTruthsParams,
        make_ground_truths_in_day,
    )
    from oonipipeline.temporal.activities.common import (
        optimize_all_tables,
        ClickhouseParams,
    )
    from oonipipeline.temporal.activities.ground_truths import get_ground_truth_db_path

# Handle temporal sandbox violations related to calls to self.processName =
# mp.current_process().name in logger, see:
# https://github.com/python/cpython/blob/1316692e8c7c1e1f3b6639e51804f9db5ed892ea/Lib/logging/__init__.py#L362
logging.logMultiprocessing = False

log = logging.getLogger("oonipipeline.workflows")

TASK_QUEUE_NAME = "oonipipeline-task-queue"

# TODO(art): come up with a nicer way to nest workflows so we don't need such a high global timeout
MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT = timedelta(hours=48)
MAKE_GROUND_TRUTHS_START_TO_CLOSE_TIMEOUT = timedelta(hours=1)
MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT = timedelta(hours=10)


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
        await workflow.execute_activity(
            update_assets,
            UpdateAssetsParams(data_dir=params.data_dir),
            start_to_close_timeout=timedelta(hours=1),
        )

        if params.bucket_date is None:
            params.bucket_date = (
                get_workflow_start_time() - timedelta(days=1)
            ).strftime("%Y-%m-%d")

        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
        )

        workflow.logger.info(
            f"Starting observation making with probe_cc={params.probe_cc},test_name={params.test_name} bucket_date={params.bucket_date}"
        )
        res = await workflow.execute_activity(
            activity=make_observation_in_day,
            arg=MakeObservationsParams(
                probe_cc=params.probe_cc,
                test_name=params.test_name,
                clickhouse=params.clickhouse,
                data_dir=params.data_dir,
                fast_fail=params.fast_fail,
                bucket_date=params.bucket_date,
            ),
            task_queue=TASK_QUEUE_NAME,
            start_to_close_timeout=MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT,
        )
        res["bucket_date"] = params.bucket_date
        return res


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
        await workflow.execute_activity(
            update_assets,
            UpdateAssetsParams(data_dir=params.data_dir),
            start_to_close_timeout=timedelta(hours=1),
        )

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
                        start_to_close_timeout=MAKE_GROUND_TRUTHS_START_TO_CLOSE_TIMEOUT,
                    )
                )


@dataclass
class AnalysisWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    parallelism: int = 10
    fast_fail: bool = False
    day: Optional[str] = None
    # TODO(art): drop this
    force_rebuild_ground_truths: bool = False
    log_level: int = logging.INFO


@workflow.defn
class AnalysisWorkflow:
    @workflow.run
    async def run(self, params: AnalysisWorkflowParams) -> dict:
        if params.day is None:
            params.day = (get_workflow_start_time() - timedelta(days=1)).strftime(
                "%Y-%m-%d"
            )

        await workflow.execute_activity(
            update_assets,
            UpdateAssetsParams(data_dir=params.data_dir),
            start_to_close_timeout=timedelta(hours=1),
        )

        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
        )

        workflow.logger.info("building ground truth databases")
        t = PerfTimer()

        await workflow.execute_activity(
            make_ground_truths_in_day,
            MakeGroundTruthsParams(
                clickhouse=params.clickhouse,
                data_dir=params.data_dir,
                day=params.day,
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )
        workflow.logger.info(f"built ground truth db in {t.pretty}")

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

        workflow.logger.info(
            f"starting processing of {len(cc_batches)} batches for {params.day} days (parallelism = {params.parallelism})"
        )
        workflow.logger.info(f"({cc_batches})")

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
                        start_to_close_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
                    )
                )
                task_list.append(task)

        total_obs_count = sum(map(lambda x: x.result()["count"], task_list))
        return {"obs_count": total_obs_count, "day": params.day}


def gen_schedule_id(probe_cc: List[str], test_name: List[str], name: str):
    probe_cc_key = "ALLCCS"
    if len(probe_cc) > 0:
        probe_cc_key = ".".join(map(lambda x: x.lower(), sorted(probe_cc)))
    test_name_key = "ALLTNS"
    if len(test_name) > 0:
        test_name_key = ".".join(map(lambda x: x.lower(), sorted(test_name)))

    return f"oonipipeline-{name}-schedule-{probe_cc_key}-{test_name_key}"


async def schedule_observations(
    client: TemporalClient, params: ObservationsWorkflowParams, delete: bool
) -> List[str]:
    base_schedule_id = gen_schedule_id(
        params.probe_cc, params.test_name, "observations"
    )

    existing_schedules = []
    schedule_list = await client.list_schedules()
    async for sched in schedule_list:
        if sched.id.startswith(base_schedule_id):
            existing_schedules.append(sched.id)

    if delete is True:
        for sched_id in existing_schedules:
            schedule_handle = client.get_schedule_handle(sched_id)
            await schedule_handle.delete()
        return existing_schedules

    if len(existing_schedules) == 1:
        return existing_schedules
    elif len(existing_schedules) > 0:
        print("WARNING: multiple schedules detected")
        return existing_schedules

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    schedule_id = f"{base_schedule_id}-{ts}"

    await client.create_schedule(
        id=schedule_id,
        schedule=Schedule(
            action=ScheduleActionStartWorkflow(
                ObservationsWorkflow.run,
                params,
                id=schedule_id.replace("-schedule-", "-workflow-"),
                task_queue=TASK_QUEUE_NAME,
                execution_timeout=MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT,
                task_timeout=MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT,
                run_timeout=MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT,
            ),
            spec=ScheduleSpec(
                intervals=[
                    ScheduleIntervalSpec(
                        every=timedelta(days=1), offset=timedelta(hours=2)
                    )
                ],
            ),
            policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.TERMINATE_OTHER),
            state=ScheduleState(
                note="Run the observations workflow every day with an offset of 2 hours to ensure the files have been written to s3"
            ),
        ),
    )
    return [schedule_id]


async def schedule_analysis(
    client: TemporalClient, params: AnalysisWorkflowParams, delete: bool
) -> List[str]:
    base_schedule_id = gen_schedule_id(params.probe_cc, params.test_name, "analysis")

    existing_schedules = []
    schedule_list = await client.list_schedules()
    async for sched in schedule_list:
        if sched.id.startswith(base_schedule_id):
            existing_schedules.append(sched.id)

    if delete is True:
        for sched_id in existing_schedules:
            schedule_handle = client.get_schedule_handle(sched_id)
            await schedule_handle.delete()
        return existing_schedules

    if len(existing_schedules) == 1:
        return existing_schedules
    elif len(existing_schedules) > 0:
        print("WARNING: multiple schedules detected")
        return existing_schedules

    # We need to append a timestamp to the schedule so that we are able to rerun
    # the backfill operations by deleting the existing schedule and
    # re-scheduling it. Not doing so will mean that temporal will believe the
    # workflow has already been execututed and will refuse to re-run it.
    # TODO(art): check if there is a more idiomatic way of implementing this
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    schedule_id = f"{base_schedule_id}-{ts}"

    await client.create_schedule(
        id=schedule_id,
        schedule=Schedule(
            action=ScheduleActionStartWorkflow(
                AnalysisWorkflow.run,
                params,
                id=schedule_id.replace("-schedule-", "-workflow-"),
                task_queue=TASK_QUEUE_NAME,
                execution_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
                task_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
                run_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
            ),
            spec=ScheduleSpec(
                intervals=[
                    ScheduleIntervalSpec(
                        # We offset the Analysis workflow by 4 hours assuming
                        # that the observation generation will take less than 4
                        # hours to complete.
                        # TODO(art): it's probably better to refactor this into some
                        # kind of DAG
                        every=timedelta(days=1),
                        offset=timedelta(hours=6),
                    )
                ],
            ),
            policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.TERMINATE_OTHER),
            state=ScheduleState(
                note="Run the analysis workflow every day with an offset of 6 hours to ensure the observation workflow has completed"
            ),
        ),
    )
    return [schedule_id]
