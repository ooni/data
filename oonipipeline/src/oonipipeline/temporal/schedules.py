from typing import List

import logging
from datetime import datetime, timedelta, timezone


from oonipipeline.temporal.workflows.analysis import AnalysisWorkflowParams
from oonipipeline.temporal.workflows.analysis import AnalysisWorkflow
from oonipipeline.temporal.workflows.common import (
    MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT,
)
from oonipipeline.temporal.workflows.common import TASK_QUEUE_NAME
from oonipipeline.temporal.workflows.common import MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT
from oonipipeline.temporal.workflows.observations import ObservationsWorkflow
from oonipipeline.temporal.workflows.observations import ObservationsWorkflowParams
from temporalio import workflow
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

log = logging.getLogger("oonipipeline.workflows")


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
            policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.BUFFER_ALL),
            state=ScheduleState(
                note="Run the analysis workflow every day with an offset of 6 hours to ensure the observation workflow has completed"
            ),
        ),
    )
    return [schedule_id]
