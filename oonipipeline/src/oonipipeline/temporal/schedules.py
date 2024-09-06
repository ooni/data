from dataclasses import dataclass
from typing import List, Optional, TypedDict

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
    ScheduleBackfill,
    ScheduleActionStartWorkflow,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
    SchedulePolicy,
    ScheduleOverlapPolicy,
)

log = logging.getLogger("oonipipeline.workflows")

OBSERVATIONS_SCHED_PREFIX = "oopln-sched-observations"
OBSERVATIONS_WF_PREFIX = "oopln-wf-observations"
ANALYSIS_WF_PREFIX = "oopln-wf-analysis"
ANALYSIS_SCHED_PREFIX = "oopln-sched-analysis"


def gen_schedule_filter_id(probe_cc: List[str], test_name: List[str]):
    probe_cc_key = "ALLCCS"
    if len(probe_cc) > 0:
        probe_cc_key = ".".join(map(lambda x: x.lower(), sorted(probe_cc)))
    test_name_key = "ALLTNS"
    if len(test_name) > 0:
        test_name_key = ".".join(map(lambda x: x.lower(), sorted(test_name)))

    return f"{probe_cc_key}-{test_name_key}"


@dataclass
class ScheduleIdMap:
    observations: Optional[str] = None
    analysis: Optional[str] = None


@dataclass
class ScheduleIdMapList:
    observations: List[str]
    analysis: List[str]


async def list_existing_schedules(
    client: TemporalClient,
    probe_cc: List[str],
    test_name: List[str],
):
    schedule_id_map_list = ScheduleIdMapList(
        observations=[],
        analysis=[],
    )
    filter_id = gen_schedule_filter_id(probe_cc, test_name)

    schedule_list = await client.list_schedules()
    async for sched in schedule_list:
        if sched.id.startswith(f"{OBSERVATIONS_SCHED_PREFIX}-{filter_id}"):
            schedule_id_map_list.observations.append(sched.id)
        elif sched.id.startswith(f"{ANALYSIS_WF_PREFIX}-{filter_id}"):
            schedule_id_map_list.analysis.append(sched.id)
    return schedule_id_map_list


async def schedule_all(
    client: TemporalClient,
    probe_cc: List[str],
    test_name: List[str],
    clickhouse_url: str,
    data_dir: str,
) -> ScheduleIdMap:
    schedule_id_map = ScheduleIdMap()
    filter_id = gen_schedule_filter_id(probe_cc, test_name)
    # We need to append a timestamp to the schedule so that we are able to rerun
    # the backfill operations by deleting the existing schedule and
    # re-scheduling it. Not doing so will mean that temporal will believe the
    # workflow has already been execututed and will refuse to re-run it.
    # TODO(art): check if there is a more idiomatic way of implementing this
    ts = datetime.now(timezone.utc).strftime("%y.%m.%d_%H%M%S")

    existing_schedules = await list_existing_schedules(
        client=client, probe_cc=probe_cc, test_name=test_name
    )
    assert (
        len(existing_schedules.observations) < 2
    ), f"duplicate schedule for observations: {existing_schedules.observations}"
    assert (
        len(existing_schedules.analysis) < 2
    ), f"duplicate schedule for analysis: {existing_schedules.analysis}"

    if len(existing_schedules.observations) == 1:
        schedule_id_map.observations = existing_schedules.observations[0]
    if len(existing_schedules.analysis) == 1:
        schedule_id_map.analysis = existing_schedules.analysis[0]

    if schedule_id_map.observations is None:
        obs_params = ObservationsWorkflowParams(
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse_url,
            data_dir=data_dir,
            fast_fail=False,
        )
        sched_handle = await client.create_schedule(
            id=f"{OBSERVATIONS_SCHED_PREFIX}-{filter_id}-{ts}",
            schedule=Schedule(
                action=ScheduleActionStartWorkflow(
                    ObservationsWorkflow.run,
                    obs_params,
                    id=f"{OBSERVATIONS_WF_PREFIX}-{filter_id}-{ts}",
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
                policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.ALLOW_ALL),
                state=ScheduleState(
                    note="Run the observations workflow every day with an offset of 2 hours to ensure the files have been written to s3"
                ),
            ),
        )
        schedule_id_map.observations = sched_handle.id

    if schedule_id_map.analysis is None:
        analysis_params = AnalysisWorkflowParams(
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse_url,
            data_dir=data_dir,
            fast_fail=False,
        )
        sched_handle = await client.create_schedule(
            id=f"{ANALYSIS_SCHED_PREFIX}-{filter_id}-{ts}",
            schedule=Schedule(
                action=ScheduleActionStartWorkflow(
                    AnalysisWorkflow.run,
                    analysis_params,
                    id=f"{ANALYSIS_WF_PREFIX}-{filter_id}-{ts}",
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
                policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.ALLOW_ALL),
                state=ScheduleState(
                    note="Run the analysis workflow every day with an offset of 6 hours to ensure the observation workflow has completed"
                ),
            ),
        )
        schedule_id_map.analysis = sched_handle.id

    return schedule_id_map


async def reschedule_all(
    client: TemporalClient,
    probe_cc: List[str],
    test_name: List[str],
    clickhouse_url: str,
    data_dir: str,
) -> ScheduleIdMap:
    existing_schedules = await list_existing_schedules(
        client=client, probe_cc=probe_cc, test_name=test_name
    )
    for schedule_id in existing_schedules.observations + existing_schedules.analysis:
        await client.get_schedule_handle(schedule_id).delete()

    return await schedule_all(
        client=client,
        probe_cc=probe_cc,
        test_name=test_name,
        clickhouse_url=clickhouse_url,
        data_dir=data_dir,
    )


async def schedule_backfill(
    client: TemporalClient,
    workflow_name: str,
    start_at: datetime,
    end_at: datetime,
    probe_cc: List[str],
    test_name: List[str],
):
    existing_schedules = await list_existing_schedules(
        client=client, probe_cc=probe_cc, test_name=test_name
    )
    if workflow_name == "observations":
        assert (
            len(existing_schedules.observations) == 1
        ), "Expected one schedule for observations"
        schedule_id = existing_schedules.observations[0]
    elif workflow_name == "analysis":
        assert (
            len(existing_schedules.analysis) == 1
        ), "Expected one schedule for analysis"
        schedule_id = existing_schedules.analysis[0]
    else:
        raise ValueError(f"Unknown workflow name: {workflow_name}")

    handle = client.get_schedule_handle(schedule_id)
    await handle.backfill(
        ScheduleBackfill(
            start_at=start_at + timedelta(hours=1),
            end_at=end_at + timedelta(hours=1),
            overlap=ScheduleOverlapPolicy.BUFFER_ALL,
        ),
    )
