import os
import asyncio
import logging
from typing import Optional
from datetime import datetime, timezone


from temporalio.types import MethodAsyncSingleParam, SelfType, ParamType, ReturnType
from temporalio.client import Client as TemporalClient
from temporalio.types import MethodAsyncSingleParam
from temporalio.worker import SharedStateManager, Worker

from oonipipeline.temporal.activities.analysis import make_analysis_in_a_day
from oonipipeline.temporal.activities.common import (
    get_obs_count_by_cc,
    optimize_all_tables,
    update_assets,
)
from oonipipeline.temporal.activities.ground_truths import make_ground_truths_in_day
from oonipipeline.temporal.activities.observations import make_observation_in_day
from oonipipeline.temporal.client_operations import (
    TemporalConfig,
    log,
    temporal_connect,
)
from oonipipeline.temporal.workflows import (
    TASK_QUEUE_NAME,
    AnalysisWorkflow,
    GroundTruthsWorkflow,
    ObservationsWorkflow,
)

log = logging.getLogger("oonipipeline.workers")

from concurrent.futures import ThreadPoolExecutor

interrupt_event = asyncio.Event()

WORKFLOWS = [
    ObservationsWorkflow,
    GroundTruthsWorkflow,
    AnalysisWorkflow,
]

ACTIVTIES = [
    make_observation_in_day,
    make_ground_truths_in_day,
    make_analysis_in_a_day,
    optimize_all_tables,
    get_obs_count_by_cc,
    update_assets,
]


async def worker_main(temporal_config: TemporalConfig):
    client = await temporal_connect(temporal_config=temporal_config)
    max_workers = max(os.cpu_count() or 4, 4)
    async with Worker(
        client,
        task_queue=TASK_QUEUE_NAME,
        workflows=WORKFLOWS,
        activities=ACTIVTIES,
        activity_executor=ThreadPoolExecutor(max_workers=max_workers+2),
        max_concurrent_activities=max_workers,
        max_concurrent_workflow_tasks=max_workers,
    ):
        log.info("Workers started, ctrl-c to exit")
        await interrupt_event.wait()
        log.info("Shutting down")


def start_workers(temporal_config: TemporalConfig):
    loop = asyncio.new_event_loop()
    # TODO(art): Investigate if we want to upgrade to python 3.12 and use this
    # instead
    # loop.set_task_factory(asyncio.eager_task_factory)
    try:
        loop.run_until_complete(worker_main(temporal_config=temporal_config))
    except KeyboardInterrupt:
        interrupt_event.set()
        loop.run_until_complete(loop.shutdown_asyncgens())
