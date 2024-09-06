import os
import asyncio
import logging

from temporalio.worker import Worker

from oonipipeline.temporal.activities.analysis import make_analysis_in_a_day
from oonipipeline.temporal.activities.common import (
    get_obs_count_by_cc,
    optimize_all_tables,
    optimize_tables,
)
from oonipipeline.temporal.activities.ground_truths import make_ground_truths_in_day
from oonipipeline.temporal.activities.observations import (
    delete_previous_range,
    get_previous_range,
    make_observations,
)
from oonipipeline.temporal.client_operations import (
    TemporalConfig,
    log,
    temporal_connect,
)
from oonipipeline.temporal.workflows.common import TASK_QUEUE_NAME
from oonipipeline.temporal.workflows.analysis import AnalysisWorkflow
from oonipipeline.temporal.workflows.ctrl import GroundTruthsWorkflow
from oonipipeline.temporal.workflows.observations import ObservationsWorkflow

log = logging.getLogger("oonipipeline.workers")

from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Executor

interrupt_event = asyncio.Event()

WORKFLOWS = [
    ObservationsWorkflow,
    GroundTruthsWorkflow,
    AnalysisWorkflow,
]

ACTIVTIES = [
    delete_previous_range,
    get_previous_range,
    make_observations,
    make_ground_truths_in_day,
    make_analysis_in_a_day,
    optimize_all_tables,
    get_obs_count_by_cc,
    optimize_tables,
]


async def worker_main(
    temporal_config: TemporalConfig, max_workers: int, executor: Executor
):
    client = await temporal_connect(temporal_config=temporal_config)
    async with Worker(
        client,
        task_queue=TASK_QUEUE_NAME,
        workflows=WORKFLOWS,
        activities=ACTIVTIES,
        activity_executor=executor,
        max_concurrent_activities=max_workers,
        max_concurrent_workflow_tasks=max_workers,
    ):
        log.info("Workers started, ctrl-c to exit")
        await interrupt_event.wait()
        log.info("Shutting down")


def start_workers(temporal_config: TemporalConfig):
    max_workers = max(os.cpu_count() or 4, 4)
    log.info(f"starting workers with max_workers={max_workers}")
    executor = ThreadPoolExecutor(max_workers=max_workers + 2)

    loop = asyncio.new_event_loop()
    loop.set_default_executor(executor)
    # TODO(art): Investigate if we want to upgrade to python 3.12 and use this
    # instead
    # loop.set_task_factory(asyncio.eager_task_factory)
    try:
        loop.run_until_complete(
            worker_main(
                temporal_config=temporal_config,
                max_workers=max_workers,
                executor=executor,
            )
        )
    except KeyboardInterrupt:
        interrupt_event.set()
        loop.run_until_complete(loop.shutdown_asyncgens())
        executor.shutdown(wait=True, cancel_futures=True)
        log.info("shut down thread pool")
