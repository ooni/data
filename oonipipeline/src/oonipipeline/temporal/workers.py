import multiprocessing
from oonipipeline.temporal.activities.analysis import make_analysis_in_a_day
from oonipipeline.temporal.activities.common import (
    get_obs_count_by_cc,
    optimize_all_tables,
)
from oonipipeline.temporal.activities.ground_truths import make_ground_truths_in_day
from oonipipeline.temporal.activities.observations import make_observation_in_day
from oonipipeline.temporal.workflows import (
    TASK_QUEUE_NAME,
    AnalysisBackfillWorkflow,
    AnalysisWorkflow,
    GroundTruthsWorkflow,
    ObservationsBackfillWorkflow,
    ObservationsWorkflow,
)


from temporalio.client import Client as TemporalClient
from temporalio.worker import SharedStateManager, Worker


from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

WORKFLOWS = [
    ObservationsWorkflow,
    GroundTruthsWorkflow,
    AnalysisWorkflow,
    ObservationsBackfillWorkflow,
    AnalysisBackfillWorkflow,
]

ACTIVTIES = [
    make_observation_in_day,
    make_ground_truths_in_day,
    make_analysis_in_a_day,
    optimize_all_tables,
    get_obs_count_by_cc,
]


def make_threaded_worker(client: TemporalClient, parallelism: int) -> Worker:
    return Worker(
        client,
        task_queue=TASK_QUEUE_NAME,
        workflows=WORKFLOWS,
        activities=ACTIVTIES,
        activity_executor=ThreadPoolExecutor(parallelism + 2),
        max_concurrent_activities=parallelism,
    )


def make_multiprocess_worker(client: TemporalClient, parallelism: int) -> Worker:
    return Worker(
        client,
        task_queue=TASK_QUEUE_NAME,
        workflows=WORKFLOWS,
        activities=ACTIVTIES,
        activity_executor=ProcessPoolExecutor(parallelism + 2),
        max_concurrent_activities=parallelism,
        shared_state_manager=SharedStateManager.create_from_multiprocessing(
            multiprocessing.Manager()
        ),
    )
