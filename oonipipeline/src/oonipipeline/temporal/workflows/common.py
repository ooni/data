from temporalio import workflow
from temporalio.common import SearchAttributeKey


from datetime import datetime, timedelta


def get_workflow_start_time() -> datetime:
    workflow_start_time = workflow.info().typed_search_attributes.get(
        SearchAttributeKey.for_datetime("TemporalScheduledStartTime")
    )
    assert workflow_start_time is not None, "TemporalScheduledStartTime not set"
    return workflow_start_time


# TODO(art): come up with a nicer way to nest workflows so we don't need such a high global timeout
MAKE_OBSERVATIONS_START_TO_CLOSE_TIMEOUT = timedelta(hours=48)
TASK_QUEUE_NAME = "oonipipeline-task-queue"
MAKE_GROUND_TRUTHS_START_TO_CLOSE_TIMEOUT = timedelta(hours=1)
MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT = timedelta(hours=10)
