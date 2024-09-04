from concurrent.futures import ThreadPoolExecutor
import pytest

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from temporalio import activity

from oonipipeline.temporal.workflows.common import TASK_QUEUE_NAME

from oonipipeline.temporal.workflows.observations import (
    ObservationsWorkflow,
    ObservationsWorkflowParams,
)
from oonipipeline.temporal.workers import ACTIVTIES


@pytest.mark.asyncio
async def test_observation_workflow(datadir, db):
    obs_params = ObservationsWorkflowParams(
        probe_cc=["BA"],
        test_name=["web_connectivity"],
        clickhouse=db.clickhouse_url,
        data_dir=str(datadir.absolute()),
        fast_fail=False,
        bucket_date="2022-10-21",
    )
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE_NAME,
            workflows=[ObservationsWorkflow],
            activities=ACTIVTIES,
            activity_executor=ThreadPoolExecutor(max_workers=4 + 2),
        ):
            wf_res = await env.client.execute_workflow(
                ObservationsWorkflow.run,
                obs_params,
                id="obs-wf",
                task_queue=TASK_QUEUE_NAME,
            )
            db.execute("OPTIMIZE TABLE buffer_obs_web")
            assert wf_res["measurement_count"] == 613
            assert wf_res["size"] == 11381440
            assert wf_res["bucket_date"] == "2022-10-21"

            res = db.execute(
                """
                SELECT bucket_date,
                COUNT(DISTINCT(measurement_uid))
                FROM obs_web WHERE probe_cc = 'BA'
                GROUP BY bucket_date
                """
            )
            bucket_dict = dict(res)
            assert bucket_dict[wf_res["bucket_date"]] == wf_res["measurement_count"]
            res = db.execute(
                """
                SELECT bucket_date,
                COUNT()
                FROM obs_web WHERE probe_cc = 'BA'
                GROUP BY bucket_date
                """
            )
            bucket_dict = dict(res)
            obs_count = bucket_dict[wf_res["bucket_date"]]
            assert obs_count == 2548

            wf_res = await env.client.execute_workflow(
                ObservationsWorkflow.run,
                obs_params,
                id="obs-wf-2",
                task_queue=TASK_QUEUE_NAME,
            )
            db.execute("OPTIMIZE TABLE buffer_obs_web")
            db.execute("OPTIMIZE TABLE obs_web")
            res = db.execute(
                """
                SELECT bucket_date,
                COUNT()
                FROM obs_web WHERE probe_cc = 'BA'
                GROUP BY bucket_date
                """
            )
            bucket_dict = dict(res)
            obs_count_2 = bucket_dict[wf_res["bucket_date"]]

            assert obs_count == obs_count_2
