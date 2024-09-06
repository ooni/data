import asyncio
from concurrent.futures import ThreadPoolExecutor
from oonipipeline.temporal.schedules import schedule_all, clear_schedules
import pytest

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from oonipipeline.temporal.workflows.common import TASK_QUEUE_NAME

from oonipipeline.temporal.workflows.observations import (
    ObservationsWorkflow,
    ObservationsWorkflowParams,
)
from oonipipeline.temporal.workers import ACTIVTIES

from .utils import wait_for_mutations


@pytest.mark.asyncio
async def test_scheduling(datadir, db):
    async with await WorkflowEnvironment.start_local() as env:
        sched_res = await schedule_all(
            client=env.client,
            probe_cc=[],
            test_name=[],
            clickhouse_url=db.clickhouse_url,
            data_dir=str(datadir),
        )
        assert sched_res.analysis
        assert sched_res.observations

        deleted_schedules = await clear_schedules(
            client=env.client,
            probe_cc=[],
            test_name=[],
        )
        assert sched_res.observations in deleted_schedules
        assert sched_res.analysis in deleted_schedules

        # Wait 1 second for the ID to change
        await asyncio.sleep(1)

        sched_res2 = await schedule_all(
            client=env.client,
            probe_cc=[],
            test_name=[],
            clickhouse_url=db.clickhouse_url,
            data_dir=str(datadir),
        )
        assert sched_res.analysis != sched_res2.analysis
        assert sched_res.observations != sched_res2.observations


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
    async with await WorkflowEnvironment.start_local() as env:
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
            db.execute("OPTIMIZE TABLE obs_web")
            wait_for_mutations(db, "obs_web")
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
