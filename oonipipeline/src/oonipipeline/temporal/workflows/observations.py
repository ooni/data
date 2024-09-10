import asyncio
from dataclasses import dataclass
from typing import List, Optional

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from oonidata.datautils import PerfTimer
    from oonipipeline.temporal.activities.common import (
        OptimizeTablesParams,
        optimize_tables,
    )
    from oonipipeline.temporal.activities.observations import (
        DeletePreviousRangeParams,
        GetPreviousRangeParams,
        MakeObservationsParams,
        delete_previous_range,
        get_previous_range,
        make_observations,
    )
    from oonipipeline.temporal.workflows.common import (
        TASK_QUEUE_NAME,
        get_workflow_start_time,
    )


@dataclass
class ObservationsWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    fast_fail: bool
    bucket_date: Optional[str] = None


@workflow.defn
class ObservationsWorkflow:
    @workflow.run
    async def run(self, params: ObservationsWorkflowParams) -> dict:
        if params.bucket_date is None:
            params.bucket_date = (
                get_workflow_start_time() - timedelta(days=1)
            ).strftime("%Y-%m-%d")

        total_t = PerfTimer()
        params_make_observations = MakeObservationsParams(
            probe_cc=params.probe_cc,
            test_name=params.test_name,
            clickhouse=params.clickhouse,
            data_dir=params.data_dir,
            fast_fail=params.fast_fail,
            bucket_date=params.bucket_date,
        )

        workflow.logger.info(
            f"finished get_previous_range for bucket_date={params.bucket_date}"
        )

        obs_res = await workflow.execute_activity(
            make_observations,
            params_make_observations,
            start_to_close_timeout=timedelta(hours=48),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )

        workflow.logger.info(
            f"finished make_observations for bucket_date={params.bucket_date} in "
            f"{total_t.pretty} speed: {obs_res['mb_per_sec']}MB/s ({obs_res['measurement_per_sec']}msmt/s)"
        )

        workflow.logger.info(
            f"finished optimize_tables for bucket_date={params.bucket_date}"
        )

        return {
            "measurement_count": obs_res["measurement_count"],
            "size": obs_res["total_size"],
            "mb_per_sec": obs_res["mb_per_sec"],
            "bucket_date": params.bucket_date,
            "measurement_per_sec": obs_res["measurement_per_sec"],
        }
