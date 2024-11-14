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
        MakeObservationsParams,
        make_observations,
    )
    from oonipipeline.temporal.workflows.common import (
        get_workflow_start_time,
    )
    from oonipipeline.settings import config

@dataclass
class ObservationsWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    fast_fail: bool
    is_reprocessing: bool = True
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
            clickhouse=config.clickhouse_url,
            data_dir=config.data_dir,
            fast_fail=params.fast_fail,
            bucket_date=params.bucket_date,
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

        # Force the recreation of all parts when reprocessing, this is not
        # needed for a daily run.
        if params.is_reprocessing:
            partition_str = params.bucket_date.replace("-", "")[:6]
            await workflow.execute_activity(
                optimize_tables,
                OptimizeTablesParams(
                    clickhouse=config.clickhouse_url,
                    table_names=["obs_web", "obs_web_ctrl", "obs_http_middlebox"],
                    partition_str=partition_str,
                ),
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=RetryPolicy(maximum_attempts=10),
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
