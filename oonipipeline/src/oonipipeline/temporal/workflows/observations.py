from dataclasses import dataclass
from typing import List, Optional

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from oonidata.datautils import PerfTimer
    from oonipipeline.temporal.activities.common import (
        ClickhouseParams,
        UpdateAssetsParams,
        optimize_all_tables,
        update_assets,
    )
    from oonipipeline.temporal.activities.observations import (
        DeletePreviousRangeParams,
        GetPreviousRangeParams,
        MakeObservationsFileEntryBatch,
        MakeObservationsParams,
        delete_previous_range,
        get_previous_range,
        make_observation_batches,
        make_observations_for_file_entry_batch,
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

        await workflow.execute_activity(
            update_assets,
            UpdateAssetsParams(data_dir=params.data_dir),
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=RetryPolicy(maximum_attempts=10),
        )

        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=10),
        )

        previous_ranges = await workflow.execute_activity(
            get_previous_range,
            GetPreviousRangeParams(
                clickhouse=params.clickhouse,
                bucket_date=params.bucket_date,
                test_name=params.test_name,
                probe_cc=params.probe_cc,
                tables=["obs_web"],
            ),
            start_to_close_timeout=timedelta(minutes=20),
            retry_policy=RetryPolicy(maximum_attempts=10),
        )

        obs_batches = await workflow.execute_activity(
            make_observation_batches,
            params_make_observations,
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )

        total_msmt_count = 0
        for batch in obs_batches["batches"]:
            batch_params = MakeObservationsFileEntryBatch(
                file_entry_batch=batch,
                clickhouse=params.clickhouse,
                write_batch_size=500_000,
                data_dir=params.data_dir,
                bucket_date=params.bucket_date,
                probe_cc=params.probe_cc,
                fast_fail=params.fast_fail,
            )
            msmt_cnt = await workflow.execute_activity(
                make_observations_for_file_entry_batch,
                batch_params,
                task_queue=TASK_QUEUE_NAME,
                start_to_close_timeout=timedelta(hours=10),
                retry_policy=RetryPolicy(maximum_attempts=10),
            )
            total_msmt_count += msmt_cnt

        mb_per_sec = round(obs_batches["total_size"] / total_t.s / 10**6, 1)
        msmt_per_sec = round(total_msmt_count / total_t.s)
        workflow.logger.info(
            f"finished processing all batches in {total_t.pretty} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
        )

        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=10),
        )

        await workflow.execute_activity(
            delete_previous_range,
            DeletePreviousRangeParams(
                clickhouse=params.clickhouse,
                previous_ranges=previous_ranges,
            ),
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=10),
        )

        return {
            "measurement_count": total_msmt_count,
            "size": obs_batches["total_size"],
            "mb_per_sec": mb_per_sec,
            "bucket_date": params.bucket_date,
            "msmt_per_sec": msmt_per_sec,
        }
