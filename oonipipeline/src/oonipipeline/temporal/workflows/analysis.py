import asyncio
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from typing import List, Optional


from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from oonidata.datautils import PerfTimer
    from oonipipeline.temporal.activities.analysis import (
        MakeAnalysisParams,
        make_analysis_in_a_day,
        make_cc_batches,
    )
    from oonipipeline.temporal.activities.common import (
        ClickhouseParams,
        ObsCountParams,
        UpdateAssetsParams,
        get_obs_count_by_cc,
        optimize_all_tables,
        update_assets,
    )
    from oonipipeline.temporal.activities.ground_truths import (
        MakeGroundTruthsParams,
        make_ground_truths_in_day,
    )
    from oonipipeline.temporal.workflows.common import (
        MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
        get_workflow_start_time,
    )


@dataclass
class AnalysisWorkflowParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    parallelism: int = 10
    fast_fail: bool = False
    day: Optional[str] = None
    force_rebuild_ground_truths: bool = False
    log_level: int = logging.INFO


@workflow.defn
class AnalysisWorkflow:
    @workflow.run
    async def run(self, params: AnalysisWorkflowParams) -> dict:
        if params.day is None:
            params.day = (get_workflow_start_time() - timedelta(days=1)).strftime(
                "%Y-%m-%d"
            )

        await workflow.execute_activity(
            update_assets,
            UpdateAssetsParams(data_dir=params.data_dir),
            start_to_close_timeout=timedelta(hours=1),
        )

        await workflow.execute_activity(
            optimize_all_tables,
            ClickhouseParams(clickhouse_url=params.clickhouse),
            start_to_close_timeout=timedelta(minutes=5),
        )

        workflow.logger.info("building ground truth databases")
        t = PerfTimer()

        await workflow.execute_activity(
            make_ground_truths_in_day,
            MakeGroundTruthsParams(
                clickhouse=params.clickhouse,
                data_dir=params.data_dir,
                day=params.day,
                force_rebuild=params.force_rebuild_ground_truths,
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )
        workflow.logger.info(f"built ground truth db in {t.pretty}")

        start_day = datetime.strptime(params.day, "%Y-%m-%d").date()
        cnt_by_cc = await workflow.execute_activity(
            get_obs_count_by_cc,
            ObsCountParams(
                clickhouse_url=params.clickhouse,
                start_day=start_day.strftime("%Y-%m-%d"),
                end_day=(start_day + timedelta(days=1)).strftime("%Y-%m-%d"),
            ),
            start_to_close_timeout=timedelta(minutes=30),
        )

        cc_batches = make_cc_batches(
            cnt_by_cc=cnt_by_cc,
            probe_cc=params.probe_cc,
            parallelism=params.parallelism,
        )

        workflow.logger.info(
            f"starting processing of {len(cc_batches)} batches for {params.day} days (parallelism = {params.parallelism})"
        )
        workflow.logger.info(f"({cc_batches})")

        task_list = []
        async with asyncio.TaskGroup() as tg:
            for probe_cc in cc_batches:
                task = tg.create_task(
                    workflow.execute_activity(
                        make_analysis_in_a_day,
                        MakeAnalysisParams(
                            probe_cc=probe_cc,
                            test_name=params.test_name,
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            fast_fail=params.fast_fail,
                            day=params.day,
                        ),
                        start_to_close_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
                    )
                )
                task_list.append(task)

        total_obs_count = sum(map(lambda x: x.result()["count"], task_list))
        return {"obs_count": total_obs_count, "day": params.day}
