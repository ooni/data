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
        count = await workflow.execute_activity(
            make_analysis_in_a_day,
            MakeAnalysisParams(
                probe_cc=params.probe_cc,
                test_name=params.test_name,
                fast_fail=params.fast_fail,
                day=params.day,
            ),
            start_to_close_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
        )

        return {"analysis_count": count, "day": params.day}
