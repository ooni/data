import asyncio
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from typing import List, Optional


from temporalio import workflow
from temporalio.common import RetryPolicy

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
    day: Optional[str] = None


@workflow.defn
class AnalysisWorkflow:
    @workflow.run
    async def run(self, params: AnalysisWorkflowParams) -> dict:
        if params.day is None:
            params.day = (get_workflow_start_time() - timedelta(days=1)).strftime(
                "%Y-%m-%d"
            )
        await workflow.execute_activity(
            make_analysis_in_a_day,
            MakeAnalysisParams(
                probe_cc=params.probe_cc,
                test_name=params.test_name,
                day=params.day,
            ),
            start_to_close_timeout=MAKE_ANALYSIS_START_TO_CLOSE_TIMEOUT,
            retry_policy=RetryPolicy(maximum_attempts=3),
        )

        return {"day": params.day}
