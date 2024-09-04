import asyncio
from dataclasses import dataclass

from oonidata.dataclient import date_interval
from oonipipeline.temporal.activities.common import UpdateAssetsParams, update_assets
from oonipipeline.temporal.activities.ground_truths import (
    MakeGroundTruthsParams,
    make_ground_truths_in_day,
)
from oonipipeline.temporal.workflows.common import (
    MAKE_GROUND_TRUTHS_START_TO_CLOSE_TIMEOUT,
)
from temporalio import workflow
from datetime import datetime, timedelta


@dataclass
class GroundTruthsWorkflowParams:
    start_day: str
    end_day: str
    clickhouse: str
    data_dir: str


@workflow.defn
class GroundTruthsWorkflow:
    @workflow.run
    async def run(
        self,
        params: GroundTruthsWorkflowParams,
    ):
        await workflow.execute_activity(
            update_assets,
            UpdateAssetsParams(data_dir=params.data_dir),
            start_to_close_timeout=timedelta(hours=1),
        )

        start_day = datetime.strptime(params.start_day, "%Y-%m-%d").date()
        end_day = datetime.strptime(params.end_day, "%Y-%m-%d").date()

        async with asyncio.TaskGroup() as tg:
            for day in date_interval(start_day, end_day):
                tg.create_task(
                    workflow.execute_activity(
                        make_ground_truths_in_day,
                        MakeGroundTruthsParams(
                            clickhouse=params.clickhouse,
                            data_dir=params.data_dir,
                            day=day.strftime("%Y-%m-%d"),
                        ),
                        start_to_close_timeout=MAKE_GROUND_TRUTHS_START_TO_CLOSE_TIMEOUT,
                    )
                )
