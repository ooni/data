from dataclasses import dataclass

from datetime import datetime, timedelta
from typing import List

from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver

    from ...analysis.web_analysis import write_analysis_web_fuzzy_logic
    from ...db.connections import ClickhouseConnection
    from ...settings import config


log = activity.logger


@dataclass
class MakeAnalysisParams:
    probe_cc: List[str]
    test_name: List[str]
    day: str


@activity.defn
def make_analysis_in_a_day(params: MakeAnalysisParams):
    day = datetime.strptime(params.day, "%Y-%m-%d")
    start_time = day
    end_time = day + timedelta(days=1)

    probe_cc = params.probe_cc
    test_name = params.test_name
    db = ClickhouseConnection(config.clickhouse_url)

    write_analysis_web_fuzzy_logic(
        db=db,
        start_time=start_time,
        end_time=end_time,
        probe_cc=probe_cc,
        test_name=test_name,
    )
