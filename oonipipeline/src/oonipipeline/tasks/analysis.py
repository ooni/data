from dataclasses import dataclass

from datetime import datetime, timedelta
from typing import List


from ..analysis.web_analysis import write_analysis_web_fuzzy_logic
from ..db.connections import ClickhouseConnection
from ..settings import config


@dataclass
class MakeAnalysisParams:
    clickhouse_url: str
    probe_cc: List[str]
    test_name: List[str]
    day: str


def make_analysis_in_a_day(params: MakeAnalysisParams):
    day = datetime.strptime(params.day, "%Y-%m-%d")
    start_time = day
    end_time = day + timedelta(days=1)

    probe_cc = params.probe_cc
    test_name = params.test_name
    db = ClickhouseConnection(params.clickhouse_url)

    write_analysis_web_fuzzy_logic(
        db=db,
        start_time=start_time,
        end_time=end_time,
        probe_cc=probe_cc,
        test_name=test_name,
    )
