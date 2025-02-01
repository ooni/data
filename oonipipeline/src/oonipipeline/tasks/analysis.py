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
    timestamp: str


def make_analysis(params: MakeAnalysisParams):
    if "T" in params.timestamp:
        start_hour = datetime.strptime(params.timestamp, "%Y-%m-%dT%H")
        end_hour = start_hour + timedelta(hours=1)
    else:
        start_hour = datetime.strptime(params.timestamp, "%Y-%m-%d")
        end_hour = start_hour + timedelta(days=1)

    probe_cc = params.probe_cc
    test_name = params.test_name
    db = ClickhouseConnection(params.clickhouse_url)

    write_analysis_web_fuzzy_logic(
        db=db,
        start_time=start_hour,
        end_time=end_hour,
        probe_cc=probe_cc,
        test_name=test_name,
    )
