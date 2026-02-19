"""
This file defines the task for the time inconsistencies analysis for faulty
measurements detection
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ..analysis.time_inconsistencies import run_time_inconsistencies_analysis


@dataclass
class MakeTimeInconsistenciesParams:
    clickhouse_url: str
    timestamp: str
    future_threshold: int
    past_threshold: int


def make_time_inconsistencies_analysis(params: MakeTimeInconsistenciesParams):
    if "T" in params.timestamp:
        start_time = (datetime.strptime(params.timestamp, "%Y-%m-%dT%H")).replace(
            tzinfo=timezone.utc
        )
        end_time = start_time + timedelta(hours=1)
    else:
        start_time = (datetime.strptime(params.timestamp, "%Y-%m-%d")).replace(
            tzinfo=timezone.utc
        )
        end_time = start_time + timedelta(days=1)

    run_time_inconsistencies_analysis(
        clickhouse_url=params.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        future_threshold=params.future_threshold,
        past_threshold=params.past_threshold,
    )
