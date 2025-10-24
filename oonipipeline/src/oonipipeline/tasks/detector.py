from dataclasses import dataclass

from datetime import datetime, timedelta, timezone
from typing import List


from clickhouse_driver import Client as ClickhouseClient

from ..analysis.detector import run_detector
from ..settings import config


@dataclass
class MakeDetectorParams:
    clickhouse_url: str
    probe_cc: List[str]
    timestamp: str


def make_detector(params: MakeDetectorParams):
    if "T" in params.timestamp:
        start_hour = (datetime.strptime(params.timestamp, "%Y-%m-%dT%H")).replace(
            tzinfo=timezone.utc
        )
        end_hour = start_hour + timedelta(hours=1)
    else:
        start_hour = (datetime.strptime(params.timestamp, "%Y-%m-%d")).replace(
            tzinfo=timezone.utc
        )
        end_hour = start_hour + timedelta(days=1)

    run_detector(
        clickhouse_url=params.clickhouse_url,
        start_time=start_hour,
        end_time=end_hour,
        probe_cc=params.probe_cc,
    )
