"""
This file defines the task for the volume analysis for faulty
measurements detection
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ..analysis.volume import run_volume_analysis


@dataclass
class MakeVolumeParams:
    clickhouse_url: str
    timestamp: str
    threshold: int


def make_volume_analysis(params: MakeVolumeParams):
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

    run_volume_analysis(
        clickhouse_url=params.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=params.threshold,
    )
