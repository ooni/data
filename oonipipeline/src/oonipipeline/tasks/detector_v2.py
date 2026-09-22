import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from ..analysis.detectorV2 import run_detector_hourly

log = logging.getLogger()


@dataclass
class MakeDetectorV2Params:
    clickhouse_url: str
    timestamp: str
    warmup_days: int = 30


def make_detector_v2(params: MakeDetectorV2Params):
    """
    Each run warms up on the
    `warmup_days` immediately before `timestamp`'s hour, then detects on
    that hour alone.
    """
    target_hour = (datetime.strptime(params.timestamp, "%Y-%m-%dT%H")).replace(
        tzinfo=timezone.utc
    )

    results = run_detector_hourly(
        clickhouse_url=params.clickhouse_url,
        target_hour=target_hour,
        warmup_days=params.warmup_days,
    )

    total_changepoints = sum(
        len(cps)
        for entry in results.values()
        for cps in (entry.dns, entry.tcp, entry.tls)
    )
    log.info(
        "detectorV2: %d changepoints found",
        total_changepoints,
        target_hour.isoformat(),
        len(results),
    )
