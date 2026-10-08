import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from ..analysis.detectorV2 import (
    notify_slack,
    run_detector_hourly,
    store_changepoints,
)

log = logging.getLogger()


@dataclass
class MakeDetectorV2Params:
    clickhouse_url: str
    timestamp: str
    warmup_days: int = 30
    p0: float = 0.05
    p1: float = 0.50
    h: float = 30
    gap_halflife: float = 24
    use_decay: bool = True
    slack_webhook: str | None = None
    explorer_base_url: str = "https://explorer.ooni.org/"
    detector_panel_base_url: str = "https://detector-panel.prod.ooni.io/"


def make_detector_v2(params: MakeDetectorV2Params):
    """
    Each run warms up on the `warmup_days` immediately before
    `timestamp`'s hour, then detects on that hour alone.
    """
    target_hour = (datetime.strptime(params.timestamp, "%Y-%m-%dT%H")).replace(
        tzinfo=timezone.utc
    )

    results = run_detector_hourly(
        clickhouse_url=params.clickhouse_url,
        target_hour=target_hour,
        warmup_days=params.warmup_days,
        p0=params.p0,
        p1=params.p1,
        h=params.h,
        gap_halflife=params.gap_halflife,
        use_decay=params.use_decay,
    )

    total_changepoints = sum(
        len(cps)
        for entry in results.values()
        for cps in (entry.dns, entry.tcp, entry.tls)
    )
    log.info(
        "detectorV2: %d changepoints found at %s across %d series",
        total_changepoints,
        target_hour.isoformat(),
        len(results),
    )

    # Same parameters as the detector, stored as run_parameters
    store_changepoints(
        params.clickhouse_url,
        results,
        warmup_days=params.warmup_days,
        p0=params.p0,
        p1=params.p1,
        h=params.h,
        gap_halflife=params.gap_halflife,
        use_decay=params.use_decay,
    )

    if params.slack_webhook is not None:
        notify_slack(
            results,
            params.slack_webhook,
            explorer_base_url=params.explorer_base_url,
            detector_panel_base_url=params.detector_panel_base_url,
            warmup_days=params.warmup_days,
        )
