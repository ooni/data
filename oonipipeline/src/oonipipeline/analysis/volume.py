"""
This file will implement volume analysis for anomaly detection.

We consider that there's a volume anomaly when a single probe seems to be sending too many measurements
in small time windows
"""

from clickhouse_driver import Client as Clickhouse
from datetime import datetime, timedelta
import logging
import orjson

log = logging.getLogger(__name__)


def run_volume_analysis(
    clickhouse_url: str, start_time: datetime, end_time: datetime, threshold: int
):

    db = Clickhouse.from_url(clickhouse_url)
    query = """
    SELECT
        probe_cc, probe_asn, engine_version,
        software_version, platform, architecture,
        toStartOfMinute(measurement_start_time) as minute_start,
        count() as total
    FROM fastpath
    WHERE
        measurement_start_time >= %(start_time)s AND
        measurement_start_time < %(end_time)s
    GROUP BY probe_cc, probe_asn, engine_version, software_version, platform, architecture, minute_start
    HAVING total >= %(treshold)s
    """

    rows = (
        db.execute(
            query,
            params={
                "start_time": start_time,
                "end_time": end_time,
                "treshold": threshold,
            },
        )
        or []
    )

    if len(rows) == 0:
        log.info("No volume anomalies where found")
        return

    # Prepare results to insert
    values = []
    for row in rows:

        (
            probe_cc,
            probe_asn,
            engine_version,
            software_version,
            platform,
            architecture,
            minute_start,
            total,
        ) = row

        # Calculate end_time as start of next minute
        minute_end = minute_start + timedelta(minutes=1)

        details = {
            "start_time": minute_start.isoformat(),
            "end_time": minute_end.isoformat(),
            "engine_version": engine_version,
            "software_version": software_version,
            "platform": platform,
            "architecture": architecture,
            "total": total,
            "threshold": threshold,
        }

        values.append(("volume", probe_cc, probe_asn, orjson.dumps(details).decode()))

    db.execute(
        "INSERT INTO faulty_measurements (type, probe_cc, probe_asn, details) VALUES",
        values,
        types_check=True,
    )
