"""
This file will implement time inconsistencies analysis for anomaly detection.

We consider that there's a time inconsistency anomaly when the measurement_start_time
differs significantly from the timestamp embedded in the measurement_uid.
"""

from clickhouse_driver import Client as Clickhouse
from datetime import datetime
import logging
import orjson

log = logging.getLogger(__name__)


def run_time_inconsistencies_analysis(
    clickhouse_url: str, start_time: datetime, end_time: datetime, threshold: int
):
    """
    This function will measure the drift between the reported measurement_start_time
    and the time it was reported to the fastpath.

    threshold: time in seconds to trigger an anomaly
    """

    db = Clickhouse.from_url(clickhouse_url)
    query = """
    SELECT
        probe_cc,
        probe_asn,
        measurement_uid,
        measurement_start_time,
        parseDateTimeBestEffort(substring(measurement_uid, 1, 15)) AS uid_timestamp,
        dateDiff('second', parseDateTimeBestEffort(substring(measurement_uid, 1, 15)), measurement_start_time) AS diff_seconds
    FROM fastpath
    WHERE
        measurement_start_time >= %(start_time)s AND
        measurement_start_time < %(end_time)s AND
        abs(dateDiff('second', parseDateTimeBestEffort(substring(measurement_uid, 1, 15)), measurement_start_time)) >= %(treshold)s
    ORDER BY diff_seconds DESC
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
        log.info("No time inconsistency anomalies where found")
        return
    else:
        log.info(f"Found {len(rows)} time inconsistencies from {start_time} to {end_time}")

    values = []
    for row in rows:

        (
            probe_cc,
            probe_asn,
            measurement_uid,
            measurement_start_time,
            uid_timestamp,
            diff_seconds,
        ) = row

        # Note that:
        #  diff_seconds < 0 => Measurement from the future
        #  diff_seconds >= 0 => Measurement too far away in the past
        details = {
            "measurement_uid": measurement_uid,
            "measurement_start_time": measurement_start_time.isoformat(),
            "uid_timestamp": uid_timestamp.isoformat(),
            "diff_seconds": diff_seconds,
            "threshold": threshold,
        }

        values.append(("time_inconsistency", probe_cc, probe_asn, orjson.dumps(details).decode()))

    db.execute(
        "INSERT INTO faulty_measurements (type, probe_cc, probe_asn, details) VALUES",
        values,
        types_check=True,
    )
