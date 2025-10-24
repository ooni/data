from datetime import datetime, timedelta
from typing import Tuple


def build_timestamps(
    start_at: datetime, end_at: datetime
) -> list[Tuple[str, datetime]]:
    """
    contruct a list of timestamps between start_at and end_at.
    They are constructed in such a way that we will have whole days expressed as
    YYYY-MM-DD, while hourly intervals will be expressed as YYYY-MM-DDTHH.

    For example given the range(2024-01-01T00 -> 2024-01-03T03) we will get:

    [
        2024-01-01T01,
        2024-01-01T02,
        2024-01-01T03,
        ...
        2024-01-02,
        2024-01-03T00,
        2024-01-03T01,
        2024-01-03T02,
        2024-01-03T02,
    ]
    """
    timestamps = []
    for start_at, end_at in build_date_range(
        start_at=start_at, end_at=end_at, day_delta=1
    ):
        if (end_at - start_at).total_seconds() == 3600:
            timestamps.append((start_at.strftime("%Y-%m-%dT%H"), start_at))
        else:
            timestamps.append((start_at.strftime("%Y-%m-%d"), start_at))

    return timestamps


def build_date_range(
    start_at: datetime, end_at: datetime, day_delta: int = 1
) -> list[Tuple[datetime, datetime]]:
    """
    contruct a list of date ranges between start_at and end_at.
    They are constructed in such a way that we will have whole days expressed as
    YYYY-MM-DD, while hourly intervals will be expressed as YYYY-MM-DDTHH.

    The day_delta parameter specifies how big the day steps should be.

    For example given the range(2024-01-01T00 -> 2024-01-9T03) and day_delta = 5 we will get:

    [
        (2024-01-01T01, 2024-01-01T02),
        (2024-01-01T02, 2024-01-01T03),
        (2024-01-01T03, 2024-01-01T04),
        ...
        (2024-01-02, 2024-01-07),
        (2024-01-07, 2024-01-09),
        (2024-01-09T00, 2024-01-09T01),
        (2024-01-09T01, 2024-01-09T02),
        (2024-01-09T02, 2024-01-09T03),
        (2024-01-09T03, 2024-01-09T04),
    ]
    """
    ranges = []
    current = start_at

    while current < end_at:
        if current.hour == 0 and current < end_at.replace(hour=0):
            start_dt = current
            # We clamp the end_dt to the end interval
            end_dt = current + timedelta(days=min(day_delta, (end_at - current).days))
            ranges.append((start_dt, end_dt))
        else:
            start_dt = current
            end_dt = current + timedelta(hours=1)
            ranges.append((start_dt, end_dt))
        current = end_dt

    return ranges
