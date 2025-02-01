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
    current = start_at

    while current < end_at:
        if (
            current.hour == 0
            and current != start_at
            and current < end_at.replace(hour=0)
        ):
            timestamps.append((current.strftime("%Y-%m-%d"), current))
            current += timedelta(days=1)
        else:
            timestamps.append((current.strftime("%Y-%m-%dT%H"), current))
            current += timedelta(hours=1)

    return timestamps
