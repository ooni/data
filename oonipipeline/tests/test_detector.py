from datetime import datetime, timedelta, timezone

from oonipipeline.analysis.detector import run_detector


def make_interval(start, end, hours):
    intervals = []
    current = start
    while current < end:
        next_hour = current + timedelta(hours=hours)
        intervals.append((current, next_hour))
        current = next_hour
    return intervals


def test_detector_uganda(db, db_analysis):
    start = datetime(2025, 12, 3, tzinfo=timezone.utc)
    end = datetime(2026, 2, 12, tzinfo=timezone.utc)

    all_updated_cusums = []
    all_changepoints = []
    all_steps = []
    for current, next_hour in make_interval(start, end, 3):
        changepoints, updated_cusums, steps = run_detector(
            clickhouse_url=db.clickhouse_url,
            start_time=current,
            end_time=next_hour,
            probe_cc=[],
            edd=10,
            trace=True,
        )
        all_changepoints.extend(changepoints)
        all_updated_cusums.extend(updated_cusums)
        all_steps.extend(steps)
    assert len(all_changepoints) == 2
