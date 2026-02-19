from oonipipeline.analysis import time_inconsistencies
from datetime import datetime, timedelta
import orjson

START_TIME = datetime(2023, 12, 31, 23, 0, 0)
END_TIME = datetime(2024, 1, 1, 4, 0, 0)


def test_time_inconsistencies_basic(db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements):
    """
    Test basic time inconsistencies analysis with data that exceeds threshold.
    """
    future_threshold = 3600
    past_threshold = 3600

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        future_threshold=future_threshold,
        past_threshold=past_threshold,
    )

    result = db.execute(
        "SELECT ts, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type LIKE 'time_inconsistency%'"
    )
    assert len(result) > 0, "Missing time inconsistency anomalies"

    for row in result:
        ts, type_val, probe_cc, probe_asn, details_str = row
        assert type_val in ("time_inconsistency_future", "time_inconsistency_past")
        assert probe_cc == "VE"
        assert probe_asn == 8048
        details = orjson.loads(details_str)
        assert "measurement_uid" in details
        assert "measurement_start_time" in details
        assert "uid_timestamp" in details
        assert "diff_seconds" in details
        assert "threshold" in details
        assert "software_name" in details
        assert "software_version" in details
        assert "platform" in details
        # Verify threshold matches the appropriate one based on type
        if type_val == "time_inconsistency_future":
            assert details["threshold"] == future_threshold
            assert details["diff_seconds"] < 0
            assert abs(details["diff_seconds"]) >= future_threshold
        else:
            assert details["threshold"] == past_threshold
            assert details["diff_seconds"] > 0
            assert details["diff_seconds"] >= past_threshold


def test_time_inconsistencies_no_anomalies(
    db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements
):
    """
    Test time inconsistencies analysis with threshold higher than differences.
    """

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        future_threshold=3600 * 24,  # 24 hours
        past_threshold=3600 * 24  # 24 hours
    )

    # No anomalies expected
    result = db.execute("SELECT type FROM faulty_measurements WHERE type LIKE 'time_inconsistency%'")
    assert len(result) == 0, f"Unexpected anomalies: {len(result)} = {result}"


def test_time_inconsistencies_time_range_filtering(
    db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements
):
    """
    Test that we only consider measurements within time range.
    """
    start_time = END_TIME + timedelta(hours=1)
    end_time = start_time + timedelta(hours=1)

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        future_threshold=1,
        past_threshold=1,
    )

    # No events expected
    results = db.execute("SELECT type FROM faulty_measurements WHERE type LIKE 'time_inconsistency%'")
    assert len(results) == 0, f"Too many results: {len(results)} - {results}"


def test_time_inconsistencies_threshold_boundary(
    db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements
):
    """
    Test that threshold boundary works correctly (3600 seconds = 1 hour).
    """
    future_threshold = 3600
    past_threshold = 3600

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        future_threshold=future_threshold,
        past_threshold=past_threshold,
    )

    result = db.execute(
        "SELECT ts, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type LIKE 'time_inconsistency%'"
    )
    assert len(result) > 0, "Expected time inconsistency anomalies"

    for row in result:
        _, type_val, _, _, details_str = row
        details = orjson.loads(details_str)
        if type_val == "time_inconsistency_future":
            assert abs(details["diff_seconds"]) >= future_threshold, f"invalid threshold: {details['diff_seconds']}"
        else:
            assert details["diff_seconds"] >= past_threshold, f"invalid threshold: {details['diff_seconds']}"


def test_time_inconsistencies_future_and_past(
    db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements
):
    """
    Test that we detect both future and past time inconsistencies.
    """
    future_threshold = 3600  # 1 hour
    past_threshold = 3600  # 1 hour

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        future_threshold=future_threshold,
        past_threshold=past_threshold,
    )

    result = db.execute(
        "SELECT ts, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type LIKE 'time_inconsistency%'"
    )

    future_anomalies = [row for row in result if row[1] == "time_inconsistency_future"]
    past_anomalies = [row for row in result if row[1] == "time_inconsistency_past"]

    assert len(future_anomalies) > 0, "Should have at least one future anomaly"
    assert len(past_anomalies) > 0, "Should have  at least one past  anomaly"

    # future anomalies should have negative diff_seconds
    for row in future_anomalies:
        _, _, _, _, details_str = row
        details = orjson.loads(details_str)
        assert details["diff_seconds"] < 0, f"Unexpected diff_seconds: {details['diff_seconds']}"
        assert abs(details["diff_seconds"]) >= future_threshold

    # past anomalies should have positive diff_seconds
    for row in past_anomalies:
        _, _, _, _, details_str = row
        details = orjson.loads(details_str)
        assert details["diff_seconds"] > 0, f"Unexpected diff_seconds: {details['diff_seconds']}"
        assert details["diff_seconds"] >= past_threshold
