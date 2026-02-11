from oonipipeline.analysis import time_inconsistencies
from datetime import datetime, timedelta
import orjson

START_TIME = datetime(2023, 12, 31, 23, 0, 0)
END_TIME = datetime(2024, 1, 1, 4, 0, 0)


def test_time_inconsistencies_basic(db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements):
    """
    Test basic time inconsistencies analysis with data that exceeds threshold.
    """
    threshold = 3600

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        threshold=threshold,
    )

    result = db.execute(
        "SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'time_inconsistency'"
    )
    assert len(result) > 0, "Missing time inconsistency anomalies"

    for row in result:
        time, type_val, probe_cc, probe_asn, details_str = row
        assert type_val == "time_inconsistency"
        assert probe_cc == "VE"
        assert probe_asn == 8048
        details = orjson.loads(details_str)
        assert "measurement_uid" in details
        assert "measurement_start_time" in details
        assert "uid_timestamp" in details
        assert "diff_seconds" in details
        assert "threshold" in details
        assert details["threshold"] == threshold
        assert abs(details["diff_seconds"]) >= threshold


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
        threshold=3600 * 24 # 24 hours,
    )

    # No anomalies expected
    result = db.execute("SELECT type FROM faulty_measurements WHERE type = 'time_inconsistency'")
    assert len(result) == 0, "Expected no time inconsistency anomalies with high threshold"


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
        threshold=1,
    )

    # Check that no events were inserted
    results = db.execute("SELECT type FROM faulty_measurements WHERE type = 'time_inconsistency'")
    assert len(results) == 0, f"Too many results: {len(results)} - {results}"


def test_time_inconsistencies_threshold_boundary(
    db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements
):
    """
    Test that threshold boundary works correctly (3600 seconds = 1 hour).
    """
    threshold = 3600  # Exactly 1 hour

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        threshold=threshold,
    )

    result = db.execute(
        "SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'time_inconsistency'"
    )
    assert len(result) > 0, "Expected time inconsistency anomalies"

    # Verify all results meet the threshold
    for row in result:
        _, _, _, _, details_str = row
        details = orjson.loads(details_str)
        assert abs(details["diff_seconds"]) >= threshold, f"diff_seconds {details['diff_seconds']} should be >= {threshold}"


def test_time_inconsistencies_details_structure(
    db, fastpath, fastpath_data_time_inconsistencies, clean_faulty_measurements
):
    """
    Test that details JSON contains all expected fields.
    """
    threshold = 1800  # 30 minutes

    time_inconsistencies.run_time_inconsistencies_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        threshold=threshold,
    )

    result = db.execute(
        "SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'time_inconsistency'"
    )
    assert len(result) > 0, "Expected time inconsistency anomalies"

    for row in result:
        _, _, _, _, details_str = row
        details = orjson.loads(details_str)

        # Verify all required fields are present
        assert "measurement_uid" in details
        assert "measurement_start_time" in details
        assert "uid_timestamp" in details
        assert "diff_seconds" in details
        assert "threshold" in details

        # Verify field types and formats
        assert isinstance(details["measurement_uid"], str)
        assert isinstance(details["measurement_start_time"], str)  # ISO format
        assert isinstance(details["uid_timestamp"], str)  # ISO format
        assert isinstance(details["diff_seconds"], (int, float))
        assert isinstance(details["threshold"], int)

        # Verify timestamps are valid ISO format
        datetime.fromisoformat(details["measurement_start_time"].replace('Z', '+00:00'))
        datetime.fromisoformat(details["uid_timestamp"].replace('Z', '+00:00'))
