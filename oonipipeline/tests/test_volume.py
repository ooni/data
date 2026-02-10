from oonipipeline.analysis import volume
from datetime import datetime, timedelta
import orjson

START_TIME = datetime(2023, 12, 31, 23, 59, 0)
END_TIME = datetime(2024, 1, 1, 0, 1, 0)
EXTENDED_END_TIME = datetime(2024, 1, 1, 0, 2, 0)


def test_volume_basic(db, fastpath, fastpath_data_fake, clean_faulty_measurements):
    """
    Test basic volume analysis with data that exceeds threshold.
    """

    threshold = 5  # Should trigger some events
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        threshold=threshold,
    )

    result = db.execute(
        "SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'"
    )
    assert len(result) > 0, "Missing volume anomalies"

    for row in result:
        time, type_val, probe_cc, probe_asn, details_str = row
        assert type_val == "volume"
        assert probe_cc == "VE"
        assert probe_asn == 8048
        details = orjson.loads(details_str)
        assert "start_time" in details
        assert "end_time" in details
        assert "software_name" in details
        assert "total" in details
        assert "threshold" in details
        assert details["threshold"] == threshold
        assert details["total"] >= threshold


def test_volume_no_anomalies(
    db, fastpath, fastpath_data_fake, clean_faulty_measurements
):
    """
    Test volume analysis with threshold higher than data count.
    """

    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        threshold=100,  # Higher than the 10 measurements we have
    )

    # No anomalies expected
    result = db.execute("SELECT type FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) == 0, "Expected no volume anomalies with high threshold"


def test_volume_time_range_filtering(
    db, fastpath, fastpath_data_fake, clean_faulty_measurements
):
    """
    Test that we only considers measurements within time range.
    """
    start_time = END_TIME + timedelta(hours=1)
    end_time = start_time + timedelta(hours=1)

    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=1,
    )

    # Check that no events were inserted
    results = db.execute("SELECT type FROM faulty_measurements WHERE type = 'volume'")
    assert len(results) == 0, f"Too many results: {len(results)} - {results}"


def test_volume_grouping_by_attributes(
    db, fastpath, fastpath_data_fake, clean_faulty_measurements
):
    """
    Test that groups by probe attributes correctly.
    """
    threshold = 5

    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=END_TIME,
        threshold=threshold,
    )

    # Only one event for 'VE'
    result = db.execute(
        "SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'"
    )
    assert len(result) == 1, f"Unexpected anomalies: {result}"

    # US only has 2 measurements, should not appear
    # VE has 10 measurements, should appear
    probe_ccs = {probe_cc for _, _, probe_cc, _, _ in result}
    assert "VE" in probe_ccs, "Expected only VE probe anomalies"


def test_volume_minute_grouping(
    db, fastpath, fastpath_data_fake, clean_faulty_measurements
):
    """
    Test that volume analysis groups measurements by minute correctly
    """

    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=START_TIME,
        end_time=EXTENDED_END_TIME,
        threshold=5,
    )

    result = db.execute(
        "SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'"
    )
    assert len(result) == 1, f"Unexpected rows: {result}"

    times = set()
    for row in result:
        _, _, _, _, details_str = row
        details = orjson.loads(details_str)
        times.add((details["start_time"], details["end_time"]))

    assert len(times) == 1, f"Unexpected times: {len(times)}"

    # interval with 10 measurements
    expected_start_time = "2024-01-01T00:00:00"
    expected_end_time = "2024-01-01T00:01:00"
    assert (
        expected_start_time,
        expected_end_time,
    ) in times, f"Expected time range ({expected_start_time}, {expected_end_time}) not in {times}"
