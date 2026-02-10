from oonipipeline.analysis import volume
from datetime import datetime, timedelta
import orjson

START_TIME = datetime(2023, 12, 31, 23, 59, 0)
END_TIME = datetime(2024, 1, 1, 0, 1, 0)
EXTENDED_END_TIME = datetime(2024, 1, 1, 0, 2, 0)


def test_volume_basic(db, fastpath, fastpath_data_fake, clean_faulty_measurements):
    """Test basic volume analysis with data that exceeds threshold."""
    start_time = START_TIME
    end_time = END_TIME
    threshold = 5  # Should trigger some events

    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    result = db.execute("SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) > 0, "Expected volume anomalies to be inserted"

    for row in result:
        time, type_val, probe_cc, probe_asn, details_str = row
        assert type_val == "volume"
        assert probe_cc == "VE"
        assert probe_asn == 8048
        details = orjson.loads(details_str)
        assert "minute" in details
        assert "total" in details
        assert "threshold" in details
        assert details["threshold"] == threshold
        assert details["total"] >= threshold


def test_volume_no_anomalies(db, fastpath, fastpath_data_fake, clean_faulty_measurements):
    """Test volume analysis with threshold higher than data count."""
    start_time = START_TIME
    end_time = END_TIME
    threshold = 100  # Higher than the 10 measurements we have

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # No anomalies expected
    result = db.execute("SELECT type FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) == 0, "Expected no volume anomalies with high threshold"


def test_volume_time_range_filtering(db, fastpath, fastpath_data_fake, clean_faulty_measurements):
    """Test that we only considers measurements within time range."""
    # excludes all our test data
    start_time = END_TIME + timedelta(hours=1)
    end_time = start_time + timedelta(hours=1)
    threshold = 1

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # Check that no results were inserted
    result = db.execute("SELECT type FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) == 0, "Expected no volume anomalies outside time range"


def test_volume_grouping_by_attributes(db, fastpath, fastpath_data_fake, clean_faulty_measurements):
    """Test that groups by probe attributes correctly."""
    # Add some measurements with different attributes
    additional_data = [
        ("20240101000010.000000_US_webconnectivity_5555555555555555", datetime(2024, 1, 1, 0, 0, 10), "US", 15169, "3.19.0", "3.19.0", "ios", "arm64"),
        ("20240101000011.000000_US_webconnectivity_6666666666666666", datetime(2024, 1, 1, 0, 0, 11), "US", 15169, "3.19.0", "3.19.0", "ios", "arm64"),
    ]

    column_names = ["measurement_uid", "measurement_start_time", "probe_cc", "probe_asn", "engine_version", "software_version", "platform", "architecture"]
    db.write_rows("fastpath", additional_data, column_names)

    start_time = START_TIME
    end_time = END_TIME
    threshold = 5

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # Check results - should have entries for both VE and US probes
    # Columns: time, type, probe_cc, probe_asn, details
    result = db.execute("SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) > 0, "Expected volume anomalies to be inserted"

    # Group results by probe_cc to verify grouping works
    probe_ccs = {probe_cc for _, _, probe_cc, _, _ in result}
    assert "VE" in probe_ccs, "Expected VE probe anomalies"
    # Note: US only has 2 measurements, so won't exceed threshold of 5
    # But VE has 10 measurements, so should appear


def test_volume_minute_grouping(db, fastpath, fastpath_data_fake, clean_faulty_measurements):
    """Test that volume analysis groups measurements by minute correctly."""
    # Add measurements in a different minute
    additional_data = [
        ("20240101000100.000000_VE_webconnectivity_7777777777777777", datetime(2024, 1, 1, 0, 1, 0), "VE", 8048, "4.20.0", "4.20.0", "android", "arm64"),
        ("20240101000101.000000_VE_webconnectivity_8888888888888888", datetime(2024, 1, 1, 0, 1, 1), "VE", 8048, "4.20.0", "4.20.0", "android", "arm64"),
    ]

    column_names = ["measurement_uid", "measurement_start_time", "probe_cc", "probe_asn", "engine_version", "software_version", "platform", "architecture"]
    db.write_rows("fastpath", additional_data, column_names)

    start_time = START_TIME
    end_time = EXTENDED_END_TIME
    threshold = 5

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # Check results - should have entries grouped by minute
    # Columns: time, type, probe_cc, probe_asn, details
    result = db.execute("SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) > 0, "Expected volume anomalies to be inserted"

    # Verify that details contain minute information
    minutes = set()
    for row in result:
        _, _, _, _, details_str = row
        details = orjson.loads(details_str)
        minutes.add(details["minute"])

    # Should have at least one minute with anomalies (00:00)
    assert len(minutes) > 0, "Expected at least one minute with anomalies"
