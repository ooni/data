from oonipipeline.analysis import volume
from datetime import datetime
import orjson


def test_volume_basic(db, fastpath, fastpath_data):
    """Test basic volume analysis with data that exceeds threshold."""
    start_time = datetime(2024, 6, 28, 13, 1, 0)
    end_time = datetime(2024, 6, 28, 13, 3, 0)
    threshold = 5  # Lower than the 10 measurements we have

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # Check that results were inserted into faulty_measurements
    # Columns: time, type, probe_cc, probe_asn, details
    result = db.execute("SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) > 0, "Expected volume anomalies to be inserted"
    
    # Verify the details structure
    for row in result:
        time, type_val, probe_cc, probe_asn, details_str = row
        assert type_val == "volume"
        assert probe_cc == "SN"
        assert probe_asn == 37577
        details = orjson.loads(details_str)
        assert "minute" in details
        assert "total" in details
        assert "threshold" in details
        assert details["threshold"] == threshold
        assert details["total"] >= threshold


def test_volume_no_anomalies(db, fastpath, fastpath_data):
    """Test volume analysis with threshold higher than data count."""
    start_time = datetime(2024, 6, 28, 13, 1, 0)
    end_time = datetime(2024, 6, 28, 13, 3, 0)
    threshold = 100  # Higher than the 10 measurements we have

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # Check that no results were inserted
    result = db.execute("SELECT type FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) == 0, "Expected no volume anomalies with high threshold"


def test_volume_time_range_filtering(db, fastpath, fastpath_data):
    """Test that volume analysis only considers measurements within time range."""
    # Use a time range that excludes all our test data
    start_time = datetime(2024, 6, 28, 14, 0, 0)
    end_time = datetime(2024, 6, 28, 15, 0, 0)
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


def test_volume_grouping_by_attributes(db, fastpath, fastpath_data):
    """Test that volume analysis groups by probe attributes correctly."""
    # Add some measurements with different attributes
    additional_data = [
        ("20240628130158.000000_US_webconnectivity_aaaaaaaaaaaaaaaa", datetime(2024, 6, 28, 13, 1, 58), "US", 15169, "3.19.0", "3.19.0", "ios", "arm64"),
        ("20240628130159.000000_US_webconnectivity_bbbbbbbbbbbbbbbb", datetime(2024, 6, 28, 13, 1, 59), "US", 15169, "3.19.0", "3.19.0", "ios", "arm64"),
    ]

    column_names = ["measurement_uid", "measurement_start_time", "probe_cc", "probe_asn", "engine_version", "software_version", "platform", "architecture"]
    db.write_rows("fastpath", additional_data, column_names)

    start_time = datetime(2024, 6, 28, 13, 1, 0)
    end_time = datetime(2024, 6, 28, 13, 3, 0)
    threshold = 5

    # Run the analysis
    volume.run_volume_analysis(
        clickhouse_url=db.clickhouse_url,
        start_time=start_time,
        end_time=end_time,
        threshold=threshold
    )

    # Check results - should have entries for both SN and US probes
    # Columns: time, type, probe_cc, probe_asn, details
    result = db.execute("SELECT time, type, probe_cc, probe_asn, details FROM faulty_measurements WHERE type = 'volume'")
    assert len(result) > 0, "Expected volume anomalies to be inserted"
    
    # Group results by probe_cc to verify grouping works
    probe_ccs = {probe_cc for _, _, probe_cc, _, _ in result}
    assert "SN" in probe_ccs, "Expected SN probe anomalies"
    # Note: US only has 2 measurements, so won't exceed threshold of 5
    # But SN has 10 measurements, so should appear


def test_volume_minute_grouping(db, fastpath, fastpath_data):
    """Test that volume analysis groups measurements by minute correctly."""
    # Add measurements in a different minute
    additional_data = [
        ("20240628130300.000000_SN_webconnectivity_cccccccccccccccc", datetime(2024, 6, 28, 13, 3, 0), "SN", 37577, "3.20.0", "3.20.0", "android", "arm64"),
        ("20240628130301.000000_SN_webconnectivity_dddddddddddddddd", datetime(2024, 6, 28, 13, 3, 1), "SN", 37577, "3.20.0", "3.20.0", "android", "arm64"),
    ]

    column_names = ["measurement_uid", "measurement_start_time", "probe_cc", "probe_asn", "engine_version", "software_version", "platform", "architecture"]
    db.write_rows("fastpath", additional_data, column_names)

    start_time = datetime(2024, 6, 28, 13, 1, 0)
    end_time = datetime(2024, 6, 28, 13, 4, 0)
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
    
    # Should have at least one minute with anomalies (13:01 or 13:02)
    assert len(minutes) > 0, "Expected at least one minute with anomalies"
