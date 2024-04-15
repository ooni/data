import datetime
from oonidata.dataclient import FileEntry


def test_normalize_oldcans():
    fe = FileEntry(
        s3path="canned/2013-01-08/http_header_field_manipulation.0.tar.lz4",
        bucket_name="ooni-data",
        timestamp=datetime.datetime(2013, 1, 8, 0, 0),
        testname="httpheaderfieldmanipulation",
        filename="http_header_field_manipulation.0.tar.lz4",
        size=3480,
        ext="tar.lz4",
        is_can=True,
        probe_cc=None,
    )
    cnt = 0
    for msmt in fe.stream_measurements():
        cnt += 1
        assert msmt["measurement_uid"] is not None
        assert msmt["test_name"].lower() == msmt["test_name"]
    assert cnt == 12
