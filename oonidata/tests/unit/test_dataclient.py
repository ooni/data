import pytest

from copy import deepcopy
from oonidata.dataclient import stream_postcan, stream_jsonl


def test_stream_postcan(postcans, jsonlgzs):
    json_msmts = []
    postcan_msmts = []

    msmt_count = 0
    with postcans["2024030100_AM_webconnectivity.n1.0.tar.gz"].open("rb") as in_file:
        for msmt in stream_postcan(in_file):
            assert msmt["measurement_uid"] is not None
            postcan_msmts.append(msmt)
            msmt_count += 1

    assert msmt_count == 100

    with jsonlgzs["2024030100_AM_webconnectivity.n1.0.jsonl.gz"].open("rb") as in_file:
        for msmt in stream_jsonl(in_file):
            json_msmts.append(msmt)
            msmt_count += 1

    assert len(json_msmts) == len(postcan_msmts)

    for idx, msmt in enumerate(json_msmts):
        pc_msmt = deepcopy(postcan_msmts[idx])
        # postcans should be identical to jsonl if not for the report_id
        pc_msmt.pop("measurement_uid")
        assert pc_msmt["report_id"] == msmt["report_id"]
        assert pc_msmt == msmt
