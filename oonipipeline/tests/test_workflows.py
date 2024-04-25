from datetime import date, datetime, timedelta, timezone
import gzip
from pathlib import Path
import sqlite3
from typing import List, Tuple
from unittest.mock import MagicMock
import time

import pytest

from oonidata.dataclient import stream_jsonl, load_measurement
from oonidata.models.nettests.dnscheck import DNSCheck
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.nettests.http_invalid_request_line import HTTPInvalidRequestLine
from oonidata.models.observations import HTTPMiddleboxObservation

from oonipipeline.transforms.measurement_transformer import MeasurementTransformer
from oonipipeline.transforms.observations import measurement_to_observations
from oonipipeline.temporal.analysis import (
    MakeAnalysisParams,
    make_analysis_in_a_day,
    make_cc_batches,
)
from oonipipeline.temporal.common import (
    get_obs_count_by_cc,
    get_prev_range,
    maybe_delete_prev_range,
)
from oonipipeline.temporal.ground_truths import (
    MakeGroundTruthsParams,
    make_ground_truths_in_day,
)
from oonipipeline.temporal.observations import (
    make_observations_for_file_entry_batch,
    write_observations_to_db,
)

# from oonipipeline.workflows.response_archiver import ResponseArchiver
# from oonipipeline.workflows.fingerprint_hunter import fingerprint_hunter


def wait_for_mutations(db, table_name):
    while True:
        res = db.execute(
            f"SELECT * FROM system.mutations WHERE is_done=0 AND table='{table_name}';"
        )
        if len(res) == 0:  # type: ignore
            break
        time.sleep(1)


def test_get_prev_range(db):
    db.execute("DROP TABLE IF EXISTS test_range")
    db.execute(
        """CREATE TABLE test_range (
        created_at DateTime64(3, 'UTC'),
        bucket_date String,
        test_name String,
        probe_cc String
    )
    ENGINE = MergeTree
    ORDER BY (bucket_date, created_at)
    """
    )
    bucket_date = "2000-01-01"
    test_name = "web_connectivity"
    probe_cc = "IT"
    min_time = datetime(2000, 1, 1, 23, 42, 00)
    rows = [(min_time, bucket_date, test_name, probe_cc)]
    for i in range(200):
        rows.append((min_time + timedelta(seconds=i), bucket_date, test_name, probe_cc))
    db.execute(
        "INSERT INTO test_range (created_at, bucket_date, test_name, probe_cc) VALUES",
        rows,
    )
    prev_range = get_prev_range(
        db,
        "test_range",
        test_name=[test_name],
        bucket_date=bucket_date,
        probe_cc=[probe_cc],
    )
    assert prev_range.min_created_at and prev_range.max_created_at
    assert prev_range.min_created_at == (min_time - timedelta(seconds=1))
    assert prev_range.max_created_at == (rows[-1][0] + timedelta(seconds=1))
    db.execute("TRUNCATE TABLE test_range")

    bucket_date = "2000-03-01"
    test_name = "web_connectivity"
    probe_cc = "IT"
    min_time = datetime(2000, 1, 1, 23, 42, 00)
    rows: List[Tuple[datetime, str, str, str]] = []
    for i in range(10):
        rows.append(
            (min_time + timedelta(seconds=i), "2000-02-01", test_name, probe_cc)
        )
    min_time = rows[-1][0]
    for i in range(10):
        rows.append((min_time + timedelta(seconds=i), bucket_date, test_name, probe_cc))

    db.execute(
        "INSERT INTO test_range (created_at, bucket_date, test_name, probe_cc) VALUES",
        rows,
    )
    prev_range = get_prev_range(
        db,
        "test_range",
        test_name=[test_name],
        bucket_date=bucket_date,
        probe_cc=[probe_cc],
    )
    assert prev_range.min_created_at and prev_range.max_created_at
    assert prev_range.min_created_at == (min_time - timedelta(seconds=1))
    assert prev_range.max_created_at == (rows[-1][0] + timedelta(seconds=1))

    maybe_delete_prev_range(
        db=db,
        prev_range=prev_range,
    )
    wait_for_mutations(db, "test_range")
    res = db.execute("SELECT COUNT() FROM test_range")
    assert res[0][0] == 10
    db.execute("DROP TABLE test_range")


def test_make_cc_batches():
    cc_batches = make_cc_batches(
        cnt_by_cc={"IT": 100, "IR": 300, "US": 1000},
        probe_cc=["IT", "IR", "US"],
        parallelism=2,
    )
    assert len(cc_batches) == 2
    # We expect the batches to be broken up into (IT, IR), ("US")
    assert any([set(x) == set(["US"]) for x in cc_batches]) == True


def test_make_file_entry_batch(datadir, db):
    file_entry_batch = [
        (
            "ooni-data-eu-fra",
            "raw/20231031/15/IR/webconnectivity/2023103115_IR_webconnectivity.n1.0.tar.gz",
            "tar.gz",
            4074306,
        )
    ]
    obs_msmt_count = make_observations_for_file_entry_batch(
        file_entry_batch, db.clickhouse_url, 100, datadir, "2023-10-31", ["IR"], False
    )
    assert obs_msmt_count == 453
    make_ground_truths_in_day(
        MakeGroundTruthsParams(
            day=date(2023, 10, 31).strftime("%Y-%m-%d"),
            clickhouse=db.clickhouse_url,
            data_dir=datadir,
            rebuild_ground_truths=True,
        ),
    )
    analysis_res = make_analysis_in_a_day(
        MakeAnalysisParams(
            probe_cc=["IR"],
            test_name=["webconnectivity"],
            clickhouse=db.clickhouse_url,
            data_dir=datadir,
            fast_fail=False,
            day=date(2023, 10, 31).strftime("%Y-%m-%d"),
        ),
    )
    assert analysis_res["count"] == obs_msmt_count


def test_write_observations(measurements, netinfodb, db):
    msmt_uids = [
        ("20210101190046.780850_US_webconnectivity_3296f126f79ca186", "2021-01-01"),
        ("20210101181154.037019_CH_webconnectivity_68ce38aa9e3182c2", "2021-01-01"),
        ("20231031032643.267235_GR_dnscheck_abcbfc460b9424b6", "2023-10-31"),
        (
            "20231101164541.763506_NP_httpinvalidrequestline_0cf676868fa36cc4",
            "2023-10-31",
        ),
        (
            "20231101164544.534107_BR_httpheaderfieldmanipulation_4caa0b0556f0b141",
            "2023-10-31",
        ),
        ("20231101164649.235575_RU_tor_ccf7519bf683c022", "2023-10-31"),
        (
            "20230907000740.785053_BR_httpinvalidrequestline_bdfe6d70dcbda5e9",
            "2023-09-07",
        ),
    ]
    for msmt_uid, bucket_date in msmt_uids:
        msmt = load_measurement(msmt_path=measurements[msmt_uid])
        write_observations_to_db(msmt, netinfodb, db, bucket_date)
    db.close()
    cnt_by_cc = get_obs_count_by_cc(
        db,
        test_name=[],
        start_day=date(2020, 1, 1),
        end_day=date(2023, 12, 1),
    )
    assert cnt_by_cc["CH"] == 2
    assert cnt_by_cc["GR"] == 4
    assert cnt_by_cc["US"] == 3
    assert cnt_by_cc["RU"] == 3


def test_hirl_observations(measurements, netinfodb):
    msmt = load_measurement(
        msmt_path=measurements[
            "20230907000740.785053_BR_httpinvalidrequestline_bdfe6d70dcbda5e9"
        ]
    )
    assert isinstance(msmt, HTTPInvalidRequestLine)
    middlebox_obs: List[HTTPMiddleboxObservation] = measurement_to_observations(
        msmt, netinfodb=netinfodb
    )[0]
    assert isinstance(middlebox_obs[0], HTTPMiddleboxObservation)
    assert middlebox_obs[0].hirl_success == True
    assert middlebox_obs[0].hirl_sent_0 != middlebox_obs[0].hirl_received_0


def test_insert_query_for_observation(measurements, netinfodb):
    http_blocked = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    assert isinstance(http_blocked, WebConnectivity)
    mt = MeasurementTransformer(measurement=http_blocked, netinfodb=netinfodb)
    all_web_obs = [
        obs
        for obs in mt.make_http_observations(
            http_blocked.test_keys.requests,
        )
    ]
    assert all_web_obs[-1].request_url == "http://proxy.org/"


def test_web_connectivity_processor(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220627131742.081225_GB_webconnectivity_e1e2cf4db492b748"
        ]
    )
    assert isinstance(msmt, WebConnectivity)

    web_obs_list, web_ctrl_list = measurement_to_observations(msmt, netinfodb=netinfodb)
    assert len(web_obs_list) == 3
    assert len(web_ctrl_list) == 3


def test_dnscheck_processor(measurements, netinfodb):
    db = MagicMock()
    db.write_row = MagicMock()

    msmt = load_measurement(
        msmt_path=measurements["20221013000000.517636_US_dnscheck_bfd6d991e70afa0e"]
    )
    assert isinstance(msmt, DNSCheck)
    obs_list = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)[0]
    assert len(obs_list) == 20


def test_full_processing(raw_measurements, netinfodb):
    for msmt_path in raw_measurements.glob("*/*/*.jsonl.gz"):
        with msmt_path.open("rb") as in_file:
            for msmt_dict in stream_jsonl(in_file):
                msmt = load_measurement(msmt_dict)
                measurement_to_observations(
                    msmt=msmt,
                    netinfodb=netinfodb,
                )


def test_archive_http_transaction(measurements, tmpdir):
    pytest.skip("TODO(art): fixme")
    db = MagicMock()
    db.write_row = MagicMock()

    msmt = load_measurement(
        msmt_path=measurements[
            "20220627131742.081225_GB_webconnectivity_e1e2cf4db492b748"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    assert msmt.test_keys.requests
    dst_dir = Path(tmpdir)
    with ResponseArchiver(dst_dir=dst_dir) as archiver:
        for http_transaction in msmt.test_keys.requests:
            if not http_transaction.response or not http_transaction.request:
                continue
            request_url = http_transaction.request.url
            status_code = http_transaction.response.code or 0
            response_headers = http_transaction.response.headers_list_bytes or []
            response_body = http_transaction.response.body_bytes
            assert response_body
            archiver.archive_http_transaction(
                request_url=request_url,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                matched_fingerprints=[],
            )

    warc_files = list(dst_dir.glob("*.warc.gz"))
    assert len(warc_files) == 1
    with gzip.open(warc_files[0], "rb") as in_file:
        assert b"Run OONI Probe to detect internet censorship" in in_file.read()

    conn = sqlite3.connect(dst_dir / "graveyard.sqlite3")
    res = conn.execute("SELECT COUNT() FROM oonibodies_archive")
    assert res.fetchone()[0] == 1


def test_fingerprint_hunter(fingerprintdb, measurements, tmpdir):
    pytest.skip("TODO(art): fixme")
    db = MagicMock()
    db.write_rows = MagicMock()

    archives_dir = Path(tmpdir)
    http_blocked = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    assert isinstance(http_blocked, WebConnectivity)
    with ResponseArchiver(dst_dir=archives_dir) as response_archiver:
        assert http_blocked.test_keys.requests
        for http_transaction in http_blocked.test_keys.requests:
            if not http_transaction.response or not http_transaction.request:
                continue
            request_url = http_transaction.request.url
            status_code = http_transaction.response.code or 0
            response_headers = http_transaction.response.headers_list_bytes or []
            response_body = http_transaction.response.body_bytes
            assert response_body
            response_archiver.archive_http_transaction(
                request_url=request_url,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                matched_fingerprints=[],
            )

    archive_path = list(archives_dir.glob("*.warc.gz"))[0]
    detected_fps = list(
        fingerprint_hunter(
            fingerprintdb=fingerprintdb,
            archive_path=archive_path,
        )
    )
    assert len(detected_fps) == 1
