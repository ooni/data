import gzip
from pathlib import Path
import sqlite3
from unittest.mock import MagicMock
from oonidata.analysis.datasources import load_measurement

from oonidata.dataclient import stream_jsonl
from oonidata.models.nettests.dnscheck import DNSCheck
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.processing import ResponseArchiver, fingerprint_hunter
from oonidata.transforms import measurement_to_observations
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer


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
            archiver.archive_http_transaction(
                request_url=request_url,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
            )

    warc_files = list(dst_dir.glob("*.warc.gz"))
    assert len(warc_files) == 1
    with gzip.open(warc_files[0], "rb") as in_file:
        assert b"Run OONI Probe to detect internet censorship" in in_file.read()

    conn = sqlite3.connect(dst_dir / "graveyard.sqlite3")
    res = conn.execute("SELECT COUNT() FROM oonibodies_archive")
    assert res.fetchone()[0] == 1


def test_fingerprint_hunter(fingerprintdb, measurements, tmpdir):
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
            response_archiver.archive_http_transaction(
                request_url=request_url,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
            )

    archive_path = list(archives_dir.glob("*.warc.gz"))[0]
    detected_fps = list(
        fingerprint_hunter(
            fingerprintdb=fingerprintdb,
            archive_path=archive_path,
        )
    )
    assert len(detected_fps) == 1
