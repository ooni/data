from datetime import date, datetime, timedelta, timezone
import gzip
from pathlib import Path
import sqlite3
from typing import Dict, List, Tuple
from unittest.mock import MagicMock

from oonipipeline.db.connections import ClickhouseConnection
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from temporalio import activity

import pytest

from oonidata.dataclient import stream_jsonl, load_measurement
from oonidata.models.nettests.dnscheck import DNSCheck
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.nettests.http_invalid_request_line import HTTPInvalidRequestLine
from oonidata.models.observations import HTTPMiddleboxObservation

from oonipipeline.temporal.activities.common import (
    ClickhouseParams,
    OptimizeTablesParams,
)
from oonipipeline.temporal.activities.observations import (
    MakeObservationsParams,
    MakeObservationsResult,
    make_observations_for_file_entry_batch,
)
from oonipipeline.transforms.measurement_transformer import MeasurementTransformer
from oonipipeline.transforms.observations import measurement_to_observations
from oonipipeline.temporal.activities.analysis import (
    MakeAnalysisParams,
    make_analysis_in_a_day,
)
from oonipipeline.temporal.common import (
    TS_FORMAT,
)
from oonipipeline.temporal.workflows.analysis import (
    AnalysisWorkflowParams,
    AnalysisWorkflow,
)
from oonipipeline.temporal.workflows.observations import (
    ObservationsWorkflowParams,
    ObservationsWorkflow,
)
from oonipipeline.temporal.workflows.common import TASK_QUEUE_NAME


def get_obs_count_by_cc(
    clickhouse_url: str, table_name: str, start_day: str, end_day: str
) -> Dict[str, int]:
    with ClickhouseConnection(clickhouse_url) as db:
        q = f"""
        SELECT
        probe_cc, COUNT()
        FROM {table_name}
        WHERE measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s
        GROUP BY probe_cc
        """
        cc_list: List[Tuple[str, int]] = db.execute(
            q, {"start_day": start_day, "end_day": end_day}
        )  # type: ignore
        assert isinstance(cc_list, list)
    return dict(cc_list)


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
        file_entry_batch=file_entry_batch,
        clickhouse=db.clickhouse_url,
        write_batch_size=1,
        data_dir=datadir,
        bucket_date="2023-10-31",
        probe_cc=["IR"],
        fast_fail=False,
    )

    assert obs_msmt_count == 453
    analysis_res = make_analysis_in_a_day(
        MakeAnalysisParams(
            probe_cc=["IR"],
            test_name=["webconnectivity"],
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
        for obs_list in measurement_to_observations(
            msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
        ):
            # Ensure observation IDS do not clash
            obs_idxs = list(map(lambda x: x.observation_idx, obs_list))
            assert len(obs_idxs) == len(set(obs_idxs))
            db.write_table_model_rows(obs_list)
    db.close()
    cnt_by_cc = get_obs_count_by_cc(
        clickhouse_url=db.clickhouse_url,
        start_day="2020-01-01",
        end_day="2023-12-01",
        table_name="obs_web",
    )
    assert cnt_by_cc["CH"] == 2
    assert cnt_by_cc["GR"] == 20
    assert cnt_by_cc["US"] == 3
    assert cnt_by_cc["RU"] == 47


def test_hirl_observations(measurements, netinfodb):
    msmt = load_measurement(
        msmt_path=measurements[
            "20230907000740.785053_BR_httpinvalidrequestline_bdfe6d70dcbda5e9"
        ]
    )
    assert isinstance(msmt, HTTPInvalidRequestLine)
    middlebox_obs_tuple = measurement_to_observations(
        msmt, netinfodb=netinfodb, bucket_date="2023-09-07"
    )
    assert len(middlebox_obs_tuple) == 1
    middlebox_obs = middlebox_obs_tuple[0]
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
    mt = MeasurementTransformer(
        measurement=http_blocked, netinfodb=netinfodb, bucket_date="2022-06-08"
    )
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

    p = measurement_to_observations(msmt, netinfodb=netinfodb, bucket_date="2022-06-27")
    assert len(p) == 2
    web_obs_list, web_ctrl_list = p
    assert len(web_obs_list) == 3
    assert len(web_ctrl_list) == 3


def test_dnscheck_processor(measurements, netinfodb):
    db = MagicMock()
    db.write_row = MagicMock()

    msmt = load_measurement(
        msmt_path=measurements["20221013000000.517636_US_dnscheck_bfd6d991e70afa0e"]
    )
    assert isinstance(msmt, DNSCheck)
    obs_tuple = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)
    assert len(obs_tuple) == 1
    obs_list = obs_tuple[0]
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


@activity.defn(name="optimize_all_tables")
async def optimize_all_tables_mocked(params: ClickhouseParams):
    return


@activity.defn(name="optimize_tables")
async def optimize_tables_mocked(params: OptimizeTablesParams):
    return


@activity.defn(name="make_observations")
async def make_observations_mocked(
    params: MakeObservationsParams,
) -> MakeObservationsResult:
    return {
        "measurement_count": 100,
        "measurement_per_sec": 3.0,
        "mb_per_sec": 1.0,
        "total_size": 2000,
    }


@activity.defn(name="make_analysis_in_a_day")
async def make_analysis_in_a_day_mocked(params: MakeAnalysisParams) -> dict:
    return {"count": 100}


@pytest.mark.asyncio
async def test_temporal_workflows():
    obs_params = ObservationsWorkflowParams(
        probe_cc=[],
        test_name=[],
        fast_fail=False,
        bucket_date="2024-01-02",
    )
    analysis_params = AnalysisWorkflowParams(
        probe_cc=[], test_name=[], clickhouse="", data_dir="", day="2024-01-01"
    )
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE_NAME,
            workflows=[ObservationsWorkflow, AnalysisWorkflow],
            activities=[
                optimize_tables_mocked,
                optimize_all_tables_mocked,
                make_analysis_in_a_day_mocked,
                make_observations_mocked,
            ],
        ):
            res = await env.client.execute_workflow(
                ObservationsWorkflow.run,
                obs_params,
                id="obs-wf",
                task_queue=TASK_QUEUE_NAME,
            )
            assert res["size"] == 2000
            assert res["measurement_count"] == 100
            assert res["bucket_date"] == "2024-01-02"

            res = await env.client.execute_workflow(
                AnalysisWorkflow.run,
                analysis_params,
                id="analysis-wf",
                task_queue=TASK_QUEUE_NAME,
            )
            assert res["analysis_count"] == 100
            assert res["day"] == "2024-01-01"


@pytest.mark.skip(reason="TODO(art): fixme")
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


@pytest.mark.skip(reason="TODO(art): fixme")
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
