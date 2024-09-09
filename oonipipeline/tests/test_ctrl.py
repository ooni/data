from datetime import date, datetime, timezone
import time

from oonidata.models.base import ProcessingMeta
from oonidata.models.observations import MeasurementMeta, ProbeMeta, WebObservation

from oonipipeline.analysis.datasources import iter_web_observations
from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.analysis.control import (
    WebGroundTruthDB,
    iter_web_ground_truths,
)
from oonipipeline.temporal.activities.observations import (
    MakeObservationsFileEntryBatch,
    make_observations_for_file_entry_batch,
)

DUMMY_PROBE_META = ProbeMeta(
    probe_asn=6167,
    probe_cc="US",
    probe_as_org_name="Verizon Business",
    probe_as_cc="US",
    probe_as_name="20211102",
    network_type="TEST",
    platform="TEST",
    origin="",
    engine_name="TEST",
    engine_version="TEST",
    architecture="TEST",
    resolver_ip="141.207.147.254",
    resolver_asn=22394,
    resolver_cc="US",
    resolver_as_org_name="Verizon Business",
    resolver_as_cc="US",
    resolver_is_scrubbed=False,
    resolver_asn_probe=22394,
    resolver_as_org_name_probe="Verizon Business",
)

DUMMY_MEASUREMENT_META = MeasurementMeta(
    software_name="TEST",
    software_version="TEST",
    bucket_datetime=datetime(2023, 10, 31),
    test_name="web_connectivity",
    test_version="0.4.2",
    measurement_uid="TEST",
    input="",
    report_id="TEST",
    measurement_start_time=datetime(2023, 10, 31, 15, 56, 12),
)


def test_web_ground_truth_from_clickhouse(db, datadir, netinfodb, tmp_path):
    file_entry_batch = [
        (
            "ooni-data-eu-fra",
            "raw/20231031/15/US/webconnectivity/2023103115_US_webconnectivity.n1.7.tar.gz",
            "tar.gz",
            5798373,
        )
    ]
    obs_msmt_count = make_observations_for_file_entry_batch(
        file_entry_batch=file_entry_batch,
        clickhouse=db.clickhouse_url,
        write_batch_size=1,
        data_dir=datadir,
        bucket_date="2023-10-31",
        probe_cc=["US"],
        fast_fail=False,
    )
    assert obs_msmt_count == 299
    # Wait for buffers to flush
    time.sleep(3)
    ground_truth_db_path = tmp_path / "test-groundtruthdbUSONLY-2023-10-31.sqlite3"
    web_ground_truth_db = WebGroundTruthDB(
        connect_str=str(ground_truth_db_path.absolute())
    )
    web_ground_truth_db.build_from_rows(
        rows=iter_web_ground_truths(
            db=db,
            measurement_day=date(2023, 10, 31),
            netinfodb=netinfodb,
        )
    )

    wgt_db = WebGroundTruthDB()
    wgt_db.build_from_existing(str(ground_truth_db_path.absolute()))

    web_obs = [
        WebObservation(
            probe_meta=DUMMY_PROBE_META,
            measurement_meta=DUMMY_MEASUREMENT_META,
            processing_meta=ProcessingMeta(
                created_at=datetime.now(timezone.utc),
            ),
            # The only things we look at to find the groundtruth are hostname, ip, http_request_url
            fqdn="explorer.ooni.org",
            ip="37.218.242.149",
            port=443,
            http_request_url="https://explorer.ooni.org/",
            observation_idx=0,
            target_id="",
            transaction_id=0,
            ip_asn=54113,
            ip_as_org_name="Fastly, Inc.",
            ip_as_cc="US",
            ip_cc="US",
            ip_is_bogon=False,
            dns_query_type="A",
            dns_failure="",
            dns_engine="system",
            dns_engine_resolver_address="",
            dns_answer_type="A",
            dns_answer="151.101.65.195",
            dns_answer_asn=54113,
            dns_answer_as_org_name="Fastly, Inc.",
            dns_t=0.117683385,
            tcp_failure="",
            tcp_success=True,
            tcp_t=0.583859739,
            tls_failure="",
            tls_server_name="",
            tls_version="",
            tls_cipher_suite="",
            tls_is_certificate_valid=True,
            tls_end_entity_certificate_fingerprint="",
            tls_end_entity_certificate_subject="",
            tls_end_entity_certificate_subject_common_name="",
            tls_end_entity_certificate_issuer="",
            tls_end_entity_certificate_issuer_common_name="",
            tls_end_entity_certificate_san_list=[],
            tls_end_entity_certificate_not_valid_after=None,
            tls_end_entity_certificate_not_valid_before=None,
            tls_certificate_chain_length=3,
            tls_certificate_chain_fingerprints=[],
            tls_handshake_read_count=2,
            tls_handshake_write_count=4,
            tls_handshake_read_bytes=7201,
            tls_handshake_write_bytes=392,
            tls_handshake_last_operation="write_4",
            tls_handshake_time=0.07061901100000001,
            tls_t=0.654237447,
            http_network="",
            http_alpn="",
            http_failure="",
            http_request_body_length=0,
            http_request_method="",
            http_runtime=0,
            http_response_body_length=0,
            http_response_body_is_truncated=False,
            http_response_body_sha1="",
            http_response_status_code=0,
            http_response_header_location="",
            http_response_header_server="",
            http_request_redirect_from="",
            http_request_body_is_truncated=False,
            http_t=0,
            probe_analysis="false",
        )
    ]

    relevant_gts = web_ground_truth_db.lookup_by_web_obs(web_obs=web_obs)
    assert len(relevant_gts) == 2
    for gt in relevant_gts:
        if gt.ip:
            assert gt.ip_asn == 47172
            assert gt.ip_as_org_name
            assert "greenhost" in gt.ip_as_org_name.lower()

    # for gt in relevant_gts:
    #    print_nice_vertical(gt)


def test_web_ground_truth_db():
    base_wgt = dict(
        vp_asn=0,
        vp_cc="ZZ",
        is_trusted_vp=True,
        timestamp=datetime.now(),
        hostname=None,
        ip=None,
        ip_asn=100,
        ip_as_org_name="fake",
        port=80,
        dns_failure=None,
        dns_success=True,
        tcp_failure="",
        tcp_success=True,
        tls_failure="",
        tls_success=True,
        tls_is_certificate_valid=True,
        http_request_url=None,
        http_failure="",
        http_success=True,
        http_response_body_length=42,
        count=1,
    )
    all_wgt = []
    for _ in range(10):
        wgt_dict = base_wgt.copy()
        wgt_dict["ip"] = "1.1.1.1"
        wgt_dict["port"] = 80
        all_wgt.append(wgt_dict)

    for _ in range(10):
        wgt_dict = base_wgt.copy()
        wgt_dict["hostname"] = "ooni.org"
        all_wgt.append(wgt_dict)

    for _ in range(10):
        wgt_dict = base_wgt.copy()
        wgt_dict["http_request_url"] = "https://ooni.org/"
        all_wgt.append(wgt_dict)

    iter_rows = map(lambda x: (list(x.keys()), list(x.values())), all_wgt)

    wgt_db = WebGroundTruthDB()
    wgt_db.build_from_rows(rows=iter_rows)
    res = wgt_db.lookup(probe_cc="IT", probe_asn=100, hostnames=["ooni.org"])
    # They should be aggregated
    assert len(res) == 1
    assert res[0].count == 10

    res = wgt_db.lookup(probe_cc="IT", probe_asn=100, ip_ports=[("1.1.1.1", 80)])
    assert len(res) == 1
    assert res[0].count == 10

    res = wgt_db.lookup(
        probe_cc="IT", probe_asn=100, http_request_urls=["https://ooni.org/"]
    )
    assert len(res) == 1
    assert res[0].count == 10
    assert res[0].http_success

    res = wgt_db.lookup(
        probe_cc="IT",
        probe_asn=100,
        http_request_urls=["https://ooni.org/"],
        ip_ports=[("1.1.1.1", 80)],
        hostnames=["ooni.org"],
    )
    assert len(res) == 3
    assert all(r.count == 10 for r in res)
