from datetime import datetime
from oonidata.experiments.control import WebGroundTruth, WebGroundTruthDB


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
        all_wgt.append(WebGroundTruth(**wgt_dict))  # type: ignore

    for _ in range(10):
        wgt_dict = base_wgt.copy()
        wgt_dict["hostname"] = "ooni.org"
        all_wgt.append(WebGroundTruth(**wgt_dict))  # type: ignore

    for _ in range(10):
        wgt_dict = base_wgt.copy()
        wgt_dict["http_request_url"] = "https://ooni.org/"
        all_wgt.append(WebGroundTruth(**wgt_dict))  # type: ignore

    wgt_db = WebGroundTruthDB(ground_truths=all_wgt)
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

    res = wgt_db.lookup(
        probe_cc="IT",
        probe_asn=100,
        http_request_urls=["https://ooni.org/"],
        ip_ports=[("1.1.1.1", 80)],
        hostnames=["ooni.org"],
    )
    assert len(res) == 3
    assert all(r.count == 10 for r in res)

    for _ in range(10):
        with wgt_db.reduced_table(
            probe_cc="IT", probe_asn=100, ip_ports=[("1.1.1.1", 80)]
        ) as reduced_db:
            res = reduced_db.lookup(
                probe_cc="IT",
                probe_asn=100,
                http_request_urls=["https://ooni.org/"],
            )
            assert len(res) == 0
