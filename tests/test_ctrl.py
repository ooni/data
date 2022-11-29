from datetime import date, datetime

import pytest
from oonidata.db.connections import ClickhouseConnection
from oonidata.experiments.control import (
    WebGroundTruthDB,
    ReducedWebGroundTruthDB,
    iter_web_ground_truths,
)


def test_web_ground_truth_from_clickhouse(netinfodb):
    db = ClickhouseConnection(conn_url="clickhouse://localhost")
    try:
        db.execute("SELECT 1")
    except:
        pytest.skip("no database connection")

    iter_rows = iter_web_ground_truths(
        db=db, netinfodb=netinfodb, measurement_day=date(2022, 11, 10)
    )
    rows = []
    for column_names, row in iter_rows:
        assert len(column_names) == len(row)
        rows.append((column_names, row))
    wgt_db = WebGroundTruthDB()
    wgt_db.build_from_rows(rows=rows)
    for res in wgt_db.lookup(probe_asn=100, probe_cc="IT", hostnames=["ooni.org"]):
        if res.dns_success == 1:
            assert res.ip_asn and res.ip_asn == 16509
            assert res.ip_as_org_name and len(res.ip_as_org_name) > 0
        if res.http_request_url:
            assert res.http_failure or res.http_success


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

    reduced_db = ReducedWebGroundTruthDB(db=wgt_db.db, idx=0)
    reduced_db.build(probe_cc="IT", probe_asn=100, ip_ports=[("1.1.1.1", 80)])
    for row in reduced_db.db.execute(f"SELECT * FROM {reduced_db._table_name}"):
        print(row)

    res = reduced_db.lookup(
        probe_cc="IT",
        probe_asn=100,
        http_request_urls=["https://ooni.org/"],
    )
    assert len(res) == 0
    res = reduced_db.lookup(
        probe_cc="IT",
        probe_asn=100,
        ip_ports=[("1.1.1.1", 80)],
    )
    assert len(res) == 1
    assert res[0].count == 10
