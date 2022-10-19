from datetime import datetime
from pathlib import Path


def test_netinfodb(netinfodb):
    day = datetime(2021, 1, 1)
    as_info = netinfodb.lookup_asn(day, 3737)
    assert as_info.asn == 3737
    assert as_info.as_cc == "US"
    assert as_info.as_org_name == "PenTeleData Inc."

    as_info = netinfodb.lookup_asn(day, 35612)
    assert as_info.asn == 35612
    assert as_info.as_cc == "IT"
    assert as_info.as_org_name == "EOLO S.p.A."

    as_info = netinfodb.lookup_asn(day, 15169)
    assert as_info.asn == 15169
    assert as_info.as_cc == "US"
    assert as_info.as_org_name == "Google LLC"

    as_info = netinfodb.lookup_ip(day, "172.253.255.34")
    assert as_info.as_info.asn == 15169
    assert as_info.as_info.as_cc == "US"
    assert as_info.as_info.as_org_name == "Google LLC"
    assert as_info.cc == "CA"
