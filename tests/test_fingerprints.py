from oonidata.apiclient import get_raw_measurement

from oonidata.dataformat import load_measurement
from oonidata.fingerprints.matcher import FingerprintDB


def test_fingerprintdb():
    dns_blocked = load_measurement(
        get_raw_measurement(
            "20220608T122003Z_webconnectivity_IR_58224_n1_AcrDNmCaHeCbDoNj",
            "https://www.youtube.com/",
        )
    )
    fingerprintdb = FingerprintDB()
    assert len(fingerprintdb.dns_fp) > 100
    assert len(fingerprintdb.http_fp) > 100
    match = fingerprintdb.match_dns(dns_blocked.test_keys.queries[0].answers[0].ipv4)
    assert "IR" in match.expected_countries

    http_blocked = load_measurement(
        get_raw_measurement(
            "20220608T120927Z_webconnectivity_RU_41668_n1_wuoaKW00hbGU12Yw",
            "http://proxy.org/",
        )
    )
    matches = fingerprintdb.match_http(http_blocked.test_keys.requests[0].response)
    assert len(matches) > 0
    assert any(["RU" in fp.expected_countries for fp in matches])
