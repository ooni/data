import orjson
from oonidata.apiclient import get_raw_measurement

from oonidata.dataformat import WebConnectivity, load_measurement


def test_fingerprintdb(fingerprintdb):
    dns_blocked = load_measurement(
        orjson.loads(
            get_raw_measurement(
                "20220608T122003Z_webconnectivity_IR_58224_n1_AcrDNmCaHeCbDoNj",
                "https://www.youtube.com/",
            )
        )
    )
    assert isinstance(dns_blocked, WebConnectivity)
    assert dns_blocked.test_keys.queries is not None
    assert dns_blocked.test_keys.queries[0].answers is not None

    assert len(fingerprintdb.dns_fp) > 100
    assert len(fingerprintdb.http_fp) > 100
    match = fingerprintdb.match_dns(dns_blocked.test_keys.queries[0].answers[0].ipv4)
    assert "IR" in match.expected_countries

    http_blocked = load_measurement(
        orjson.loads(
            get_raw_measurement(
                "20220608T120927Z_webconnectivity_RU_41668_n1_wuoaKW00hbGU12Yw",
                "http://proxy.org/",
            )
        )
    )
    assert isinstance(http_blocked, WebConnectivity)
    assert http_blocked.test_keys.requests is not None

    matches = fingerprintdb.match_http(http_blocked.test_keys.requests[0].response)
    assert len(matches) > 0
    assert any(["RU" in fp.expected_countries for fp in matches])
