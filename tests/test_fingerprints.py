from oonidata.dataformat import WebConnectivity, load_measurement


def test_fingerprintdb(fingerprintdb, measurements):
    dns_blocked = load_measurement(
        msmt_path=measurements[
            "20220608122138.241075_IR_webconnectivity_c4240e52c7ca025f"
        ]
    )
    assert isinstance(dns_blocked, WebConnectivity)
    assert dns_blocked.test_keys.queries is not None
    assert dns_blocked.test_keys.queries[0].answers is not None

    assert len(fingerprintdb.dns_fp) > 100
    assert len(fingerprintdb.http_fp) > 100
    match = fingerprintdb.match_dns(dns_blocked.test_keys.queries[0].answers[0].ipv4)
    assert "IR" in match.expected_countries

    http_blocked = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    assert isinstance(http_blocked, WebConnectivity)
    assert http_blocked.test_keys.requests
    assert http_blocked.test_keys.requests[0].response

    matches = fingerprintdb.match_http(
        response_body=http_blocked.test_keys.requests[0].response.body_bytes,
        headers=http_blocked.test_keys.requests[0].response.headers_list_str,
    )
    assert len(matches) > 0
    assert any(["RU" in fp.expected_countries for fp in matches])
