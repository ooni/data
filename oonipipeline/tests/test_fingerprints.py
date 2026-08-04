from oonidata.models.nettests.web_connectivity import WebConnectivity

from oonidata.dataclient import load_measurement

# Pattern types the analysis query can actually evaluate. The DNS fingerprint
# join in analysis/web_analysis.py is an equality match on dns_answer, so it
# implements 'full' and nothing else.
DNS_PATTERN_TYPES_SUPPORTED_BY_ANALYSIS = {"full"}


def test_dns_fingerprints_are_all_evaluable_by_the_analysis_query(fingerprintdb):
    """
    Canary on externally-maintained data.

    The DNS fingerprint set is fetched from ooni/blocking-fingerprints, which we
    do not control. If a 'prefix', 'contains' or 'regexp' pattern is introduced
    there, the analysis query's equality join would silently never match it —
    the blockpage rule would just stop firing for that fingerprint with no
    error. Fail loudly instead, so the query gets taught the new pattern type.
    """
    unsupported = {
        fp.pattern_type
        for fp in fingerprintdb.dns_fp.values()
        if fp.pattern_type not in DNS_PATTERN_TYPES_SUPPORTED_BY_ANALYSIS
    }
    assert not unsupported, (
        f"fingerprints_dns now contains pattern_type(s) {sorted(unsupported)}, "
        "which the equality join in analysis/web_analysis.py cannot evaluate. "
        "Those fingerprints are being silently ignored — extend the join."
    )


def test_expected_countries_parsing_matches_upstream_format(fingerprintdb):
    """
    Upstream documents expected_countries as a comma-separated list ("IT, IR"),
    and the analysis query splits on ',' then trims spaces. Assert the data uses
    that separator and nothing else, so the SQL-side parsing stays valid.

    Note Fingerprint.expected_countries is annotated List[str] but is loaded
    straight from the CSV column, so it is actually a raw str here.
    """
    for fp in fingerprintdb.dns_fp.values():
        raw = fp.expected_countries
        assert isinstance(raw, str)
        if not raw.strip():
            continue
        for cc in raw.split(","):
            cc = cc.strip()
            assert cc.isalpha() and len(cc) == 2, (
                f"{fp.name}: expected_countries {raw!r} does not parse as "
                "comma-separated ISO country codes"
            )


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
