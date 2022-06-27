from unittest.mock import MagicMock

from datetime import date

from oonidata.apiclient import get_raw_measurement
from oonidata.dataformat import load_measurement

from oonidata.observations import DNSObservation, make_dns_observations
from oonidata.verdicts import Outcome, make_dns_baseline, make_tcp_baseline_map, make_http_baseline_map
from oonidata.verdicts import make_website_dns_verdict, make_website_tcp_verdicts, make_website_tls_verdict

def baseline_query_mock(q, q_params):
    if "SELECT DISTINCT(ip) FROM obs_tls" in q:
        return [
            ["162.159.137.6"],
            ["162.159.136.6"],
            ["2606:4700:7::a29f:8906"]
        ] 
    if "SELECT DISTINCT(probe_cc, probe_asn, failure) FROM obs_dns" in q:
        return [
            [["IT", 12345, None]],
            [["GB", 789, None]],
            [["FR", 5410, "dns_nxdomain_error"]]
        ]

    if "SELECT probe_cc, probe_asn, request_url, failure FROM obs_http" in q:
        return [
            ["IT", 12345, "https://thepiratebay.org/", ""],
            ["FR", 5410, "https://thepiratebay.org/", "dns_nxdomain_error"],
            ["GB", 789, "https://thepiratebay.org/", ""]
        ]

    if "response_body_sha1" in q:
        return [
            [
                "http://thepiratebay.org/",
                ["1965c4952cc8c082a6307ed67061a57aab6632fa"],
                [134],
                [""],
                [""],
                [301]
            ],
            [
                "http://thepiratebay.org/index.html",
                [""],
                [],
                [""],
                [""],
                [301]
            ],
            [
                "https://thepiratebay.org/index.html",
                ["c2062ae3fb19fa0d9657b1827a80e10c937b4691"],
                [4712],
                [""],
                [""],
                [200]
            ],
            [
                "https://thepiratebay.org/index.html",
                ["cf7a17ad4d1cb7683a1f8592588e5c7b49629cc3"],
                [154],
                [""],
                [""],
                [302]
            ],
        ]

    if "SELECT probe_cc, probe_asn, ip, port, failure FROM obs_tcp" in q:
        return [
            ["IT", 12345, "162.159.137.6", 443, ""],
            ["FR", 5410, "162.159.137.6", 443, ""],
            ["GB", 789, "162.159.137.6", 443, ""],
        ]

def make_mock_baselinedb():
    db = MagicMock()
    db.execute = MagicMock()
    db.execute.side_effect = baseline_query_mock
    return db

def test_baselines():
    day = date(2022, 1, 1)
    domain_name = "ooni.org"
    db = make_mock_baselinedb()

    dns_baseline = make_dns_baseline(day, domain_name, db)
    assert len(dns_baseline.failure_cc_asn) == 1
    assert len(dns_baseline.ok_cc_asn) == 2
    assert "162.159.137.6" in dns_baseline.tls_consistent_answers

    http_baseline_map = make_http_baseline_map(day, domain_name, db)
    assert len(http_baseline_map["https://thepiratebay.org/"].failure_cc_asn) == 1

    tcp_baseline_map = make_tcp_baseline_map(day, domain_name, db)
    len(tcp_baseline_map["162.159.137.6:443"].reachable_cc_asn) == 3

def test_website_dns_verdict(fingerprintdb, netinfodb):
    day = date(2022, 1, 1)
    domain_name = "ooni.org"

    db = make_mock_baselinedb()

    msmt = load_measurement(
        get_raw_measurement(
            "20220626T215355Z_webconnectivity_IR_206065_n1_aoeFoexkL6onyiqN",
            "https://thepiratebay.org/",
        )
    )
    dns_baseline = make_dns_baseline(day, domain_name, db)
    for dns_o in make_dns_observations(msmt, msmt.test_keys.queries, fingerprintdb, netinfodb):
        verdict = make_website_dns_verdict(dns_o, dns_baseline, fingerprintdb, netinfodb)
        assert verdict.outcome == Outcome.BLOCKED
        assert verdict.outcome_detail == "dns.blockpage"

    msmt = load_measurement(
        get_raw_measurement(
            "20220627T134105Z_webconnectivity_DE_3209_n1_OxtDrquootq2Ud5G",
            "https://thepiratebay.org/",
        )
    )
    dns_baseline = make_dns_baseline(day, domain_name, db)
    for dns_o in make_dns_observations(msmt, msmt.test_keys.queries, fingerprintdb, netinfodb):
        verdict = make_website_dns_verdict(dns_o, dns_baseline, fingerprintdb, netinfodb)
        assert verdict.outcome == Outcome.BLOCKED
        assert verdict.outcome_detail == "dns.bogon"


    msmt = load_measurement(
        get_raw_measurement(
            "20220627T125710Z_webconnectivity_FR_5410_n1_KMkIWk9q4gZRq9gS",
            "https://thepiratebay.org/",
        )
    )
    dns_baseline = make_dns_baseline(day, domain_name, db)
    for dns_o in make_dns_observations(msmt, msmt.test_keys.queries, fingerprintdb, netinfodb):
        verdict = make_website_dns_verdict(dns_o, dns_baseline, fingerprintdb, netinfodb)
        assert verdict.outcome == Outcome.BLOCKED
        assert verdict.outcome_detail == "dns.nxdomain"

    msmt = load_measurement(
        get_raw_measurement(
            "20220625T234722Z_webconnectivity_HU_20845_n1_Kg7ARyGpKG58zIZU",
            "https://thepiratebay.org/",
        )
    )
    dns_baseline = make_dns_baseline(day, domain_name, db)
    for dns_o in make_dns_observations(msmt, msmt.test_keys.queries, fingerprintdb, netinfodb):
        verdict = make_website_dns_verdict(dns_o, dns_baseline, fingerprintdb, netinfodb)
        assert verdict is None
        break