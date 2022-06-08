from oonidata.observations import make_http_observations, make_dns_observations
from oonidata.apiclient import get_raw_measurement

from oonidata.dataformat import load_measurement
from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB


def test_http_observations():
    msmt = load_measurement(
        get_raw_measurement(
            "20220608T131504Z_webconnectivity_AM_49800_n1_AqEZWsh35AuSmwMv",
            "http://hahr.am",
        )
    )
    fingerprintdb = FingerprintDB()
    netinfodb = NetinfoDB()

    all_http_obs = [
        obs
        for obs in make_http_observations(
            msmt,
            msmt.test_keys.requests,
            fingerprintdb=fingerprintdb,
            netinfodb=netinfodb,
        )
    ]
    assert len(all_http_obs) == 2
    assert all_http_obs[0].probe_cc == "AM"
    assert all_http_obs[0].probe_asn == 49800
    assert all_http_obs[0].request_url == "https://hahr.am/"

    all_dns_obs = [
        obs
        for obs in make_dns_observations(
            msmt,
            msmt.test_keys.queries,
            fingerprintdb=fingerprintdb,
            netinfodb=netinfodb,
        )
    ]

    assert len(all_dns_obs) == 1
    all_dns_obs[0].answer == "46.19.96.204"

    http_blocked = load_measurement(
        get_raw_measurement(
            "20220608T120927Z_webconnectivity_RU_41668_n1_wuoaKW00hbGU12Yw",
            "http://proxy.org/",
        )
    )
    all_http_obs = [
        obs
        for obs in make_http_observations(
            http_blocked,
            http_blocked.test_keys.requests,
            fingerprintdb=fingerprintdb,
            netinfodb=netinfodb,
        )
    ]
    assert all_http_obs[0].response_matches_blockpage == True
    assert all_http_obs[0].fingerprint_country_consistent == True
