from oonidata.observations import make_http_observations
from oonidata.apiclient import get_raw_measurement

from oonidata.dataformat import load_measurement, HTTPTransaction
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

    all_obs = [
        obs
        for obs in make_http_observations(
            msmt,
            msmt.test_keys.requests,
            fingerprintdb=fingerprintdb,
            netinfodb=netinfodb,
        )
    ]
    assert len(all_obs) == 2
    assert all_obs[0].probe_cc == "AM"
    assert all_obs[0].probe_asn == 49800
    assert all_obs[0].request_url == "https://hahr.am/"
