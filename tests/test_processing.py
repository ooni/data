from oonidata.apiclient import get_raw_measurement
from oonidata.dataformat import load_measurement
from oonidata.observations import make_http_observations
from oonidata.processing import make_observation_row

from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB


def test_insert_query_for_observation():

    fingerprintdb = FingerprintDB()
    netinfodb = NetinfoDB()

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

    assert all_http_obs.__table_name__ == "obs_http"

    params = make_observation_row(all_http_obs[0])
    print(params)
    assert "timestamp" in params
    assert "__table_name__" not in params

    assert "request_url" in params
