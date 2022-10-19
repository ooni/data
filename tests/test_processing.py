from unittest.mock import MagicMock

from oonidata.apiclient import get_measurement_dict
from oonidata.dataformat import load_measurement
from oonidata.observations import make_http_observations
from oonidata.processing import make_observation_row, web_connectivity_processor


def test_insert_query_for_observation(fingerprintdb, netinfodb):

    http_blocked = load_measurement(
        get_measurement_dict(
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

    assert all_http_obs[0].__table_name__ == "obs_http"

    params = make_observation_row(all_http_obs[0])
    assert "timestamp" in params
    assert "__table_name__" not in params

    assert "request_url" in params


def test_web_connectivity_processor(fingerprintdb, netinfodb):
    msmt = load_measurement(
        get_measurement_dict(
            "20220627T131610Z_webconnectivity_GB_5089_n1_hPwPFmWSlBooLToC",
            "https://ooni.org/",
        )
    )
    db = MagicMock()
    db.write_row = MagicMock()
    web_connectivity_processor(msmt, db, fingerprintdb, netinfodb)
    for call in db.write_row.call_args_list:
        table_name, row = call[0]
        if table_name == "obs_tls":
            assert row["is_certificate_valid"] == True and row["domain_name"]
        if table_name == "obs_dns":
            assert row["is_tls_consistent"] == True
