from unittest.mock import MagicMock

from oonidata.apiclient import get_measurement_dict
from oonidata.dataformat import load_measurement
from oonidata.observations import make_http_observations
from oonidata.processing import make_observation_row, web_connectivity_processor


def test_insert_query_for_observation(fingerprintdb, netinfodb, measurements):

    http_blocked = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
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


def test_web_connectivity_processor(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220627131742.081225_GB_webconnectivity_e1e2cf4db492b748"
        ]
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
