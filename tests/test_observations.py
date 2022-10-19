import orjson
from oonidata.observations import (
    make_http_observations,
    make_dns_observations,
    make_tcp_observations,
    make_tls_observations,
)
from oonidata.apiclient import get_measurement_dict

from oonidata.dataformat import WebConnectivity, load_measurement


def test_http_observations(fingerprintdb, netinfodb):
    msmt = load_measurement(
        get_measurement_dict(
            "20220608T131504Z_webconnectivity_AM_49800_n1_AqEZWsh35AuSmwMv",
            "http://hahr.am",
        )
    )
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

    msmt = load_measurement(
        get_measurement_dict(
            "20220608T154458Z_webconnectivity_AM_49800_n1_Xz3UTlXhINnvPC0o",
            "https://aysor.am",
        )
    )
    assert isinstance(msmt, WebConnectivity)
    all_dns_obs = [
        obs
        for obs in make_dns_observations(
            msmt,
            msmt.test_keys.queries,
            fingerprintdb=fingerprintdb,
            netinfodb=netinfodb,
        )
    ]

    assert len(all_dns_obs) == 4
    assert all_dns_obs[0].answer == "172.67.187.120"

    ip_to_domain = {obs.answer: obs.domain_name for obs in all_dns_obs}
    all_tcp_obs = [
        obs
        for obs in make_tcp_observations(
            msmt,
            msmt.test_keys.tcp_connect,
            netinfodb=netinfodb,
            ip_to_domain=ip_to_domain,
        )
    ]
    assert len(all_tcp_obs) == 4

    all_tls_obs = [
        obs
        for obs in make_tls_observations(
            msmt,
            msmt.test_keys.tls_handshakes,
            msmt.test_keys.network_events,
            netinfodb=netinfodb,
            ip_to_domain=ip_to_domain,
        )
    ]
    assert len(all_tls_obs) == 2
    assert all_tls_obs[0].tls_handshake_time > 0
    assert all_tls_obs[0].tls_handshake_last_operation.startswith("write_")
    assert all_tls_obs[0].ip == "172.67.187.120"
    assert all_tls_obs[0].port == 443

    assert all_tls_obs[1].ip == "104.21.32.206"
    assert all_tls_obs[1].port == 443

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
