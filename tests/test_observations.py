from oonidata.observations import (
    consume_chained_observations,
    make_http_observations,
    make_dns_observations,
    make_tcp_observations,
    make_tls_observations,
    make_web_connectivity_observations,
    make_ip_to_domain,
)

from oonidata.observations import TCPObservation, TLSObservation, DNSObservation
from oonidata.dataformat import WebConnectivity, load_measurement


def test_wc_v5_observations(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_obs, tcp_obs, tls_obs, http_obs = make_web_connectivity_observations(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert isinstance(tcp_obs[0], TCPObservation)
    assert len(tcp_obs) == 13

    for obs in tls_obs:
        assert isinstance(obs, TLSObservation)
        assert obs.server_name == obs.domain_name
    assert len(tls_obs) == 6

    for obs in dns_obs:
        assert isinstance(obs, DNSObservation)
        assert obs.domain_name == "doh.dns.apple.com"
    assert len(dns_obs) == 3

    assert len(http_obs) == 0


def test_http_observations(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
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
        msmt_path=measurements[
            "20220608155654.044764_AM_webconnectivity_ccb727b4812234a5"
        ]
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

    ip_to_domain = make_ip_to_domain(all_dns_obs)
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
    assert all_tls_obs[0].handshake_time
    assert all_tls_obs[0].handshake_time > 0
    assert all_tls_obs[0].handshake_last_operation
    assert all_tls_obs[0].handshake_last_operation.startswith("write_")
    assert all_tls_obs[0].ip == "172.67.187.120"
    assert all_tls_obs[0].port == 443

    assert all_tls_obs[1].ip == "104.21.32.206"
    assert all_tls_obs[1].port == 443

    http_blocked = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )

    assert isinstance(http_blocked, WebConnectivity)
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


def test_wc_v5_observations_chained(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_obs, tcp_obs, tls_obs, http_obs = make_web_connectivity_observations(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    chained_observations = consume_chained_observations(
        dns_obs, tcp_obs, tls_obs, http_obs
    )
    # TODO: there is something weird here.
    # Both DNS query answers are labeled with
    # transaction_id=2.
    # transaction_id=3 is mapped to one of these two with transaction_id=2, it's
    # unclear to me if that is a bug in the because it's unclear where the TCP
    # transaction with ID 3 got it's data from.

    # XXX commented out, see above comment
    # transaction_ids = list(map(lambda o: o.transaction_id, chained_observations))
    # assert len(transaction_ids) == len(set(transaction_ids))
    assert len(chained_observations) == 15


def test_wc_observations_chained(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_obs, tcp_obs, tls_obs, http_obs = make_web_connectivity_observations(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    chained_observations = consume_chained_observations(
        dns_obs, tcp_obs, tls_obs, http_obs
    )

    # Check if DNS and TCP connect observations are being linked together
    assert (
        len(list(filter(lambda o: o.ip == "188.186.154.79", chained_observations))) == 1
    )
    assert len(chained_observations) == 4

    msmt = load_measurement(
        msmt_path=measurements[
            "20221114002335.786418_BR_webconnectivity_6b203219ec4ded0e"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_obs, tcp_obs, tls_obs, http_obs = make_web_connectivity_observations(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    chained_observations = consume_chained_observations(
        dns_obs, tcp_obs, tls_obs, http_obs
    )

    assert (
        len(list(filter(lambda o: o.ip == "172.67.16.69", chained_observations))) == 1
    )
    assert len(chained_observations) == 4
