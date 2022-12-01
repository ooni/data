from oonidata.observations import (
    WebObservation,
    make_dnscheck_observations,
    make_http_observations,
    make_dns_observations,
    make_tcp_observations,
    make_tls_observations,
    make_web_connectivity_observations,
)

from oonidata.dataformat import DNSCheck, WebConnectivity, load_measurement


def test_wc_v5_observations(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    web_obs = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]
    assert isinstance(web_obs[0], WebObservation)
    assert len(web_obs) == 15


def test_http_observations(measurements):
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
        )
    ]
    assert len(all_http_obs) == 2
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
        )
    ]

    assert len(all_dns_obs) == 4
    assert all_dns_obs[0].answer == "172.67.187.120"

    all_tcp_obs = [
        obs
        for obs in make_tcp_observations(
            msmt,
            msmt.test_keys.tcp_connect,
        )
    ]
    assert len(all_tcp_obs) == 4

    all_tls_obs = [
        obs
        for obs in make_tls_observations(
            msmt,
            msmt.test_keys.tls_handshakes,
            msmt.test_keys.network_events,
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
        )
    ]
    assert all_http_obs[-1].request_url == "http://proxy.org/"


def test_wc_v5_observations_chained(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    web_obs = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]
    # TODO: there is something weird here.
    # Both DNS query answers are labeled with
    # transaction_id=2.
    # transaction_id=3 is mapped to one of these two with transaction_id=2, it's
    # unclear to me if that is a bug in the because it's unclear where the TCP
    # transaction with ID 3 got it's data from.

    # XXX commented out, see above comment
    # transaction_ids = list(map(lambda o: o.transaction_id, chained_observations))
    # assert len(transaction_ids) == len(set(transaction_ids))
    assert len(web_obs) == 15


# TODO:
# Investigate why this is failing:
# https://explorer.ooni.org/measurement/20221003T005456Z_webconnectivity_IR_44244_n1_efHx49XR5Na6XLQ2?input=https://raw.githubusercontent.com/ooni/spec/master/README.md
def test_wc_observations_chained(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    web_obs = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]

    # Check if DNS and TCP connect observations are being linked together
    assert len(list(filter(lambda o: o.ip == "188.186.154.79", web_obs))) == 1
    assert len(web_obs) == 4

    msmt = load_measurement(
        msmt_path=measurements[
            "20221114002335.786418_BR_webconnectivity_6b203219ec4ded0e"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    web_obs = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]

    assert len(list(filter(lambda o: o.ip == "172.67.16.69", web_obs))) == 1
    assert len(web_obs) == 4


def test_dns_check_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20221013000000.517636_US_dnscheck_bfd6d991e70afa0e"]
    )
    assert isinstance(msmt, DNSCheck)
    web_obs = make_dnscheck_observations(msmt=msmt, netinfodb=netinfodb)[0]
    assert len(web_obs) == 20
