from base64 import b64decode
from datetime import datetime
from oonidata.dataformat import load_measurement, Signal, SIGNAL_PEM_STORE
from oonidata.datautils import validate_cert_chain
from oonidata.blockingevents import make_signal_blocking_event
from oonidata.observations import make_signal_observations, NettestObservation


def test_signal(fingerprintdb, netinfodb, measurements):

    signal_old_ca = load_measurement(
        msmt_path=measurements["20221016235944.266268_GB_signal_1265ff650ee17b44"]
    )
    assert isinstance(signal_old_ca, Signal)
    assert signal_old_ca.test_keys.tls_handshakes

    for tls_handshake in signal_old_ca.test_keys.tls_handshakes:
        assert tls_handshake.peer_certificates
        assert tls_handshake.server_name
        certificate_chain = list(
            map(lambda c: b64decode(c.data), tls_handshake.peer_certificates)
        )
        validate_cert_chain(
            datetime(2021, 10, 16),
            certificate_chain=certificate_chain,
            pem_cert_store=SIGNAL_PEM_STORE,
        )

    signal_new_ca = load_measurement(
        msmt_path=measurements["20221020235950.432819_NL_signal_27b05458f186a906"]
    )
    assert isinstance(signal_new_ca, Signal)
    assert signal_new_ca.test_keys.tls_handshakes

    for tls_handshake in signal_new_ca.test_keys.tls_handshakes:
        assert tls_handshake.peer_certificates
        assert tls_handshake.server_name
        certificate_chain = list(
            map(lambda c: b64decode(c.data), tls_handshake.peer_certificates)
        )
        validate_cert_chain(
            datetime(2022, 10, 20),
            certificate_chain=certificate_chain,
            pem_cert_store=SIGNAL_PEM_STORE,
        )

    nt_obs = NettestObservation.from_measurement(signal_new_ca, netinfodb)
    dns_obs, tcp_obs, tls_obs, http_obs = make_signal_observations(
        signal_new_ca, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    blocking_event = make_signal_blocking_event(
        nt_obs=nt_obs,
        dns_o_list=dns_obs,
        tcp_o_list=tcp_obs,
        tls_o_list=tls_obs,
        http_o_list=http_obs,
        netinfodb=netinfodb,
        fingerprintdb=fingerprintdb,
    )
    print(blocking_event.outcomes)
    assert blocking_event.anomaly == False
    assert blocking_event.confirmed == False

    signal_blocked_uz = load_measurement(
        msmt_path=measurements["20210926222047.205897_UZ_signal_95fab4a2e669573f"]
    )
    assert isinstance(signal_blocked_uz, Signal)
    nt_obs = NettestObservation.from_measurement(signal_blocked_uz, netinfodb)
    dns_obs, tcp_obs, tls_obs, http_obs = make_signal_observations(
        signal_blocked_uz, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    blocking_event = make_signal_blocking_event(
        nt_obs=nt_obs,
        dns_o_list=dns_obs,
        tcp_o_list=tcp_obs,
        tls_o_list=tls_obs,
        http_o_list=http_obs,
        netinfodb=netinfodb,
        fingerprintdb=fingerprintdb,
    )
    assert blocking_event.anomaly == True
    assert blocking_event.confirmed == False
    tls_outcomes = list(
        filter(
            lambda outcome: outcome.outcome_detail.startswith("tls."),
            blocking_event.outcomes,
        )
    )
    assert len(tls_outcomes) > 0

    signal_blocked_ir = load_measurement(
        msmt_path=measurements["20221018174612.488229_IR_signal_f8640b28061bec06"]
    )
    assert isinstance(signal_blocked_ir, Signal)
    nt_obs = NettestObservation.from_measurement(signal_blocked_ir, netinfodb)
    dns_obs, tcp_obs, tls_obs, http_obs = make_signal_observations(
        signal_blocked_ir, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    blocking_event = make_signal_blocking_event(
        nt_obs=nt_obs,
        dns_o_list=dns_obs,
        tcp_o_list=tcp_obs,
        tls_o_list=tls_obs,
        http_o_list=http_obs,
        netinfodb=netinfodb,
        fingerprintdb=fingerprintdb,
    )
    assert blocking_event.anomaly == True
    dns_outcomes = list(
        filter(
            lambda outcome: outcome.outcome_detail.startswith("dns."),
            blocking_event.outcomes,
        )
    )
    assert len(dns_outcomes) > 0
    assert blocking_event.confirmed == True
