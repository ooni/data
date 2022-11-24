from base64 import b64decode
from datetime import date, datetime
from unittest.mock import MagicMock
from oonidata.dataformat import (
    WebConnectivity,
    load_measurement,
    Signal,
    SIGNAL_PEM_STORE,
)
from oonidata.datautils import validate_cert_chain
from oonidata.experiments.control import (
    make_dns_control,
    make_dns_control_from_wc,
    make_http_control_from_wc,
    make_http_control_map,
    make_tcp_control_from_wc,
    make_tcp_control_map,
)
from oonidata.experiments.experiment_result import BlockingType
from oonidata.experiments.signal import make_signal_experiment_result
from oonidata.experiments.websites import (
    make_website_dns_blocking_event,
    make_website_experiment_result,
)
from oonidata.observations import (
    make_signal_observations,
    make_web_connectivity_observations,
    WebObservation,
)


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

    web_observations = make_signal_observations(signal_new_ca, netinfodb=netinfodb)[0]
    er = make_signal_experiment_result(
        web_observations=web_observations,
        fingerprintdb=fingerprintdb,
    )
    assert er.anomaly == False
    assert er.confirmed == False

    signal_blocked_uz = load_measurement(
        msmt_path=measurements["20210926222047.205897_UZ_signal_95fab4a2e669573f"]
    )
    assert isinstance(signal_blocked_uz, Signal)
    web_observations = make_signal_observations(signal_blocked_uz, netinfodb=netinfodb)[
        0
    ]
    blocking_event = make_signal_experiment_result(
        web_observations=web_observations,
        fingerprintdb=fingerprintdb,
    )
    assert blocking_event.anomaly == True
    assert blocking_event.confirmed == False
    tls_be = list(
        filter(
            lambda be: be.blocking_detail.startswith("tls."),
            blocking_event.blocking_events,
        )
    )
    assert len(tls_be) > 0

    signal_blocked_ir = load_measurement(
        msmt_path=measurements["20221018174612.488229_IR_signal_f8640b28061bec06"]
    )
    assert isinstance(signal_blocked_ir, Signal)
    web_observations = make_signal_observations(signal_blocked_ir, netinfodb=netinfodb)[
        0
    ]
    blocking_event = make_signal_experiment_result(
        web_observations=web_observations,
        fingerprintdb=fingerprintdb,
    )
    assert blocking_event.anomaly == True
    dns_outcomes = list(
        filter(
            lambda be: be.blocking_detail.startswith("dns."),
            blocking_event.blocking_events,
        )
    )
    assert len(dns_outcomes) > 0
    assert blocking_event.confirmed == True


def ctrl_query_mock(q, q_params):
    # This pattern of mocking is a bit brittle.
    # TODO: come up with a better way of mocking these things out
    if "SELECT DISTINCT(ip) FROM obs_tls" in q:
        return [["162.159.137.6"], ["162.159.136.6"], ["2606:4700:7::a29f:8906"]]
    if "SELECT probe_cc, probe_asn, failure, answer FROM obs_dns" in q:
        return [
            ["IT", 12345, None, "162.159.137.6"],
            ["GB", 789, None, "162.159.137.6"],
            ["FR", 5410, "dns_nxdomain_error", ""],
        ]

    if "SELECT probe_cc, probe_asn, request_url, failure FROM obs_http" in q:
        return [
            ["IT", 12345, "https://thepiratebay.org/", ""],
            ["FR", 5410, "https://thepiratebay.org/", "dns_nxdomain_error"],
            ["GB", 789, "https://thepiratebay.org/", ""],
        ]

    if "response_body_sha1" in q:
        return [
            [
                "http://thepiratebay.org/",
                ["1965c4952cc8c082a6307ed67061a57aab6632fa"],
                [134],
                [""],
                [""],
                [301],
            ],
            ["http://thepiratebay.org/index.html", [""], [], [""], [""], [301]],
            [
                "https://thepiratebay.org/index.html",
                ["c2062ae3fb19fa0d9657b1827a80e10c937b4691"],
                [4712],
                [""],
                [""],
                [200],
            ],
            [
                "https://thepiratebay.org/index.html",
                ["cf7a17ad4d1cb7683a1f8592588e5c7b49629cc3"],
                [154],
                [""],
                [""],
                [302],
            ],
        ]

    if "SELECT probe_cc, probe_asn, ip, port, failure FROM obs_tcp" in q:
        return [
            ["IT", 12345, "162.159.137.6", 443, ""],
            ["FR", 5410, "162.159.137.6", 443, ""],
            ["GB", 789, "162.159.137.6", 443, ""],
        ]


def make_mock_ctrldb():
    db = MagicMock()
    db.execute = MagicMock()
    db.execute.side_effect = ctrl_query_mock
    return db


def test_controls():
    day = date(2022, 1, 1)
    domain_name = "ooni.org"
    db = make_mock_ctrldb()

    dns_ctrl = make_dns_control(day, domain_name, db)
    assert len(dns_ctrl.failure_cc_asn) == 1
    assert len(dns_ctrl.ok_cc_asn) == 2
    assert "162.159.137.6" in dns_ctrl.tls_consistent_answers

    http_baseline_map = make_http_control_map(day, domain_name, db)
    assert len(http_baseline_map["https://thepiratebay.org/"].failure_cc_asn) == 1

    tcp_baseline_map = make_tcp_control_map(day, domain_name, db)
    assert len(tcp_baseline_map["162.159.137.6:443"].reachable_cc_asn) == 3


def test_website_dns_blocking_event(fingerprintdb, netinfodb, measurements):
    day = date(2022, 1, 1)
    domain_name = "ooni.org"

    db = make_mock_ctrldb()

    msmt = load_measurement(
        msmt_path=measurements[
            "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_ctrl = make_dns_control(day, domain_name, db)

    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]
    for web_o in web_observations:
        if not web_o.dns_answer:
            continue
        blocking_event = make_website_dns_blocking_event(
            web_o, dns_ctrl, fingerprintdb, netinfodb
        )
        assert blocking_event
        assert blocking_event.blocking_type == BlockingType.NATIONAL_BLOCK
        assert blocking_event.blocking_detail == "dns.inconsistent.blockpage"

    msmt = load_measurement(
        msmt_path=measurements[
            "20220627134426.194308_DE_webconnectivity_15675b61ec62e268"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_ctrl = make_dns_control(day, domain_name, db)

    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]
    for web_o in web_observations:
        if not web_o.dns_answer:
            continue
        blocking_event = make_website_dns_blocking_event(
            web_o, dns_ctrl, fingerprintdb, netinfodb
        )
        assert blocking_event
        assert blocking_event.blocking_type == BlockingType.BLOCKED
        assert blocking_event.blocking_detail == "dns.inconsistent.bogon"

    msmt = load_measurement(
        msmt_path=measurements[
            "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_ctrl = make_dns_control(day, domain_name, db)
    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]
    for web_o in web_observations:
        assert isinstance(web_o, WebObservation)
        if not web_o.dns_answer:
            continue
        blocking_event = make_website_dns_blocking_event(
            web_o, dns_ctrl, fingerprintdb, netinfodb
        )
        assert blocking_event
        assert blocking_event.blocking_type == BlockingType.BLOCKED
        assert blocking_event.blocking_detail == "dns.inconsistent.nxdomain"

    msmt = load_measurement(
        msmt_path=measurements[
            "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    dns_ctrl = make_dns_control(day, domain_name, db)
    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]
    for web_o in web_observations:
        if not web_o.dns_answer:
            continue
        blocking_event = make_website_dns_blocking_event(
            web_o, dns_ctrl, fingerprintdb, netinfodb
        )
        assert blocking_event
        assert blocking_event.blocking_type == BlockingType.OK
        break


def make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb):
    msmt = load_measurement(msmt_path=msmt_path)
    assert isinstance(msmt, WebConnectivity)
    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]

    assert msmt.test_keys.control
    assert isinstance(msmt.input, str)
    dns_ctrl = make_dns_control_from_wc(
        msmt_input=msmt.input, control=msmt.test_keys.control
    )
    http_ctrl_map = make_http_control_from_wc(msmt=msmt, control=msmt.test_keys.control)
    tcp_ctrl_map = make_tcp_control_from_wc(control=msmt.test_keys.control)

    return make_website_experiment_result(
        web_observations=web_observations,
        dns_ctrl=dns_ctrl,
        tcp_ctrl_map=tcp_ctrl_map,
        http_ctrl_map=http_ctrl_map,
        fingerprintdb=fingerprintdb,
        netinfodb=netinfodb,
    )


def test_website_experiment_result_blocked(
    fingerprintdb, netinfodb, measurements, benchmark
):
    experiment_result = benchmark(
        make_experiment_result_from_wc_ctrl,
        measurements["20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"],
        fingerprintdb,
        netinfodb,
    )
    assert experiment_result.anomaly == True
    # FIXME this is currently generating two separate blocking events, one for
    # HTTPS and another for DNS. That is because we aren't able to match up the
    # DNS query to the HTTPS requests, leading us to not know if the blocking is
    # happening at the DNS level or not.
    # I'm not even sure if this is a bug tbh, since the measurement data doesn't
    # include enough details to tell which of the two cases it is.
    #
    # assert len(experiment_result.blocking_events) == 1

    assert len(experiment_result.blocking_events) == 2


def test_website_experiment_result_ok(
    fingerprintdb, netinfodb, measurements, benchmark
):
    experiment_result = benchmark(
        make_experiment_result_from_wc_ctrl,
        measurements["20220608132401.787399_AM_webconnectivity_2285fc373f62729e"],
        fingerprintdb,
        netinfodb,
    )
    assert experiment_result.anomaly == False
    for be in experiment_result.blocking_events:
        assert be.blocking_type == BlockingType.OK
    assert len(experiment_result.blocking_events) == 4
