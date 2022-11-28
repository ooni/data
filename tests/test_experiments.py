from base64 import b64decode
from datetime import datetime
from unittest.mock import MagicMock
from oonidata.dataformat import (
    WebConnectivity,
    load_measurement,
    Signal,
    SIGNAL_PEM_STORE,
)
from oonidata.datautils import validate_cert_chain
from oonidata.experiments.control import (
    iter_ground_truths_from_web_control,
)
from oonidata.experiments.experiment_result import BlockingScope, BlockingStatus
from oonidata.experiments.signal import make_signal_experiment_result
from oonidata.experiments.websites import (
    make_website_experiment_result,
    WebGroundTruthDB,
)
from oonidata.observations import (
    make_signal_observations,
    make_web_control_observations,
    make_web_connectivity_observations,
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
    er = list(
        make_signal_experiment_result(
            web_observations=web_observations,
            fingerprintdb=fingerprintdb,
        )
    )
    assert er[0].anomaly == False
    assert er[0].confirmed == False

    signal_blocked_uz = load_measurement(
        msmt_path=measurements["20210926222047.205897_UZ_signal_95fab4a2e669573f"]
    )
    assert isinstance(signal_blocked_uz, Signal)
    web_observations = make_signal_observations(signal_blocked_uz, netinfodb=netinfodb)[
        0
    ]
    blocking_event = list(
        make_signal_experiment_result(
            web_observations=web_observations,
            fingerprintdb=fingerprintdb,
        )
    )
    assert blocking_event[0].anomaly == True
    assert blocking_event[0].confirmed == False
    tls_be = list(
        filter(
            lambda be: be.blocking_detail.startswith("tls."),
            blocking_event,
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
    blocking_event = list(
        make_signal_experiment_result(
            web_observations=web_observations,
            fingerprintdb=fingerprintdb,
        )
    )
    assert blocking_event[0].anomaly == True
    dns_outcomes = list(
        filter(
            lambda be: be.blocking_detail.startswith("dns."),
            blocking_event,
        )
    )
    assert len(dns_outcomes) > 0
    assert blocking_event[0].confirmed == True


def test_website_dns_blocking_event(fingerprintdb, netinfodb, measurements):
    msmt_path = measurements[
        "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"
    ]
    er = list(make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb))
    be = list(
        filter(
            lambda be: be.blocking_scope == "n",
            er,
        )
    )
    assert len(be) == 1

    msmt_path = measurements[
        "20220627134426.194308_DE_webconnectivity_15675b61ec62e268"
    ]
    er = list(make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb))
    be = list(
        filter(
            lambda be: be.blocking_status == "b",
            er,
        )
    )
    assert len(be) == 1
    assert be[0].blocking_detail == "dns.inconsistent.bogon"

    msmt_path = measurements[
        "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a"
    ]
    er = make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb)
    be = list(
        filter(
            lambda be: be.blocking_status == "b",
            er,
        )
    )
    # TODO: is it reasonable to double count NXDOMAIN for AAAA and A queries?
    assert len(be) == 2
    assert be[0].blocking_detail == "dns.inconsistent.nxdomain"

    msmt_path = measurements[
        "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39"
    ]
    er = list(make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb))
    be = list(
        filter(
            lambda be: be.blocking_status == "k",
            er,
        )
    )
    nok_be = list(
        filter(
            lambda be: be.blocking_status != "k",
            er,
        )
    )
    assert len(be) == len(er)
    assert len(nok_be) == 0


def make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb):
    msmt = load_measurement(msmt_path=msmt_path)
    assert isinstance(msmt, WebConnectivity)
    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]

    assert msmt.test_keys.control
    assert isinstance(msmt.input, str)
    web_ground_truth_db = WebGroundTruthDB()
    web_ground_truth_db.build_from_rows(
        rows=iter_ground_truths_from_web_control(
            web_control_observations=make_web_control_observations(msmt),
            netinfodb=netinfodb,
        ),
    )

    body_db = MagicMock()
    body_db.lookup = MagicMock()
    body_db.lookup.return_value = []

    return make_website_experiment_result(
        web_observations=web_observations,
        web_ground_truth_db=web_ground_truth_db,
        body_db=body_db,
        fingerprintdb=fingerprintdb,
    )


def test_website_experiment_result_blocked(fingerprintdb, netinfodb, measurements):
    experiment_results = list(
        make_experiment_result_from_wc_ctrl(
            measurements["20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"],
            fingerprintdb,
            netinfodb,
        )
    )
    assert len(experiment_results) == 1
    assert experiment_results[0].anomaly == True


def test_website_experiment_result_ok(fingerprintdb, netinfodb, measurements):
    experiment_results = list(
        make_experiment_result_from_wc_ctrl(
            measurements["20220608132401.787399_AM_webconnectivity_2285fc373f62729e"],
            fingerprintdb,
            netinfodb,
        )
    )
    assert len(experiment_results) == 4
    assert experiment_results[0].anomaly == False
    for er in experiment_results:
        assert er.blocking_status == "k"
