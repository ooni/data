from base64 import b64decode
from datetime import datetime
import random
from typing import List
from unittest.mock import MagicMock

import pytest

from oonidata.dataclient import load_measurement
from oonidata.models.nettests.signal import Signal
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.observations import WebObservation, print_nice, print_nice_vertical
from oonidata.datautils import validate_cert_chain

from oonipipeline.analysis.web_analysis import make_web_analysis
from oonipipeline.analysis.control import (
    BodyDB,
    WebGroundTruth,
    iter_ground_truths_from_web_control,
    WebGroundTruthDB,
)
from oonipipeline.analysis.signal import make_signal_experiment_result
from oonipipeline.transforms.nettests.signal import SIGNAL_PEM_STORE
from oonipipeline.transforms.observations import measurement_to_observations


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

    web_observations = measurement_to_observations(signal_new_ca, netinfodb=netinfodb)[
        0
    ]
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
    web_observations = measurement_to_observations(
        signal_blocked_uz, netinfodb=netinfodb
    )[0]
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
            lambda be: be.outcome_category == "tls",
            blocking_event,
        )
    )
    assert len(tls_be) > 0

    signal_blocked_ir = load_measurement(
        msmt_path=measurements["20221018174612.488229_IR_signal_f8640b28061bec06"]
    )
    assert isinstance(signal_blocked_ir, Signal)
    web_observations = measurement_to_observations(
        signal_blocked_ir, netinfodb=netinfodb
    )[0]
    blocking_event = list(
        make_signal_experiment_result(
            web_observations=web_observations,
            fingerprintdb=fingerprintdb,
        )
    )
    assert blocking_event[0].anomaly == True
    dns_outcomes = list(
        filter(
            lambda be: be.outcome_category == "dns",
            blocking_event,
        )
    )
    assert len(dns_outcomes) > 0
    assert blocking_event[0].confirmed == True


def test_website_dns_blocking_event(fingerprintdb, netinfodb, measurements):
    pytest.skip("TODO(arturo): implement this with the new analysis")
    msmt_path = measurements[
        "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"
    ]
    er = list(make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb))
    be = list(
        filter(
            lambda be: be.outcome_scope == "n",
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
            lambda be: be.blocked_score > 0.5,
            er,
        )
    )
    assert len(be) == 1
    assert be[0].outcome_detail == "inconsistent.bogon"

    msmt_path = measurements[
        "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a"
    ]
    er = make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb)
    be = list(
        filter(
            lambda be: be.blocked_score > 0.6,
            er,
        )
    )
    # TODO: is it reasonable to double count NXDOMAIN for AAAA and A queries?
    assert len(be) == 2
    assert be[0].outcome_detail == "inconsistent.nxdomain"

    msmt_path = measurements[
        "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39"
    ]
    er = list(make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb))
    be = list(
        filter(
            lambda be: be.ok_score > 0.5,
            er,
        )
    )
    nok_be = list(
        filter(
            lambda be: be.ok_score < 0.5,
            er,
        )
    )
    assert len(be) == len(er)
    assert len(nok_be) == 0


def make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb):
    msmt = load_measurement(msmt_path=msmt_path)
    assert isinstance(msmt, WebConnectivity)
    _, web_control_observations = measurement_to_observations(msmt, netinfodb=netinfodb)

    assert msmt.test_keys.control
    assert isinstance(msmt.input, str)
    web_ground_truth_db = WebGroundTruthDB()
    web_ground_truth_db.build_from_rows(
        rows=iter_ground_truths_from_web_control(
            web_control_observations=web_control_observations,
            netinfodb=netinfodb,
        ),
    )

    body_db = MagicMock()
    body_db.lookup = MagicMock()
    body_db.lookup.return_value = []

    return []


def test_website_experiment_result_blocked(fingerprintdb, netinfodb, measurements):
    pytest.skip("TODO(arturo): implement this with the new analysis")
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
    pytest.skip("TODO(arturo): implement this with the new analysis")
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
        assert er.ok_score > 0.5


def test_website_web_analysis_blocked(fingerprintdb, netinfodb, measurements, datadir):
    msmt = load_measurement(
        msmt_path=measurements[
            "20221110235922.335062_IR_webconnectivity_e4114ee32b8dbf74"
        ],
    )
    web_obs: List[WebObservation] = measurement_to_observations(
        msmt, netinfodb=netinfodb
    )[0]
    FASTLY_IPS = [
        "151.101.1.140",
        "151.101.129.140",
        "151.101.193.140",
        "151.101.65.140",
        "199.232.253.140",
        "2a04:4e42:400::396",
        "2a04:4e42::396",
        "2a04:4e42:fd3::396",
    ]
    # Equivalent to the following call, but done manually
    # relevant_gts = web_ground_truth_db.lookup_by_web_obs(web_obs=web_obs)
    relevant_gts = []
    for is_trusted in [True, False]:
        for ip in FASTLY_IPS:
            relevant_gts.append(
                WebGroundTruth(
                    vp_asn=0,
                    vp_cc="ZZ",
                    # TODO FIXME in lookup
                    is_trusted_vp=is_trusted,
                    hostname="www.reddit.com",
                    ip=ip,
                    # TODO FIXME in webgroundtruth lookup
                    port=443,
                    dns_failure=None,
                    # TODO fixme in lookup
                    dns_success=True,
                    tcp_failure=None,
                    # TODO fixme in lookup
                    tcp_success=True,
                    tls_failure=None,
                    tls_success=True,
                    tls_is_certificate_valid=True,
                    http_request_url=None,
                    http_failure=None,
                    http_success=None,
                    # FIXME in lookup function "ZZ",
                    http_response_body_length=131072 - random.randint(0, 100),
                    # TODO FIXME in lookup function
                    timestamp=datetime(
                        2022,
                        11,
                        10,
                        0,
                        0,
                    ),
                    count=2,
                    ip_asn=54113,
                    # TODO FIXME in lookup function
                    ip_as_org_name="Fastly, Inc.",
                ),
            )
    # XXX currently not working
    body_db = BodyDB(db=None)  # type: ignore

    web_analysis = list(
        make_web_analysis(
            web_observations=web_obs,
            body_db=body_db,
            web_ground_truths=relevant_gts,
            fingerprintdb=fingerprintdb,
        )
    )
    assert len(web_analysis) == len(web_obs)
    # for wa in web_analysis:
    #    print(wa.measurement_uid)
    #    print_nice_vertical(wa)
