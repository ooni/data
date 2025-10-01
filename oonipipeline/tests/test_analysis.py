from base64 import b64decode
from datetime import datetime, timedelta
from pprint import pprint
import random
from typing import List, Tuple
from unittest.mock import MagicMock

from oonipipeline.analysis.web_analysis import (
    get_analysis_web_fuzzy_logic,
)
from oonipipeline.tasks.observations import write_observations_to_db
import pytest

from oonidata.dataclient import load_measurement
from oonidata.models.nettests.signal import Signal
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.observations import (
    WebControlObservation,
    WebObservation,
)
from oonidata.datautils import validate_cert_chain

from oonipipeline.transforms.nettests.signal import SIGNAL_PEM_STORE
from oonipipeline.transforms.observations import measurement_to_observations


# @pytest.mark.skip(reason="TODO(art): fixme")
# def test_signal(fingerprintdb, netinfodb, measurements):
#     signal_old_ca = load_measurement(
#         msmt_path=measurements["20221016235944.266268_GB_signal_1265ff650ee17b44"]
#     )
#     assert isinstance(signal_old_ca, Signal)
#     assert signal_old_ca.test_keys.tls_handshakes

#     for tls_handshake in signal_old_ca.test_keys.tls_handshakes:
#         assert tls_handshake.peer_certificates
#         assert tls_handshake.server_name
#         certificate_chain = list(
#             map(lambda c: b64decode(c.data), tls_handshake.peer_certificates)
#         )
#         validate_cert_chain(
#             datetime(2021, 10, 16),
#             certificate_chain=certificate_chain,
#             pem_cert_store=SIGNAL_PEM_STORE,
#         )

#     signal_new_ca = load_measurement(
#         msmt_path=measurements["20221020235950.432819_NL_signal_27b05458f186a906"]
#     )
#     assert isinstance(signal_new_ca, Signal)
#     assert signal_new_ca.test_keys.tls_handshakes

#     for tls_handshake in signal_new_ca.test_keys.tls_handshakes:
#         assert tls_handshake.peer_certificates
#         assert tls_handshake.server_name
#         certificate_chain = list(
#             map(lambda c: b64decode(c.data), tls_handshake.peer_certificates)
#         )
#         validate_cert_chain(
#             datetime(2022, 10, 20),
#             certificate_chain=certificate_chain,
#             pem_cert_store=SIGNAL_PEM_STORE,
#         )

#     web_observations = measurement_to_observations(signal_new_ca, netinfodb=netinfodb)[
#         0
#     ]
#     er = list(
#         make_signal_experiment_result(
#             web_observations=web_observations,
#             fingerprintdb=fingerprintdb,
#         )
#     )
#     assert er[0].anomaly == False
#     assert er[0].confirmed == False

#     signal_blocked_uz = load_measurement(
#         msmt_path=measurements["20210926222047.205897_UZ_signal_95fab4a2e669573f"]
#     )
#     assert isinstance(signal_blocked_uz, Signal)
#     web_observations = measurement_to_observations(
#         signal_blocked_uz, netinfodb=netinfodb
#     )[0]
#     blocking_event = list(
#         make_signal_experiment_result(
#             web_observations=web_observations,
#             fingerprintdb=fingerprintdb,
#         )
#     )
#     assert blocking_event[0].anomaly == True
#     assert blocking_event[0].confirmed == False
#     tls_be = list(
#         filter(
#             lambda be: be.outcome_category == "tls",
#             blocking_event,
#         )
#     )
#     assert len(tls_be) > 0

#     signal_blocked_ir = load_measurement(
#         msmt_path=measurements["20221018174612.488229_IR_signal_f8640b28061bec06"]
#     )
#     assert isinstance(signal_blocked_ir, Signal)
#     web_observations = measurement_to_observations(
#         signal_blocked_ir, netinfodb=netinfodb
#     )[0]
#     blocking_event = list(
#         make_signal_experiment_result(
#             web_observations=web_observations,
#             fingerprintdb=fingerprintdb,
#         )
#     )
#     assert blocking_event[0].anomaly == True
#     dns_outcomes = list(
#         filter(
#             lambda be: be.outcome_category == "dns",
#             blocking_event,
#         )
#     )
#     assert len(dns_outcomes) > 0
#     assert blocking_event[0].confirmed == True


def perform_analysis(
    db,
    netinfodb,
    measurements,
    measurement_uid: str,
):
    msmt = load_measurement(msmt_path=measurements[measurement_uid])
    ts = datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
    write_observations_to_db(
        db=db,
        netinfodb=netinfodb,
        msmt=msmt,
        bucket_date="1984-01-01",
    )
    db.flush()
    analysis_list = list(
        get_analysis_web_fuzzy_logic(
            db=db,
            start_time=ts - timedelta(days=1),
            end_time=ts + timedelta(days=1),
            probe_cc=[],
            measurement_uid=measurement_uid,
        )
    )
    assert len(analysis_list) == 1
    return analysis_list[0]


def test_website_web_analysis_blocked(db, netinfodb, measurements):
    measurement_uid = "20221110235922.335062_IR_webconnectivity_e4114ee32b8dbf74"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] > 0.9


def test_website_web_analysis_plaintext_ok(db, netinfodb, measurements):
    measurement_uid = "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] < 0.2
    assert analysis["tcp_blocked"] < 0.2
    assert analysis["tls_blocked"] < 0.2
    # assert analysis["http_blocked"] < 0.5
    assert analysis["dns_ok"] > 0.8
    assert analysis["tcp_ok"] > 0.8


def test_website_web_analysis_blocked_2(db, netinfodb, measurements):
    measurement_uid = "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] > 0.8
    assert analysis["dns_ok"] < 0.2


def test_website_dns_blocking_event(db, netinfodb, measurements):
    measurement_uid = "20220627134426.194308_DE_webconnectivity_15675b61ec62e268"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] > 0.8
    assert analysis["dns_ok"] < 0.2


def test_website_dns_blocking_event_2(db, netinfodb, measurements):
    measurement_uid = "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] > 0.6
    assert analysis["dns_ok"] < 0.4


def test_website_dns_ok(db, netinfodb, measurements):
    measurement_uid = "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_ok"] == 1.0
    assert analysis["tcp_ok"] == 1.0
    assert analysis["tls_ok"] == 1.0


# # Check this for wc 0.5 overwriting tls analsysis
# # 20231031000227.813597_MY_webconnectivity_2f0b80761373aa7e
def test_website_experiment_results(measurements, netinfodb, db):
    measurement_uid = "20221101055235.141387_RU_webconnectivity_046ce024dd76b564"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] < 0.5
    assert analysis["tcp_blocked"] > 0.6
    assert analysis["top_tcp_failure"] == "generic_timeout_error"
    assert analysis["tls_blocked"] == 0.0


def test_website_web_analysis_down(measurements, netinfodb, db):
    measurement_uid = "20240420235427.477327_US_webconnectivity_9b3cac038dc2ba22"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] < 0.5
    assert analysis["tcp_down"] > 0.6
    assert analysis["top_tcp_failure"] == "generic_timeout_error"
    assert analysis["tls_blocked"] == 0.0


def test_website_web_analysis_blocked_connect_reset(measurements, netinfodb, db):
    measurement_uid = "20240302000048.790188_RU_webconnectivity_e7ffd3bc0f525eb7"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] < 0.5
    assert analysis["tcp_blocked"] < 0.5
    assert analysis["tls_blocked"] > 0.7
    assert analysis["top_tls_failure"] == "connection_reset"


def test_website_web_analysis_nxdomain_down(measurements, netinfodb, db):
    measurement_uid = "20240302000050.000654_SN_webconnectivity_fe4221088fbdcb0a"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_down"] > 0.6
    assert analysis["top_dns_failure"] == "dns_nxdomain_error"


def test_website_web_analysis_nxdomain_blocked(measurements, netinfodb, db):
    measurement_uid = "20240302000305.316064_EG_webconnectivity_397bca9091b07444"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked"] > 0.6
    assert analysis["top_dns_failure"] == "dns_nxdomain_error"


def test_website_web_analysis_blocked_inconsistent_country(measurements, netinfodb, db):
    measurement_uid = "20240309112858.009725_SE_webconnectivity_dce757ef4ec9b6c8"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_ok"] < 0.3
    assert analysis["dns_blocked"] > 0.5
    assert analysis["top_dns_failure"] == None
