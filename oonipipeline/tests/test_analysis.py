from base64 import b64decode
from datetime import datetime
from pprint import pprint
import random
from typing import List, Tuple
from unittest.mock import MagicMock

import pytest

from oonidata.dataclient import load_measurement
from oonidata.models.analysis import WebAnalysis
from oonidata.models.experiment_result import MeasurementExperimentResult
from oonidata.models.nettests.signal import Signal
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.observations import (
    WebControlObservation,
    WebObservation,
)
from oonidata.datautils import validate_cert_chain

from oonipipeline.analysis.web_analysis import make_web_analysis
from oonipipeline.analysis.control import (
    BodyDB,
    WebGroundTruth,
    iter_ground_truths_from_web_control,
    WebGroundTruthDB,
)
from oonipipeline.transforms.nettests.signal import SIGNAL_PEM_STORE
from oonipipeline.transforms.observations import measurement_to_observations

from oonipipeline.analysis.signal import make_signal_experiment_result
from oonipipeline.analysis.website_experiment_results import (
    make_website_experiment_results,
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


def make_web_er_from_msmt(msmt, fingerprintdb, netinfodb) -> Tuple[
    List[MeasurementExperimentResult],
    List[WebAnalysis],
    List[WebObservation],
    List[WebControlObservation],
]:
    assert isinstance(msmt, WebConnectivity)
    web_observations, web_control_observations = measurement_to_observations(
        msmt, netinfodb=netinfodb
    )
    assert isinstance(msmt.input, str)
    web_ground_truth_db = WebGroundTruthDB()
    web_ground_truth_db.build_from_rows(
        rows=iter_ground_truths_from_web_control(
            web_control_observations=web_control_observations,
            netinfodb=netinfodb,
        ),
    )

    web_ground_truths = web_ground_truth_db.lookup_by_web_obs(web_obs=web_observations)
    web_analysis = list(
        make_web_analysis(
            web_observations=web_observations,
            web_ground_truths=web_ground_truths,
            body_db=BodyDB(db=None),  # type: ignore
            fingerprintdb=fingerprintdb,
        )
    )

    return (
        list(make_website_experiment_results(web_analysis)),
        web_analysis,
        web_observations,
        web_control_observations,
    )


def test_website_web_analysis_blocked(fingerprintdb, netinfodb, measurements, datadir):
    msmt = load_measurement(
        msmt_path=measurements[
            "20221110235922.335062_IR_webconnectivity_e4114ee32b8dbf74"
        ],
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 5

    assert len(er) == 1
    assert er[0].loni_blocked_values == [1.0]
    assert er[0].loni_ok_value == 0
    assert er[0].loni_blocked_keys[0].startswith("dns.")


def test_website_web_analysis_plaintext_ok(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
        ],
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 2

    assert len(er) == 1
    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["dns"] > 0.8
    assert ok_dict["tcp"] > 0.8
    assert ok_dict["tls"] > 0.8
    assert ok_dict["http"] > 0.8

    assert er[0].loni_ok_value > 0.8


def test_website_web_analysis_blocked_2(fingerprintdb, netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"
        ],
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 6

    assert len(er) == 1
    assert er[0].loni_blocked_values == [1.0]
    assert er[0].loni_ok_value == 0
    assert er[0].loni_blocked_keys[0].startswith("dns.")


def test_website_dns_blocking_event(fingerprintdb, netinfodb, measurements):
    msmt_path = measurements[
        "20220627134426.194308_DE_webconnectivity_15675b61ec62e268"
    ]
    msmt = load_measurement(
        msmt_path=msmt_path,
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 6

    assert len(er) == 1
    assert er[0].loni_ok_value == 0
    assert er[0].loni_blocked_values[0] > 0.7
    assert er[0].loni_blocked_keys[0].startswith("dns.")


def test_website_dns_blocking_event_2(fingerprintdb, netinfodb, measurements):
    msmt_path = measurements[
        "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a"
    ]
    msmt = load_measurement(
        msmt_path=msmt_path,
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 5

    assert len(er) == 1
    assert er[0].loni_ok_value == 0
    assert er[0].loni_blocked_values[0] > 0.5
    assert er[0].loni_blocked_keys[0].startswith("dns.")


def test_website_dns_ok(fingerprintdb, netinfodb, measurements):
    msmt_path = measurements[
        "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39"
    ]
    msmt = load_measurement(
        msmt_path=msmt_path,
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    # assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 5

    assert len(er) == 1
    assert er[0].loni_ok_value == 1


# Check this for wc 0.5 overwriting tls analsysis
# 20231031000227.813597_MY_webconnectivity_2f0b80761373aa7e
def test_website_experiment_results(measurements, netinfodb, fingerprintdb):
    msmt = load_measurement(
        msmt_path=measurements[
            "20221101055235.141387_RU_webconnectivity_046ce024dd76b564"
        ]
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 3

    assert len(er) == 1
    assert er[0].loni_ok_value < 0.2
    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["tcp"] == 0

    blocked_dict = dict(zip(er[0].loni_blocked_keys, er[0].loni_blocked_values))
    assert blocked_dict["tcp.timeout"] > 0.4


def test_website_web_analysis_down(measurements, netinfodb, fingerprintdb):
    msmt = load_measurement(
        msmt_path=measurements[
            "20240420235427.477327_US_webconnectivity_9b3cac038dc2ba22"
        ]
    )
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 3

    assert len(er) == 1
    assert er[0].loni_ok_value < 0.2
    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["tcp"] == 0

    down_dict = dict(zip(er[0].loni_down_keys, er[0].loni_down_values))

    blocked_dict = dict(zip(er[0].loni_blocked_keys, er[0].loni_blocked_values))

    assert sum(down_dict.values()) > sum(blocked_dict.values())
    assert down_dict["tcp.timeout"] > 0.5


def test_website_web_analysis_blocked_connect_reset(
    measurements, netinfodb, fingerprintdb
):
    msmt_path = measurements[
        "20240302000048.790188_RU_webconnectivity_e7ffd3bc0f525eb7"
    ]
    msmt = load_measurement(msmt_path=msmt_path)
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    # assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 4

    assert len(er) == 1
    # TODO(art): this should be changed
    # assert er[0].loni_ok_value == 0
    assert er[0].loni_ok_value < 0.2

    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["tls"] == 0

    down_dict = dict(zip(er[0].loni_down_keys, er[0].loni_down_values))
    blocked_dict = dict(zip(er[0].loni_blocked_keys, er[0].loni_blocked_values))

    assert sum(down_dict.values()) < sum(blocked_dict.values())
    assert blocked_dict["tls.connection_reset"] > 0.5


def print_debug_er(er):
    for idx, e in enumerate(er):
        print(f"\n# ER#{idx}")
        for idx, transcript in enumerate(e.analysis_transcript_list):
            print(f"## Analysis #{idx}")
            print("\n".join(transcript))
        pprint(er)


def test_website_web_analysis_nxdomain_down(measurements, netinfodb, fingerprintdb):
    msmt_path = measurements[
        "20240302000050.000654_SN_webconnectivity_fe4221088fbdcb0a"
    ]
    msmt = load_measurement(msmt_path=msmt_path)
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 2

    assert len(er) == 1
    assert er[0].loni_ok_value < 0.2

    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["dns"] == 0

    down_dict = dict(zip(er[0].loni_down_keys, er[0].loni_down_values))
    blocked_dict = dict(zip(er[0].loni_blocked_keys, er[0].loni_blocked_values))

    assert sum(down_dict.values()) > sum(blocked_dict.values())
    assert down_dict["dns.nxdomain"] > 0.7


def test_website_web_analysis_nxdomain_blocked(measurements, netinfodb, fingerprintdb):
    msmt_path = measurements[
        "20240302000305.316064_EG_webconnectivity_397bca9091b07444"
    ]
    msmt = load_measurement(msmt_path=msmt_path)
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 7

    assert len(er) == 1
    assert er[0].loni_ok_value < 0.2

    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["dns"] == 0

    down_dict = dict(zip(er[0].loni_down_keys, er[0].loni_down_values))
    blocked_dict = dict(zip(er[0].loni_blocked_keys, er[0].loni_blocked_values))

    assert sum(down_dict.values()) < sum(blocked_dict.values())
    assert blocked_dict["dns.nxdomain"] > 0.7


def test_website_web_analysis_blocked_inconsistent_country(
    measurements, netinfodb, fingerprintdb
):
    msmt_path = measurements[
        "20240309112858.009725_SE_webconnectivity_dce757ef4ec9b6c8"
    ]
    msmt = load_measurement(msmt_path=msmt_path)
    er, web_analysis, web_obs, web_ctrl_obs = make_web_er_from_msmt(
        msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
    )
    assert len(web_analysis) == len(web_obs)
    assert len(web_ctrl_obs) == 3

    assert len(er) == 1
    assert er[0].loni_ok_value < 0.2

    ok_dict = dict(zip(er[0].loni_ok_keys, er[0].loni_ok_values))
    assert ok_dict["dns"] == 0

    down_dict = dict(zip(er[0].loni_down_keys, er[0].loni_down_values))
    blocked_dict = dict(zip(er[0].loni_blocked_keys, er[0].loni_blocked_values))

    assert sum(down_dict.values()) > sum(blocked_dict.values())
