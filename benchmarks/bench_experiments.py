from unittest.mock import MagicMock
from oonidata.dataformat import (
    WebConnectivity,
    load_measurement,
)
from oonidata.experiments.control import make_ground_truths_from_web_control
from oonidata.experiments.experiment_result import BlockingType
from oonidata.experiments.websites import (
    make_website_experiment_result,
    WebGroundTruthDB,
)
from oonidata.observations import (
    make_web_control_observations,
    make_web_connectivity_observations,
)


def make_experiment_result_from_wc_ctrl(msmt_path, fingerprintdb, netinfodb):
    msmt = load_measurement(msmt_path=msmt_path)
    assert isinstance(msmt, WebConnectivity)
    web_observations = make_web_connectivity_observations(msmt, netinfodb=netinfodb)[0]

    assert msmt.test_keys.control
    assert isinstance(msmt.input, str)
    web_ground_truth_db = WebGroundTruthDB(
        ground_truths=make_ground_truths_from_web_control(
            make_web_control_observations(msmt)
        )
    )

    body_db = MagicMock()
    body_db.lookup = MagicMock()
    body_db.lookup.return_value = []

    return make_website_experiment_result(
        web_observations=web_observations,
        web_ground_truth_db=web_ground_truth_db,
        body_db=body_db,
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
    assert len(experiment_result.blocking_events) == 1


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
