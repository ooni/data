from unittest.mock import MagicMock

import pytest

from oonidata.models.experiment_result import print_nice_er
from oonidata.dataclient import load_measurement

from oonipipeline.analysis.control import (
    WebGroundTruthDB,
    iter_ground_truths_from_web_control,
)
from oonipipeline.transforms.observations import measurement_to_observations


def test_tcp_scoring(measurements, netinfodb, fingerprintdb):
    pytest.skip("TODO(arturo): implement this with the new analysis")
    msmt = load_measurement(
        msmt_path=measurements[
            "20221101055235.141387_RU_webconnectivity_046ce024dd76b564"
        ]
    )
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
    gt = web_ground_truth_db.lookup(
        probe_cc="RU", probe_asn=8402, ip_ports=[("104.244.42.1", 443)]
    )
    assert len(gt) == 1
    assert gt[0].tcp_success == 1

    body_db = MagicMock()
    body_db.lookup = MagicMock()
    body_db.lookup.return_value = []

    web_ground_truths = web_ground_truth_db.lookup_by_web_obs(web_obs=web_observations)
    assert len(web_ground_truths) == 3
    er = make_website_experiment_result(
        web_observations=web_observations,
        web_ground_truths=web_ground_truths,
        body_db=body_db,
        fingerprintdb=fingerprintdb,
    )
    all_er = list(er)

    tcp_er = list(filter(lambda er: er.outcome_category == "tcp", all_er))
    assert len(tcp_er) == 1
    assert tcp_er[0].blocked_score > 0.6
