from pprint import pprint

from oonidata.models.observations import print_nice, print_nice_vertical
from oonidata.dataclient import load_measurement

from oonipipeline.analysis.control import (
    BodyDB,
    WebGroundTruthDB,
    iter_ground_truths_from_web_control,
)
from oonipipeline.analysis.web_analysis import make_web_analysis
from oonipipeline.analysis.website_experiment_results import (
    make_website_experiment_results,
)
from oonipipeline.transforms.observations import measurement_to_observations


# Check this for wc 0.5 overwriting tls analsysis
# 20231031000227.813597_MY_webconnectivity_2f0b80761373aa7e
def test_website_experiment_results(measurements, netinfodb, fingerprintdb):
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

    web_ground_truths = web_ground_truth_db.lookup_by_web_obs(web_obs=web_observations)
    web_analysis = list(
        make_web_analysis(
            web_observations=web_observations,
            web_ground_truths=web_ground_truths,
            body_db=BodyDB(db=None),  # type: ignore
            fingerprintdb=fingerprintdb,
        )
    )

    # TODO(arturo): there is currently an edge case here which is when we get an
    # IPv6 answer, since we are ignoring them in the analysis, we will have N
    # less analysis where N is the number of IPv6 addresses.
    assert len(web_analysis) == len(web_observations)
    # for wa in web_analysis:
    #    print_nice_vertical(wa)

    website_er = list(make_website_experiment_results(web_analysis))
    assert len(website_er) == 1

    wer = website_er[0]
    analysis_transcript_list = wer.analysis_transcript_list

    assert (
        sum(wer.loni_blocked_values) + sum(wer.loni_down_values) + wer.loni_ok_value
        == 1
    )
    assert wer.anomaly == True

    # wer.analysis_transcript_list = None
    # print_nice_vertical(wer)
    # for loni in wer.loni_list:
    #    pprint(loni.to_dict())
    # print(analysis_transcript_list)
