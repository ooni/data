from dataclasses import asdict
import json
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.templating import Jinja2Templates

from oonidata.dataclient import load_measurement
from oonidata.apiclient import get_measurement_dict_by_uid
from oonipipeline.dataviz.dependencies import get_settings

from ..analysis.control import (
    BodyDB,
    WebGroundTruthDB,
    iter_ground_truths_from_web_control,
)
from ..analysis.web_analysis import make_web_analysis
from ..analysis.website_experiment_results import make_website_experiment_results

from ..fingerprintdb import FingerprintDB
from ..netinfo import NetinfoDB

from ..transforms.observations import measurement_to_observations

app = FastAPI()

current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=f"{current_dir}/templates")


@app.get("/analysis/m/{measurement_uid}")
def analysis_by_msmt(
    request: Request,
    measurement_uid: str,
    settings=Depends(get_settings),
):
    data_dir = Path(settings.data_dir)

    fingerprintdb = FingerprintDB(datadir=data_dir, download=False)
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    raw_msmt = get_measurement_dict_by_uid(measurement_uid)
    msmt = load_measurement(msmt=raw_msmt)
    web_observations, web_control_observations = measurement_to_observations(
        msmt, netinfodb=netinfodb
    )
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

    # assert len(web_analysis) == len(
    #    web_observations
    # ), f"web_analysis != web_obs {len(web_analysis)} != {len(web_observations)}"
    # for wa in web_analysis:
    #    print_nice_vertical(wa)

    website_er = list(make_website_experiment_results(web_analysis))
    assert len(website_er) == 1

    wer = website_er[0]
    analysis_transcript_list = wer.analysis_transcript_list

    # wer.analysis_transcript_list = None
    # print_nice_vertical(wer)
    # for loni in loni_list:
    #    pprint(loni.to_dict())
    # print(analysis_transcript_list)

    return templates.TemplateResponse(
        request=request,
        name="analysis.html",
        context=dict(
            website_experiment_result=asdict(wer),
            analysis_transcript_list=analysis_transcript_list,
            loni_list=wer.loni_list,
            raw_msmt=raw_msmt,
            measurement_uid=measurement_uid,
            web_analysis=list(map(lambda x: asdict(x), web_analysis)),
            web_observations=list(map(lambda x: asdict(x), web_observations)),
            loni_blocked_dict=dict(zip(wer.loni_blocked_keys, wer.loni_blocked_values)),
            loni_blocked_value=sum(wer.loni_blocked_values),
            loni_down_dict=dict(zip(wer.loni_down_keys, wer.loni_down_values)),
            loni_down_value=sum(wer.loni_down_values),
            loni_ok_value=wer.loni_ok_value,
        ),
    )
