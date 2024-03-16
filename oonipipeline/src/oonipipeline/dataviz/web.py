from dataclasses import asdict
import json
from pathlib import Path
from oonidata.analysis.control import (
    BodyDB,
    WebGroundTruthDB,
    iter_ground_truths_from_web_control,
)
from oonidata.analysis.datasources import load_measurement
from oonidata.analysis.web_analysis import make_web_analysis
from oonidata.analysis.website_experiment_results import make_website_experiment_results
from oonidata.apiclient import get_measurement_dict_by_uid
from oonidata.dataviz.viz import (
    plot_blocking_world_map,
    plot_blocking_of_domain_in_asn,
    plot_blocking_of_domain_by_asn,
)
from oonidata.dataviz.viz import (
    get_df_blocking_world_map,
    get_df_blocking_of_domain_in_asn,
    get_df_blocking_of_domain_by_asn,
    get_df_dns_analysis,
    get_df_dns_analysis_raw,
)
from flask import Flask, request, render_template
from oonipipeline.src.oonipipeline.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB

from oonidata.transforms import measurement_to_observations

app = Flask(__name__)


def to_pretty_json(value):
    return json.dumps(
        value, sort_keys=True, indent=4, separators=(",", ": "), default=str
    )


app.jinja_env.filters["tojson_pretty"] = to_pretty_json


@app.route("/analysis/m/<measurement_uid>")
def analysis_by_msmt(measurement_uid):
    data_dir = Path("tests/data/datadir/")

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

    return render_template(
        "analysis.html",
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
    )


@app.route("/api/_/viz/data/world_map")
def data_world_map():
    blocking_threshold = float(request.args.get("blocking_threshold", 0.7))
    return get_df_blocking_world_map(blocking_threshold=blocking_threshold).to_json(
        orient="records"
    )


@app.route("/api/_/viz/chart/world_map")
def chart_world_map():
    return plot_blocking_world_map(data_name="data").to_json()


@app.route("/viz/world_map")
def viz_world_map():
    return render_template("vega.html", endpoint="chart_world_map")


@app.route("/api/_/viz/data/blocking_of_domain_in_asn")
def data_blocking_of_domain_in_asn():
    return get_df_blocking_of_domain_in_asn(
        domain_name=request.args.get("domain_name", None),
        probe_cc=request.args.get("probe_cc", None),
        probe_asn=int(request.args.get("probe_asn", 0)),
        start_time=request.args.get("start_time", "2022-11-03"),
        end_time=request.args.get("start_time", "2022-12-03"),
    ).to_json(orient="records")


@app.route("/api/_/viz/chart/blocking_of_domain_in_asn")
def chart_blocking_of_domain_in_asn():
    return plot_blocking_of_domain_in_asn(
        domain_name=request.args.get("domain_name", None),
        probe_cc=request.args.get("probe_cc", None),
        probe_asn=int(request.args.get("probe_asn", 0)),
        start_time=request.args.get("start_time", "2022-11-03"),
        end_time=request.args.get("start_time", "2022-12-03"),
    ).to_json()


@app.route("/viz/blocking_of_domain_in_asn")
def viz_blocking_of_domain_in_asn():
    return render_template(
        "vega.html",
        endpoint="chart_blocking_of_domain_in_asn",
        query_args=request.args.to_dict(),
    )


@app.route("/api/_/viz/chart/blocking_of_domain_by_asn")
def chart_blocking_of_domain_by_asn():
    return plot_blocking_of_domain_by_asn(
        domain_name=request.args.get("domain_name", None),
        probe_cc=request.args.get("probe_cc", None),
        start_time=request.args.get("start_time", "2022-11-03"),
        end_time=request.args.get("start_time", "2022-12-03"),
    ).to_json()


@app.route("/viz/blocking_of_domain_by_asn")
def viz_blocking_of_domain_by_asn():
    return render_template(
        "vega.html",
        endpoint="chart_blocking_of_domain_by_asn",
        query_args=request.args.to_dict(),
    )


@app.route("/api/_/data/dns_analysis")
def data_dns_analysis():
    return get_df_dns_analysis(
        start_day="2023-01-01", end_day="2023-01-02", limit=100
    ).to_json(orient="records")


@app.route("/api/_/data/dns_analysis_raw")
def data_dns_analysis_raw():
    return get_df_dns_analysis_raw(
        measurement_uid=request.args["measurement_uid"],
        start_day="2023-01-01",
        end_day="2023-01-02",
    ).to_json(orient="records")


@app.route("/")
def index():
    return render_template("react.html")


if __name__ == "__main__":
    app.run(debug=True)
