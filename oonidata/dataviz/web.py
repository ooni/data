from oonidata.dataviz.viz import (
    plot_blocking_world_map,
    plot_blocking_of_domain_in_asn,
    plot_blocking_of_domain_by_asn,
)
from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/api/_/viz/chart/world_map")
def chart_world_map():
    blocking_threshold = float(request.args.get("blocking_threshold", "0.7"))
    return plot_blocking_world_map(blocking_threshold=blocking_threshold).to_json()


@app.route("/viz/world_map")
def viz_world_map():
    return render_template("vega.html", endpoint="chart_world_map")


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


if __name__ == "__main__":
    app.run(debug=True)
