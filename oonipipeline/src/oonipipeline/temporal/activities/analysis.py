import dataclasses
from dataclasses import dataclass
import logging
import pathlib

from datetime import date, datetime, timezone
from typing import Dict, List

from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    import clickhouse_driver

    import orjson
    import statsd

    from oonidata.datautils import PerfTimer
    from oonidata.models.analysis import WebAnalysis
    from oonidata.models.experiment_result import MeasurementExperimentResult

    from ...analysis.control import BodyDB, WebGroundTruthDB
    from ...analysis.datasources import iter_web_observations
    from ...analysis.web_analysis import make_web_analysis
    from ...analysis.website_experiment_results import make_website_experiment_results
    from ...db.connections import ClickhouseConnection
    from ...fingerprintdb import FingerprintDB

    from ..common import (
        get_prev_range,
        make_db_rows,
        maybe_delete_prev_range,
        optimize_all_tables,
    )

log = logging.getLogger("oonidata.processing")


@dataclass
class MakeAnalysisParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    fast_fail: bool
    day: str


@activity.defn
def make_analysis_in_a_day(params: MakeAnalysisParams) -> dict:
    t_total = PerfTimer()
    log.info("Optimizing all tables")
    optimize_all_tables(params.clickhouse)
    data_dir = pathlib.Path(params.data_dir)
    clickhouse = params.clickhouse
    day = datetime.strptime(params.day, "%Y-%m-%d").date()
    probe_cc = params.probe_cc
    test_name = params.test_name

    statsd_client = statsd.StatsClient("localhost", 8125)
    fingerprintdb = FingerprintDB(datadir=data_dir, download=False)
    body_db = BodyDB(db=ClickhouseConnection(clickhouse))
    db_writer = ClickhouseConnection(clickhouse, row_buffer_size=10_000)
    db_lookup = ClickhouseConnection(clickhouse)

    column_names_wa = [f.name for f in dataclasses.fields(WebAnalysis)]
    column_names_er = [f.name for f in dataclasses.fields(MeasurementExperimentResult)]

    prev_range_list = [
        get_prev_range(
            db=db_lookup,
            table_name=WebAnalysis.__table_name__,
            timestamp=datetime.combine(day, datetime.min.time()),
            test_name=[],
            probe_cc=probe_cc,
            timestamp_column="measurement_start_time",
        ),
        get_prev_range(
            db=db_lookup,
            table_name=MeasurementExperimentResult.__table_name__,
            timestamp=datetime.combine(day, datetime.min.time()),
            test_name=[],
            probe_cc=probe_cc,
            timestamp_column="timeofday",
            probe_cc_column="location_network_cc",
        ),
    ]

    log.info(f"loading ground truth DB for {day}")
    t = PerfTimer()
    ground_truth_db_path = (
        data_dir / "ground_truths" / f"web-{day.strftime('%Y-%m-%d')}.sqlite3"
    )
    web_ground_truth_db = WebGroundTruthDB()
    web_ground_truth_db.build_from_existing(str(ground_truth_db_path.absolute()))
    statsd_client.timing("oonidata.web_analysis.ground_truth", t.ms)
    log.info(f"loaded ground truth DB for {day} in {t.pretty}")

    idx = 0
    for web_obs in iter_web_observations(
        db_lookup, measurement_day=day, probe_cc=probe_cc, test_name="web_connectivity"
    ):
        try:
            t_er_gen = PerfTimer()
            t = PerfTimer()
            relevant_gts = web_ground_truth_db.lookup_by_web_obs(web_obs=web_obs)
        except:
            log.error(
                f"failed to lookup relevant_gts for {web_obs[0].measurement_uid}",
                exc_info=True,
            )
            continue

        try:
            statsd_client.timing("oonidata.web_analysis.gt_lookup", t.ms)
            website_analysis = list(
                make_web_analysis(
                    web_observations=web_obs,
                    body_db=body_db,
                    web_ground_truths=relevant_gts,
                    fingerprintdb=fingerprintdb,
                )
            )
            log.info(f"generated {len(website_analysis)} website_analysis")
            if len(website_analysis) == 0:
                log.info(f"no website analysis for {probe_cc}, {test_name}")
                continue
            idx += 1
            table_name, rows = make_db_rows(
                dc_list=website_analysis, column_names=column_names_wa
            )
            statsd_client.incr("oonidata.web_analysis.analysis.obs", 1, rate=0.1)  # type: ignore
            statsd_client.gauge("oonidata.web_analysis.analysis.obs_idx", idx, rate=0.1)  # type: ignore
            statsd_client.timing("oonidata.web_analysis.analysis.obs", t_er_gen.ms, rate=0.1)  # type: ignore

            with statsd_client.timer("db_write_rows.timing"):
                db_writer.write_rows(
                    table_name=table_name,
                    rows=rows,
                    column_names=column_names_wa,
                )

            with statsd_client.timer("oonidata.web_analysis.experiment_results.timing"):
                website_er = list(make_website_experiment_results(website_analysis))
                log.info(f"generated {len(website_er)} website_er")
                table_name, rows = make_db_rows(
                    dc_list=website_er,
                    column_names=column_names_er,
                    custom_remap={"loni_list": orjson.dumps},
                )

            db_writer.write_rows(
                table_name=table_name,
                rows=rows,
                column_names=column_names_er,
            )

        except:
            web_obs_ids = ",".join(map(lambda wo: wo.observation_id, web_obs))
            log.error(f"failed to generate analysis for {web_obs_ids}", exc_info=True)

    for prev_range in prev_range_list:
        maybe_delete_prev_range(db=db_lookup, prev_range=prev_range)
    db_writer.close()

    with ClickhouseConnection(clickhouse) as db:
        db.execute(
            "INSERT INTO oonidata_processing_logs (key, timestamp, runtime_ms, bytes, msmt_count, comment) VALUES",
            [
                [
                    "oonidata.analysis.made_day_analysis",
                    datetime.now(timezone.utc).replace(tzinfo=None),
                    int(t_total.ms),
                    0,
                    idx,
                    day.strftime("%Y-%m-%d"),
                ]
            ],
        )
    return {"count": idx}


def make_cc_batches(
    cnt_by_cc: Dict[str, int],
    probe_cc: List[str],
    parallelism: int,
) -> List[List[str]]:
    """
    The goal of this function is to spread the load of each batch of
    measurements by probe_cc. This allows us to parallelize analysis on a
    per-country basis based on the number of measurements.
    We assume that the measurements are uniformly distributed over the tested
    interval and then break them up into a number of batches equivalent to the
    parallelism count based on the number of measurements in each country.

    Here is a concrete example, suppose we have 3 countries IT, IR, US with 300,
    400, 1000 measurements respectively and a parallelism of 2, we will be
    creating 2 batches where the first has in it IT, IR and the second has US.
    """
    if len(probe_cc) > 0:
        selected_ccs_with_cnt = set(probe_cc).intersection(set(cnt_by_cc.keys()))
        if len(selected_ccs_with_cnt) == 0:
            raise Exception(
                f"No observations for {probe_cc} in the time range. Try adjusting the date range or choosing different countries"
            )
        # We remove from the cnt_by_cc all the countries we are not interested in
        cnt_by_cc = {k: cnt_by_cc[k] for k in selected_ccs_with_cnt}

    total_obs_cnt = sum(cnt_by_cc.values())

    # We assume uniform distribution of observations per (country, day)
    max_obs_per_batch = total_obs_cnt / parallelism

    # We break up the countries into batches where the count of observations in
    # each batch is roughly equal.
    # This is done so that we can spread the load based on the countries in
    # addition to the time range.
    cc_batches = []
    current_cc_batch_size = 0
    current_cc_batch = []
    cnt_by_cc_sorted = sorted(cnt_by_cc.items(), key=lambda x: x[0])
    while cnt_by_cc_sorted:
        while current_cc_batch_size <= max_obs_per_batch:
            try:
                cc, cnt = cnt_by_cc_sorted.pop()
            except IndexError:
                break
            current_cc_batch.append(cc)
            current_cc_batch_size += cnt
        cc_batches.append(current_cc_batch)
        current_cc_batch = []
        current_cc_batch_size = 0
    if len(current_cc_batch) > 0:
        cc_batches.append(current_cc_batch)
    return cc_batches


# TODO(art)
# We disable the sanbox for all this workflow, since otherwise pytz fails to
# work which is a requirement for clickhouse.
# This is most likely due to it doing an open() in order to read the timezone
# definitions.
# I spent some time debugging this, but eventually gave up. We should eventually
# look into making this run OK inside of the sandbox.
