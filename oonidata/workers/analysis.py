import dataclasses
import logging
import pathlib
from datetime import date, datetime
from typing import List

import statsd

from dask.distributed import Client as DaskClient
from dask.distributed import progress as dask_progress
from dask.distributed import wait as dask_wait
from dask.distributed import as_completed

from oonidata.analysis.control import BodyDB, WebGroundTruthDB
from oonidata.analysis.datasources import iter_web_observations
from oonidata.analysis.web_analysis import make_web_analysis
from oonidata.dataclient import date_interval
from oonidata.datautils import PerfTimer
from oonidata.db.connections import ClickhouseConnection
from oonidata.fingerprintdb import FingerprintDB
from oonidata.models.analysis import WebAnalysis
from oonidata.netinfo import NetinfoDB
from oonidata.workers.ground_truths import maybe_build_web_ground_truth

from .common import (
    get_obs_count_by_cc,
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
)

log = logging.getLogger("oonidata.processing")


def make_ctrl(
    clickhouse: str,
    data_dir: pathlib.Path,
    rebuild_ground_truths: bool,
    day: date,
):
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    db_lookup = ClickhouseConnection(clickhouse)
    maybe_build_web_ground_truth(
        db=db_lookup,
        netinfodb=netinfodb,
        day=day,
        data_dir=data_dir,
        rebuild_ground_truths=rebuild_ground_truths,
    )
    db_lookup.close()


def make_analysis_in_a_day(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: str,
    data_dir: pathlib.Path,
    fast_fail: bool,
    day: date,
):
    statsd_client = statsd.StatsClient("localhost", 8125)
    fingerprintdb = FingerprintDB(datadir=data_dir, download=False)
    body_db = BodyDB(db=ClickhouseConnection(clickhouse))
    db_writer = ClickhouseConnection(clickhouse, row_buffer_size=10_000)
    db_lookup = ClickhouseConnection(clickhouse)

    column_names = [f.name for f in dataclasses.fields(WebAnalysis)]

    prev_range = get_prev_range(
        db=db_lookup,
        table_name=WebAnalysis.__table_name__,
        timestamp=datetime.combine(day, datetime.min.time()),
        test_name=[],
        probe_cc=probe_cc,
        timestamp_column="measurement_start_time",
    )

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
            if len(website_analysis) == 0:
                log.info(f"no website analysis for {probe_cc}, {test_name}")
                continue
            idx += 1
            table_name, rows = make_db_rows(
                dc_list=website_analysis, column_names=column_names
            )
            statsd_client.incr("oonidata.web_analysis.analysis.obs", 1, rate=0.1)  # type: ignore
            statsd_client.gauge("oonidata.web_analysis.analysis.obs_idx", idx, rate=0.1)  # type: ignore
            statsd_client.timing("oonidata.web_analysis.analysis.obs", t_er_gen.ms, rate=0.1)  # type: ignore

            with statsd_client.timer("db_write_rows.timing"):
                db_writer.write_rows(
                    table_name=table_name,
                    rows=rows,
                    column_names=column_names,
                )
        except:
            web_obs_ids = ",".join(map(lambda wo: wo.observation_id, web_obs))
            log.error(f"failed to generate analysis for {web_obs_ids}", exc_info=True)

    maybe_delete_prev_range(
        db=db_lookup, prev_range=prev_range, table_name=WebAnalysis.__table_name__
    )
    return idx


def start_analysis(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    data_dir: pathlib.Path,
    clickhouse: str,
    parallelism: int,
    fast_fail: bool,
    rebuild_ground_truths: bool,
    log_level: int = logging.INFO,
):
    t_total = PerfTimer()
    dask_client = DaskClient(
        threads_per_worker=2,
        n_workers=parallelism,
    )

    t = PerfTimer()
    # TODO: maybe use dask for this too
    log.info("building ground truth databases")
    for day in date_interval(start_day, end_day):
        make_ctrl(
            clickhouse=clickhouse,
            data_dir=data_dir,
            rebuild_ground_truths=rebuild_ground_truths,
            day=day,
        )
    log.info(f"built ground truth db in {t.pretty}")

    with ClickhouseConnection(clickhouse) as db:
        cnt_by_cc = get_obs_count_by_cc(
            db, start_day=start_day, end_day=end_day, test_name=test_name
        )
    if len(probe_cc) > 0:
        selected_ccs_with_cnt = set(probe_cc).intersection(set(cnt_by_cc.keys()))
        if len(selected_ccs_with_cnt) == 0:
            log.error(
                f"No observations for {probe_cc} in the time range {start_day} - {end_day}. Try adjusting the date range or choosing different countries"
            )
            return
        # We remove from the cnt_by_cc all the countries we are not interested in
        cnt_by_cc = {k: cnt_by_cc[k] for k in selected_ccs_with_cnt}

    total_obs_cnt = sum(cnt_by_cc.values())
    total_days = (end_day - start_day).days

    # We assume uniform distribution of observations per (country, day)
    max_obs_per_batch = (total_obs_cnt / total_days) / parallelism

    # We break up the countries into batches where the count of observations in
    # each batch is roughly equal.
    # This is done so that we can spread the load based on the countries in
    # addition to the time range.
    cc_batches = []
    current_cc_batch_size = 0
    current_cc_batch = []
    while cnt_by_cc:
        while current_cc_batch_size <= max_obs_per_batch:
            try:
                cc, cnt = cnt_by_cc.popitem()
            except KeyError:
                break
            current_cc_batch.append(cc)
            current_cc_batch_size += cnt
        cc_batches.append(current_cc_batch)
        current_cc_batch = []
        current_cc_batch_size = 0
    if len(current_cc_batch) > 0:
        cc_batches.append(current_cc_batch)

    log.info(
        f"starting processing of {len(cc_batches)} batches over {total_days} days (parallelism = {parallelism})"
    )
    log.info(f"({cc_batches} from {start_day} to {end_day}")

    future_list = []
    for probe_cc in cc_batches:
        for day in date_interval(start_day, end_day):
            t = dask_client.submit(
                make_analysis_in_a_day,
                probe_cc,
                test_name,
                clickhouse,
                data_dir,
                fast_fail,
                day,
            )
            future_list.append(t)

    log.debug("starting progress monitoring")
    dask_progress(future_list)
    log.debug("waiting on task_list")
    dask_wait(future_list)
    total_obs_count = 0
    for _, result in as_completed(future_list, with_results=True):
        total_obs_count += result  # type: ignore

    log.info(f"produces a total of {total_obs_count} analysis")
    obs_per_sec = round(total_obs_count / t_total.s)
    log.info(f"finished processing {start_day} - {end_day} speed: {obs_per_sec}obs/s)")
    log.info(f"{total_obs_count} msmts in {t_total.pretty}")
