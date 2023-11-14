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
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
)

log = logging.getLogger("oonidata.processing")


def make_analysis_in_a_day(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: str,
    data_dir: pathlib.Path,
    rebuild_ground_truths: bool,
    fast_fail: bool,
    day: date,
):
    statsd_client = statsd.StatsClient("localhost", 8125)
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    fingerprintdb = FingerprintDB(datadir=data_dir, download=False)
    body_db = BodyDB(db=ClickhouseConnection(clickhouse))
    db_lookup = ClickhouseConnection(clickhouse)
    db_writer = ClickhouseConnection(clickhouse, row_buffer_size=10_000)
    maybe_build_web_ground_truth(
        db=db_lookup,
        netinfodb=netinfodb,
        day=day,
        data_dir=data_dir,
        rebuild_ground_truths=rebuild_ground_truths,
    )
    db_lookup.close()

    column_names = [f.name for f in dataclasses.fields(WebAnalysis)]
    db_lookup = ClickhouseConnection(clickhouse)

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
    dask_client = DaskClient(
        threads_per_worker=2,
        n_workers=parallelism,
    )

    future_list = []
    for day in date_interval(start_day, end_day):
        t = dask_client.submit(
            make_analysis_in_a_day,
            probe_cc,
            test_name,
            clickhouse,
            data_dir,
            rebuild_ground_truths,
            fast_fail,
            day,
        )
        future_list.append(t)
    log.debug("starting progress monitoring")
    dask_progress(future_list)
    log.debug("waiting on task_list")
    dask_wait(future_list)
    total_count = 0
    for _, result in as_completed(future_list, with_results=True):
        total_count += result  # type: ignore

    log.info(f"produces a total of {total_count} analysis")
