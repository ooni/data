import logging
import multiprocessing as mp
import pathlib
import queue
from datetime import date, datetime
from multiprocessing.synchronize import Event as EventClass
from threading import Thread
from typing import List

import statsd

from oonidata.analysis.control import BodyDB, WebGroundTruthDB
from oonidata.analysis.datasources import iter_web_observations
from oonidata.analysis.websites import make_website_experiment_result
from oonidata.dataclient import date_interval
from oonidata.datautils import PerfTimer
from oonidata.db.connections import ClickhouseConnection
from oonidata.fingerprintdb import FingerprintDB
from oonidata.models.experiment_result import ExperimentResult
from oonidata.netinfo import NetinfoDB
from oonidata.workers.ground_truths import maybe_build_web_ground_truth

from .common import (
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
    run_progress_thread,
)

log = logging.getLogger("oonidata.processing")


def run_experiment_results(
    day: date,
    probe_cc: List[str],
    fingerprintdb: FingerprintDB,
    data_dir: pathlib.Path,
    body_db: BodyDB,
    db_writer: ClickhouseConnection,
    clickhouse: str,
):
    statsd_client = statsd.StatsClient("localhost", 8125)

    column_names = [f for f in ExperimentResult._fields]
    db_lookup = ClickhouseConnection(clickhouse)

    prev_range = get_prev_range(
        db=db_lookup,
        table_name=ExperimentResult.__table_name__,
        timestamp=datetime.combine(day, datetime.min.time()),
        test_name=[],
        probe_cc=probe_cc,
    )

    log.info(f"loading ground truth DB for {day}")
    t = PerfTimer()
    ground_truth_db_path = (
        data_dir / "ground_truths" / f"web-{day.strftime('%Y-%m-%d')}.sqlite3"
    )
    web_ground_truth_db = WebGroundTruthDB()
    web_ground_truth_db.build_from_existing(str(ground_truth_db_path.absolute()))
    statsd_client.timing("wgt_er_all.timed", t.ms)
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
            if statsd_client:
                statsd_client.timing("wgt_er_reduced.timed", t.ms)
            experiment_results = list(
                make_website_experiment_result(
                    web_observations=web_obs,
                    body_db=body_db,
                    web_ground_truths=relevant_gts,
                    fingerprintdb=fingerprintdb,
                )
            )
            idx += 1
            table_name, rows = make_db_rows(
                dc_list=experiment_results, column_names=column_names
            )
            if idx % 100 == 0:
                statsd_client.incr("make_website_er.er_count", count=100)
                statsd_client.gauge("make_website_er.er_gauge", 100, delta=True)
                idx = 0

            statsd_client.timing("make_website_er.timing", t_er_gen.ms)

            with statsd_client.timer("db_write_rows.timing"):
                db_writer.write_rows(
                    table_name=table_name,
                    rows=rows,
                    column_names=column_names,
                )
            yield experiment_results
        except:
            web_obs_ids = ",".join(map(lambda wo: wo.observation_id, web_obs))
            log.error(f"failed to generate er for {web_obs_ids}", exc_info=True)

    maybe_delete_prev_range(
        db=db_lookup, prev_range=prev_range, table_name=ExperimentResult.__table_name__
    )


class ExperimentResultMakerWorker(mp.Process):
    def __init__(
        self,
        day_queue: mp.JoinableQueue,
        progress_queue: mp.Queue,
        shutdown_event: EventClass,
        data_dir: pathlib.Path,
        probe_cc: List[str],
        test_name: List[str],
        clickhouse: str,
        fast_fail: bool,
        log_level: int = logging.INFO,
    ):
        super().__init__(daemon=True)
        self.day_queue = day_queue
        self.progress_queue = progress_queue
        self.probe_cc = probe_cc
        self.test_name = test_name
        self.clickhouse = clickhouse
        self.fast_fail = fast_fail
        self.data_dir = data_dir

        self.shutdown_event = shutdown_event
        log.setLevel(log_level)

    def run(self):

        db_writer = ClickhouseConnection(self.clickhouse, row_buffer_size=10_000)
        fingerprintdb = FingerprintDB(datadir=self.data_dir, download=False)

        body_db = BodyDB(db=ClickhouseConnection(self.clickhouse))

        while not self.shutdown_event.is_set():
            try:
                day = self.day_queue.get(block=True, timeout=0.1)
            except queue.Empty:
                continue

            log.info(f"generating experiment results from {day}")
            try:
                for _ in run_experiment_results(
                    day=day,
                    probe_cc=self.probe_cc,
                    fingerprintdb=fingerprintdb,
                    data_dir=self.data_dir,
                    body_db=body_db,
                    db_writer=db_writer,
                    clickhouse=self.clickhouse,
                ):
                    self.progress_queue.put(1)
            except Exception:
                log.error(f"failed to process {day}", exc_info=True)

            finally:
                log.info(f"finished processing day {day}")
                self.day_queue.task_done()

        log.info("process is done")
        try:
            db_writer.close()
        except:
            log.error("failed to flush database", exc_info=True)


def start_experiment_result_maker(
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
    netinfodb = NetinfoDB(datadir=data_dir, download=False)

    shutdown_event = mp.Event()
    worker_shutdown_event = mp.Event()

    progress_queue = mp.JoinableQueue()

    progress_thread = Thread(
        target=run_progress_thread, args=(progress_queue, shutdown_event)
    )
    progress_thread.start()

    workers = []
    day_queue = mp.JoinableQueue()
    for _ in range(parallelism):
        worker = ExperimentResultMakerWorker(
            day_queue=day_queue,
            progress_queue=progress_queue,
            shutdown_event=worker_shutdown_event,
            probe_cc=probe_cc,
            test_name=test_name,
            data_dir=data_dir,
            clickhouse=clickhouse,
            fast_fail=fast_fail,
            log_level=log_level,
        )
        worker.start()
        log.info(f"started worker {worker.pid}")
        workers.append(worker)

    db_lookup = ClickhouseConnection(clickhouse)

    for day in date_interval(start_day, end_day):
        maybe_build_web_ground_truth(
            db=db_lookup,
            netinfodb=netinfodb,
            day=day,
            data_dir=data_dir,
            rebuild_ground_truths=rebuild_ground_truths,
        )
        day_queue.put(day)

    log.info("waiting for the day queue to finish")
    day_queue.join()

    log.info("sending shutdown signal to workers")
    worker_shutdown_event.set()

    log.info("waiting for experiment workers to finish running")
    for idx, p in enumerate(workers):
        log.info(f"waiting worker {idx} to join")
        p.join()
        log.info(f"waiting worker {idx} to close")
        p.close()

    log.info("waiting for progress queue to finish")
    progress_queue.join()
    log.info("sending shutdown event progress thread")
    shutdown_event.set()
    log.info("waiting on progress queue")
    progress_thread.join()
