import queue
import pathlib
import logging

import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass

from threading import Thread
from datetime import date
from oonidata.dataclient import date_interval

from oonidata.datautils import PerfTimer
from oonidata.analysis.control import (
    WebGroundTruthDB,
    iter_web_ground_truths,
)
from oonidata.netinfo import NetinfoDB

from oonidata.db.connections import (
    ClickhouseConnection,
)
from oonidata.workers.common import run_progress_thread

log = logging.getLogger("oonidata.processing")


def maybe_build_web_ground_truth(
    db: ClickhouseConnection,
    netinfodb: NetinfoDB,
    day: date,
    data_dir: pathlib.Path,
    rebuild_ground_truths: bool = False,
):
    ground_truth_dir = data_dir / "ground_truths"
    ground_truth_dir.mkdir(exist_ok=True)
    dst_path = ground_truth_dir / f"web-{day.strftime('%Y-%m-%d')}.sqlite3"
    if not dst_path.exists() or rebuild_ground_truths != False:
        if dst_path.exists():
            dst_path.unlink()

        t = PerfTimer()
        log.info(f"building ground truth DB for {day}")
        web_ground_truth_db = WebGroundTruthDB(connect_str=str(dst_path.absolute()))
        web_ground_truth_db.build_from_rows(
            rows=iter_web_ground_truths(db=db, measurement_day=day, netinfodb=netinfodb)
        )
        log.info(f"built ground truth DB {day} in {t.pretty}")


class GroundTrutherWorker(mp.Process):
    def __init__(
        self,
        day_queue: mp.JoinableQueue,
        progress_queue: mp.Queue,
        clickhouse: str,
        shutdown_event: EventClass,
        data_dir: pathlib.Path,
        log_level: int = logging.INFO,
    ):
        super().__init__(daemon=True)
        self.day_queue = day_queue
        self.progress_queue = progress_queue
        self.data_dir = data_dir
        self.clickhouse = clickhouse

        self.shutdown_event = shutdown_event
        log.setLevel(log_level)

    def run(self):
        db = ClickhouseConnection(self.clickhouse)
        netinfodb = NetinfoDB(datadir=self.data_dir, download=False)

        while not self.shutdown_event.is_set():
            try:
                day = self.day_queue.get(block=True, timeout=0.1)
            except queue.Empty:
                continue

            try:
                maybe_build_web_ground_truth(
                    db=db,
                    netinfodb=netinfodb,
                    day=day,
                    data_dir=self.data_dir,
                    rebuild_ground_truths=True,
                )
            except:
                log.error(f"failed to build ground truth for {day}", exc_info=True)

            finally:
                self.day_queue.task_done()
                self.progress_queue.put(1)


def start_ground_truth_builder(
    start_day: date,
    end_day: date,
    clickhouse: str,
    data_dir: pathlib.Path,
    parallelism: int,
    log_level: int = logging.INFO,
):
    # Use spawn to avoid race condition that leads to deadlocks on unix
    # See: https://bugs.python.org/issue6721
    mp.set_start_method("spawn")

    shutdown_event = mp.Event()
    worker_shutdown_event = mp.Event()

    progress_queue = mp.JoinableQueue()

    progress_thread = Thread(
        target=run_progress_thread,
        args=(progress_queue, shutdown_event, "generating ground truths"),
    )
    progress_thread.start()

    workers = []
    day_queue = mp.JoinableQueue()
    for _ in range(parallelism):
        worker = GroundTrutherWorker(
            day_queue=day_queue,
            progress_queue=progress_queue,
            shutdown_event=worker_shutdown_event,
            clickhouse=clickhouse,
            data_dir=data_dir,
            log_level=log_level,
        )
        worker.start()
        log.info(f"started worker {worker.pid}")
        workers.append(worker)

    for day in date_interval(start_day, end_day):
        day_queue.put(day)

    log.info("waiting for the day queue to finish")
    day_queue.join()

    log.info(f"sending shutdown signal to workers")
    worker_shutdown_event.set()

    log.info("waiting for progress queue to finish")
    progress_queue.join()

    log.info(f"waiting for ground truth workers to finish running")
    for idx, p in enumerate(workers):
        log.info(f"waiting worker {idx} to join")
        p.join()
        log.info(f"waiting worker {idx} to close")
        p.close()

    log.info("sending shutdown event progress thread")
    shutdown_event.set()
    log.info("waiting on progress queue")
    progress_thread.join()
