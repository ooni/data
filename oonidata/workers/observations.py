import queue
import pathlib
import logging
import traceback
import dataclasses
import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass

from threading import Thread
from base64 import b32decode
from datetime import date, timedelta

from typing import (
    Callable,
    List,
    Optional,
    Union,
)

import statsd
from oonidata.analysis.datasources import load_measurement
from oonidata.datautils import PerfTimer

from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    MeasurementListProgress,
    date_interval,
    iter_measurements,
)
from oonidata.db.connections import (
    ClickhouseConnection,
    CSVConnection,
)
from oonidata.transforms import measurement_to_observations
from oonidata.workers.common import (
    StatusMessage,
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
    run_status_thread,
)

log = logging.getLogger("oonidata.processing")


def make_observation_in_day(
    db: Union[ClickhouseConnection, CSVConnection],
    netinfodb: NetinfoDB,
    day: date,
    test_name=[],
    probe_cc=[],
    fast_fail=False,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
):
    bucket_date = day.strftime("%Y-%m-%d")

    statsd_client = statsd.StatsClient("localhost", 8125)

    prev_ranges = []
    if isinstance(db, ClickhouseConnection):
        for table_name in ["obs_web"]:
            prev_ranges.append(
                (
                    table_name,
                    get_prev_range(
                        db=db,
                        table_name=table_name,
                        bucket_date=bucket_date,
                        test_name=test_name,
                        probe_cc=probe_cc,
                    ),
                )
            )

    for idx, msmt_dict in enumerate(
        iter_measurements(
            probe_cc=probe_cc,
            test_name=test_name,
            start_day=day,
            end_day=day + timedelta(days=1),
            progress_callback=progress_callback,
        )
    ):
        msmt = None
        try:
            t = PerfTimer()
            msmt = load_measurement(msmt_dict)
            for observations in measurement_to_observations(msmt, netinfodb=netinfodb):
                if len(observations) == 0:
                    continue

                column_names = [f.name for f in dataclasses.fields(observations[0])]
                table_name, rows = make_db_rows(
                    bucket_date=bucket_date,
                    dc_list=observations,
                    column_names=column_names,
                )
                db.write_rows(
                    table_name=table_name, rows=rows, column_names=column_names
                )
            statsd_client.timing("make_observations.timed", t.ms)
            statsd_client.incr("make_observations.msmt_count")
        except Exception as exc:
            msmt_str = ""
            if msmt:
                msmt_str = msmt.report_id
                if msmt.input:
                    msmt_str += f"?input={msmt.input}"
            log.error(f"failed at idx: {idx} ({msmt_str})", exc_info=True)

            if fast_fail:
                db.close()
                raise exc

    if len(prev_ranges) > 0 and isinstance(db, ClickhouseConnection):
        for table_name, pr in prev_ranges:
            maybe_delete_prev_range(db=db, prev_range=pr, table_name=table_name)
    db.close()


class ObservationMakerWorker(mp.Process):
    def __init__(
        self,
        status_queue: mp.JoinableQueue,
        day_queue: mp.JoinableQueue,
        shutdown_event: EventClass,
        data_dir: pathlib.Path,
        probe_cc: List[str],
        test_name: List[str],
        clickhouse: Optional[str],
        csv_dir: Optional[pathlib.Path],
        fast_fail: bool,
        process_id: int,
        log_level: int = logging.INFO,
    ):
        super().__init__(daemon=True)
        assert clickhouse or csv_dir, "missing either clickhouse or csv_dir"

        self.day_queue = day_queue
        self.data_dir = data_dir
        self.probe_cc = probe_cc
        self.test_name = test_name
        self.clickhouse = clickhouse
        self.csv_dir = csv_dir
        self.fast_fail = fast_fail
        self.process_id = process_id

        self.shutdown_event = shutdown_event

        self.status_queue = status_queue

        log.setLevel(log_level)

    def run(self):
        current_idx = 0
        day_str = ""

        assert self.clickhouse or self.csv_dir, "missing either clickhouse or csv_dir"

        netinfodb = NetinfoDB(datadir=self.data_dir, download=False)

        db = None
        if self.clickhouse:
            db = ClickhouseConnection(self.clickhouse, row_buffer_size=10_000)
        elif self.csv_dir:
            db = CSVConnection(self.csv_dir)
        assert db

        def progress_callback(p: MeasurementListProgress):
            self.status_queue.put(
                StatusMessage(
                    src="observation_maker",
                    progress=p,
                    idx=current_idx,
                    day_str=day_str,
                )
            )

        while not self.shutdown_event.is_set():
            try:
                day = self.day_queue.get(block=True, timeout=0.1)
            except queue.Empty:
                continue
            try:
                make_observation_in_day(
                    db=db,
                    netinfodb=netinfodb,
                    day=day,
                    test_name=self.test_name,
                    probe_cc=self.probe_cc,
                    fast_fail=self.fast_fail,
                    progress_callback=progress_callback,
                )
            except Exception as exc:
                log.error(f"failed to process {day}", exc_info=True)
                self.status_queue.put(
                    StatusMessage(
                        src="observation_maker",
                        exception=exc,
                        traceback=traceback.format_exc(),
                    )
                )
            finally:
                log.info(f"finished processing day {day_str}")
                self.day_queue.task_done()

        log.info("process is done")
        try:
            db.close()
            log.info("database closed")
        except Exception as exc:
            log.error("failed to flush database", exc_info=True)
            self.status_queue.put(
                StatusMessage(
                    src="observation_maker",
                    exception=exc,
                    traceback=traceback.format_exc(),
                )
            )


def start_observation_maker(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    csv_dir: Optional[pathlib.Path],
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    parallelism: int,
    fast_fail: bool,
    log_level: int = logging.INFO,
):
    shutdown_event = mp.Event()
    worker_shutdown_event = mp.Event()

    status_queue = mp.JoinableQueue()

    status_thread = Thread(
        target=run_status_thread, args=(status_queue, shutdown_event)
    )
    status_thread.start()

    observation_workers = []
    day_queue = mp.JoinableQueue()
    for idx in range(parallelism):
        worker = ObservationMakerWorker(
            status_queue=status_queue,
            day_queue=day_queue,
            shutdown_event=worker_shutdown_event,
            data_dir=data_dir,
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse,
            csv_dir=csv_dir,
            fast_fail=fast_fail,
            log_level=log_level,
            process_id=idx,
        )
        worker.start()
        log.info(f"started worker {worker.pid}")
        observation_workers.append(worker)

    for day in date_interval(start_day, end_day):
        day_queue.put(day)

    log.info("waiting for the day queue to finish")
    day_queue.join()

    # we first need to tell the workers to stop doing their work, so that they
    # flush all their bodies to the archiver thread
    log.info("sending shutdown event")
    worker_shutdown_event.set()
    status_queue.join()

    log.info(f"waiting for observation workers to finish running")
    for idx, p in enumerate(observation_workers):
        log.info(f"waiting observation_maker {idx} to join")
        p.join()
        log.info(f"waiting observation_maker {idx} to close")
        p.close()

    # We are done, we can now tell everybody to go home
    log.info("sending shutdown event")
    shutdown_event.set()

    # Shutdown the status thread
    log.info("shutting down the status thread")
    status_thread.join()
