import gzip
import io
import queue
import time
import pathlib
import logging
import sqlite3
import hashlib
import traceback
import http.client
import dataclasses
import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass

from collections import defaultdict
from threading import Lock, Thread
from base64 import b32decode
from datetime import date, datetime, timedelta

from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

import orjson
import msgpack
from tqdm import tqdm
from warcio.warcwriter import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders

from oonidata.fingerprintdb import FingerprintDB, Fingerprint
from oonidata.observations import WebObservation, make_observations
from oonidata.dataformat import (
    WebConnectivity,
    load_measurement,
)
from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    MeasurementListProgress,
    date_interval,
    iter_measurements,
    ProgressStatus,
)
from oonidata.db.connections import (
    DatabaseConnection,
    ClickhouseConnection,
    CSVConnection,
)

log = logging.getLogger("oonidata.processing")


def make_db_rows(
    bucket_date: str, observations: List[WebObservation]
) -> Tuple[str, List[Dict]]:
    if len(observations) == 0:
        return "", []

    table_name = observations[0].__table_name__
    rows = []
    for idx, obs in enumerate(observations):
        obs.bucket_date = bucket_date
        assert table_name == obs.__table_name__, "inconsistent group of observations"
        # TODO: should probably come up with a better ID, but this will work for
        # the time being.
        obs.observation_id = f"{obs.measurement_uid}_{idx}"
        obs.created_at = datetime.utcnow()
        rows.append(dataclasses.asdict(obs))

    return table_name, rows


def write_observations_to_db(
    db: DatabaseConnection, bucket_date: str, observations: List[WebObservation]
) -> None:
    if len(observations) == 0:
        return

    table_name, rows = make_db_rows(bucket_date=bucket_date, observations=observations)
    db.write_rows(table_name, rows)


class BufferredRowWriter:
    def __init__(self, db: DatabaseConnection, buffer_size: int = 10_000):
        self.db = db
        self.buffer_size = buffer_size
        self.row_buffer_map = defaultdict(list)
        self.fields_map = {}

    def write_rows(self, table_name: str, rows: List[Dict[str, Any]]):
        if len(rows) == 0:
            return

        if table_name not in self.fields_map:
            self.fields_map[table_name] = tuple(rows[0].keys())

        for r in rows:
            self.row_buffer_map[table_name].append(
                tuple(r[k] for k in self.fields_map[table_name])
            )

        if len(self.row_buffer_map[table_name]) > self.buffer_size:
            self.flush(table_name)

    def flush_all(self):
        for table_name in self.row_buffer_map.keys():
            self.flush(table_name=table_name)

    def flush(self, table_name):
        rows = self.row_buffer_map[table_name]
        if len(rows) > 0:
            self.db.write_rows(
                table_name=table_name,
                rows=rows,
                fields=self.fields_map[table_name],
            )
            self.row_buffer_map[table_name] = []


class ResponseArchiver:
    def __init__(
        self,
        dst_dir: pathlib.Path,
        max_archive_size=10_000_000,
        machine_id="oonidata",
    ):
        self.dst_dir = dst_dir
        self.machine_id = machine_id
        self.max_archive_size = max_archive_size
        self.start_time = int(time.time())
        self.serial = 0
        self.record_idx = 0

        # Where else would you put your bodies?
        self.db_conn = sqlite3.connect(dst_dir / "graveyard.sqlite3")
        self.maybe_create_table()

        self._fh = None
        self._warc_writer = None
        self._lock = Lock()

    def maybe_create_table(self):
        self.db_conn.execute(
            """CREATE TABLE IF NOT EXISTS oonibodies_archive (
                response_body_sha1 TEXT NOT NULL,
                archive_filename TEXT NOT NULL,
                record_idx INT NOT NULL,
                response_fingerprints TEXT,
                is_fingerprint_false_positive INT
            );"""
        )
        self.db_conn.commit()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def is_already_archived(self, response_body_sha1):
        res = self.db_conn.execute(
            "SELECT response_body_sha1 FROM oonibodies_archive WHERE response_body_sha1 = :response_body_sha1",
            dict(response_body_sha1=response_body_sha1),
        )
        return res.fetchone() is not None

    def archive_http_transaction(
        self,
        status_code: int,
        request_url: str,
        response_headers: List[Tuple[str, bytes]],
        response_body: Optional[bytes],
    ):
        if not response_body:
            return

        response_body_sha1 = hashlib.sha1(response_body).hexdigest()

        if self.is_already_archived(response_body_sha1):
            # No point in archiving empty bodies
            return

        self.maybe_open()

        assert (
            self._warc_writer is not None and self._fh is not None
        ), "you must call open before you can begin archiving"

        self.maybe_open_next_archive()

        status_code = status_code or 0
        status_str = http.client.responses.get(status_code, "Unknown")
        protocol_v = "HTTP/1.1"
        http_headers = StatusAndHeaders(
            f"{status_code} {status_str}",
            response_headers,
            protocol=protocol_v,
        )
        payload = io.BytesIO(response_body)

        record = self._warc_writer.create_warc_record(
            request_url,
            "response",
            http_headers=http_headers,
            payload=payload,
        )
        digest_alg, digest_b32 = record.rec_headers.get_header(
            "WARC-Payload-Digest"
        ).split(":")
        assert digest_alg == "sha1", "using wrong algorithm to create digest"

        # TODO: maybe we can tell warc_writer to not compute the hash to
        # optimize this
        assert b32decode(digest_b32).hex() == response_body_sha1

        self._warc_writer.write_record(record)
        self.record_idx += 1
        self.db_conn.execute(
            "INSERT INTO oonibodies_archive (response_body_sha1, archive_filename, record_idx) VALUES (?, ?, ?)",
            (response_body_sha1, self.archive_path.name, self.record_idx),
        )
        self.db_conn.commit()

    @property
    def archive_path(self) -> pathlib.Path:
        return (
            self.dst_dir
            / f"ooniresponses-{self.start_time}-{self.serial}-{self.machine_id}.warc.gz"
        )

    def maybe_open(self):
        if self._fh is not None:
            assert self._warc_writer, "warc_writer is none"
            return

        assert not self.archive_path.exists(), f"{self.archive_path} already exists"
        self._fh = self.archive_path.open("wb")
        self._warc_writer = WARCWriter(self._fh, gzip=True)

    def maybe_open_next_archive(self):
        assert self._fh is not None

        self._lock.acquire()

        if self._fh.tell() > self.max_archive_size:
            self.close()
            self.serial += 1
            self.maybe_open()

        self._lock.release()

    def close(self):
        if self._fh is None:
            return
        self._fh.close()
        self._fh = None


def fingerprint_hunter(
    fingerprintdb: FingerprintDB, archive_path: pathlib.Path
) -> Generator[Tuple[str, List[Fingerprint]], None, None]:
    with archive_path.open("rb") as in_file:
        for record in ArchiveIterator(in_file):
            if record.rec_type == "response":
                response_body = record.raw_stream.read()
                matched_fingerprints = fingerprintdb.match_http(
                    response_body=response_body, headers=record.http_headers.headers
                )
                if len(matched_fingerprints) > 0:
                    digest_alg, digest_b32 = record.rec_headers.get_header(
                        "WARC-Payload-Digest"
                    ).split(":")
                    assert (
                        digest_alg == "sha1"
                    ), "using wrong algorithm to create digest"
                    yield b32decode(digest_b32).hex(), matched_fingerprints


def fingerprint_hunter_worker(
    archive_queue: mp.Queue,
    sqlite_path: pathlib.Path,
    datadir: pathlib.Path,
    log_level: int,
):
    log.setLevel(log_level)
    db_conn = sqlite3.connect(sqlite_path)
    fingerprintdb = FingerprintDB(datadir=datadir)

    while True:
        try:
            archive_path = archive_queue.get(block=True, timeout=0.1)
        except queue.Empty:
            continue

        if archive_path == None:
            break
        log.info(f"inspecting bodies inside {archive_path}")
        for response_body_sha1, matched_fingerprints in fingerprint_hunter(
            fingerprintdb=fingerprintdb, archive_path=archive_path
        ):
            response_fingerprints = []
            is_fingerprint_false_positive = 0
            for fp in matched_fingerprints:
                if fp.scope == "fp":
                    is_fingerprint_false_positive = 1
                response_fingerprints.append(fp.name)

            db_conn.execute(
                """
            UPDATE oonibodies_archive
            SET response_fingerprints = :response_fingerprints,
            is_fingerprint_false_positive = :is_fingerprint_false_positive
            WHERE response_body_sha1 = :response_body_sha1
            """,
                dict(
                    response_body_sha1=response_body_sha1,
                    response_fingerprints=orjson.dumps(response_fingerprints),
                    is_fingerprint_false_positive=is_fingerprint_false_positive,
                ),
            )
            db_conn.commit()


def start_fingerprint_hunter(
    archives_dir: pathlib.Path,
    data_dir: pathlib.Path,
    parallelism: int,
    log_level: int = logging.INFO,
):
    archive_queue = mp.Queue()

    sqlite_path = archives_dir / "graveyard.sqlite3"
    pool = mp.Pool(
        processes=parallelism,
        initializer=fingerprint_hunter_worker,
        initargs=(archive_queue, sqlite_path, data_dir, log_level),
    )
    for archive_path in archives_dir.glob("*.warc.gz"):
        archive_queue.put(archive_path)

    for _ in range(parallelism):
        archive_queue.put(None)

    archive_queue.join()
    pool.close()

    log.info("waiting for the worker processes to finish")
    pool.join()


def process_day(
    db: Union[ClickhouseConnection, CSVConnection],
    netinfodb: NetinfoDB,
    day: date,
    test_name=[],
    probe_cc=[],
    start_at_idx=0,
    fast_fail=False,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
) -> Generator[
    Tuple[int, str, Optional[List[Tuple[str, bytes]]], Optional[bytes]], None, None
]:
    t0 = time.monotonic()
    bucket_date = day.strftime("%Y-%m-%d")
    row_writer = BufferredRowWriter(db=db, buffer_size=10_000)

    for idx, msmt_dict in enumerate(
        iter_measurements(
            probe_cc=probe_cc,
            test_name=test_name,
            start_day=day,
            end_day=day + timedelta(days=1),
            progress_callback=progress_callback,
        )
    ):
        # TODO: in multithreading environment this doesn't really make a lot of
        # sense. It's still useful for debugging to slice a specific date and
        # reprocess it.
        if idx <= start_at_idx:
            continue

        msmt = None
        try:
            msmt = load_measurement(msmt_dict)
            table_name, rows = make_db_rows(
                bucket_date=bucket_date,
                observations=make_observations(msmt, netinfodb=netinfodb),
            )
            row_writer.write_rows(table_name=table_name, rows=rows)
            if isinstance(msmt, WebConnectivity) and msmt.test_keys.requests:
                for http_transaction in msmt.test_keys.requests:
                    if not http_transaction.response or not http_transaction.request:
                        continue
                    request_url = http_transaction.request.url
                    status_code = http_transaction.response.code or 0
                    response_headers = (
                        http_transaction.response.headers_list_bytes or []
                    )
                    response_body = http_transaction.response.body_bytes
                    yield status_code, request_url, response_headers, response_body
        except Exception as exc:
            msmt_str = ""
            if msmt:
                msmt_str = msmt.report_id
                if msmt.input:
                    msmt_str += f"?input={msmt.input}"
            log.error(f"failed at idx: {idx} ({msmt_str})", exc_info=True)

            if fast_fail:
                row_writer.flush_all()
                raise exc

    row_writer.flush_all()

    # return time.monotonic() - t0, day


class ObservationMakerWorker(mp.Process):
    def __init__(
        self,
        status_queue: mp.JoinableQueue,
        day_queue: mp.JoinableQueue,
        archiver_queue: Optional[mp.JoinableQueue],
        archives_dir: Optional[pathlib.Path],
        shutdown_event: EventClass,
        data_dir: pathlib.Path,
        probe_cc: List[str],
        test_name: List[str],
        clickhouse: Optional[str],
        csv_dir: Optional[pathlib.Path],
        start_at_idx: int,
        fast_fail: bool,
        process_id: int,
        log_level: int = logging.INFO,
    ):
        super().__init__(daemon=True)
        assert clickhouse or csv_dir, "missing either clickhouse or csv_dir"

        if archives_dir:
            assert (
                archives_dir and archiver_queue
            ), "when archives_dir is set also the queue needs to be set"

        self.day_queue = day_queue
        self.archiver_queue = archiver_queue
        self.data_dir = data_dir
        self.probe_cc = probe_cc
        self.test_name = test_name
        self.clickhouse = clickhouse
        self.csv_dir = csv_dir
        self.start_at_idx = start_at_idx
        self.fast_fail = fast_fail
        self.process_id = process_id

        self.shutdown_event = shutdown_event

        self.archives_dir = archives_dir
        self.archive_ts = int(time.time())
        self.current_archive_file_idx = 0
        self.archive_fh = None
        self.body_buffer_size = 100_000_000

        self.status_queue = status_queue

        log.setLevel(log_level)

    @property
    def archive_path(self):
        if self.archives_dir:
            return (
                self.archives_dir
                / f"bodydump-{self.process_id}-{self.archive_ts}-{self.current_archive_file_idx}.msgpack.gz"
            )

    def run(self):
        def maybe_write_request_tuple(request_tuple):
            if not self.archive_path or not self.archiver_queue:
                return

            if not self.archive_fh:
                self.archive_fh = gzip.open(self.archive_path, "wb")

            self.archive_fh.write(msgpack.packb(request_tuple, use_bin_type=True))  # type: ignore
            if self.archive_fh.tell() > self.body_buffer_size:
                self.archive_fh.close()
                self.archiver_queue.put(self.archive_path)
                self.current_archive_file_idx += 1
                self.archive_fh = None

        current_idx = 0
        day_str = ""

        assert self.clickhouse or self.csv_dir, "missing either clickhouse or csv_dir"

        netinfodb = NetinfoDB(datadir=self.data_dir, download=False)

        db = None
        if self.clickhouse:
            db = ClickhouseConnection(self.clickhouse)
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
                for request_tup in process_day(
                    db=db,
                    netinfodb=netinfodb,
                    day=day,
                    test_name=self.test_name,
                    probe_cc=self.probe_cc,
                    start_at_idx=self.start_at_idx,
                    fast_fail=self.fast_fail,
                    progress_callback=progress_callback,
                ):
                    maybe_write_request_tuple(request_tuple=request_tup)
                    current_idx += 1
                    day_str = day.strftime("%Y-%m-%d")
            except Exception as exc:
                log.error(f"failed to process {day}", exc_info=True)
                self.status_queue.put(
                    StatusMessage(
                        src="observation_maker",
                        exception=exc,
                        traceback=traceback.format_exc(),
                    )
                )
            log.info(f"finished processing day {day_str}")
            self.day_queue.task_done()

        log.info("process is done")
        try:
            db.close()
        except Exception as exc:
            log.error("failed to flush database", exc_info=True)
            self.status_queue.put(
                StatusMessage(
                    src="observation_maker",
                    exception=exc,
                    traceback=traceback.format_exc(),
                )
            )

        if self.archive_fh and self.archiver_queue:
            self.archive_fh.close()
            self.archiver_queue.put(self.archive_path)


def run_archiver_thread(
    status_queue: mp.JoinableQueue,
    archiver_queue: mp.JoinableQueue,
    archives_dir: pathlib.Path,
    shutdown_event: EventClass,
    log_level: int,
):
    log.setLevel(log_level)
    log.info("starting archiver")
    response_archiver = ResponseArchiver(dst_dir=archives_dir)
    while not shutdown_event.is_set():
        try:
            archive_path = archiver_queue.get(block=True, timeout=0.1)
        except queue.Empty:
            continue

        try:
            with gzip.open(archive_path, "rb") as in_file:
                requests_unpacker = msgpack.Unpacker(in_file, raw=False)
                for (
                    status_code,
                    request_url,
                    response_headers,
                    response_body,
                ) in requests_unpacker:
                    response_archiver.archive_http_transaction(
                        status_code=status_code,
                        request_url=request_url,
                        response_headers=response_headers,
                        response_body=response_body,
                    )
                archive_path.unlink()
        except Exception as exc:
            log.error(f"failed to process requests", exc_info=True)
            status_queue.put(
                StatusMessage(
                    src="archiver", exception=exc, traceback=traceback.format_exc()
                )
            )
        archiver_queue.task_done()
    try:
        response_archiver.close()
    except Exception as exc:
        log.error(f"failed to close archiver", exc_info=True)
        status_queue.put(
            StatusMessage(
                src="archiver", exception=exc, traceback=traceback.format_exc()
            )
        )


class StatusMessage(NamedTuple):
    src: str
    exception: Optional[Exception] = None
    traceback: Optional[str] = None
    progress: Optional[MeasurementListProgress] = None
    idx: Optional[int] = None
    day_str: Optional[str] = None
    archive_queue_size: Optional[int] = None


def run_status_thread(status_queue: mp.Queue, shutdown_event: EventClass):
    total_prefixes = 0
    current_prefix_idx = 0

    total_file_entries = 0
    current_file_entry_idx = 0
    download_desc = ""
    last_idx_desc = ""
    qsize_desc = ""

    pbar_listing = tqdm(position=0)
    pbar_download = tqdm(unit="B", unit_scale=True, position=1)

    log.info("starting error handling thread")
    while not shutdown_event.is_set():
        try:
            res = status_queue.get(block=True, timeout=0.1)
        except queue.Empty:
            continue

        if res.exception:
            log.error(f"got an error from {res.src}: {res.exception} {res.traceback}")

        if res.progress:
            p = res.progress
            if p.progress_status == ProgressStatus.LISTING_BEGIN:
                total_prefixes += p.total_prefixes
                pbar_listing.total = total_prefixes

                pbar_listing.set_description("starting listing")

            if p.progress_status == ProgressStatus.LISTING:
                current_prefix_idx += 1
                pbar_listing.update(1)
                pbar_listing.set_description(
                    f"listed {current_prefix_idx}/{total_prefixes} prefixes"
                )

            if p.progress_status == ProgressStatus.DOWNLOAD_BEGIN:
                if not pbar_download.total:
                    pbar_download.total = 0
                total_file_entries += p.total_file_entries
                pbar_download.total += p.total_file_entry_bytes

            if p.progress_status == ProgressStatus.DOWNLOADING:
                current_file_entry_idx += 1
                download_desc = (
                    f"downloading {current_file_entry_idx}/{total_file_entries} files"
                )
                pbar_download.update(p.current_file_entry_bytes)

        if res.idx:
            last_idx_desc = f" idx: {res.idx} ({res.day_str})"

        if res.archive_queue_size:
            qsize_desc = f" aqsize: {res.archive_queue_size}"

        pbar_download.set_description(download_desc + last_idx_desc + qsize_desc)

        status_queue.task_done()


def start_observation_maker(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    csv_dir: Optional[pathlib.Path],
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    archives_dir: Optional[pathlib.Path],
    parallelism: int,
    start_at_idx: int,
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

    archiver_thread = None
    archiver_queue = None
    if archives_dir:
        archiver_queue = mp.JoinableQueue()
        archiver_thread = Thread(
            target=run_archiver_thread,
            args=(
                status_queue,
                archiver_queue,
                archives_dir,
                shutdown_event,
                log_level,
            ),
        )
        archiver_thread.start()

    observation_workers = []
    day_queue = mp.JoinableQueue()
    for idx in range(parallelism):
        worker = ObservationMakerWorker(
            status_queue=status_queue,
            day_queue=day_queue,
            archiver_queue=archiver_queue,
            archives_dir=archives_dir,
            shutdown_event=worker_shutdown_event,
            data_dir=data_dir,
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse,
            csv_dir=csv_dir,
            start_at_idx=start_at_idx,
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

    log.info(f"waiting for workers to finish running")
    for idx, p in enumerate(observation_workers):
        log.info(f"waiting observation_maker {idx} to stop")
        p.join()
        p.close()

    if archiver_queue:
        log.info("waiting for archiving to finish")
        archiver_queue.join()
    status_queue.join()

    # We are done, we can now tell everybody to go home
    log.info("sending shutdown event")
    shutdown_event.set()

    if archiver_thread:
        log.info("waiting on archiver thread")
        archiver_thread.join()

    # Shutdown the status thread
    log.info("shutting down the status thread")
    status_thread.join()
