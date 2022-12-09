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

from threading import Lock, Thread
from base64 import b32decode
from datetime import date, datetime, timedelta

from typing import (
    Callable,
    Generator,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

import orjson
import msgpack
import statsd
from tqdm import tqdm
from warcio.warcwriter import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders
from oonidata.analysis.datasources import iter_web_observations, load_measurement
from oonidata.datautils import PerfTimer
from oonidata.analysis.control import (
    BodyDB,
    WebGroundTruthDB,
    iter_web_ground_truths,
)
from oonidata.models.experiment_result import ExperimentResult
from oonidata.analysis.websites import make_website_experiment_result

from oonidata.fingerprintdb import FingerprintDB, Fingerprint
from oonidata.models.nettests import WebConnectivity
from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    MeasurementListProgress,
    date_interval,
    iter_measurements,
    ProgressStatus,
)
from oonidata.db.connections import (
    ClickhouseConnection,
    CSVConnection,
)
from oonidata.transforms import measurement_to_observations

log = logging.getLogger("oonidata.processing")


def make_db_rows(
    dc_list: List, column_names: List[str], bucket_date: Optional[str] = None
) -> Tuple[str, List[str]]:
    assert len(dc_list) > 0

    table_name = dc_list[0].__table_name__
    rows = []
    for d in dc_list:
        if bucket_date:
            d.bucket_date = bucket_date
        assert table_name == d.__table_name__, "inconsistent group of observations"
        rows.append(tuple(getattr(d, k) for k in column_names))

    return table_name, rows


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

    pool.close()

    log.info("waiting for the worker processes to finish")
    pool.join()


class PrevRange(NamedTuple):
    bucket_date: Optional[str]
    start_timestamp: Optional[datetime]
    end_timestamp: Optional[datetime]
    max_created_at: Optional[datetime]
    min_created_at: Optional[datetime]
    where: str


def get_prev_range(
    db: ClickhouseConnection,
    table_name: str,
    test_name: List[str],
    probe_cc: List[str],
    bucket_date: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> PrevRange:
    """
    We lookup the range of previously generated rows so we can drop
    them from the database once we have finished processing.

    We can't rely just on deduplication happening at the clickhouse level,
    because we might in the future add or remove certain rows, so it's
    more robust to just drop them once we are done reprocessing.

    Moreover, you don't have any guarantee on when the deduplication is
    happening, which means that if you run queries while the reprocessing is
    happening you don't know when exactly it's going to be safe to run
    deduplcated queries on the DB.

    For observation tables we use the bucket_date field. For experiment results
    we use a range of timestamp in a day.
    In both cases we delimit the range via the created_at column and any
    additional filters that may have been applied to the reprocessing process.

    TODO: while the reprocessing is running we should probably flag this
    bucket as reprocessing in progress and guard against running queries for
    it.
    """
    q = f"SELECT MAX(created_at), MIN(created_at) FROM {table_name} "
    assert (
        timestamp or bucket_date
    ), "either timestamp or bucket_date should be provided"
    start_timestamp = None
    end_timestamp = None
    where = None
    where = "WHERE bucket_date = %(bucket_date)s"
    q_args = {"bucket_date": bucket_date}
    if timestamp:
        start_timestamp = timestamp
        end_timestamp = timestamp + timedelta(days=1)
        q_args = {"start_timestamp": start_timestamp, "end_timestamp": end_timestamp}
        where = (
            "WHERE timestamp >= %(start_timestamp)s AND timestamp < %(end_timestamp)s"
        )

    if len(test_name) > 0:
        test_name_list = []
        for tn in test_name:
            # sanitize the test_names. It should not be a security issue since
            # it's not user provided, but better safe than sorry
            assert tn.replace("_", "").isalnum(), f"not alphabetic testname {tn}"
            test_name_list.append(f"'{tn}'")
        where += " AND test_name IN ({})".format(",".join(test_name_list))
    if len(probe_cc) > 0:
        probe_cc_list = []
        for cc in probe_cc:
            assert cc.replace("_", "").isalnum(), f"not alphabetic probe_cc"
            probe_cc_list.append(f"'{cc}'")
        where += " AND probe_cc IN ({})".format(",".join(probe_cc_list))

    prev_obs_range = db.execute(q + where, q_args)
    assert isinstance(prev_obs_range, list) and len(prev_obs_range) == 1
    max_created_at, min_created_at = prev_obs_range[0]

    # We pad it by 1 second to take into account the time resolution downgrade
    # happening when going from clickhouse to python data types
    if max_created_at and min_created_at:
        max_created_at += timedelta(seconds=1)
        min_created_at -= timedelta(seconds=1)

    return PrevRange(
        max_created_at=max_created_at,
        min_created_at=min_created_at,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        where=where,
        bucket_date=bucket_date,
    )


def maybe_delete_prev_range(
    db: ClickhouseConnection, table_name: str, prev_range: PrevRange
):
    """
    We perform a lightweight delete of all the rows which have been
    regenerated, so we don't have any duplicates in the table
    """
    if not prev_range.max_created_at:
        return

    # Disabled due to: https://github.com/ClickHouse/ClickHouse/issues/40651
    # db.execute("SET allow_experimental_lightweight_delete = true;")
    q_args = {
        "max_created_at": prev_range.max_created_at,
        "min_created_at": prev_range.min_created_at,
    }
    if prev_range.bucket_date:
        q_args["bucket_date"] = prev_range.bucket_date
    elif prev_range.start_timestamp:
        q_args["start_timestamp"] = prev_range.start_timestamp
        q_args["end_timestamp"] = prev_range.end_timestamp
    else:
        raise Exception("either bucket_date or timestamps should be set")

    where = f"{prev_range.where} AND created_at <= %(max_created_at)s AND created_at >= %(min_created_at)s"
    return db.execute(f"ALTER TABLE {table_name} DELETE " + where, q_args)


def make_observation_in_day(
    db: Union[ClickhouseConnection, CSVConnection],
    netinfodb: NetinfoDB,
    day: date,
    test_name=[],
    probe_cc=[],
    fast_fail=False,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
) -> Generator[
    Tuple[int, str, Optional[List[Tuple[str, bytes]]], Optional[bytes]], None, None
]:
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
        archiver_queue: Optional[mp.JoinableQueue],
        archives_dir: Optional[pathlib.Path],
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
                for request_tup in make_observation_in_day(
                    db=db,
                    netinfodb=netinfodb,
                    day=day,
                    test_name=self.test_name,
                    probe_cc=self.probe_cc,
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
        finally:
            # We only add to the queue if we have an archive
            if self.archive_fh and self.archiver_queue:
                log.info("closing archiver_fh and adding to queue")
                try:
                    self.archive_fh.close()
                    self.archiver_queue.put(self.archive_path, timeout=5)
                except:
                    log.error("failed to put on the archiver_queue", exc_info=True)
                log.info("closed and added to archiver_queue")


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
        log.info(f"archiving {archive_path}")
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
        finally:
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
            daemon=True,
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

    log.info(f"waiting for observation workers to finish running")
    for idx, p in enumerate(observation_workers):
        log.info(f"waiting observation_maker {idx} to join")
        p.join()
        log.info(f"waiting observation_maker {idx} to close")
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


def run_progress_thread(
    status_queue: mp.Queue, shutdown_event: EventClass, desc: str = "analyzing data"
):
    pbar = tqdm(position=0)

    log.info("starting error handling thread")
    while not shutdown_event.is_set():
        try:
            res = status_queue.get(block=True, timeout=0.1)
        except queue.Empty:
            continue

        try:
            pbar.update()
            pbar.set_description(desc)
        finally:
            status_queue.task_done()


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

    log.info(f"waiting for ground truth workers to finish running")
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
