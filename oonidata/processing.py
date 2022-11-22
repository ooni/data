from collections import defaultdict
import hashlib
import io
import multiprocessing
import pathlib
import time
import logging
import traceback
from base64 import b32decode
import http.client
import orjson
import sqlite3

from threading import Lock

from datetime import date, datetime, timedelta
import dataclasses

from typing import (
    Any,
    Dict,
    Generator,
    List,
    Optional,
    Tuple,
    Union,
)

from tqdm import tqdm
from warcio.warcwriter import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders

from oonidata.fingerprintdb import FingerprintDB, Fingerprint
from oonidata.observations import WebObservation, make_observations
from oonidata.dataformat import (
    WebConnectivity,
    load_measurement,
    HTTPTransaction,
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

    def archive_http_transaction(self, http_transaction: HTTPTransaction):
        response_body_sha1 = None
        if http_transaction.response and http_transaction.response.body_bytes:
            response_body_sha1 = hashlib.sha1(
                http_transaction.response.body_bytes
            ).hexdigest()

        if not response_body_sha1 or self.is_already_archived(response_body_sha1):
            # No point in archiving empty bodies
            return

        self.maybe_open()

        assert (
            self._warc_writer is not None and self._fh is not None
        ), "you must call open before you can begin archiving"

        if not http_transaction.request or not http_transaction.response:
            return

        self.maybe_open_next_archive()

        status_code = http_transaction.response.code or 0
        status_str = http.client.responses.get(status_code, "Unknown")
        protocol_v = "HTTP/1.1"
        http_headers = StatusAndHeaders(
            f"{status_code} {status_str}",
            http_transaction.response.headers_list_bytes or [],
            protocol=protocol_v,
        )
        payload = None
        if http_transaction.response.body_bytes:
            payload = io.BytesIO(http_transaction.response.body_bytes)

        record = self._warc_writer.create_warc_record(
            http_transaction.request.url,
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
    archive_queue: multiprocessing.JoinableQueue,
    sqlite_path: pathlib.Path,
    datadir: pathlib.Path,
):
    db_conn = sqlite3.connect(sqlite_path)
    fingerprintdb = FingerprintDB(datadir=datadir)

    while True:
        archive_path = archive_queue.get(block=True)
        if archive_path == None:
            archive_queue.task_done()
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

        archive_queue.task_done()


def start_fingerprint_hunter(
    archives_dir: pathlib.Path,
    data_dir: pathlib.Path,
    parallelism: int,
):
    archive_queue = multiprocessing.JoinableQueue()

    sqlite_path = archives_dir / "graveyard.sqlite3"
    pool = multiprocessing.Pool(
        processes=parallelism,
        initializer=fingerprint_hunter_worker,
        initargs=(
            archive_queue,
            sqlite_path,
            data_dir,
        ),
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
):
    t0 = time.monotonic()
    bucket_date = day.strftime("%Y-%m-%d")
    row_writer = BufferredRowWriter(db=db, buffer_size=10_000)

    with tqdm(unit="B", unit_scale=True) as pbar:

        def progress_callback(p: MeasurementListProgress):
            if p.progress_status == ProgressStatus.LISTING:
                if not pbar.total:
                    pbar.total = p.total_prefixes
                pbar.update(1)
                pbar.set_description(
                    f"listed {p.total_file_entries} files in {p.current_prefix_idx}/{p.total_prefixes} prefixes"
                )
                return

            if p.progress_status == ProgressStatus.DOWNLOAD_BEGIN:
                pbar.unit = "B"
                pbar.reset(total=p.total_file_entry_bytes)

            pbar.set_description(
                f"downloading {p.current_file_entry_idx}/{p.total_file_entries} files"
            )
            pbar.update(p.current_file_entry_bytes)

        for idx, msmt_dict in enumerate(
            iter_measurements(
                probe_cc=probe_cc,
                test_name=test_name,
                start_day=day,
                end_day=day + timedelta(days=1),
                progress_callback=progress_callback,
            )
        ):
            pbar.set_description(f"idx {idx} ({day})")
            if idx < start_at_idx:
                continue

            msmt = None
            try:
                msmt = load_measurement(msmt_dict)
                table_name, rows = make_db_rows(
                    bucket_date=bucket_date,
                    observations=make_observations(msmt, netinfodb=netinfodb),
                )
                row_writer.write_rows(table_name=table_name, rows=rows)
                yield msmt
            except Exception as exc:
                log.error(f"Failed at idx: {idx}")
                if msmt:
                    msmt_str = msmt.report_id
                    if msmt.input:
                        msmt_str += f"?input={msmt.input}"
                    log.error(f"msmt: {msmt_str}")
                log.error(exc)
                log.error("--BEGIN-TRACEBACK--")
                log.error(traceback.format_exc())
                log.error("--END-TRACEBACK--")

                if fast_fail:
                    row_writer.flush_all()
                    raise exc

    row_writer.flush_all()

    return time.monotonic() - t0, day


def processing_worker(
    day_queue: multiprocessing.JoinableQueue,
    archiver_queue: Optional[multiprocessing.JoinableQueue],
    data_dir: pathlib.Path,
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: Optional[str],
    csv_dir: Optional[str],
    start_at_idx: int,
    fast_fail: bool,
):
    netinfodb = NetinfoDB(datadir=data_dir, download=False)

    if clickhouse:
        db = ClickhouseConnection(clickhouse)
    elif csv_dir:
        db = CSVConnection(csv_dir)
    else:
        raise Exception("Missing --csv-dir or --clickhouse")

    while True:
        day = day_queue.get(block=True)
        if day == None:
            day_queue.task_done()
            break
        for msmt in process_day(
            db=db,
            netinfodb=netinfodb,
            day=day,
            test_name=test_name,
            probe_cc=probe_cc,
            start_at_idx=start_at_idx,
            fast_fail=fast_fail,
        ):
            if isinstance(msmt, WebConnectivity) and msmt.test_keys.requests:
                if archiver_queue:
                    archiver_queue.put(msmt.test_keys.requests)

        day_queue.task_done()

    db.close()


def archiver_worker(
    archiver_queue: multiprocessing.Queue,
    dst_dir: pathlib.Path,
    clickhouse: Optional[str],
):
    db = ClickhouseConnection(clickhouse)

    with ResponseArchiver(dst_dir=dst_dir) as archiver:
        while True:
            requests = archiver_queue.get(block=True)
            if requests == None:
                archiver_queue.task_done()
                break
            try:
                for http_transaction in requests:
                    archiver.archive_http_transaction(http_transaction=http_transaction)
            except Exception:
                log.error(f"failed to process {requests}")
                log.error(traceback.format_exc())
            archiver_queue.task_done()

    db.close()


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
):
    day_queue = multiprocessing.JoinableQueue()

    archiver_queue = None
    archiver_process = None
    if archives_dir:
        archiver_queue = multiprocessing.JoinableQueue()
        archiver_process = multiprocessing.Process(
            target=archiver_worker, args=(archiver_queue, archives_dir, clickhouse)
        )
        archiver_process.start()

    pool = multiprocessing.Pool(
        processes=parallelism,
        initializer=processing_worker,
        initargs=(
            day_queue,
            archiver_queue,
            data_dir,
            probe_cc,
            test_name,
            clickhouse,
            csv_dir,
            start_at_idx,
            fast_fail,
        ),
    )
    for day in date_interval(start_day, end_day):
        day_queue.put(day)

    for _ in range(parallelism):
        day_queue.put(None)

    log.info("waiting for the day queue to finish")
    day_queue.join()

    log.info("waiting for the pool to close")
    pool.close()

    log.info("waiting for the worker processes to finish")
    pool.join()

    log.info("shutting down the archiving process")
    if archiver_process and archiver_queue:
        # Singal the archiver we have put everything in it
        archiver_queue.put(None)
        archiver_queue.join()
        archiver_process.join()
        archiver_process.close()
