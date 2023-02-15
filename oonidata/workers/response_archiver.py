from datetime import date, timedelta
import gzip
import io
import queue
import time
import pathlib
import logging
import sqlite3
import hashlib
import http.client
import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass
from threading import Lock
from base64 import b32decode
import traceback

from typing import (
    List,
    Optional,
    Tuple,
)

from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders
from oonidata.analysis.datasources import load_measurement
from oonidata.dataclient import date_interval, iter_measurements
from oonidata.models.nettests.web_connectivity import WebConnectivity

log = logging.getLogger("oonidata.processing")


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


def start_response_archiver(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    clickhouse: Optional[str],
    archives_dir: pathlib.Path,
    log_level: int = logging.INFO,
):
    def progress_callback(p):
        print(p)

    response_archiver = ResponseArchiver(dst_dir=archives_dir)
    for day in date_interval(start_day, end_day):
        log.info(f"Archiving bodies for {day}")
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
                msmt = load_measurement(msmt_dict)
                if isinstance(msmt, WebConnectivity) and msmt.test_keys.requests:
                    for http_transaction in msmt.test_keys.requests:
                        if (
                            not http_transaction.response
                            or not http_transaction.request
                        ):
                            continue
                        request_url = http_transaction.request.url
                        status_code = http_transaction.response.code or 0
                        response_headers = (
                            http_transaction.response.headers_list_bytes or []
                        )
                        response_body = http_transaction.response.body_bytes
                        response_archiver.archive_http_transaction(
                            status_code=status_code,
                            request_url=request_url,
                            response_headers=response_headers,
                            response_body=response_body,
                        )
            except Exception:
                msmt_str = ""
                if msmt:
                    msmt_str = msmt.report_id
                    if msmt.input:
                        msmt_str += f"?input={msmt.input}"
                log.error(f"failed at idx: {idx} ({msmt_str})", exc_info=True)
