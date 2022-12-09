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

import msgpack
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders
from oonidata.workers.common import StatusMessage

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
