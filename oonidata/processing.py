from collections import defaultdict
import hashlib
import io
import pathlib
import time
import logging
import traceback
from base64 import b32decode
import http.client

from threading import Lock

from datetime import date, datetime, timedelta
import dataclasses

from typing import (
    Any,
    Dict,
    List,
    Tuple,
    Union,
)

import orjson
from tqdm import tqdm
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders

from oonidata.observations import WebObservation, make_observations
from oonidata.dataformat import load_measurement, HTTPTransaction
from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    MeasurementListProgress,
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
            self.fields_map[table_name] = rows[0].keys()

        self.row_buffer_map[table_name] += list(
            map(lambda row: [row[k] for k in self.fields_map[table_name]], rows)
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
        db: DatabaseConnection,
        dst_dir: pathlib.Path,
        max_archive_size=10_000_000,
        host_suffix="oonidata",
    ):
        self.db = db
        self.dst_dir = dst_dir
        self.host_suffix = host_suffix
        self.max_archive_size = max_archive_size
        self.start_time = int(time.time())
        self.serial = 0
        self.record_idx = 0

        self._fh = None
        self._warc_writer = None
        self._lock = Lock()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def is_already_archived(self, response_body_sha1):
        res = self.db.execute(
            "SELECT response_body_sha1 FROM oonibodies_archive WHERE response_body_sha1 = %(response_body_sha1)s",
            dict(response_body_sha1=response_body_sha1),
        )
        return res and len(res) > 0

    def archive_http_transaction(self, http_transaction: HTTPTransaction):
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
        response_body_sha1 = b32decode(digest_b32).hex()

        if http_transaction.response.body_bytes:
            # TODO: remove this sanity check once we figure out it's working as intended
            assert (
                hashlib.sha1(http_transaction.response.body_bytes).hexdigest()
                == response_body_sha1
            ), "inconsistent body hash"

        if self.is_already_archived(response_body_sha1):
            return

        self._warc_writer.write_record(record)
        self.record_idx += 1
        self.db.execute(
            "INSERT INTO oonibodies_archive (response_body_sha1, archive_filename, record_idx) VALUES",
            [[response_body_sha1, self.archive_path.name, self.record_idx]],
        )

    @property
    def archive_path(self) -> pathlib.Path:
        return self.dst_dir / f"ooniresponses-{self.start_time}-{self.serial}.warc.gz"

    def open(self):
        assert self._fh is None, "attempting to open an already open FH"
        assert not self.archive_path.exists(), f"{self.archive_path} already exists"

        self._fh = self.archive_path.open("wb")
        self._warc_writer = WARCWriter(self._fh, gzip=True)

    def maybe_open_next_archive(self):
        assert self._fh is not None

        self._lock.acquire()

        if self._fh.tell() > self.max_archive_size:
            self.close()
            self.serial += 1
            self.open()

        self._lock.release()

    def close(self):
        assert self._fh is not None, "Attempting to close an unopen archiver"
        self._fh.close()
        self._fh = None


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
            pbar.set_description(f"idx {idx}")
            if idx < start_at_idx:
                continue
            try:
                msmt = load_measurement(msmt_dict)
                table_name, rows = make_db_rows(
                    bucket_date=bucket_date,
                    observations=make_observations(msmt, netinfodb=netinfodb),
                )
                row_writer.write_rows(table_name=table_name, rows=rows)
                yield msmt
            except Exception as exc:
                # This is a bit sketchy, we ought to eventually move it to some
                # better logging function
                log.error(f"failed at idx:{idx} {exc}")
                with open(
                    f"bad_msmts-{day.strftime('%Y%m%d')}.jsonl", "ab+"
                ) as out_file:
                    out_file.write(orjson.dumps(msmt_dict))
                    out_file.write(b"\n")
                with open(
                    f"bad_msmts_fail_log-{day.strftime('%Y%m%d')}.txt", "a+"
                ) as out_file:
                    out_file.write(traceback.format_exc())
                    out_file.write("ENDTB----\n")

                if fast_fail:
                    row_writer.flush_all()
                    raise exc

    row_writer.flush_all()

    return time.monotonic() - t0, day
