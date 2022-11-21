import io
import pathlib
import time
import logging
import traceback
from base64 import b32decode
import http.client

from datetime import date, timedelta
import dataclasses

from typing import (
    Tuple,
    List,
    Union,
    Dict,
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


def write_observations_to_db(
    db: DatabaseConnection, bucket_date: str, observations: List[WebObservation]
) -> None:
    if len(observations) == 0:
        return

    table_name = observations[0].__table_name__
    rows = []
    for obs in observations:
        assert table_name == obs.__table_name__, "inconsistent table name in group"
        obs.bucket_date = bucket_date
        rows.append(dataclasses.asdict(obs))
    db.write_rows(table_name, rows)


class ResponseArchiver:
    def __init__(self, db: DatabaseConnection, dst_dir: pathlib.Path):
        self.db = db
        self.dst_dir = dst_dir
        self.archive_idx = self._init_idx()
        self.record_idx = 0
        self._fh = None
        self._warc_writer = None
        self.max_archive_size = 100_000_000

    def _init_idx(self):
        try:
            return (
                max(
                    map(
                        lambda x: int(x.name.split("-")[-1].split(".")[0]),
                        self.dst_dir.glob("*.warc.gz"),
                    )
                )
                + 1
            )
        except ValueError:
            return 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @property
    def archive_path(self) -> pathlib.Path:
        return self.dst_dir / f"ooniresponses-{self.archive_idx}.warc.gz"

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

        if self._fh.tell() > self.max_archive_size:
            self.open_next_archive()

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

        if self.is_already_archived(response_body_sha1):
            return

        self._warc_writer.write_record(record)
        self.record_idx += 1
        self.db.execute(
            "INSERT INTO oonibodies_archive (response_body_sha1, archive_filename, record_idx) VALUES",
            [[response_body_sha1, self.archive_path.name, self.record_idx]],
        )

    def open(self):
        assert self._fh is None, "Attempting to open an already open FH"
        self._fh = self.archive_path.open("wb")
        self._warc_writer = WARCWriter(self._fh, gzip=True)

    def open_next_archive(self):
        self.close()
        self.archive_idx += 1
        self.open()

    def close(self):
        assert self._fh is not None, "Attempting to close an unopen archiver"
        self._fh.close()


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
                write_observations_to_db(
                    db=db,
                    bucket_date=bucket_date,
                    observations=make_observations(msmt, netinfodb=netinfodb),
                )
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
                    raise exc

    return time.monotonic() - t0, day
