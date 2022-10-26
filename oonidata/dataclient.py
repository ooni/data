import io
import gzip
import itertools
import tarfile
import logging
import lz4.frame
import shutil
import orjson
import multiprocessing.pool
from datetime import date, timedelta, datetime

from dataclasses import dataclass

from enum import Enum
from typing import Callable, Generator, Set, List, Optional, NamedTuple, Union

import boto3
from botocore import UNSIGNED as botoSigUNSIGNED
from botocore.config import Config as botoConfig

from oonidata.normalize import iter_yaml_msmt_normalized
from oonidata.dataformat import trivial_id

LEGACY_BUCKET_NAME = "ooni-data"
MC_BUCKET_NAME = "ooni-data-eu-fra"

log = logging.getLogger("oonidata.dataclient")


def create_s3_client():
    return boto3.client("s3", config=botoConfig(signature_version=botoSigUNSIGNED))


s3 = create_s3_client()


def date_interval(start_day: date, end_day: date):
    """
    A generator for a date_interval.

    The end_day is not included in the range.
    """
    if start_day > end_day:
        return
    for d in range((end_day - start_day).days):
        yield start_day + timedelta(days=d)


def get_file_entry_ext(filename: str):
    supported_extensions = [
        # New jsonl gzips
        "jsonl.gz",
        # Old json gzips
        "json.gz",
        # New postcans
        "tar.gz",
        # Old cans
        "tar.lz4",
        "json.lz4",
        "yaml.lz4",
    ]
    for ext in supported_extensions:
        if filename.endswith("." + ext):
            return ext
    return filename.split(".")[-1]


class FilenameMeta(NamedTuple):
    timestamp: datetime
    probe_cc: Optional[str]
    testname: str


def get_filename_meta_v2(filename: str) -> FilenameMeta:
    p = filename.split("_")
    ts = p[0]
    # Some older timestamps don't have the hour in them, so we add the hour back
    # into it and set it to midnight.
    if len(ts) == 8:
        ts += "00"

    return FilenameMeta(
        timestamp=datetime.strptime(ts, "%Y%m%d%H"),
        probe_cc=p[1],
        testname=p[2].split(".")[0],
    )


def get_filename_meta_tarcan(s3path: str, filename: str) -> FilenameMeta:
    """
    These look like this:
    canned/2020-10-21/web_connectivity.0.tar.lz4
    """
    return FilenameMeta(
        timestamp=datetime.strptime(s3path.split("/")[-2], "%Y-%m-%d"),
        # These test_names have an underscore, we uniform them to the new format
        # without the underscore
        testname=filename.split(".")[0].replace("_", ""),
        # We don't know the probe_cc in these cases
        probe_cc=None,
    )


def get_filename_meta_reportcan(s3path: str, filename: str) -> FilenameMeta:
    """
    These look like this:
    canned/2020-10-21/20201021T141726Z-US-AS20093-facebook_messenger-20201021T141726Z_AS20093_MBCoLaOwlb5pq7CWYvsqhN5qc1Nd3rHQC0xmvoG1bCTn5ZCpS6-0.2.0-probe.json.lz4
    """
    p = filename.split("-")
    return FilenameMeta(
        # Note: we don't use the timestamp inside of the filename, because that
        # is the timestamp of the measurement, not of the measurement upload and
        # publication time.
        timestamp=datetime.strptime(s3path.split("/")[-2], "%Y-%m-%d"),
        # These test_names have an underscore, we uniform them to the new format
        # without the underscore
        testname=p[3].replace("_", ""),
        probe_cc=p[1],
    )


def read_to_bytesio(body: io.BytesIO) -> io.BytesIO:
    read_body = io.BytesIO()
    shutil.copyfileobj(body, read_body)
    read_body.seek(0)
    return read_body


def stream_jsonl(body: io.BytesIO) -> Generator[dict, None, None]:
    with gzip.GzipFile(fileobj=body) as in_file:
        for line in in_file:
            if line == "":
                continue
            yield orjson.loads(line)


def stream_postcan(body: io.BytesIO) -> Generator[dict, None, None]:
    # Since some older postcans have the .gz extension, but are actually not
    # compressed, tar needs to be able to re-seek back to the beginning of the
    # file in the event of it not finding the gzip magic header when operating
    # in "transparent compression mode".
    # When we we fix that in the source data, we might be able to avoid this.
    read_body = read_to_bytesio(body)

    with tarfile.open(fileobj=read_body) as tar:
        for m in tar:
            if not m.name.endswith(".post"):
                log.error(f"invalid filename in tar {m.name}")
                continue
            in_file = tar.extractfile(m)
            if in_file is None:
                log.error(f"empty file in tar {m.name}")
                continue

            post = orjson.loads(in_file.read())
            fmt = post.get("format", "")
            if fmt == "json":
                msmt = post.get("content", {})
                # extract msmt_uid from filename e.g:
                # ... /20210614004521.999962_JO_signal_68eb19b439326d60.post
                msmt_uid = m.name.rsplit("/", 1)[1]
                msmt_uid = msmt_uid[:-5]
                msmt["measurement_uid"] = msmt_uid
                yield msmt

            elif fmt == "yaml":
                log.info("Skipping YAML")

            else:
                log.error("Ignoring invalid post")


def stream_jsonlz4(body: io.BytesIO):
    # lz4.frame requires the input stream to be seekable, so we need to load it
    # in memory
    read_body = read_to_bytesio(body)

    with lz4.frame.open(read_body, mode="rb") as in_file:
        for line in in_file:
            try:
                msmt = orjson.loads(line)
            except ValueError:
                log.error("oldcan: unable to parse json measurement")
                continue

            msmt_uid = trivial_id(line, msmt)  # type: ignore due to bad types in lz4
            msmt["measurement_uid"] = msmt_uid
            yield msmt


def stream_yamllz4(body: io.BytesIO, s3path: str):
    # lz4.frame requires the input stream to be seekable, so we need to load it
    # in memory
    read_body = read_to_bytesio(body)

    with lz4.frame.open(read_body) as in_file:
        bucket_tstamp = s3path.split("/")[-2]
        rfn = f"{bucket_tstamp}/" + s3path.split("/")[-1]
        # The normalize function already add the measurement_uid
        yield from iter_yaml_msmt_normalized(in_file, bucket_tstamp, rfn)


def stream_oldcan(body: io.BytesIO, s3path: str) -> Generator[dict, None, None]:
    # lz4.frame requires the input stream to be seekable, so we need to load it
    # in memory
    read_body = read_to_bytesio(body)

    with lz4.frame.open(read_body) as lz4_file:
        with tarfile.open(fileobj=lz4_file) as tar:  # type: ignore due to bad types in lz4
            for m in tar:
                in_file = tar.extractfile(m)
                if in_file is None:
                    log.error(f"empty file in tar {m.name}")
                    continue

                if m.name.endswith(".json"):
                    for line in in_file:
                        try:
                            msmt = orjson.loads(line)
                        except ValueError:
                            log.error("oldcan: unable to parse json measurement")
                            continue

                        msmt_uid = trivial_id(line, msmt)
                        msmt["measurement_uid"] = msmt_uid
                        yield msmt

                elif m.name.endswith(".yaml"):
                    bucket_tstamp = s3path.split("/")[-2]
                    rfn = f"{bucket_tstamp}/" + s3path.split("/")[-1]
                    # The normalize function already add the measurement_uid
                    yield from iter_yaml_msmt_normalized(in_file, bucket_tstamp, rfn)


@dataclass
class FileEntry:
    s3path: str
    bucket_name: str
    timestamp: datetime
    testname: str
    filename: str
    size: int
    ext: str
    is_can: bool
    probe_cc: Optional[str] = None

    def matches_filter(
        self,
        ccs: Set[str],
        testnames: Set[str],
        start_timestamp: datetime,
        end_timestamp: datetime,
    ) -> bool:
        if self.probe_cc and ccs and self.probe_cc not in ccs:
            return False

        if self.testname and testnames and self.testname not in testnames:
            return False

        if self.timestamp < start_timestamp or self.timestamp >= end_timestamp:
            return False

        return True

    def log_download(self) -> None:
        s = self.size / 1024 / 1024
        d = "M"
        if s < 1:
            s = self.size / 1024
            d = "K"
        print(f"Downloading can {self.s3path} size {s:.1f} {d}B")

    def stream_measurements(self):
        body = s3.get_object(Bucket=self.bucket_name, Key=self.s3path)["Body"]
        log.debug(f"streaming file {self}")
        if self.ext == "jsonl.gz":
            yield from stream_jsonl(body)
        elif self.ext == "tar.gz":
            yield from stream_postcan(body)
        elif self.ext == "tar.lz4":
            yield from stream_oldcan(body, self.s3path)
        elif self.ext == "json.lz4":
            yield from stream_jsonlz4(body)
        elif self.ext == "yaml.lz4":
            yield from stream_jsonlz4(body)
        else:
            log.error(
                f"found a file with an unknown extension: {self.ext} s3://{self.bucket_name}/{self.s3path}"
            )

    @staticmethod
    def from_obj_dict(bucket_name: str, obj_dict: dict) -> "FileEntry":
        s3path = obj_dict["Key"]
        filename = s3path.split("/")[-1]
        ext = get_file_entry_ext(filename)

        if ext == "jsonl.gz" or ext == "tar.gz":
            fm = get_filename_meta_v2(filename)
            is_can = False
            if ext == "tar.gz":
                is_can = True
        elif ext == "tar.lz4":
            fm = get_filename_meta_tarcan(s3path, filename)
            is_can = True
        elif ext == "json.lz4" or ext == "yaml.lz4":
            fm = get_filename_meta_reportcan(s3path, filename)
            is_can = True
        else:
            raise ValueError(f"unsupported file entry extension: {ext}")

        return FileEntry(
            s3path=s3path,
            bucket_name=bucket_name,
            timestamp=fm.timestamp,
            testname=fm.testname,
            filename=filename,
            size=obj_dict["Size"],
            ext=ext,
            probe_cc=fm.probe_cc,
            is_can=is_can,
        )


def list_all_testnames() -> Set[str]:
    testnames = set()
    paginator = s3.get_paginator("list_objects_v2")
    for r in paginator.paginate(Bucket=MC_BUCKET_NAME, Prefix="jsonl/", Delimiter="/"):
        for f in r.get("CommonPrefixes", []):
            testnames.add(f["Prefix"].split("/")[-2])
    return testnames


class Prefix(NamedTuple):
    bucket_name: str
    prefix: str


def get_v2_search_prefixes(testnames: Set[str], ccs: Set[str]) -> List[Prefix]:
    """
    get_search_prefixes will return all the prefixes inside of the new jsonl
    bucket that match the given testnames and ccs.
    If the ccs list is empty we will return prefixes for all countries for
    which that particular testname as measurements.
    """
    prefixes = []
    paginator = s3.get_paginator("list_objects_v2")
    for tn in testnames:
        for r in paginator.paginate(
            Bucket=MC_BUCKET_NAME, Prefix=f"jsonl/{tn}/", Delimiter="/"
        ):
            for f in r.get("CommonPrefixes", []):
                prefix = f["Prefix"]
                cc = prefix.split("/")[-2]
                if ccs and cc not in ccs:
                    continue
                prefixes.append(prefix)
    return prefixes


def get_v2_prefixes(
    ccs: Set[str], testnames: Set[str], start_day: date, end_day: date
) -> List[Prefix]:
    legacy_prefixes = [
        Prefix(bucket_name=MC_BUCKET_NAME, prefix=f"raw/{d:%Y%m%d}")
        for d in date_interval(max(date(2020, 10, 20), start_day), end_day)
    ]
    if not testnames:
        testnames = list_all_testnames()
    prefixes = []
    if start_day < date(2020, 10, 21):
        prefixes = get_v2_search_prefixes(testnames, ccs)
        combos = list(itertools.product(prefixes, date_interval(start_day, end_day)))
        # This results in a faster listing in cases where we need only a small time
        # window or few testnames. For larger windows of time, we are better off
        # just listing everything.
        if len(combos) < 1_000_000:  # XXX we might want to tweak this parameter a bit
            prefixes = [
                Prefix(bucket_name=MC_BUCKET_NAME, prefix=f"{p}{d:%Y%m%d}")
                for p, d in combos
            ]

    return prefixes + legacy_prefixes


def get_can_prefixes(start_day: date, end_day: date) -> List[Prefix]:
    """
    Returns the list of search prefixes for cans. In most cases, since we don't
    have the country code or test name in the path, all we do is return the
    range of dates.
    """
    new_cans = [
        Prefix(prefix=f"canned/{d:%Y-%m-%d}", bucket_name=MC_BUCKET_NAME)
        for d in date_interval(
            # The new cans are between 2020-06-02 and 2020-10-21 inclusive
            max(date(2020, 6, 2), start_day),
            min(date(2020, 10, 22), end_day),
        )
    ]
    old_cans = [
        Prefix(prefix=f"canned/{d:%Y-%m-%d}", bucket_name=LEGACY_BUCKET_NAME)
        for d in date_interval(
            # The new cans are between 2020-06-02 and 2020-10-21 inclusive
            # Note: the cans between 2020-06-02 and 2020-10-21 appears to be duplicated between the new and old cans.
            # TODO: check if they are actually identical or not.
            max(date(2012, 12, 5), start_day),
            min(date(2020, 6, 2), end_day),
        )
    ]
    return old_cans + new_cans


def iter_file_entries(prefix: Prefix) -> Generator[FileEntry, None, None]:
    s3_client = create_s3_client()
    paginator = s3_client.get_paginator("list_objects_v2")
    for r in paginator.paginate(Bucket=prefix.bucket_name, Prefix=prefix.prefix):
        for obj_dict in r.get("Contents", []):
            try:
                yield FileEntry.from_obj_dict(prefix.bucket_name, obj_dict)
            except ValueError as exc:
                log.error(exc)


def list_file_entries(prefix: Prefix) -> List[FileEntry]:
    return [fe for fe in iter_file_entries(prefix)]


class ProgressStatus(Enum):
    LISTING = "listing"
    DOWNLOAD_BEGIN = "download_begin"
    DOWNLOADING = "downloading"


class MeasurementListProgress(NamedTuple):
    current_prefix_idx: int
    total_prefixes: int

    current_file_entry_idx: int
    total_file_entries: int

    progress_status: ProgressStatus

    current_file_entry_bytes: int
    total_file_entry_bytes: int


def make_listing_progress(
    current_prefix_idx: int, total_prefixes: int, total_file_entries: int
):
    return MeasurementListProgress(
        current_prefix_idx=current_prefix_idx,
        total_prefixes=total_prefixes,
        progress_status=ProgressStatus.LISTING,
        current_file_entry_idx=0,
        total_file_entries=total_file_entries,
        current_file_entry_bytes=0,
        total_file_entry_bytes=0,
    )


def make_download_progress(
    current_file_entry_bytes: int,
    total_file_entry_bytes: int,
    current_file_entry_idx: int,
    total_file_entries: int,
    progress_status: ProgressStatus = ProgressStatus.DOWNLOADING,
):
    return MeasurementListProgress(
        current_file_entry_idx=current_file_entry_idx,
        total_file_entries=total_file_entries,
        current_file_entry_bytes=current_file_entry_bytes,
        total_file_entry_bytes=total_file_entry_bytes,
        progress_status=progress_status,
        total_prefixes=0,
        current_prefix_idx=0,
    )


def get_file_entries(
    start_day: date,
    end_day: date,
    ccs: Set[str],
    testnames: Set[str],
    from_cans: bool,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
) -> List[FileEntry]:
    start_timestamp = datetime.combine(start_day, datetime.min.time())
    end_timestamp = datetime.combine(end_day, datetime.min.time())

    prefix_list = get_v2_prefixes(ccs, testnames, start_day, end_day)
    if from_cans == True:
        prefix_list = get_can_prefixes(start_day, end_day) + prefix_list

    log.debug(f"using prefix list {prefix_list}")
    file_entries = []
    prefix_idx = 0
    total_prefixes = len(prefix_list)

    if progress_callback:
        progress_callback(
            make_listing_progress(
                current_prefix_idx=0,
                total_prefixes=total_prefixes,
                total_file_entries=0,
            )
        )
    with multiprocessing.pool.ThreadPool() as pool:
        for fe_list in pool.imap_unordered(list_file_entries, prefix_list):
            for fe in fe_list:
                if not fe.matches_filter(
                    ccs, testnames, start_timestamp, end_timestamp
                ):
                    continue

                if from_cans == True and not fe.is_can:
                    continue
                if from_cans == False and fe.is_can:
                    continue

                file_entries.append(fe)
            prefix_idx += 1
            if progress_callback:
                progress_callback(
                    make_listing_progress(
                        current_prefix_idx=prefix_idx,
                        total_prefixes=total_prefixes,
                        total_file_entries=len(file_entries),
                    )
                )

    return file_entries


def iter_measurements(
    start_day: Union[date, str],
    end_day: Union[date, str],
    probe_cc: Optional[Union[List[str], str]] = None,
    test_name: Optional[Union[List[str], str]] = None,
    from_cans: bool = True,
    file_entries: Optional[List[FileEntry]] = None,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
) -> Generator[dict, None, None]:
    ccs = set()
    if probe_cc is not None:
        if isinstance(probe_cc, str):
            probe_cc = probe_cc.split(",")
        ccs = set(list(map(lambda x: x.upper(), probe_cc)))

    testnames = set()
    if test_name is not None:
        if isinstance(test_name, str):
            test_name = test_name.split(",")
        testnames = set(list(map(lambda x: x.lower().replace("_", ""), test_name)))

    if isinstance(start_day, str):
        start_day = datetime.strptime(start_day, "%Y-%m-%d").date()
    if isinstance(end_day, str):
        end_day = datetime.strptime(end_day, "%Y-%m-%d").date()

    if file_entries is None:
        file_entries = get_file_entries(
            start_day=start_day,
            end_day=end_day,
            ccs=ccs,
            testnames=testnames,
            from_cans=from_cans,
            progress_callback=progress_callback,
        )

    total_file_entry_bytes = sum(map(lambda fe: fe.size, file_entries))
    if progress_callback:
        progress_callback(
            make_download_progress(
                current_file_entry_bytes=0,
                total_file_entry_bytes=total_file_entry_bytes,
                current_file_entry_idx=0,
                total_file_entries=len(file_entries),
                progress_status=ProgressStatus.DOWNLOAD_BEGIN,
            )
        )

    for idx, fe in enumerate(file_entries):
        for msmt in fe.stream_measurements():
            # Legacy cans don't allow us to pre-filter on the probe_cc, so we do
            # it before returning the data to the caller
            if ccs and msmt["probe_cc"] not in ccs:
                continue
            yield msmt

        if progress_callback:
            progress_callback(
                make_download_progress(
                    current_file_entry_bytes=fe.size,
                    total_file_entry_bytes=total_file_entry_bytes,
                    current_file_entry_idx=idx,
                    total_file_entries=len(file_entries),
                )
            )
