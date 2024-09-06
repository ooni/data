import io
import gzip
import itertools
import tarfile
import logging
import lz4.frame
import shutil
import orjson
import multiprocessing
import multiprocessing.pool
from pathlib import Path
from datetime import date, timedelta, datetime
from collections import defaultdict
from functools import partial

from dataclasses import dataclass

from enum import Enum
from typing import Callable, Generator, Set, List, Optional, NamedTuple, Tuple, Union

import boto3
from botocore import UNSIGNED as botoSigUNSIGNED
from botocore.config import Config as botoConfig

from tqdm.contrib.logging import tqdm_logging_redirect

from .models.nettests import NETTEST_MODELS
from .models.nettests.base_measurement import BaseMeasurement
from .models.nettests import SupportedDataformats

from .datautils import PerfTimer
from .datautils import trim_measurement, trivial_id
from .legacy.normalize_yamlooni import iter_yaml_msmt_normalized

LEGACY_BUCKET_NAME = "ooni-data"
MC_BUCKET_NAME = "ooni-data-eu-fra"

log = logging.getLogger("oonidata.dataclient")


def create_s3_client():
    return boto3.client("s3", config=botoConfig(signature_version=botoSigUNSIGNED))


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
    del body
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
    with tarfile.open(fileobj=body, mode="r|*") as tar:
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
                log.error("stream_jsonlz4: unable to parse json measurement")
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
        yield from iter_yaml_msmt_normalized(in_file)


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
                            log.error("stream_oldcan: unable to parse json measurement")
                            continue

                        msmt_uid = trivial_id(line, msmt)
                        msmt["measurement_uid"] = msmt_uid
                        yield msmt

                elif m.name.endswith(".yaml"):
                    bucket_tstamp = s3path.split("/")[-2]
                    rfn = f"{bucket_tstamp}/" + s3path.split("/")[-1]
                    # The normalize function already add the measurement_uid
                    yield from iter_yaml_msmt_normalized(in_file)


def stream_measurements(bucket_name, s3path, ext):
    s3 = create_s3_client()
    body = s3.get_object(Bucket=bucket_name, Key=s3path)["Body"]
    log.debug(f"streaming file s3://{bucket_name}/{s3path}")
    if ext == "jsonl.gz":
        yield from stream_jsonl(body)
    elif ext == "tar.gz":
        yield from stream_postcan(body)
    elif ext == "tar.lz4":
        yield from stream_oldcan(body, s3path)
    elif ext == "json.lz4":
        yield from stream_jsonlz4(body)
    elif ext == "yaml.lz4":
        yield from stream_yamllz4(body, s3path)
    else:
        log.error(
            f"found a file with an unknown extension: {ext} s3://{bucket_name}/{s3path}"
        )


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

    @property
    def full_s3path(self):
        return f"s3://{self.bucket_name}/{self.s3path}"

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

    def stream_measurements(self):
        yield from stream_measurements(
            bucket_name=self.bucket_name, s3path=self.s3path, ext=self.ext
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
    s3 = create_s3_client()
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
    s3 = create_s3_client()
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
                if obj_dict["Key"].endswith(".json.gz"):
                    # We ignore the legacy can index files
                    continue

                yield FileEntry.from_obj_dict(prefix.bucket_name, obj_dict)
            except ValueError as exc:
                log.error(exc)


def list_file_entries(prefix: Prefix) -> List[FileEntry]:
    return [fe for fe in iter_file_entries(prefix)]


class ProgressStatus(Enum):
    LISTING = "listing"
    LISTING_BEGIN = "listing_begin"
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
    current_prefix_idx: int,
    total_prefixes: int,
    total_file_entries: int,
    progress_status: ProgressStatus = ProgressStatus.LISTING,
):
    return MeasurementListProgress(
        current_prefix_idx=current_prefix_idx,
        total_prefixes=total_prefixes,
        progress_status=progress_status,
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


CSVList = Optional[Union[List[str], str]]


def testnames_set(test_name: CSVList) -> Set[str]:
    if test_name is not None:
        if isinstance(test_name, str):
            test_name = test_name.split(",")
        return set(list(map(lambda x: x.lower().replace("_", ""), test_name)))
    return set()


def ccs_set(probe_cc: CSVList) -> Set[str]:
    if probe_cc is not None:
        if isinstance(probe_cc, str):
            probe_cc = probe_cc.split(",")
        return set(list(map(lambda x: x.upper(), probe_cc)))
    return set()


def get_file_entries(
    start_day: date,
    end_day: date,
    probe_cc: CSVList,
    test_name: CSVList,
    from_cans: bool,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
) -> List[FileEntry]:
    ccs = ccs_set(probe_cc)
    testnames = testnames_set(test_name)

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
                progress_status=ProgressStatus.LISTING_BEGIN,
            )
        )

    for prefix in prefix_list:
        for fe in iter_file_entries(prefix):
            if not fe.matches_filter(ccs, testnames, start_timestamp, end_timestamp):
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


def list_file_entries_batches(
    start_day: Union[date, str],
    end_day: Union[date, str],
    probe_cc: CSVList = None,
    test_name: CSVList = None,
    from_cans: bool = True,
) -> Tuple[List[List[Tuple]], int]:
    if isinstance(start_day, str):
        start_day = datetime.strptime(start_day, "%Y-%m-%d").date()
    if isinstance(end_day, str):
        end_day = datetime.strptime(end_day, "%Y-%m-%d").date()

    t = PerfTimer()
    file_entries = get_file_entries(
        start_day=start_day,
        end_day=end_day,
        test_name=test_name,
        probe_cc=probe_cc,
        from_cans=from_cans,
    )
    total_file_entry_size = sum(map(lambda fe: fe.size, file_entries))
    max_batch_size = max(
        60_000_000, int(total_file_entry_size / 100)
    )  # split into approximately 100 batches or 60 MB each batch, whichever is greater

    log.info(
        f"took {t.pretty} to get {len(file_entries)} entries (batch size: {round(max_batch_size/10**6, 2)}MB)"
    )
    batches = []
    current_batch = []
    current_batch_size = 0
    total_size = 0
    while len(file_entries) > 0:
        while current_batch_size < max_batch_size:
            try:
                fe = file_entries.pop()
            except IndexError:
                break
            current_batch_size += fe.size
            total_size += fe.size
            current_batch.append((fe.bucket_name, fe.s3path, fe.ext, fe.size))
        log.debug(
            f"batch size for {start_day}-{end_day} ({probe_cc},{test_name}): {len(current_batch)}"
        )
        batches.append(current_batch)
        current_batch = []
        current_batch_size = 0

    if len(current_batch) > 0:
        batches.append(current_batch)
    return batches, total_size


def iter_measurements(
    start_day: Union[date, str],
    end_day: Union[date, str],
    probe_cc: CSVList = None,
    test_name: CSVList = None,
    from_cans: bool = True,
    file_entries: Optional[List[FileEntry]] = None,
    progress_callback: Optional[Callable[[MeasurementListProgress], None]] = None,
) -> Generator[dict, None, None]:
    ccs = ccs_set(probe_cc)

    if isinstance(start_day, str):
        start_day = datetime.strptime(start_day, "%Y-%m-%d").date()
    if isinstance(end_day, str):
        end_day = datetime.strptime(end_day, "%Y-%m-%d").date()

    if file_entries is None:
        file_entries = get_file_entries(
            start_day=start_day,
            end_day=end_day,
            test_name=test_name,
            probe_cc=probe_cc,
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
        try:
            for msmt in fe.stream_measurements():
                # Legacy cans don't allow us to pre-filter on the probe_cc, so we do
                # it before returning the data to the caller
                if ccs and msmt["probe_cc"] not in ccs:
                    continue
                yield msmt
        except Exception as exc:
            log.error(f"failed to stream measurements from {fe.full_s3path}")
            log.error(exc)

        if progress_callback:
            progress_callback(
                make_download_progress(
                    current_file_entry_bytes=fe.size,
                    total_file_entry_bytes=total_file_entry_bytes,
                    current_file_entry_idx=idx,
                    total_file_entries=len(file_entries),
                )
            )


def make_filename(
    filter_probe_cc: List[str], max_string_size: Optional[int], fe: FileEntry
) -> str:
    flags = ""
    if max_string_size:
        flags = f"_max{max_string_size}"
    ts = fe.timestamp.strftime("%Y%m%d%H")

    probe_cc = fe.probe_cc
    # Legacy file entries don't have a probe_cc in the filename, so we replace
    # the probe_cc component with whatever the user passed as filter
    if probe_cc == None:
        probe_cc = "ALL"
        if len(filter_probe_cc) > 0:
            probe_cc = "-".join(sorted(filter_probe_cc))

    filename = f"{ts}_{probe_cc}_{fe.testname}{flags}.jsonl.gz"
    return filename


def download_file_entry_list(
    fe_list: List[FileEntry],
    output_dir: Path,
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    max_string_size: Optional[int],
):
    """
    Download a list of file entries to the output dir.

    It assumes that the list of file entries in the list are all pertinent to
    the same testname, probe_cc, hour tuple
    """
    total_fe_size = 0
    output_dir = (
        output_dir / fe_list[0].testname / fe_list[0].timestamp.strftime("%Y-%m-%d")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / make_filename(probe_cc, max_string_size, fe_list[0])

    with gzip.open(output_path.with_suffix(".tmp"), "wb") as out_file:
        for fe in fe_list:
            assert fe.testname == fe_list[0].testname
            assert fe.timestamp == fe_list[0].timestamp
            assert fe.probe_cc == fe_list[0].probe_cc
            total_fe_size += fe.size

        for msmt_dict in iter_measurements(
            start_day=start_day,
            end_day=end_day,
            probe_cc=probe_cc,
            test_name=test_name,
            file_entries=fe_list,
        ):
            if max_string_size:
                msmt_dict = trim_measurement(msmt_dict, max_string_size)
            out_file.write(orjson.dumps(msmt_dict))
            out_file.write(b"\n")

    output_path.with_suffix(".tmp").rename(output_path)
    return total_fe_size


def sync_measurements(
    output_dir: Path,
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    max_string_size: Optional[int] = None,
):
    with tqdm_logging_redirect(unit_scale=True) as pbar:

        def cb_list_fe(p):
            if p.current_prefix_idx == 0:
                pbar.total = p.total_prefixes
                pbar.update(0)
                pbar.set_description("starting prefix listing")
                return
            pbar.update(1)
            pbar.set_description(
                f"listed {p.total_file_entries} files in {p.current_prefix_idx}/{p.total_prefixes} prefixes"
            )

        all_file_entries = get_file_entries(
            start_day=start_day,
            end_day=end_day,
            test_name=test_name,
            probe_cc=probe_cc,
            from_cans=True,
            progress_callback=cb_list_fe,
        )

        total_fe_size = 0
        to_download_fe = defaultdict(list)
        for fe in all_file_entries:
            dst_path = (
                output_dir
                / fe.testname
                / fe.timestamp.strftime("%Y-%m-%d")
                / make_filename(probe_cc, max_string_size, fe)
            )
            if dst_path.exists():
                continue

            ts = fe.timestamp.strftime("%Y%m%d%H")
            # We group based on this key, so each process is writing to the same file.
            # Each raw folder can have multiple files on a given hour
            key = f"{ts}-{fe.testname}-{fe.probe_cc}"
            to_download_fe[key].append(fe)
            total_fe_size += fe.size

        pbar.unit = "B"
        pbar.reset(total=total_fe_size)
        pbar.set_description("downloading files")
        download_count = 0
        with multiprocessing.Pool() as pool:
            for fe_size in pool.imap_unordered(
                partial(
                    download_file_entry_list,
                    output_dir=output_dir,
                    probe_cc=probe_cc,
                    test_name=test_name,
                    start_day=start_day,
                    end_day=end_day,
                    max_string_size=max_string_size,
                ),
                to_download_fe.values(),
            ):
                download_count += 1
                pbar.update(fe_size)
                pbar.set_description(
                    f"downloaded {download_count}/{len(to_download_fe)}"
                )


def load_measurement(
    msmt: Optional[dict] = None, msmt_path: Optional[Path] = None
) -> SupportedDataformats:
    if msmt_path:
        with msmt_path.open() as in_file:
            msmt = orjson.loads(in_file.read())

    assert msmt, "either msmt or msmt_path should be set"
    dc = NETTEST_MODELS.get(msmt["test_name"], BaseMeasurement)
    return dc.from_dict(msmt)
