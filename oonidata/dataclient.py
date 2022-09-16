import io
import gzip
import itertools

from datetime import date, timedelta, datetime

from dataclasses import dataclass

from typing import Generator, Set, List
from pathlib import Path

import boto3  # debdeps: python3-boto3
from botocore import UNSIGNED as botoSigUNSIGNED
from botocore.config import Config as botoConfig

MC_BUCKET_NAME = "ooni-data-eu-fra"


def create_s3_client():
    return boto3.client("s3", config=botoConfig(signature_version=botoSigUNSIGNED))


s3 = create_s3_client()


def date_interval(start_day: date, end_day: date):
    """
    A generator for a date_interval.

    The end_day is not included in the range.
    """
    if start_day > end_day:
        raise ValueError("start_day > end_day")
    for d in range((end_day - start_day).days):
        yield start_day + timedelta(days=d)


@dataclass
class FileEntry:
    day: date
    country_code: str
    test_name: str
    filename: str
    size: int
    ext: str
    s3path: str
    bucket_name: str

    def output_path(self, dst_dir: Path) -> Path:
        return (
            dst_dir
            / self.test_name
            / self.country_code
            / f"{self.day:%Y-%m-%d}"
            / self.filename
        )

    def matches_filter(self, ccs: Set[str], testnames: Set[str]) -> bool:
        if self.country_code and ccs and self.country_code not in ccs:
            return False

        if self.test_name and testnames and self.test_name not in testnames:
            return False

        return True

    def log_download(self) -> None:
        s = self.size / 1024 / 1024
        d = "M"
        if s < 1:
            s = self.size / 1024
            d = "K"
        print(f"Downloading can {self.s3path} size {s:.1f} {d}B")


def list_all_testnames() -> Set[str]:
    testnames = set()
    paginator = s3.get_paginator("list_objects_v2")
    for r in paginator.paginate(Bucket=MC_BUCKET_NAME, Prefix="jsonl/", Delimiter="/"):
        for f in r.get("CommonPrefixes", []):
            testnames.add(f["Prefix"].split("/")[-2])
    return testnames


def get_search_prefixes(testnames: Set[str], ccs: Set[str]) -> List[str]:
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


def get_jsonl_prefixes(
    ccs: Set[str], testnames: Set[str], start_day: date, end_day: date
) -> List[str]:
    legacy_prefixes = [
        f"raw/{d:%Y%m%d}"
        for d in date_interval(max(date(2020, 10, 20), start_day), end_day)
    ]
    if not testnames:
        testnames = list_all_testnames()
    prefixes = []
    if start_day < date(2020, 10, 21):
        prefixes = get_search_prefixes(testnames, ccs)
        combos = list(itertools.product(prefixes, date_interval(start_day, end_day)))
        # This results in a faster listing in cases where we need only a small time
        # window or few testnames. For larger windows of time, we are better off
        # just listing everything.
        if len(combos) > 1_000_000:  # XXX we might want to tweak this parameter a bit
            prefixes = [f"{p}{d:%Y%m%d}" for p, d in combos]

    return prefixes + legacy_prefixes


def iter_file_entries(prefix: str) -> Generator[FileEntry, None, None]:
    paginator = s3.get_paginator("list_objects_v2")
    for r in paginator.paginate(Bucket=MC_BUCKET_NAME, Prefix=prefix):
        for f in r.get("Contents", []):
            s3path = f["Key"]
            filename = s3path.split("/")[-1]
            parts = filename.split("_")
            test_name, _, _, ext = parts[2].split(".", 3)
            file_entry = FileEntry(
                # We need to truncate the first 8 chars, because of
                # inconsitencies between the old and new filenames
                day=datetime.strptime(parts[0][:8], "%Y%m%d").date(),
                country_code=parts[1],
                test_name=test_name,
                filename=filename,
                s3path=s3path,
                size=f["Size"],
                ext=ext,
                bucket_name=MC_BUCKET_NAME,
            )
            yield file_entry


def list_file_entries(prefix):
    return [fe for fe in iter_file_entries(prefix)]


def jsonl_in_range(
    ccs: Set[str], testnames: Set[str], start_day: date, end_day: date
) -> Generator[FileEntry, None, None]:
    prefix_list = get_jsonl_prefixes(ccs, testnames, start_day, end_day)
    print(f"Listing {len(prefix_list)} prefixes")
    for prefix in prefix_list:
        for file_entry in iter_file_entries(prefix):
            if file_entry.ext != "jsonl.gz":
                continue

            if not file_entry.matches_filter(ccs, testnames):
                continue

            if file_entry.day < start_day or file_entry.day >= end_day:
                continue

            if file_entry.size > 0:
                yield file_entry


def iter_raw_measurements(
    ccs: Set[str], testnames: Set[str], start_day: date, end_day: date
) -> Generator[bytes, None, None]:
    for fe in jsonl_in_range(ccs, testnames, start_day, end_day):
        out_file = io.BytesIO()
        s3.download_fileobj(fe.bucket_name, fe.s3path, out_file)

        yield from filter(
            lambda x: x != b"", gzip.decompress(out_file.getvalue()).split(b"\n")
        )
