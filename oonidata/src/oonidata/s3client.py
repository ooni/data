import gzip
import io
import logging
import pathlib
import shutil
import tarfile
from datetime import date, datetime
from typing import Generator, List, Optional, Set
from urllib.parse import urlparse

import boto3
from botocore import UNSIGNED as botoSigUNSIGNED
from botocore.config import Config as botoConfig

import lz4.frame
import orjson

from .datautils import trivial_id
from .legacy.normalize_yamlooni import iter_yaml_msmt_normalized

log = logging.getLogger(__name__)

LEGACY_BUCKET_NAME = "ooni-data"
NEW_BUCKET_NAME = "ooni-data-eu-fra"


def read_to_bytesio(body: io.BytesIO) -> io.BytesIO:
    read_body = io.BytesIO()
    shutil.copyfileobj(body, read_body)
    read_body.seek(0)
    del body
    return read_body


def stream_jsonl(body: io.BytesIO) -> Generator[dict, None, None]:
    """
    JSONL is the most simple OONI measurement format. They are basically just a
    bunch of report files concatenated together for the same test_name, country,
    timestamp and compressed with gzip.
    """
    with gzip.GzipFile(fileobj=body) as in_file:
        for line in in_file:
            if line == "":
                continue
            yield orjson.loads(line)


def stream_postcan(body: io.BytesIO) -> Generator[dict, None, None]:
    """
    Postcans are the newer format, where each individual measurement entry has
    it's own file inside of a tarball.

    Here is an example of the tar layout:

    $ tar tf 2024030100_AM_webconnectivity.n1.0.tar.gz | head -n 3
    var/lib/ooniapi/measurements/incoming/2024030100_AM_webconnectivity/20240301003627.966169_AM_webconnectivity_76f66893a38a3de6.post
    var/lib/ooniapi/measurements/incoming/2024030100_AM_webconnectivity/20240301003629.092464_AM_webconnectivity_48be39a609d1dcb7.post
    var/lib/ooniapi/measurements/incoming/2024030100_AM_webconnectivity/20240301003630.694204_AM_webconnectivity_a95c7da2775bf109.post

    You should not expect the prefix of
    `var/lib/ooniapi/measurement/incoming/XXX` to remain constant over time, but
    rather you should only use the last of the file name to determine the
    measurement ID
    `20240301003630.694204_AM_webconnectivity_a95c7da2775bf109.post`.

    Each `.post` file is a JSON document, which contains two top level keys:

    {
        "format": "json",
        "content": {
        }
    }

    Format is always set to `json` and content as the data for the actual
    measurement.

    FIXME
    Some older postcans have the .gz extension, but are actually not
    compressed, tar needs to be able to re-seek back to the beginning of the
    file in the event of it not finding the gzip magic header when operating in
    "transparent compression mode". When we we fix that in the source data, we
    might be able to avoid this.
    """
    with tarfile.open(fileobj=body, mode="r|*") as tar:
        for m in tar:
            assert m.name.endswith(".post"), f"{m.name} doesn't end with .post"
            in_file = tar.extractfile(m)

            assert in_file is not None, "found empty tarfile in {m.name}"

            j = orjson.loads(in_file.read())
            assert j["format"] == "json", "postcan with non json format"

            msmt = j["content"]
            # extract msmt_uid from filename e.g:
            # ... /20210614004521.999962_JO_signal_68eb19b439326d60.post
            msmt_uid = pathlib.PurePath(m.name).with_suffix("").name
            msmt["measurement_uid"] = msmt_uid
            yield msmt


def stream_jsonlz4(body: io.BytesIO):
    """
    lz4.frame requires the input stream to be seekable, so we need to load it
    in memory
    """
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


def stream_yamllz4(body: io.BytesIO):
    """
    lz4.frame requires the input stream to be seekable, so we need to load it
    in memory
    """
    read_body = read_to_bytesio(body)

    with lz4.frame.open(read_body) as in_file:
        # The normalize function already add the measurement_uid
        yield from iter_yaml_msmt_normalized(in_file)


def stream_oldcan(body: io.BytesIO) -> Generator[dict, None, None]:
    """
    lz4.frame requires the input stream to be seekable, so we need to load it
    in memory.
    """
    read_body = read_to_bytesio(body)

    with lz4.frame.open(read_body) as lz4_file:
        with tarfile.open(fileobj=lz4_file) as tar:  # type: ignore due to bad types in lz4
            for m in tar:
                in_file = tar.extractfile(m)
                assert in_file is not None, "{m.name} is None"

                if m.name.endswith(".json"):
                    for line in in_file:
                        msmt = orjson.loads(line)
                        msmt_uid = trivial_id(line, msmt)
                        msmt["measurement_uid"] = msmt_uid
                        yield msmt

                elif m.name.endswith(".yaml"):
                    # The normalize function already add the measurement_uid
                    yield from iter_yaml_msmt_normalized(in_file)


def create_s3_anonymous_client():
    return boto3.client("s3", config=botoConfig(signature_version=botoSigUNSIGNED))


class OONIMeasurementLister:
    def __init__(
        self,
        *,
        probe_cc_filter: Optional[set] = None,
        test_name_filter: Optional[set] = None,
    ):
        self.s3 = create_s3_anonymous_client()
        self.probe_cc_filter = probe_cc_filter
        self.test_name_filter = test_name_filter

    def get_body(self, bucket_name: str, key: str) -> io.BytesIO:
        return self.s3.get_object(Bucket=bucket_name, Key=key)["Body"]

    def apply_filter(self, stream_func, body):
        """
        Some of the formats don't support doing filtering by path, so we
        do it here as well.
        """
        for msmt in stream_func(body):

            if (
                self.probe_cc_filter is not None
                and msmt["probe_cc"] not in self.probe_cc_filter
            ):
                continue

            if (
                self.test_name_filter is not None
                and msmt["test_name"] not in self.test_name_filter
            ):
                continue

            yield msmt

    def measurements(self, s3_url: str):
        u = urlparse(s3_url)
        bucket_name = u.netloc
        assert u.scheme == "s3", "must be s3 URL"
        assert bucket_name in ["ooni-data-eu-fra", "ooni-data"]

        body = self.get_body(bucket_name=bucket_name, key=u.path)
        s3path = pathlib.PurePath(u.path)

        stream_func = None
        if s3path.name.endswith("jsonl.gz"):
            stream_func = stream_jsonl
        elif s3path.name.endswith("tar.gz"):
            stream_func = stream_postcan
        elif s3path.name.endswith("tar.lz4"):
            stream_func = stream_oldcan
        elif s3path.name.endswith("json.lz4"):
            stream_func = stream_jsonlz4
        elif s3path.name.endswith("yaml.lz4"):
            stream_func = stream_yamllz4

        assert stream_func is not None, f"invalid format for {s3path.name}"
        yield from self.apply_filter(stream_func, body)


def get_v2_search_prefixes(s3, testnames: Set[str], ccs: Set[str]) -> List[str]:
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
            Bucket=NEW_BUCKET_NAME, Prefix=f"jsonl/{tn}/", Delimiter="/"
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
) -> List[str]:
    legacy_prefixes = [
        Prefix(bucket_name=NEW_BUCKET_NAME, prefix=f"raw/{d:%Y%m%d}")
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
                Prefix(bucket_name=NEW_BUCKET_NAME, prefix=f"{p}{d:%Y%m%d}")
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
        Prefix(prefix=f"canned/{d:%Y-%m-%d}", bucket_name=NEW_BUCKET_NAME)
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


def make_measurement_listers(
    bucket_start_day: date,
    bucket_end_day: date,
    probe_cc_filter: Optional[set] = None,
    test_name_filter: Optional[set] = None,
):
    start_timestamp = datetime.combine(bucket_start_day, datetime.min.time())
    end_timestamp = datetime.combine(bucket_end_day, datetime.min.time())

    prefix_list = get_v2_prefixes(ccs, testnames, start_day, end_day)
    if from_cans == True:
        prefix_list = get_can_prefixes(start_day, end_day) + prefix_list

    log.debug(f"using prefix list {prefix_list}")
    file_entries = []
    prefix_idx = 0
    total_prefixes = len(prefix_list)
