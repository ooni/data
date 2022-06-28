import argparse
from functools import partial
import gzip
import logging
import datetime as dt
import pathlib
import sys

import ujson

from multiprocessing.pool import ThreadPool

from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from .s3feeder import (
    FileEntry,
    download_measurement_container,
)
from .s3feeder import jsonl_in_range

log = logging.getLogger("oonidata")
logging.basicConfig(level=logging.INFO)


def trim_container(s3cachedir: pathlib.Path, fe: FileEntry, max_string_size: int):
    mc = fe.output_path(s3cachedir)
    temp_path = diskf.with_suffix(".tmp")
    try:
        with gzip.open(
            temp_path, mode="wt", encoding="utf-8", newline="\n"
        ) as out_file:
            for msmt in load_multiple(mc.as_posix()):
                msmt = trim_measurement(msmt, args.max_string_size)
                ujson.dump(msmt, out_file)
                out_file.write("\n")
            temp_path.replace(mc)
    except:
        temp_path.unlink()
        raise


def download_and_trim(fe, output_dir, max_string_size):
    mc = download_measurement_container(output_dir, fe)
    if max_string_size:
        trim_container(output_dir, fe, max_string_size)


def sync(args):
    testnames = []
    if args.test_names:
        # Replace _ with a -
        testnames = list(map(lambda x: x.replace("_", ""), args.test_names))

    log.info(
        f"Listing measurement in s3 for {args.since} - {args.until} probe_cc:"
        f" {args.country_codes}"
    )
    log.info("This may take a while...")

    file_entries = list(
        jsonl_in_range(args.country_codes, testnames, args.since, args.until)
    )
    with logging_redirect_tqdm():
        func = partial(
            download_and_trim,
            output_dir=args.output_dir,
            max_string_size=args.max_string_size,
        )
        with ThreadPool() as pool:
            list(
                tqdm(
                    pool.imap_unordered(func, file_entries),
                    total=len(file_entries),
                )
            )


def _parse_date_flag(date_str: str) -> dt.date:
    return dt.datetime.strptime(date_str, "%Y-%m-%d").date()


def main():
    parser = argparse.ArgumentParser("OONI Data tools")
    parser.set_defaults(func=lambda r: parser.print_usage())

    subparsers = parser.add_subparsers()

    parser_sync = subparsers.add_parser("sync", help="Sync OONI measurements")
    parser_sync.add_argument(
        "--country-codes",
        type=str,
        nargs="*",
        help="List of probe_cc values to filter by",
    )
    parser_sync.add_argument(
        "--since",
        type=_parse_date_flag,
        default=dt.date.today() - dt.timedelta(days=14),
    )
    parser_sync.add_argument("--until", type=_parse_date_flag, default=dt.date.today())
    parser_sync.add_argument(
        "--test-names", nargs="*", help="List of test_name values to filter by"
    )
    parser_sync.add_argument("--max-string-size", type=int)
    parser_sync.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser_sync.add_argument("--debug", action="store_true")
    parser_sync.set_defaults(func=sync)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
