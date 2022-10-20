import argparse
import gzip
import logging
import multiprocessing
from pathlib import Path
import sys
from typing import List, Tuple
from functools import partial
from datetime import date, timedelta, datetime
from collections import defaultdict

import orjson

from oonidata.dataclient import (
    get_file_entries,
    iter_measurements,
    FileEntry,
)
from oonidata.datautils import trim_measurement

from tqdm.contrib.logging import tqdm_logging_redirect


log = logging.getLogger("oonidata")
logging.basicConfig(level=logging.INFO)


def make_filename(args, fe):
    flags = ""
    if args.max_string_size:
        flags = f"_max{args.max_string_size}"
    ts = fe.timestamp.strftime("%Y%m%d%H")
    filename = f"{ts}_{fe.probe_cc}_{fe.testname}{flags}.jsonl.gz"
    return filename


def download_file_entry_list(fe_list: List[FileEntry], args):
    """
    Download a list of file entries to the output dir.

    It assumes that the list of file entries in the list are all pertinent to
    the same testname, probe_cc, hour tuple
    """
    total_fe_size = 0
    output_dir = (
        args.output_dir
        / fe_list[0].testname
        / fe_list[0].timestamp.strftime("%Y-%m-%d")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / make_filename(args, fe_list[0])

    with gzip.open(output_path.with_suffix(".tmp"), "wb") as out_file:
        for fe in fe_list:
            assert fe.testname == fe_list[0].testname
            assert fe.timestamp == fe_list[0].timestamp
            assert fe.probe_cc == fe_list[0].probe_cc
            total_fe_size += fe.size

        for msmt_dict in iter_measurements(
            start_day=args.start_day,
            end_day=args.end_day,
            probe_cc=args.probe_cc,
            test_name=args.test_name,
            file_entries=fe_list,
        ):
            if args.max_string_size:
                msmt_dict = trim_measurement(msmt_dict, args.max_string_size)
            out_file.write(orjson.dumps(msmt_dict))
            out_file.write(b"\n")

    output_path.with_suffix(".tmp").rename(output_path)
    return total_fe_size


def sync(args):
    log.info(
        f"Downloading measurement in s3 for {args.start_day} - {args.end_day} probe_cc:"
        f" {args.probe_cc}"
    )
    testnames = set()
    if args.test_name is not None:
        testnames = set(list(map(lambda x: x.lower().replace("_", ""), args.test_name)))

    ccs = set()
    if args.probe_cc is not None:
        ccs = set(list(map(lambda x: x.upper(), args.probe_cc)))

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

        log.info("Listing file entries...")
        all_file_entries = get_file_entries(
            start_day=args.start_day,
            end_day=args.end_day,
            ccs=ccs,
            testnames=testnames,
            from_cans=True,
            progress_callback=cb_list_fe,
        )

        total_fe_size = 0
        to_download_fe = defaultdict(list)
        for fe in all_file_entries:
            if (
                args.output_dir
                / fe.testname
                / fe.timestamp.strftime("%Y%-m-%d")
                / make_filename(args, fe)
            ).exists():
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
                    args=args,
                ),
                to_download_fe.values(),
            ):
                download_count += 1
                pbar.update(fe_size)
                pbar.set_description(
                    f"downloaded {download_count}/{len(to_download_fe)}"
                )


def _parse_date_flag(date_str: str) -> date:
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def _parse_csv(s: str) -> List[str]:
    return s.split(",")


def main():
    parser = argparse.ArgumentParser("OONI Data tools")
    parser.set_defaults(func=lambda r: parser.print_usage())

    subparsers = parser.add_subparsers()

    parser_sync = subparsers.add_parser(
        "sync", help="Sync OONI measurements to a directory"
    )
    parser_sync.add_argument(
        "--probe-cc",
        type=_parse_csv,
        help="two letter country code, can be comma separated for a list (eg. IT,US). If omitted will select process all countries.",
    )

    parser_sync.add_argument(
        "--test-name",
        type=_parse_csv,
        help="test_name you care to process, can be comma separated for a list (eg. web_connectivity,whatsapp). If omitted will select process all test names.",
    )
    parser_sync.add_argument(
        "--start-day",
        type=_parse_date_flag,
        default=date.today() - timedelta(days=14),
        help=(
            "the timestamp of the day for which we should start processing data (inclusive). "
            "Note: this is the upload date, which doesn't necessarily match the measurement date."
        ),
    )
    parser_sync.add_argument(
        "--end-day",
        type=_parse_date_flag,
        default=date.today() + timedelta(days=1),
        help="the timestamp of the day for which we should stop processing data, this date is not included.",
    )

    parser_sync.add_argument("--max-string-size", type=int)
    parser_sync.add_argument("--output-dir", type=Path, required=True)
    parser_sync.add_argument("--debug", action="store_true")
    parser_sync.set_defaults(func=sync)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
