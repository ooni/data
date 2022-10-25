import argparse
import logging
import multiprocessing
from pathlib import Path
import sys
from datetime import date, timedelta, datetime
from typing import List

from oonidata.cli.sync import run_sync
from oonidata.cli.process import run_process

log = logging.getLogger("oonidata")

log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


def _parse_date_flag(date_str: str) -> date:
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def _parse_csv(s: str) -> List[str]:
    return s.split(",")


def arg_test_name(p: argparse.ArgumentParser):
    p.add_argument(
        "--test-name",
        type=_parse_csv,
        help="test_name you care to process, can be comma separated for a list (eg. web_connectivity,whatsapp). If omitted will select process all test names.",
    )


def arg_start_day(p: argparse.ArgumentParser):
    p.add_argument(
        "--start-day",
        type=_parse_date_flag,
        default=date.today() - timedelta(days=14),
        help=(
            "the timestamp of the day for which we should start processing data (inclusive). "
            "Note: this is the upload date, which doesn't necessarily match the measurement date."
        ),
    )


def arg_end_day(p: argparse.ArgumentParser):
    p.add_argument(
        "--end-day",
        type=_parse_date_flag,
        default=date.today() + timedelta(days=1),
        help="the timestamp of the day for which we should stop processing data, this date is not included.",
    )


def arg_probe_cc(p: argparse.ArgumentParser):
    p.add_argument(
        "--probe-cc",
        type=_parse_csv,
        help="two letter country code, can be comma separated for a list (eg. IT,US). If omitted will select process all countries.",
    )


def main():
    parser = argparse.ArgumentParser("OONI Data tools")
    parser.set_defaults(func=lambda r: parser.print_usage())

    subparsers = parser.add_subparsers()

    # oonidata sync command
    parser_sync = subparsers.add_parser(
        "sync", help="Sync OONI measurements to a directory"
    )
    arg_probe_cc(parser_sync)
    arg_test_name(parser_sync)
    arg_start_day(parser_sync)
    arg_end_day(parser_sync)
    parser_sync.add_argument("--max-string-size", type=int)
    parser_sync.add_argument("--output-dir", type=Path, required=True)
    parser_sync.add_argument("--debug", action="store_true")
    parser_sync.set_defaults(func=run_sync)

    # oonidata process command
    parser_process = subparsers.add_parser(
        "process", help="Process OONI measurements to clickhouse or csv"
    )
    parser_process.add_argument(
        "--csv-dir",
        type=Path,
    )
    parser_process.add_argument(
        "--clickhouse",
        type=str,
    )
    parser_process.add_argument(
        "--data-dir",
        default=Path("datadir"),
        type=Path,
    )
    parser_process.add_argument(
        "--parallelism",
        type=int,
        default=multiprocessing.cpu_count(),
        help="number of processes to use. Only works when writing to a database.",
    )
    parser_process.add_argument(
        "--start-at-idx",
        type=int,
        default=0,
    )
    arg_probe_cc(parser_process)
    arg_test_name(parser_process)
    arg_start_day(parser_process)
    arg_end_day(parser_process)
    parser_process.add_argument("--only-verdicts", action="store_true")
    parser_process.add_argument("--skip-verdicts", action="store_true")
    parser_process.add_argument("--fast-fail", action="store_true")
    parser_process.set_defaults(func=run_process)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
