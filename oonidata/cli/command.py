import sys
import gzip
import logging
import multiprocessing
from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime
from typing import List, Optional

import click

from oonidata import __version__
from oonidata.dataclient import (
    date_interval,
    sync_measurements,
)
from oonidata.db.connections import CSVConnection, ClickhouseConnection
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.processing import process_day


log = logging.getLogger("oonidata")

log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


def _parse_date(ctx, param, date_str: str) -> date:
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def _parse_csv(ctx, param, s: Optional[str]) -> List[str]:
    if s:
        return s.split(",")
    return []


probe_cc_option = click.option(
    "--probe-cc",
    callback=_parse_csv,
    help="two letter country code, can be comma separated for a list (eg. IT,US). If omitted will select process all countries.",
)
test_name_option = click.option(
    "--test-name",
    type=str,
    callback=_parse_csv,
    help="test_name you care to process, can be comma separated for a list (eg. web_connectivity,whatsapp). If omitted will select process all test names.",
)
start_day_option = click.option(
    "--start-day",
    default=date.today() - timedelta(days=14),
    callback=_parse_date,
    help="""the timestamp of the day for which we should start processing data (inclusive).

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)
end_day_option = click.option(
    "--end-day",
    default=date.today() + timedelta(days=1),
    callback=_parse_date,
    help="""the timestamp of the day for which we should start processing data (inclusive). 

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)


@click.group()
@click.version_option(__version__)
def cli():
    pass


@cli.command()
@click.option("--output-dir", type=Path, required=True)
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@click.option("--max-string-size", type=int)
def sync(
    output_dir: Path,
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    max_string_size: Optional[int] = None,
):
    """
    Sync OONI measurements to a directory
    """
    click.echo(
        f"Downloading measurements for {start_day} - {end_day} into {output_dir}"
    )
    if probe_cc:
        click.echo(f"probe_cc: {','.join(probe_cc)}")
    if test_name:
        click.echo(f"test_name: {','.join(test_name)}")

    sync_measurements(
        output_dir=output_dir,
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        max_string_size=max_string_size,
    )


def processing_worker(
    day_queue: multiprocessing.Queue,
    data_dir: Path,
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: Optional[str],
    csv_dir: Optional[str],
    start_at_idx: int,
    fast_fail: bool,
):
    fingerprintdb = FingerprintDB(datadir=data_dir, download=False)
    netinfodb = NetinfoDB(datadir=data_dir, download=False)

    if clickhouse:
        db = ClickhouseConnection(clickhouse)
    elif csv_dir:
        db = CSVConnection(csv_dir)
    else:
        raise Exception("Missing --csv-dir or --clickhouse")

    while True:
        day = day_queue.get(block=True)
        if day == None:
            break
        process_day(
            db,
            fingerprintdb,
            netinfodb,
            day,
            test_name=test_name,
            probe_cc=probe_cc,
            start_at_idx=start_at_idx,
            fast_fail=fast_fail,
        )

    db.close()


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@click.option("--csv-dir", type=Path)
@click.option("--clickhouse", type=str)
@click.option(
    "--data-dir",
    type=Path,
    required=True,
    help="data directory to store fingerprint and geoip databases",
)
@click.option(
    "--parallelism",
    type=int,
    help="number of processes to use. Only works when writing to a database",
)
@click.option("--start-at-idx", type=int, default=0)
@click.option("--fast-fail", default=False)
def mkobs(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    csv_dir: Optional[Path],
    clickhouse: Optional[str],
    data_dir: Path,
    parallelism: int,
    start_at_idx: int,
    fast_fail: bool,
):
    """
    Make observations for OONI measurements and write them into clickhouse or a CSV file
    """
    FingerprintDB(datadir=data_dir, download=True)
    NetinfoDB(datadir=data_dir, download=True)

    if csv_dir:
        click.echo(
            "When generating CSV outputs we currently only support parallelism of 1"
        )
        parallelism = 1

    day_queue = multiprocessing.Queue()
    pool = multiprocessing.Pool(
        processes=parallelism,
        initializer=processing_worker,
        initargs=(
            day_queue,
            data_dir,
            probe_cc,
            test_name,
            clickhouse,
            csv_dir,
            start_at_idx,
            fast_fail,
        ),
    )
    for day in date_interval(start_day, end_day):
        day_queue.put(day)

    for _ in range(parallelism):
        day_queue.put(None)

    day_queue.close()
    day_queue.join_thread()

    pool.close()
    pool.join()


if __name__ == "__main__":
    cli()
