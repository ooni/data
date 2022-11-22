import logging
import multiprocessing
from pathlib import Path
import traceback
from typing import List, Optional
from datetime import date, timedelta, datetime
from typing import List, Optional

import click

from oonidata import __version__
from oonidata.dataclient import (
    date_interval,
    sync_measurements,
)
from oonidata.dataformat import WebConnectivity
from oonidata.db.connections import CSVConnection, ClickhouseConnection
from oonidata.db.create_tables import create_queries
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.processing import ResponseArchiver, process_day


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
    day_queue: multiprocessing.JoinableQueue,
    archiver_queue: Optional[multiprocessing.JoinableQueue],
    data_dir: Path,
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: Optional[str],
    csv_dir: Optional[str],
    start_at_idx: int,
    fast_fail: bool,
):
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
            day_queue.task_done()
            break
        for msmt in process_day(
            db=db,
            netinfodb=netinfodb,
            day=day,
            test_name=test_name,
            probe_cc=probe_cc,
            start_at_idx=start_at_idx,
            fast_fail=fast_fail,
        ):
            if isinstance(msmt, WebConnectivity) and msmt.test_keys.requests:
                if archiver_queue:
                    archiver_queue.put(msmt.test_keys.requests)
        day_queue.task_done()

    db.close()


def archiver_worker(
    archiver_queue: multiprocessing.Queue,
    dst_dir: Path,
    clickhouse: Optional[str],
):
    db = ClickhouseConnection(clickhouse)

    with ResponseArchiver(db, dst_dir=dst_dir) as archiver:
        while True:
            requests = archiver_queue.get(block=True)
            if requests == None:
                archiver_queue.task_done()
                break
            try:
                for http_transaction in requests:
                    archiver.archive_http_transaction(http_transaction=http_transaction)
            except Exception:
                log.error(f"failed to process {requests}")
                log.error(traceback.format_exc())
            archiver_queue.task_done()

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
@click.option("--archives-dir", type=Path)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use. Only works when writing to a database",
)
@click.option("--start-at-idx", type=int, default=0)
@click.option(
    "--fast-fail",
    is_flag=True,
    help="should we fail immediately when we encounter an error?",
)
@click.option(
    "--create-tables",
    is_flag=True,
    help="should we attempt to create the required clickhouse tables",
)
@click.option(
    "--drop-tables",
    is_flag=True,
    help="should we drop tables before creating them",
)
def mkobs(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    csv_dir: Optional[Path],
    clickhouse: Optional[str],
    data_dir: Path,
    archives_dir: Optional[Path],
    parallelism: int,
    start_at_idx: int,
    fast_fail: bool,
    create_tables: bool,
    drop_tables: bool,
):
    """
    Make observations for OONI measurements and write them into clickhouse or a CSV file
    """
    if csv_dir:
        click.echo(
            "When generating CSV outputs we currently only support parallelism of 1"
        )
        parallelism = 1

    if create_tables:
        if not clickhouse:
            click.echo("--clickhouse needs to be specified when creating tables")
            return 1
        if drop_tables:
            click.confirm(
                "Are you sure you want to drop the tables before creation?", abort=True
            )

        db = ClickhouseConnection(clickhouse)
        for query, table_name in create_queries:
            if drop_tables:
                db.execute(f"DROP TABLE IF EXISTS {table_name};")
            db.execute(query)

    FingerprintDB(datadir=data_dir, download=True)
    NetinfoDB(datadir=data_dir, download=True)

    day_queue = multiprocessing.JoinableQueue()

    archiver_queue = None
    archiver_process = None
    if archives_dir:
        archiver_queue = multiprocessing.JoinableQueue()
        archiver_process = multiprocessing.Process(
            target=archiver_worker, args=(archiver_queue, archives_dir, clickhouse)
        )
        archiver_process.start()

    pool = multiprocessing.Pool(
        processes=parallelism,
        initializer=processing_worker,
        initargs=(
            day_queue,
            archiver_queue,
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

    day_queue.join()
    pool.close()
    log.info("waiting for the worker processes to finish")
    pool.join()

    log.info("shutting down the archiving process")
    if archiver_process and archiver_queue:
        # Singal the archiver we have put everything in it
        archiver_queue.put(None)
        archiver_queue.join()
        archiver_process.join()
        archiver_process.close()


if __name__ == "__main__":
    cli()
