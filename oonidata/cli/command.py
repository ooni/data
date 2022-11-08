import sys
import gzip
import logging
import multiprocessing
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime
from typing import List, Optional

import orjson
import click
from tqdm.contrib.logging import tqdm_logging_redirect

from oonidata import __version__
from oonidata.dataclient import (
    FileEntry,
    get_file_entries,
    iter_measurements,
    date_interval,
)
from oonidata.datautils import trim_measurement
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


def make_filename(max_string_size: Optional[int], fe: FileEntry) -> str:
    flags = ""
    if max_string_size:
        flags = f"_max{max_string_size}"
    ts = fe.timestamp.strftime("%Y%m%d%H")
    filename = f"{ts}_{fe.probe_cc}_{fe.testname}{flags}.jsonl.gz"
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

    output_path = output_dir / make_filename(max_string_size, fe_list[0])

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
            if (
                output_dir
                / fe.testname
                / fe.timestamp.strftime("%Y%-m-%d")
                / make_filename(max_string_size, fe)
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
def process(
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
    Process OONI measurements to clickhouse or csv
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
