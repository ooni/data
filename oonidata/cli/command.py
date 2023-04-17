import logging
import multiprocessing
from pathlib import Path
import sys
from typing import List, Optional
from datetime import date, timedelta, datetime
from typing import List, Optional

import click

from oonidata import __version__
from oonidata.dataclient import (
    sync_measurements,
)
from oonidata.db.connections import ClickhouseConnection
from oonidata.db.create_tables import create_queries
from oonidata.netinfo import NetinfoDB
from oonidata.workers import (
    start_experiment_result_maker,
    start_fingerprint_hunter,
    start_observation_maker,
    start_ground_truth_builder,
    start_response_archiver,
)
from oonidata.workers.analysis import start_analysis


log = logging.getLogger("oonidata")


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
@click.option("--error-log-file", type=Path)
@click.version_option(__version__)
def cli(error_log_file: Path):
    log.addHandler(logging.StreamHandler(sys.stderr))
    log.setLevel(logging.INFO)
    if error_log_file:
        logging.basicConfig(
            filename=error_log_file, encoding="utf-8", level=logging.ERROR
        )


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
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use. Only works when writing to a database",
)
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
    parallelism: int,
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

        with ClickhouseConnection(clickhouse) as db:
            for query, table_name in create_queries:
                if drop_tables:
                    db.execute(f"DROP TABLE IF EXISTS {table_name};")
                db.execute(query)

    NetinfoDB(datadir=data_dir, download=True)

    start_observation_maker(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        csv_dir=csv_dir,
        clickhouse=clickhouse,
        data_dir=data_dir,
        parallelism=parallelism,
        fast_fail=fast_fail,
    )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@click.option("--clickhouse", type=str, required=True)
@click.option(
    "--data-dir",
    type=Path,
    required=True,
    help="data directory to store fingerprint and geoip databases",
)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count(),
    help="number of processes to use. Only works when writing to a database",
)
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
    "--rebuild-ground-truths",
    is_flag=True,
    help="should we force the rebuilding of ground truths",
)
def mker(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    clickhouse: str,
    data_dir: Path,
    parallelism: int,
    fast_fail: bool,
    create_tables: bool,
    rebuild_ground_truths: bool,
):
    if create_tables:
        with ClickhouseConnection(clickhouse) as db:
            for query, table_name in create_queries:
                click.echo(f"Running create query for {table_name}")
                db.execute(query)

    start_experiment_result_maker(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        clickhouse=clickhouse,
        data_dir=data_dir,
        parallelism=parallelism,
        fast_fail=fast_fail,
        rebuild_ground_truths=rebuild_ground_truths,
    )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@click.option("--clickhouse", type=str, required=True)
@click.option(
    "--data-dir",
    type=Path,
    required=True,
    help="data directory to store fingerprint and geoip databases",
)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use. Only works when writing to a database",
)
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
    "--rebuild-ground-truths",
    is_flag=True,
    help="should we force the rebuilding of ground truths",
)
def mkanalysis(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    clickhouse: str,
    data_dir: Path,
    parallelism: int,
    fast_fail: bool,
    create_tables: bool,
    rebuild_ground_truths: bool,
):
    if create_tables:
        with ClickhouseConnection(clickhouse) as db:
            for query, table_name in create_queries:
                click.echo(f"Running create query for {table_name}")
                db.execute(query)

    start_analysis(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        clickhouse=clickhouse,
        data_dir=data_dir,
        parallelism=parallelism,
        fast_fail=fast_fail,
        rebuild_ground_truths=rebuild_ground_truths,
    )


@cli.command()
@start_day_option
@end_day_option
@click.option("--clickhouse", type=str, required=True)
@click.option(
    "--data-dir",
    type=Path,
    required=True,
    help="data directory to store fingerprint and geoip databases",
)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use. Only works when writing to a database",
)
def mkgt(
    start_day: date,
    end_day: date,
    clickhouse: str,
    data_dir: Path,
    parallelism: int,
):
    start_ground_truth_builder(
        start_day=start_day,
        end_day=end_day,
        clickhouse=clickhouse,
        data_dir=data_dir,
        parallelism=parallelism,
    )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@click.option("--clickhouse", type=str)
@click.option("--data-dir", type=Path, required=True)
@click.option("--archives-dir", type=Path, required=True)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use. Only works when writing to a database",
)
def mkbodies(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    clickhouse: str,
    data_dir: Path,
    archives_dir: Path,
    parallelism: int,
):
    """
    Make response body archives
    """
    start_response_archiver(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        data_dir=data_dir,
        archives_dir=archives_dir,
        clickhouse=clickhouse,
        parallelism=parallelism,
    )


@cli.command()
@click.option(
    "--data-dir",
    type=Path,
    required=True,
    help="data directory to store fingerprint and geoip databases",
)
@click.option("--archives-dir", type=Path, required=True)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use",
)
def fphunt(data_dir: Path, archives_dir: Path, parallelism: int):

    click.echo("🏹 starting the hunt for blockpage fingerprints!")
    start_fingerprint_hunter(
        archives_dir=archives_dir,
        data_dir=data_dir,
        parallelism=parallelism,
    )


if __name__ == "__main__":
    cli()
