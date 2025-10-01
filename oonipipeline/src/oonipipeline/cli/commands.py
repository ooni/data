import logging
from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime, timezone

import click
from click_loglevel import LogLevel

from oonipipeline.cli.utils import build_timestamps, build_date_range
from oonipipeline.db.maintenance import (
    optimize_all_tables_by_partition,
    list_partitions_to_delete,
    list_duplicates_in_buckets,
)
from oonipipeline.tasks.common import OptimizeTablesParams, optimize_tables
from oonipipeline.tasks.observations import (
    MakeObservationsParams,
    make_observations,
)
from oonipipeline.tasks.analysis import (
    MakeAnalysisParams,
    make_analysis,
)
from oonipipeline.analysis.detector import run_detector
from tqdm import tqdm

from ..__about__ import VERSION
from ..db.connections import ClickhouseConnection
from ..db.create_tables import make_create_queries, list_all_table_diffs
from ..netinfo import NetinfoDB
from ..settings import config


def _parse_csv(ctx, param, s: Optional[str]) -> List[str]:
    if s:
        return s.split(",")
    return []


def _to_utc(ctx, param, d: datetime) -> datetime:
    return d.replace(tzinfo=timezone.utc)


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
start_at_option = click.option(
    "--start-at",
    type=click.DateTime(),
    callback=_to_utc,
    default=str(datetime.now(timezone.utc).date() - timedelta(days=14)),
    help="""the timestamp of the day for which we should start processing data (inclusive).

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)
end_at_option = click.option(
    "--end-at",
    type=click.DateTime(),
    callback=_to_utc,
    default=str(datetime.now(timezone.utc).date() + timedelta(days=1)),
    help="""the timestamp of the day for which we should start processing data (inclusive). 

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)
start_workers_option = click.option("--start-workers/--no-start-workers", default=True)

def maybe_create_delete_tables(
    clickhouse_url: str,
    create_tables: bool,
    drop_tables: bool,
):
    if create_tables:
        if drop_tables:
            click.confirm(
                "Are you sure you want to drop the tables before creation?", abort=True
            )

        with ClickhouseConnection(clickhouse_url) as db:
            for query, table_name in make_create_queries():
                if drop_tables:
                    db.execute(f"DROP TABLE IF EXISTS {table_name};")
                db.execute(query)


@click.group()
@click.option(
    "-l",
    "--log-level",
    type=LogLevel(),
    default="INFO",
    help="Set logging level",
    show_default=True,
)
@click.version_option(VERSION)
def cli(log_level: int):
    logging.basicConfig(level=log_level)


@cli.command()
@start_at_option
@end_at_option
@probe_cc_option
@test_name_option
@click.option("--workflow-name", type=str, required=True, default="observations")
@click.option(
    "--only-observations",
    is_flag=True,
    default=False,
    help="should we only run the observations generation workflow?",
)
@click.option(
    "--only-analysis",
    is_flag=True,
    default=False,
    help="should we only run the analysis workflow?",
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
def run(
    probe_cc: List[str],
    test_name: List[str],
    workflow_name: str,
    start_at: datetime,
    end_at: datetime,
    only_observations: bool,
    only_analysis: bool,
    create_tables: bool,
    drop_tables: bool,
):
    """
    Process OONI measurements and write them into clickhouse
    """
    click.echo(f"Runnning workflow {workflow_name}")

    maybe_create_delete_tables(
        clickhouse_url=config.clickhouse_url,
        create_tables=create_tables,
        drop_tables=drop_tables,
    )

    last_month = None
    for timestamp, current_day in tqdm(build_timestamps(start_at, end_at)):
        click.echo(f"Processing {timestamp}")
        if not only_analysis:
            make_observations(
                MakeObservationsParams(
                    probe_cc=probe_cc,
                    test_name=test_name,
                    clickhouse=config.clickhouse_url,
                    data_dir=config.data_dir,
                    fast_fail=False,
                    bucket_date=timestamp,
                )
            )
            click.echo("finished running make_observations")

        if not only_observations:
            make_analysis(
                MakeAnalysisParams(
                    clickhouse_url=config.clickhouse_url,
                    probe_cc=probe_cc,
                    test_name=test_name,
                    timestamp=timestamp,
                )
            )
            click.echo("finished running make_analysis")

        def optimize_params(partition_str: str):
            return OptimizeTablesParams(
                clickhouse=config.clickhouse_url,
                table_names=[
                    "obs_web",
                    "obs_web_ctrl",
                    "obs_http_middlebox",
                    "analysis_web_measurement",
                ],
                partition_str=partition_str,
            )

        # optimize tables at the end of the month
        # this is done using the PARTITION key to remove duplicate entries that
        # may have been inserted during reprocessing
        if last_month is None:
            last_month = current_day.month
        elif last_month != current_day.month:
            partition_str = current_day.strftime("%Y%m")
            click.echo(f"optimizing tables with {partition_str}")
            optimize_tables(optimize_params(partition_str))
            click.echo("finished optimizing tables")
            last_month = current_day.month

    # Ensure the last month in the range is also optimized
    partition_str = current_day.strftime("%Y%m")
    click.echo(f"optimizing tables with {partition_str}")
    optimize_tables(optimize_params(partition_str))
    click.echo("finished optimizing tables")

    click.echo("finished all runs")


@cli.command()
@click.option(
    "--create-tables/--no-create-tables",
    default=False,
    help="should we attempt to create the required clickhouse tables",
)
@click.option(
    "--drop-tables/--no-drop-tables",
    default=False,
    help="should we drop tables before creating them",
)
@click.option(
    "--print-create/--no-print-create",
    default=True,
    help="should we print the create table queries",
)
@click.option(
    "--print-diff/--no-print-diff",
    default=False,
    help="should we print the table diff",
)
def checkdb(
    create_tables: bool, drop_tables: bool, print_create: bool, print_diff: bool
):
    """
    Check if the database tables require migrations. If the create-tables flag
    is not specified, it will not perform any operations.
    """
    if print_create:
        for query, table_name in make_create_queries():
            click.echo(f"## Create for {table_name}")
            click.echo(query)

    if create_tables or drop_tables:
        maybe_create_delete_tables(
            clickhouse_url=config.clickhouse_url,
            create_tables=create_tables,
            drop_tables=drop_tables,
        )

    if print_diff:
        with ClickhouseConnection(config.clickhouse_url) as db:
            list_all_table_diffs(db)


@cli.command()
@start_at_option
@end_at_option
@click.option(
    "--optimize/--no-optimize",
    default=False,
    help="should we perform an optimization of the tables as well",
)
def check_duplicates(start_at: datetime, end_at: datetime, optimize: bool):
    """
    Perform checks on the bucket ranges to ensure no duplicate entries are
    present. This is useful when backfilling the database to make sure the
    optimize operations have converged.
    """
    duplicates = list_duplicates_in_buckets(
        clickhouse_url=config.clickhouse_url,
        start_bucket=start_at,
        end_bucket=end_at,
    )
    found_duplicates = False
    for count, bucket_date in duplicates:
        if count > 0:
            found_duplicates = True
            click.echo(f"* {bucket_date}: {count}")
    if not found_duplicates:
        click.echo("no duplicates found")
    if optimize:
        optimize_all_tables_by_partition(
            clickhouse_url=config.clickhouse_url,
            partition_list=list_partitions_to_delete(duplicates),
        )


@cli.command()
@start_at_option
@end_at_option
@probe_cc_option
def event_detector(start_at: datetime, end_at: datetime, probe_cc: List[str]):
    if start_at < end_at:
        raise click.BadParameter(f"start_at ({start_at}) should be < end_at {end_at}")

    for start_dt, end_dt in tqdm(build_date_range(start_at, end_at, day_delta=10)):
        click.echo(f"Processing {start_dt} - {end_dt}")
        run_detector(
            clickhouse_url=config.clickhouse_url,
            start_time=start_dt,
            end_time=end_dt,
            probe_cc=probe_cc,
        )
