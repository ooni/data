import logging
import multiprocessing
from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime, timezone
from typing import List, Optional

from oonipipeline.temporal.client_operations import WorkerParams
from oonipipeline.temporal.client_operations import start_workers
from oonipipeline.temporal.client_operations import run_workflow

import click
from click_loglevel import LogLevel

from temporalio.types import SelfType


from ..temporal.workflows import (
    AnalysisBackfillWorkflow,
    BackfillWorkflowParams,
    GroundTruthsWorkflow,
    GroundTruthsWorkflowParams,
    ObservationsBackfillWorkflow,
)

from ..__about__ import VERSION
from ..db.connections import ClickhouseConnection
from ..db.create_tables import make_create_queries, list_all_table_diffs
from ..netinfo import NetinfoDB


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
    default=(date.today() - timedelta(days=14)).strftime("%Y-%m-%d"),
    help="""the timestamp of the day for which we should start processing data (inclusive).

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)
end_day_option = click.option(
    "--end-day",
    default=(date.today() + timedelta(days=1)).strftime("%Y-%m-%d"),
    help="""the timestamp of the day for which we should start processing data (inclusive). 

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)

start_at_option = click.option(
    "--start-at",
    type=click.DateTime(),
    default=str(datetime.now(timezone.utc).date() - timedelta(days=14)),
    help="""the timestamp of the day for which we should start processing data (inclusive).

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)
end_at_option = click.option(
    "--end-at",
    type=click.DateTime(),
    default=str(datetime.now(timezone.utc).date() + timedelta(days=1)),
    help="""the timestamp of the day for which we should start processing data (inclusive). 

    Note: this is the upload date, which doesn't necessarily match the measurement date.
    """,
)

clickhouse_option = click.option(
    "--clickhouse", type=str, required=True, default="clickhouse://localhost"
)
clickhouse_buffer_min_time_option = click.option(
    "--clickhouse-buffer-min-time",
    type=int,
    required=True,
    default=10,
    help="min_time for the Buffer tables in clickhouse. only applied during create. see: https://clickhouse.com/docs/en/engines/table-engines/special/buffer",
)
clickhouse_buffer_max_time_option = click.option(
    "--clickhouse-buffer-max-time",
    type=int,
    required=True,
    default=60,
    help="max_time for the Buffer tables in clickhouse. only applied during create. see: https://clickhouse.com/docs/en/engines/table-engines/special/buffer",
)
telemetry_endpoint_option = click.option(
    "--telemetry-endpoint", type=Optional[str], required=False, default=None
)
temporal_address_option = click.option(
    "--temporal-address", type=str, required=True, default="localhost:7233"
)
start_workers_option = click.option("--start-workers/--no-start-workers", default=True)

datadir_option = click.option(
    "--data-dir",
    type=str,
    required=True,
    default="tests/data/datadir",
    help="data directory to store fingerprint and geoip databases",
)
parallelism_option = click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use. Only works when writing to a database",
)


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
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@clickhouse_option
@clickhouse_buffer_min_time_option
@clickhouse_buffer_max_time_option
@datadir_option
@parallelism_option
@telemetry_endpoint_option
@temporal_address_option
@start_workers_option
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
    start_day: str,
    end_day: str,
    clickhouse: str,
    clickhouse_buffer_min_time: int,
    clickhouse_buffer_max_time: int,
    data_dir: str,
    parallelism: int,
    fast_fail: bool,
    create_tables: bool,
    drop_tables: bool,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    start_workers: bool,
):
    """
    Make observations for OONI measurements and write them into clickhouse or a CSV file
    """
    if create_tables:
        if drop_tables:
            click.confirm(
                "Are you sure you want to drop the tables before creation?", abort=True
            )

        with ClickhouseConnection(clickhouse) as db:
            for query, table_name in make_create_queries(
                min_time=clickhouse_buffer_min_time, max_time=clickhouse_buffer_max_time
            ):
                if drop_tables:
                    db.execute(f"DROP TABLE IF EXISTS {table_name};")
                db.execute(query)

    click.echo("Starting to process observations")
    NetinfoDB(datadir=Path(data_dir), download=True)
    click.echo("downloaded netinfodb")

    params = BackfillWorkflowParams(
        probe_cc=probe_cc,
        test_name=test_name,
        clickhouse=clickhouse,
        data_dir=str(data_dir),
        fast_fail=fast_fail,
        start_day=start_day,
        end_day=end_day,
    )
    click.echo(f"starting to make observations with params={params}")
    run_workflow(
        ObservationsBackfillWorkflow.run,
        params,
        parallelism=parallelism,
        workflow_id_prefix="oonipipeline-mkobs",
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        start_workers=start_workers,
    )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@clickhouse_option
@clickhouse_buffer_min_time_option
@clickhouse_buffer_max_time_option
@datadir_option
@parallelism_option
@telemetry_endpoint_option
@temporal_address_option
@start_workers_option
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
def mkanalysis(
    probe_cc: List[str],
    test_name: List[str],
    start_day: str,
    end_day: str,
    clickhouse: str,
    clickhouse_buffer_min_time: int,
    clickhouse_buffer_max_time: int,
    data_dir: Path,
    parallelism: int,
    fast_fail: bool,
    create_tables: bool,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    start_workers: bool,
):
    if create_tables:
        with ClickhouseConnection(clickhouse) as db:
            for query, table_name in make_create_queries(
                min_time=clickhouse_buffer_min_time, max_time=clickhouse_buffer_max_time
            ):
                click.echo(f"Running create query for {table_name}")
                db.execute(query)

    click.echo("Starting to perform analysis")
    NetinfoDB(datadir=Path(data_dir), download=True)
    click.echo("downloaded netinfodb")

    params = BackfillWorkflowParams(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        clickhouse=clickhouse,
        data_dir=str(data_dir),
        fast_fail=fast_fail,
    )
    run_workflow(
        AnalysisBackfillWorkflow.run,
        params,
        parallelism=parallelism,
        workflow_id_prefix="oonipipeline-mkanalysis",
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        start_workers=start_workers,
    )


@cli.command()
@start_day_option
@end_day_option
@clickhouse_option
@datadir_option
@parallelism_option
@telemetry_endpoint_option
@temporal_address_option
@start_workers_option
def mkgt(
    start_day: str,
    end_day: str,
    clickhouse: str,
    data_dir: Path,
    parallelism: int,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    start_workers: bool,
):
    click.echo("Starting to build ground truths")
    NetinfoDB(datadir=Path(data_dir), download=True)
    click.echo("downloaded netinfodb")

    params = GroundTruthsWorkflowParams(
        start_day=start_day,
        end_day=end_day,
        clickhouse=clickhouse,
        data_dir=str(data_dir),
    )
    click.echo(f"starting to make ground truths with arg={params}")
    run_workflow(
        GroundTruthsWorkflow.run,
        params,
        parallelism=parallelism,
        workflow_id_prefix="oonipipeline-mkgt",
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        start_workers=start_workers,
    )


@cli.command()
@datadir_option
@parallelism_option
@telemetry_endpoint_option
@temporal_address_option
def startworkers(
    data_dir: Path,
    parallelism: int,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
):
    click.echo(f"starting {parallelism} workers")
    click.echo(f"downloading NetinfoDB to {data_dir}")
    NetinfoDB(datadir=Path(data_dir), download=True)
    click.echo("done downloading netinfodb")
    start_workers(
        params=WorkerParams(
            temporal_address=temporal_address,
            telemetry_endpoint=telemetry_endpoint,
            thread_count=parallelism,
        ),
        process_count=parallelism,
    )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@clickhouse_option
@datadir_option
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
    # start_response_archiver(
    #     probe_cc=probe_cc,
    #     test_name=test_name,
    #     start_day=start_day,
    #     end_day=end_day,
    #     data_dir=data_dir,
    #     archives_dir=archives_dir,
    #     clickhouse=clickhouse,
    #     parallelism=parallelism,
    # )
    raise NotImplemented("TODO(art)")


@cli.command()
@datadir_option
@click.option("--archives-dir", type=Path, required=True)
@click.option(
    "--parallelism",
    type=int,
    default=multiprocessing.cpu_count() + 2,
    help="number of processes to use",
)
def fphunt(data_dir: Path, archives_dir: Path, parallelism: int):
    click.echo("🏹 starting the hunt for blockpage fingerprints!")
    # start_fingerprint_hunter(
    #     archives_dir=archives_dir,
    #     data_dir=data_dir,
    #     parallelism=parallelism,
    # )
    raise NotImplemented("TODO(art)")


@cli.command()
@click.option("--clickhouse", type=str)
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
def checkdb(
    clickhouse: Optional[str],
    create_tables: bool,
    drop_tables: bool,
):
    """
    Check if the database tables require migrations. If the create-tables flag
    is not specified, it will not perform any operations.
    """

    if create_tables:
        if not clickhouse:
            click.echo("--clickhouse needs to be specified when creating tables")
            return 1
        if drop_tables:
            click.confirm(
                "Are you sure you want to drop the tables before creation?", abort=True
            )

        with ClickhouseConnection(clickhouse) as db:
            for query, table_name in make_create_queries():
                if drop_tables:
                    db.execute(f"DROP TABLE IF EXISTS {table_name};")
                db.execute(query)

    with ClickhouseConnection(clickhouse) as db:
        list_all_table_diffs(db)
