import logging
from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime, timezone
from typing import List, Optional

from oonipipeline.temporal.client_operations import (
    TemporalConfig,
    run_backfill,
    run_create_schedules,
    run_status,
    run_reschedule,
)
from oonipipeline.temporal.workers import start_workers

import click
from click_loglevel import LogLevel


from ..__about__ import VERSION
from ..db.connections import ClickhouseConnection
from ..db.create_tables import make_create_queries, list_all_table_diffs
from ..netinfo import NetinfoDB
from ..settings import config

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
start_workers_option = click.option("--start-workers/--no-start-workers", default=True)

def maybe_create_delete_tables(
    clickhouse_url: str,
    create_tables: bool,
    drop_tables: bool,
    clickhouse_buffer_min_time: int = 10,
    clickhouse_buffer_max_time: int = 60,
):
    if create_tables:
        if drop_tables:
            click.confirm(
                "Are you sure you want to drop the tables before creation?", abort=True
            )

        with ClickhouseConnection(clickhouse_url) as db:
            for query, table_name in make_create_queries(
                min_time=clickhouse_buffer_min_time, max_time=clickhouse_buffer_max_time
            ):
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
@click.option("--workflow-name", type=str, required=True)
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
def backfill(
    probe_cc: List[str],
    test_name: List[str],
    workflow_name: str,
    start_at: datetime,
    end_at: datetime,
    create_tables: bool,
    drop_tables: bool,
):
    """
    Backfill for OONI measurements and write them into clickhouse
    """
    click.echo(f"Runnning backfill of worfklow {workflow_name}")

    maybe_create_delete_tables(
        clickhouse_url=config.clickhouse_url,
        create_tables=create_tables,
        drop_tables=drop_tables,
        clickhouse_buffer_min_time=config.clickhouse_buffer_min_time,
        clickhouse_buffer_max_time=config.clickhouse_buffer_max_time,
    )

    temporal_config = TemporalConfig(
        prometheus_bind_address=config.prometheus_bind_address,
        telemetry_endpoint=config.telemetry_endpoint,
        temporal_address=config.temporal_address,
        temporal_namespace=config.temporal_namespace,
        temporal_tls_client_cert_path=config.temporal_tls_client_cert_path,
        temporal_tls_client_key_path=config.temporal_tls_client_key_path,
    )

    run_backfill(
        workflow_name=workflow_name,
        temporal_config=temporal_config,
        probe_cc=probe_cc,
        test_name=test_name,
        start_at=start_at,
        end_at=end_at,
    )


@cli.command()
@probe_cc_option
@test_name_option
@click.option(
    "--fast-fail",
    is_flag=True,
    help="should we fail immediately when we encounter an error?",
)
def schedule(
    probe_cc: List[str],
    test_name: List[str],
    fast_fail: bool,
):
    """
    Create schedules for the specified parameters
    """
    temporal_config = TemporalConfig(
        telemetry_endpoint=config.telemetry_endpoint,
        prometheus_bind_address=config.prometheus_bind_address,
        temporal_address=config.temporal_address,
        temporal_namespace=config.temporal_namespace,
        temporal_tls_client_cert_path=config.temporal_tls_client_cert_path,
        temporal_tls_client_key_path=config.temporal_tls_client_key_path,
    )

    run_create_schedules(
        probe_cc=probe_cc,
        test_name=test_name,
        clickhouse_url=config.clickhouse_url,
        data_dir=config.data_dir,
        temporal_config=temporal_config,
    )


@cli.command()
@probe_cc_option
@test_name_option
def reschedule(
    probe_cc: List[str],
    test_name: List[str],
):
    """
    Create schedules for the specified parameters
    """
    temporal_config = TemporalConfig(
        telemetry_endpoint=config.telemetry_endpoint,
        prometheus_bind_address=config.prometheus_bind_address,
        temporal_address=config.temporal_address,
        temporal_namespace=config.temporal_namespace,
        temporal_tls_client_cert_path=config.temporal_tls_client_cert_path,
        temporal_tls_client_key_path=config.temporal_tls_client_key_path,
    )

    run_reschedule(
        probe_cc=probe_cc,
        test_name=test_name,
        clickhouse_url=config.clickhouse_url,
        data_dir=config.data_dir,
        temporal_config=temporal_config,
    )


@cli.command()
def status():
    click.echo(f"getting status from {config.temporal_address}")
    temporal_config = TemporalConfig(
        prometheus_bind_address=config.prometheus_bind_address,
        telemetry_endpoint=config.telemetry_endpoint,
        temporal_address=config.temporal_address,
        temporal_namespace=config.temporal_namespace,
        temporal_tls_client_cert_path=config.temporal_tls_client_cert_path,
        temporal_tls_client_key_path=config.temporal_tls_client_key_path,
    )
    run_status(temporal_config=temporal_config)


@cli.command()
def startworkers():
    click.echo(f"starting workers")
    click.echo(f"downloading NetinfoDB to {config.data_dir}")
    NetinfoDB(datadir=Path(config.data_dir), download=True)
    click.echo("done downloading netinfodb")

    temporal_config = TemporalConfig(
        prometheus_bind_address=config.prometheus_bind_address,
        telemetry_endpoint=config.telemetry_endpoint,
        temporal_address=config.temporal_address,
        temporal_namespace=config.temporal_namespace,
        temporal_tls_client_cert_path=config.temporal_tls_client_cert_path,
        temporal_tls_client_key_path=config.temporal_tls_client_key_path,
    )

    start_workers(temporal_config=temporal_config)


@cli.command()
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
    create_tables: bool,
    drop_tables: bool,
):
    """
    Check if the database tables require migrations. If the create-tables flag
    is not specified, it will not perform any operations.
    """
    maybe_create_delete_tables(
        clickhouse_url=config.clickhouse_url,
        create_tables=create_tables,
        drop_tables=drop_tables,
        clickhouse_buffer_min_time=config.clickhouse_buffer_min_time,
        clickhouse_buffer_max_time=config.clickhouse_buffer_max_time,
    )

    with ClickhouseConnection(config.clickhouse_url) as db:
        list_all_table_diffs(db)
