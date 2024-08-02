from configparser import ConfigParser
import logging
import multiprocessing
import os
from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime, timezone, time
from typing import List, Optional

from oonipipeline.temporal.client_operations import (
    TemporalConfig,
    run_backfill,
    run_create_schedules,
    run_status,
)
from oonipipeline.temporal.workers import start_workers

import click
from click_loglevel import LogLevel

from ..temporal.workflows import (
    GroundTruthsWorkflow,
    GroundTruthsWorkflowParams,
    ObservationsWorkflowParams,
    AnalysisWorkflowParams,
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
temporal_namespace_option = click.option(
    "--temporal-namespace", type=str, required=False, default=None
)
temporal_tls_client_cert_path_option = click.option(
    "--temporal-tls-client-cert-path", type=str, required=False, default=None
)
temporal_tls_client_key_path_option = click.option(
    "--temporal-tls-client-key-path", type=str, required=False, default=None
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


def parse_config_file(ctx, path):
    cfg = ConfigParser()
    cfg.read(path)
    ctx.default_map = {}

    try:
        default_options = cfg["options"]
        for name, _ in cli.commands.items():
            ctx.default_map.setdefault(name, {})
            ctx.default_map[name].update(default_options)
    except KeyError:
        # No default section
        pass

    for sect in cfg.sections():
        command_path = sect.split(".")
        defaults = ctx.default_map
        for cmdname in command_path[1:]:
            defaults = defaults.setdefault(cmdname, {})
        defaults.update(cfg[sect])
    return ctx.default_map


@click.group()
@click.option(
    "-l",
    "--log-level",
    type=LogLevel(),
    default="INFO",
    help="Set logging level",
    show_default=True,
)
@click.option(
    "-c",
    "--config",
    type=click.Path(dir_okay=False),
    default="config.ini",
    help="Read option defaults from the specified INI file",
    show_default=True,
)
@click.version_option(VERSION)
@click.pass_context
def cli(ctx, log_level: int, config: str):
    logging.basicConfig(level=log_level)
    if os.path.exists(config):
        ctx.default_map = parse_config_file(ctx, config)


@cli.command()
@start_at_option
@end_at_option
@clickhouse_option
@clickhouse_buffer_min_time_option
@clickhouse_buffer_max_time_option
@telemetry_endpoint_option
@temporal_address_option
@temporal_namespace_option
@temporal_tls_client_cert_path_option
@temporal_tls_client_key_path_option
@click.option("--schedule-id", type=str, required=True)
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
    start_at: datetime,
    end_at: datetime,
    clickhouse: str,
    clickhouse_buffer_min_time: int,
    clickhouse_buffer_max_time: int,
    create_tables: bool,
    drop_tables: bool,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    temporal_namespace: Optional[str],
    temporal_tls_client_cert_path: Optional[str],
    temporal_tls_client_key_path: Optional[str],
    schedule_id: str,
):
    """
    Backfill for OONI measurements and write them into clickhouse
    """
    click.echo(f"Runnning backfill of schedule {schedule_id}")

    maybe_create_delete_tables(
        clickhouse_url=clickhouse,
        create_tables=create_tables,
        drop_tables=drop_tables,
        clickhouse_buffer_min_time=clickhouse_buffer_min_time,
        clickhouse_buffer_max_time=clickhouse_buffer_max_time,
    )

    temporal_config = TemporalConfig(
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        temporal_namespace=temporal_namespace,
        temporal_tls_client_cert_path=temporal_tls_client_cert_path,
        temporal_tls_client_key_path=temporal_tls_client_key_path,
    )

    run_backfill(
        schedule_id=schedule_id,
        temporal_config=temporal_config,
        start_at=start_at,
        end_at=end_at,
    )


@cli.command()
@probe_cc_option
@test_name_option
@clickhouse_option
@clickhouse_buffer_min_time_option
@clickhouse_buffer_max_time_option
@datadir_option
@telemetry_endpoint_option
@temporal_address_option
@temporal_namespace_option
@temporal_tls_client_cert_path_option
@temporal_tls_client_key_path_option
@click.option(
    "--fast-fail",
    is_flag=True,
    help="should we fail immediately when we encounter an error?",
)
@click.option(
    "--analysis/--no-analysis",
    is_flag=True,
    help="should we schedule an analysis",
    default=False,
)
@click.option(
    "--observations/--no-observations",
    is_flag=True,
    help="should we schedule observations",
    default=True,
)
@click.option(
    "--delete",
    is_flag=True,
    default=False,
    help="if we should delete the schedule instead of creating it",
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
def schedule(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: str,
    clickhouse_buffer_min_time: int,
    clickhouse_buffer_max_time: int,
    data_dir: str,
    fast_fail: bool,
    create_tables: bool,
    drop_tables: bool,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    temporal_namespace: Optional[str],
    temporal_tls_client_cert_path: Optional[str],
    temporal_tls_client_key_path: Optional[str],
    analysis: bool,
    observations: bool,
    delete: bool,
):
    """
    Create schedules for the specified parameters
    """
    if not observations and not analysis:
        click.echo("either observations or analysis should be set")
        return 1

    maybe_create_delete_tables(
        clickhouse_url=clickhouse,
        create_tables=create_tables,
        drop_tables=drop_tables,
        clickhouse_buffer_min_time=clickhouse_buffer_min_time,
        clickhouse_buffer_max_time=clickhouse_buffer_max_time,
    )
    what_we_schedule = []
    if analysis:
        what_we_schedule.append("analysis")
    if observations:
        what_we_schedule.append("observations")

    click.echo(f"Scheduling {' and'.join(what_we_schedule)}")

    temporal_config = TemporalConfig(
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        temporal_namespace=temporal_namespace,
        temporal_tls_client_cert_path=temporal_tls_client_cert_path,
        temporal_tls_client_key_path=temporal_tls_client_key_path,
    )
    obs_params = None
    if observations:
        obs_params = ObservationsWorkflowParams(
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse,
            data_dir=str(data_dir),
            fast_fail=fast_fail,
        )
    analysis_params = None
    if analysis:
        analysis_params = AnalysisWorkflowParams(
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse,
            data_dir=str(data_dir),
        )

    run_create_schedules(
        obs_params=obs_params,
        analysis_params=analysis_params,
        temporal_config=temporal_config,
        delete=delete,
    )


@cli.command()
@telemetry_endpoint_option
@temporal_address_option
@temporal_namespace_option
@temporal_tls_client_cert_path_option
@temporal_tls_client_key_path_option
def status(
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    temporal_namespace: Optional[str],
    temporal_tls_client_cert_path: Optional[str],
    temporal_tls_client_key_path: Optional[str],
):
    click.echo(f"getting stattus")
    temporal_config = TemporalConfig(
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        temporal_namespace=temporal_namespace,
        temporal_tls_client_cert_path=temporal_tls_client_cert_path,
        temporal_tls_client_key_path=temporal_tls_client_key_path,
    )
    run_status(temporal_config=temporal_config)


@cli.command()
@datadir_option
@parallelism_option
@telemetry_endpoint_option
@temporal_address_option
@temporal_namespace_option
@temporal_tls_client_cert_path_option
@temporal_tls_client_key_path_option
def startworkers(
    data_dir: Path,
    parallelism: int,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
    temporal_namespace: Optional[str],
    temporal_tls_client_cert_path: Optional[str],
    temporal_tls_client_key_path: Optional[str],
):
    click.echo(f"starting {parallelism} workers")
    click.echo(f"downloading NetinfoDB to {data_dir}")
    NetinfoDB(datadir=Path(data_dir), download=True)
    click.echo("done downloading netinfodb")

    temporal_config = TemporalConfig(
        telemetry_endpoint=telemetry_endpoint,
        temporal_address=temporal_address,
        temporal_namespace=temporal_namespace,
        temporal_tls_client_cert_path=temporal_tls_client_cert_path,
        temporal_tls_client_key_path=temporal_tls_client_key_path,
    )

    start_workers(temporal_config=temporal_config)


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
@clickhouse_buffer_min_time_option
@clickhouse_buffer_max_time_option
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
    clickhouse: str,
    clickhouse_buffer_min_time: int,
    clickhouse_buffer_max_time: int,
    create_tables: bool,
    drop_tables: bool,
):
    """
    Check if the database tables require migrations. If the create-tables flag
    is not specified, it will not perform any operations.
    """
    maybe_create_delete_tables(
        clickhouse_url=clickhouse,
        create_tables=create_tables,
        drop_tables=drop_tables,
        clickhouse_buffer_min_time=clickhouse_buffer_min_time,
        clickhouse_buffer_max_time=clickhouse_buffer_max_time,
    )

    with ClickhouseConnection(clickhouse) as db:
        list_all_table_diffs(db)
