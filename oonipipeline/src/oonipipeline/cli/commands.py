import logging
import multiprocessing
from pathlib import Path
import sys
from typing import List, Optional
from datetime import date, timedelta, datetime
from typing import List, Optional

import click
from click_loglevel import LogLevel

from ..__about__ import VERSION
from ..db.connections import ClickhouseConnection
from ..db.create_tables import create_queries, list_all_table_diffs
from ..netinfo import NetinfoDB

log = logging.getLogger("oonidata")

import asyncio

import concurrent.futures

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.types import MethodAsyncSingleParam, SelfType, ParamType, ReturnType
from ..workflows.observations import ObservationsWorkflow, ObservationsWorkflowParams
from ..workflows.observations import make_observation_in_day

TASK_QUEUE_NAME = "oonipipeline-task-queue"


async def run_workflow(
    workflow: MethodAsyncSingleParam[SelfType, ParamType, ReturnType], arg: ParamType
):
    client = await Client.connect("localhost:7233")

    await client.execute_workflow(
        workflow,
        arg,
        id=TASK_QUEUE_NAME,
        task_queue=TASK_QUEUE_NAME,
    )


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

clickhouse_option = click.option(
    "--clickhouse", type=str, required=True, default="clickhouse://localhost"
)

datadir_option = click.option(
    "--data-dir",
    type=str,
    required=True,
    default="tests/data/datadir",
    help="data directory to store fingerprint and geoip databases",
)


@click.group()
@click.option("--error-log-file", type=Path)
@click.option(
    "-l",
    "--log-level",
    type=LogLevel(),
    default="INFO",
    help="Set logging level",
    show_default=True,
)
@click.version_option(VERSION)
def cli(error_log_file: Path, log_level: int):
    log.addHandler(logging.StreamHandler(sys.stderr))
    log.setLevel(log_level)
    if error_log_file:
        logging.basicConfig(
            filename=error_log_file, encoding="utf-8", level=logging.ERROR
        )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@clickhouse_option
@datadir_option
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
    start_day: str,
    end_day: str,
    clickhouse: str,
    data_dir: str,
    parallelism: int,
    fast_fail: bool,
    create_tables: bool,
    drop_tables: bool,
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
            for query, table_name in create_queries:
                if drop_tables:
                    db.execute(f"DROP TABLE IF EXISTS {table_name};")
                db.execute(query)

    click.echo("Starting to process observations")
    NetinfoDB(datadir=Path(data_dir), download=True)
    click.echo("downloaded netinfodb")

    arg = ObservationsWorkflowParams(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=start_day,
        end_day=end_day,
        clickhouse=clickhouse,
        data_dir=str(data_dir),
        parallelism=parallelism,
        fast_fail=fast_fail,
    )
    click.echo(f"starting to make observations with arg={arg}")
    asyncio.run(
        run_workflow(
            ObservationsWorkflow.run,
            arg,
        )
    )


@cli.command()
@probe_cc_option
@test_name_option
@start_day_option
@end_day_option
@clickhouse_option
@datadir_option
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

    # start_analysis(
    #     probe_cc=probe_cc,
    #     test_name=test_name,
    #     start_day=start_day,
    #     end_day=end_day,
    #     clickhouse=clickhouse,
    #     data_dir=data_dir,
    #     parallelism=parallelism,
    #     fast_fail=fast_fail,
    #     rebuild_ground_truths=rebuild_ground_truths,
    # )
    raise NotImplemented("TODO(art)")


@cli.command()
@start_day_option
@end_day_option
@clickhouse_option
@datadir_option
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
    # start_ground_truth_builder(
    #     start_day=start_day,
    #     end_day=end_day,
    #     clickhouse=clickhouse,
    #     data_dir=data_dir,
    #     parallelism=parallelism,
    # )
    raise NotImplemented("TODO(art)")


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
            for query, table_name in create_queries:
                if drop_tables:
                    db.execute(f"DROP TABLE IF EXISTS {table_name};")
                db.execute(query)

    with ClickhouseConnection(clickhouse) as db:
        list_all_table_diffs(db)


@cli.command()
def start_workers():
    async def run():
        client = await Client.connect("localhost:7233")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=100
        ) as activity_executor:
            worker = Worker(
                client,
                task_queue=TASK_QUEUE_NAME,
                workflows=[ObservationsWorkflow],
                activities=[make_observation_in_day],
                activity_executor=activity_executor,
            )
            await worker.run()

    asyncio.run(run())
