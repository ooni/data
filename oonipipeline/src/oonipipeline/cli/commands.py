import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import click
from click_loglevel import LogLevel
from clickhouse_driver import Client as ClickhouseClient
from tqdm import tqdm

from oonipipeline.analysis.detector import run_detector
from oonipipeline.cli.utils import build_date_range, build_timestamps
from oonipipeline.db.maintenance import (
    list_duplicates_in_buckets,
    list_partitions_to_delete,
    optimize_all_tables_by_partition,
)
from oonipipeline.tasks.analysis import (
    MakeAnalysisParams,
    make_analysis,
)
from oonipipeline.tasks.common import OptimizeTablesParams, optimize_tables
from oonipipeline.tasks.observations import (
    MakeObservationsParams,
    make_observations,
)

from ..__about__ import VERSION
from ..db.connections import ClickhouseConnection
from ..db.create_tables import list_all_table_diffs, make_create_queries
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
@click.option(
    "--truncate-cusums/--no-truncate-cusums",
    default=False,
    help="if the event_detector_cusums table should be truncated prior to processing",
)
@click.option(
    "--clear-changepoints/--no-clear-changepoints",
    default=False,
    help="if the event_detector_changepoints table should be cleared for the specified time range",
)
@click.option(
    "--warmup/--no-warmup",
    default=False,
    help="if we should warmup the event_detector_cusums table",
)
def event_detector(
    start_at: datetime,
    end_at: datetime,
    probe_cc: List[str],
    truncate_cusums: bool,
    clear_changepoints: bool,
    warmup: bool,
):
    if start_at > end_at:
        raise click.BadParameter(f"start_at ({start_at}) should be < end_at {end_at}")

    if truncate_cusums or clear_changepoints:
        with ClickhouseClient.from_url(config.clickhouse_url) as db:
            if truncate_cusums:
                click.echo("Truncating event_detector_cusums table...")
                db.execute("TRUNCATE TABLE event_detector_cusums SYNC")
            if clear_changepoints:
                click.echo("Clearing event_detector_changepoints table...")
                db.execute(
                    "ALTER TABLE event_detector_changepoints DELETE WHERE ts >= %(start_at)s AND ts <= %(end_at)s",
                    params={"start_at": start_at, "end_at": end_at},
                )

    if warmup:
        click.echo("Warming up event_detector_cusums table...")
        changepoints, updated_cusums, _ = run_detector(
            clickhouse_url=config.clickhouse_url,
            start_time=start_at - timedelta(days=30),
            end_time=start_at,
            probe_cc=probe_cc,
        )

    for start_dt, end_dt in tqdm(build_date_range(start_at, end_at, day_delta=10)):
        click.echo(f"Processing {start_dt} - {end_dt}")
        changepoints, updated_cusums, _ = run_detector(
            clickhouse_url=config.clickhouse_url,
            start_time=start_dt,
            end_time=end_dt,
            probe_cc=probe_cc,
        )
        click.echo(
            f"Found {len(changepoints)} changepoints and updated {len(updated_cusums)} cusums"
        )

@cli.command()
@click.option("--port", default=8501, help="Port the web server will listen to")
def events_panel(port: int):
    """
    Starts a streamlit web app with the events detector debugging panel
    """
    try:
        from streamlit.web import bootstrap
    except ImportError:
        click.echo("Streamlit not available. Install with oonipipeline[analysis]")
        return

    import importlib.util

    spec = importlib.util.find_spec("oonipipeline.events_panel.panel")
    assert spec is not None, "Unable to find events panel module"
    panel_path = spec.origin  # file path, no execution

    flag_options = {"server.port": port}
    bootstrap.load_config_options(flag_options=flag_options)
    bootstrap.run(panel_path, is_hello=False, args=[], flag_options=flag_options)


@cli.command()
@click.argument("events_path", type=click.Path(exists=True))
@click.option("--tolerance-hours", default=24, show_default=True,
              help="How far outside the onset bracket a changepoint still counts as a hit")
@click.option("--lead-days", default=14, show_default=True,
              help="Quiet window before the bracket, used for the false-alarm rate")
@click.option("--edd", default=10, show_default=True, help="CUSUM expected detection delay")
@click.option("--gap-halflife", default=48.0, show_default=True)
@click.option("--json-out", type=click.Path(), default=None,
              help="Write the per-event results, for diffing two configurations")
@click.option("--intervals", "intervals_path", type=click.Path(exists=True), default=None,
              help="Interval-grain export. Adds the weighted false-alarm rate, "
                   "which the event corpus cannot express: it is curated, so it "
                   "has no denominator in it")
@click.option("--max-false-alarms", type=float, default=None,
              help="Fail when the false-alarm rate per quiet series-week is "
                   "above this. Needs --intervals")
@click.option("--bootstrap", default=400, show_default=True,
              help="Cluster-bootstrap resamples for the false-alarm interval")
def event_eval(events_path, tolerance_hours, lead_days, edd, gap_halflife, json_out,
               intervals_path, max_false_alarms, bootstrap):
    """
    Score a detector configuration against the adjudicated corpora.

    Takes an event-grain export from the event labeller, and optionally an
    interval-grain export from the quiet-interval labeller. Prints the
    scorecards and exits non-zero if any event fails, so it can gate a detector
    change.

    The two grains answer different questions and neither substitutes for the
    other. Events say whether a change still finds what it should. Intervals
    say what it costs in false alarms, as a weighted estimate over a sampled
    frame rather than a count over whatever surrounds the known events.
    """
    import json as _json
    from dataclasses import asdict

    from ..analysis.event_eval import run_harness

    card = run_harness(
        clickhouse_url=config.clickhouse_url,
        events_path=events_path,
        tolerance_hours=tolerance_hours,
        lead_days=lead_days,
        edd=edd,
        gap_halflife=gap_halflife,
    )
    click.echo(card.format())
    if json_out:
        with open(json_out, "w") as fh:
            _json.dump([asdict(r) for r in card.results], fh, indent=2)
        click.echo(f"wrote {json_out}")

    interval_card = None
    if intervals_path:
        from ..analysis.interval_eval import run_interval_harness

        interval_card = run_interval_harness(
            clickhouse_url=config.clickhouse_url,
            intervals_path=intervals_path,
            lead_days=lead_days,
            bootstrap=bootstrap,
            edd=edd,
            gap_halflife=gap_halflife,
        )
        click.echo("")
        click.echo(interval_card.format())
        if json_out:
            with open(json_out.replace(".json", "") + "-intervals.json", "w") as fh:
                _json.dump([asdict(r) for r in interval_card.results], fh, indent=2)
    elif max_false_alarms is not None:
        raise click.UsageError("--max-false-alarms needs --intervals")

    failed = [r for r in card.results if not r.passed]
    if failed:
        raise SystemExit(1)

    if interval_card is not None and max_false_alarms is not None:
        from ..analysis.interval_eval import gate

        ok, why = gate(interval_card, max_false_alarms)
        click.echo(f"false-alarm budget: {'pass' if ok else 'FAIL'} — {why}")
        if not ok:
            raise SystemExit(1)
