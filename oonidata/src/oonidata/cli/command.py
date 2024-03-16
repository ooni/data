import logging
import sys

from pathlib import Path
from typing import List, Optional
from datetime import date, timedelta, datetime

import click
from click_loglevel import LogLevel

from oonidata.__about__ import VERSION
from oonidata.dataclient import (
    sync_measurements,
)

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


if __name__ == "__main__":
    cli()
