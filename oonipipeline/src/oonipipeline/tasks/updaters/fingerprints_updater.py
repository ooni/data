"""
Fetch fingerprints from https://github.com/ooni/blocking-fingerprints
Populate 2 tables atomically using the citizenlab user.

Local test run:
    PYTHONPATH=analysis ./run_analysis --update-fingerprints --stdout
"""

from argparse import Namespace
from urllib.request import urlopen
import logging
import csv

from clickhouse_driver import Client as Clickhouse

from ...db.create_tables import (
    FINGERPRINT_COLUMN_NAMES,
    FINGERPRINT_SCOPES_DNS,
    FINGERPRINT_SCOPES_HTTP,
    format_fingerprints_create_query,
)

# from analysis.metrics import setup_metrics

BASE_URL = "https://raw.githubusercontent.com/"
HTTP_URL = f"{BASE_URL}/ooni/blocking-fingerprints/main/fingerprints_http.csv"
DNS_URL = f"{BASE_URL}/ooni/blocking-fingerprints/main/fingerprints_dns.csv"


log = logging.getLogger("analysis.fingerprints_updater")
# metrics = setup_metrics(name="fingerprints_updater")
progress_cnt = 0


def progress(msg: str) -> None:
    global progress_cnt
    # metrics.gauge("fingerprints_update_progress", progress_cnt)
    log.info(f"{progress_cnt} {msg}")
    progress_cnt += 1


# @metrics.timer("fetch_csv")
def fetch_csv(url):
    resp = urlopen(url)
    if resp.status != 200:
        raise Exception(f"Failed to fetch {url}")
    lines = [x.decode("utf-8") for x in resp.readlines()]
    log.info(f"Fetched {len(lines)} lines")
    rows = csv.DictReader(lines)
    return [r for r in rows]


def _fill_tmp_table(click, table_name: str, scopes: list, url: str) -> None:
    """
    Recreate {table_name}_tmp and fill it from url. The live table is left
    untouched until the caller EXCHANGEs it in.
    """
    # Make sure the live table exists so the later EXCHANGE has something to
    # swap against on a first-ever run.
    click.execute(format_fingerprints_create_query(table_name, scopes))

    click.execute(f"DROP TABLE IF EXISTS {table_name}_tmp")
    click.execute(format_fingerprints_create_query(f"{table_name}_tmp", scopes))
    progress(f"{table_name}_tmp recreated")

    log.info(f"Ingesting {url}")
    data = fetch_csv(url)
    for row in data:
        row["confidence_no_fp"] = int(row["confidence_no_fp"])
    progress("CSV data fetched")

    col_str = ", ".join(FINGERPRINT_COLUMN_NAMES)
    click.execute(f"INSERT INTO {table_name}_tmp ({col_str}) VALUES", data)
    progress(f"{table_name}_tmp filled")

    r = click.execute(f"SELECT count() FROM {table_name}_tmp")
    row_cnt = r[0][0]
    assert isinstance(row_cnt, int)
    assert 100 < row_cnt < 50_000


def update_fingerprints(clickhouse_url: str) -> None:
    progress("starting")
    # assert not conf.dry_run, "Dry run mode not supported"
    click = Clickhouse.from_url(clickhouse_url)

    _fill_tmp_table(click, "fingerprints_dns", FINGERPRINT_SCOPES_DNS, DNS_URL)
    _fill_tmp_table(click, "fingerprints_http", FINGERPRINT_SCOPES_HTTP, HTTP_URL)

    for table_name in ("fingerprints_dns", "fingerprints_http"):
        log.info("Swapping tables")
        click.execute(f"EXCHANGE TABLES {table_name}_tmp AND {table_name}")
        progress(f"{table_name} ready")
