"""
Fetch test lists from https://github.com/citizenlab/test-lists

Populate citizenlab table from the tests lists git repository and the
url_priorities table

The tables have few constraints on the database side: most of the validation
is done here and it is meant to be strict.

Local test run:
    PYTHONPATH=analysis ./run_analysis --update-citizenlab --dry-run --stdout

"""

from argparse import Namespace
from pathlib import Path
from subprocess import check_call
from tempfile import TemporaryDirectory
from typing import List, Optional
import csv
import logging
import re

from clickhouse_driver import Client as Clickhouse

# from analysis.metrics import setup_metrics

# citizenlab/citizenlab_flip live on the replicated oonidata_cluster, same
# swap-table pattern as asnmeta/asnmeta_tmp (see asnmeta_updater.py for the
# full rationale on why CREATE/EXCHANGE need ON CLUSTER here while
# TRUNCATE/INSERT don't). ooni/devops's own cluster migration schema
# (scripts/cluster-migration/schema.sql) defines these tables as
# ReplicatedReplacingMergeTree at this same path -- the CREATE statements
# below need to match that exactly, since CREATE TABLE IF NOT EXISTS is a
# no-op whenever the table already exists (regardless of what engine the
# statement itself specifies), so a genuine from-scratch bootstrap is the
# only place a mismatch here would actually bite.
CLUSTER_NAME = "oonidata_cluster"

HTTPS_GIT_URL = "https://github.com/citizenlab/test-lists.git"

log = logging.getLogger("analysis.citizenlab_test_lists_updater")
# metrics = setup_metrics(name="citizenlab_test_lists_updater")


VALID_URL = re.compile(
    r"(^(?:http)s?://)?"  # http:// or https://
    r"((?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"  # ...or ipaddr
    r"(?::\d+)?"  # optional port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)

URL_BAD_CHARS = {"\r", "\n", "\t", "\\"}


def _extract_domain(url: str) -> Optional[str]:
    if any(c in URL_BAD_CHARS for c in url):
        return None

    m = VALID_URL.match(url)
    if m:
        return m.group(2)

    return None


# @metrics.timer("fetch_citizen_lab_lists")
def fetch_citizen_lab_lists() -> List[dict]:
    """Clone repository in a temporary directory and extract files"""
    out = []  # (cc or "ZZ", domain, url, category_code)
    with TemporaryDirectory() as tmpdir:
        cmd = ("git", "clone", "--depth", "1", HTTPS_GIT_URL, tmpdir)
        check_call(cmd, timeout=120)
        p = Path(tmpdir) / "lists"
        for i in sorted(p.glob("*.csv")):
            cc = i.stem
            if cc == "global":
                cc = "ZZ"
            if len(cc) != 2:
                continue
            log.info("Processing %s", i.name)
            with i.open() as f:
                for item in csv.DictReader(f):
                    url = item["url"]
                    domain = _extract_domain(url)
                    if not domain:
                        log.debug("Ignoring", url)
                        continue
                    category_code = item["category_code"]
                    d = dict(
                        domain=domain,
                        url=url,
                        cc=cc,
                        category_code=category_code,
                    )
                    out.append(d)

    assert len(out) > 20000
    assert len(out) < 1000000
    #metrics.gauge("citizenlab_test_list_len", len(out))
    return out


def query_c(click, query: str, qparams: dict):
    click.execute(query, qparams, types_check=True)


# @metrics.timer("update_citizenlab_table")
def update_citizenlab_table(clickhouse_url: str, citizenlab: list) -> None:
    """Overwrite citizenlab_flip and swap tables atomically"""
    click = Clickhouse.from_url(clickhouse_url)
    for table_name in ("citizenlab_flip", "citizenlab"):
        click.execute(
            f"""CREATE TABLE IF NOT EXISTS {table_name} ON CLUSTER {CLUSTER_NAME}
(
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/{{cluster}}/tables/ooni/{table_name}/{{shard}}', '{{replica}}')
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4
    """
        )
    log.info("Emptying Clickhouse citizenlab_flip table")
    q = "TRUNCATE TABLE citizenlab_flip"
    click.execute(q)

    log.info("Inserting %d citizenlab table entries", len(citizenlab))
    q = "INSERT INTO citizenlab_flip (domain, url, cc, category_code) VALUES"
    click.execute(q, citizenlab, types_check=True)

    log.info("Swapping Clickhouse citizenlab tables")
    q = f"EXCHANGE TABLES citizenlab_flip AND citizenlab ON CLUSTER {CLUSTER_NAME}"
    click.execute(q)


def update_citizenlab_test_lists(clickhouse_url: str) -> None:
    log.info("update_citizenlab_test_lists")
    citizenlab = fetch_citizen_lab_lists()
    update_citizenlab_table(clickhouse_url, citizenlab)
