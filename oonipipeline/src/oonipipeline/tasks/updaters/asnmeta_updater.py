"""
Fetch asn metadata from https://archive.org/download/ip2country-as (generated via: https://github.com/ooni/historical-geoip)

Local test run:
    PYTHONPATH=analysis ./run_analysis --update-asnmeta --stdout
"""

from datetime import datetime
from typing import List
from urllib.request import urlopen
import json
import logging

from clickhouse_driver import Client as Clickhouse

# from analysis.metrics import setup_metrics

AS_ORG_MAP_URL = "https://archive.org/download/ip2country-as/all_as_org_map.json"

log = logging.getLogger("analysis.asnmeta_updater")
# metrics = setup_metrics(name="asnmeta_updater")
progress_cnt = 0


def progress(msg: str) -> None:
    global progress_cnt
    # metrics.gauge("asnmeta_update_progress", progress_cnt)
    log.info(f"{progress_cnt} {msg}")
    progress_cnt += 1


# @metrics.timer("fetch_data")
def fetch_data() -> List[dict]:
    resp = urlopen(AS_ORG_MAP_URL)
    if resp.status != 200:
        raise Exception(f"Failed to fetch {AS_ORG_MAP_URL}")
    j = json.load(resp)
    rows = []
    for asn, history in j.items():
        asn = int(asn)
        for v in history:
            changed = datetime.strptime(v[2], "%Y%m%d").date()
            rows.append(
                {
                    "asn": asn,
                    "org_name": v[0],
                    "cc": v[1],
                    "changed": changed,
                    "aut_name": v[3],
                    "source": v[4],
                }
            )
    del j
    return rows


# Same pattern as citizenlab_test_lists_updater: asnmeta is a single, stable
# replicated table and each run swaps its data in from a session-scoped
# TEMPORARY table with REPLACE PARTITION, which replicates through asnmeta's
# own replication log instead of renaming tables with EXCHANGE on only the
# node this script is connected to.
CLUSTER_NAME = "oonidata_cluster"


def update_asnmeta(clickhouse_url: str) -> None:
    progress("starting")
    click = Clickhouse.from_url(clickhouse_url)
    click.execute(
        f"""CREATE TABLE IF NOT EXISTS asnmeta ON CLUSTER {CLUSTER_NAME}
(
    asn UInt32,
    org_name String,
    cc String,
    changed Date,
    aut_name String,
    source String
)
ENGINE = ReplicatedMergeTree('/clickhouse/{{cluster}}/tables/ooni/asnmeta', '{{replica}}')
ORDER BY (asn, changed)
    """
    )

    click.execute(
        """CREATE TEMPORARY TABLE IF NOT EXISTS asnmeta_tmp
(
    asn UInt32,
    org_name String,
    cc String,
    changed Date,
    aut_name String,
    source String
)
ENGINE = MergeTree
ORDER BY (asn, changed)
    """
    )
    progress("asnmeta_tmp created")

    log.info(f"Ingesting {AS_ORG_MAP_URL}")
    data = fetch_data()
    progress(f"JSON data fetched: {len(data)} items")

    q = """
    INSERT INTO asnmeta_tmp
        (asn, org_name, cc, changed, aut_name, source)
    VALUES
    """
    click.execute(q, data)
    progress("asnmeta_tmp filled")

    r = click.execute("SELECT count() FROM asnmeta_tmp")
    row_cnt = r[0][0]
    assert isinstance(row_cnt, int)
    # metrics.gauge("asnmeta_tmp_len", row_cnt)
    assert 100_000 < row_cnt < 1_000_000

    log.info("Swapping asnmeta data")
    q = "ALTER TABLE asnmeta REPLACE PARTITION tuple() FROM asnmeta_tmp SETTINGS alter_sync = 3"
    click.execute(q)
    progress("asnmeta ready")
