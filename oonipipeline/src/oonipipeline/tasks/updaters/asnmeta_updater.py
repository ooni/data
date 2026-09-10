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

# asnmeta lives on the replicated oonidata_cluster, as a permanent pair of
# tables -- asnmeta and asnmeta_tmp -- matching the same swap-table pattern
# used for citizenlab/citizenlab_flip. This script creates both tables
# itself (idempotently) if they don't already exist.
#
# TRUNCATE and INSERT are data operations: ClickHouse replicates those
# automatically to every replica via the table's own replication log, no
# ON CLUSTER needed. CREATE and EXCHANGE TABLES are different -- they're
# catalog-level operations, and `ooni` is a plain Atomic database, so table
# *names* are local to each node's own catalog and do not follow the
# table's data replication. Without ON CLUSTER on these, the swap would
# only rename things on whichever single node this script's client
# connects to -- the other replicas would keep calling the OLD data
# "asnmeta" indefinitely, every single run.
#
# Plain ReplicatedMergeTree, not Replacing: asnmeta intentionally keeps
# every historical row per ASN (queries pick the latest via
# `changed`/argMax at read time) rather than relying on background merges
# to dedup them away.
CLUSTER_NAME = "oonidata_cluster"

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


def update_asnmeta(clickhouse_url: str) -> None:
    progress("starting")
    click = Clickhouse.from_url(clickhouse_url)

    # Ensure both tables exist (first-ever run, a fresh test/dev
    # environment, or after manual recovery). IF NOT EXISTS makes this a
    # no-op on every normal run once they're already there -- unlike a
    # DROP+CREATE-every-run pattern, this doesn't churn each table's
    # ZooKeeper replication metadata on every single scheduled update.
    for table_name in ("asnmeta", "asnmeta_tmp"):
        q = f"""
        CREATE TABLE IF NOT EXISTS {table_name} ON CLUSTER {CLUSTER_NAME} (
            asn UInt32,
            org_name String,
            cc String,
            changed Date,
            aut_name String,
            source String
        ) ENGINE = ReplicatedMergeTree('/clickhouse/{{cluster}}/tables/ooni/{table_name}/{{shard}}', '{{replica}}')
        ORDER BY (asn, changed)
        """
        click.execute(q)
    progress("asnmeta/asnmeta_tmp ensured")

    log.info("Emptying Clickhouse asnmeta_tmp table")
    q = "TRUNCATE TABLE asnmeta_tmp"
    click.execute(q)
    progress("asnmeta_tmp truncated")

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

    log.info("Swapping tables")
    q = f"EXCHANGE TABLES asnmeta_tmp AND asnmeta ON CLUSTER {CLUSTER_NAME}"
    click.execute(q)
    progress("asnmeta ready")
