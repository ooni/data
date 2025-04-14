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

#from analysis.metrics import setup_metrics

AS_ORG_MAP_URL = "https://archive.org/download/ip2country-as/all_as_org_map.json"

log = logging.getLogger("analysis.asnmeta_updater")
#metrics = setup_metrics(name="asnmeta_updater")
progress_cnt = 0


def progress(msg: str) -> None:
    global progress_cnt
    #metrics.gauge("asnmeta_update_progress", progress_cnt)
    log.info(f"{progress_cnt} {msg}")
    progress_cnt += 1


#@metrics.timer("fetch_data")
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

    q = "DROP TABLE IF EXISTS asnmeta_tmp"
    click.execute(q)

    q = """
    CREATE TABLE asnmeta_tmp (
        asn UInt32,
        org_name String,
        cc String,
        changed Date,
        aut_name String,
        source String
    ) ENGINE = MergeTree()
    ORDER BY (asn, changed)
    """
    click.execute(q)
    progress("asnmeta_tmp recreated")

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
    #metrics.gauge("asnmeta_tmp_len", row_cnt)
    assert 100_000 < row_cnt < 1_000_000

    log.info("Swapping tables")
    q = "EXCHANGE TABLES asnmeta_tmp AND asnmeta"
    click.execute(q)
    progress("asnmeta ready")
