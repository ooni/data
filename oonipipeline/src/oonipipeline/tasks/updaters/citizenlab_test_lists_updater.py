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

# citizenlab lives on the replicated oonidata_cluster; citizenlab_tmp is a
# session-scoped TEMPORARY table that only ever exists on whichever node
# this script is connected to.
#
# We used to repopulate citizenlab by writing into citizenlab_flip and then
# EXCHANGE-ing the two table names. That relies on ClickHouse keeping every
# replica's table-name -> ZooKeeper-path binding in sync, which EXCHANGE
# only does on a best-effort basis (see ClickHouse/ClickHouse#60489): a
# replica that misses the EXCHANGE (rebuilt from scratch, or offline past
# the ON CLUSTER DDL queue's retention window) can silently end up pointing
# "citizenlab" and "citizenlab_flip" at the wrong underlying data, with no
# error raised.
#
# We now instead keep "citizenlab" as a single, stable table and swap in
# its *data* with REPLACE PARTITION from citizenlab_tmp. This never touches
# table identity/ZooKeeper-path bindings, so it can't develop the kind of
# cross-replica divergence EXCHANGE can -- citizenlab replicates the change
# out to its own replicas the same way it already does for TRUNCATE/INSERT,
# and the swap is atomic on every replica (readers never see a partial or
# empty table, on any node, at any point).
#
# citizenlab_tmp only needs to match citizenlab's structure/partition
# key/order-by for REPLACE PARTITION to accept it as a source -- it doesn't
# need to be replicated itself, since it's only ever read once, locally, to
# build the parts that citizenlab then replicates out on its own. That
# makes a plain session-scoped TEMPORARY TABLE a good fit: ClickHouse
# doesn't allow TEMPORARY tables to use a Replicated engine or ON CLUSTER
# anyway, and this way there's nothing left behind on any node between
# runs -- it's dropped automatically when this script's connection closes.
#
# These tables are small and don't need a sharding key, so citizenlab's ZK
# path below has no {shard} macro: every replica in the cluster shares one
# path (single shard, N replicas), which is also what keeps REPLACE
# PARTITION usable without ON CLUSTER -- there's only one replication
# domain to reach. ooni/devops's own cluster migration schema
# (scripts/cluster-migration/schema.sql) defines citizenlab as
# ReplicatedReplacingMergeTree at this same path -- the CREATE statement
# below needs to match that exactly, since CREATE TABLE IF NOT EXISTS is a
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
    """Reload a session-scoped staging table and atomically swap its data into citizenlab"""
    click = Clickhouse.from_url(clickhouse_url)

    # citizenlab is the one persistent, cluster-wide table. CREATE is DDL
    # (not table data), so it needs ON CLUSTER to reach every replica; this
    # only matters on a genuine from-scratch bootstrap, since CREATE IF NOT
    # EXISTS is a no-op once the table already exists.
    click.execute(
        f"""CREATE TABLE IF NOT EXISTS citizenlab ON CLUSTER {CLUSTER_NAME}
(
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/{{cluster}}/tables/ooni/citizenlab', '{{replica}}')
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4
    """
    )

    log.info("Creating citizenlab_tmp staging table for this run")
    # TEMPORARY TABLE: scoped to this one connection, dropped automatically
    # once it closes -- nothing persists on any node between runs. No ON
    # CLUSTER (ClickHouse doesn't allow it for TEMPORARY tables, and we
    # don't need it: only this session ever touches this table). No
    # Replicated engine either (also disallowed for TEMPORARY tables) --
    # REPLACE PARTITION below only requires citizenlab_tmp to share
    # citizenlab's structure/partition key/order-by, not its replication
    # status, since citizenlab_tmp is read once, locally, to build the
    # parts that citizenlab then replicates out on its own. Matching
    # index_granularity to citizenlab since REPLACE PARTITION requires it
    # to match whenever granularity is non-adaptive.
    click.execute(
        """CREATE TEMPORARY TABLE IF NOT EXISTS citizenlab_tmp
(
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
)
ENGINE = ReplacingMergeTree
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4
    """
    )

    log.info("Inserting %d citizenlab table entries", len(citizenlab))
    q = "INSERT INTO citizenlab_tmp (domain, url, cc, category_code) VALUES"
    click.execute(q, citizenlab, types_check=True)

    log.info("Swapping Clickhouse citizenlab data")
    # REPLACE PARTITION swaps citizenlab_tmp's data into citizenlab
    # atomically -- readers on every replica see either the fully-old or
    # fully-new data, never a mix or a gap, so there's no outage window on
    # any node. alter_sync=3 waits only for currently *active* citizenlab
    # replicas to confirm the swap, rather than alter_sync=2's "wait for
    # everyone" -- so one replica being restarted/offline can't block this
    # job. That replica still catches up automatically once it reconnects:
    # this goes through citizenlab's own per-table replication log (the
    # same one TRUNCATE/INSERT already rely on), not the ON CLUSTER DDL
    # queue's best-effort/retention-limited mechanism EXCHANGE depended on,
    # so a replica that's been down a while either replays the entries it
    # missed or, if too far behind, does a full resync of citizenlab's
    # (small) current data from a healthy replica -- either way it
    # converges automatically, with no risk of the kind of silent
    # table-identity divergence EXCHANGE was exposed to. citizenlab has no
    # PARTITION BY, so the whole table is one implicit partition, addressed
    # here as tuple(). No ON CLUSTER needed here either, for the same
    # reason TRUNCATE/INSERT don't need it -- citizenlab_tmp being local
    # and non-replicated doesn't weaken any of this, since that guarantee
    # comes entirely from citizenlab's own Replicated engine.
    q = "ALTER TABLE citizenlab REPLACE PARTITION tuple() FROM citizenlab_tmp SETTINGS alter_sync = 3"
    click.execute(q)


def update_citizenlab_test_lists(clickhouse_url: str) -> None:
    log.info("update_citizenlab_test_lists")
    citizenlab = fetch_citizen_lab_lists()
    update_citizenlab_table(clickhouse_url, citizenlab)
