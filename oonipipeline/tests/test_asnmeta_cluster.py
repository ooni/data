"""
Integration tests that exercise asnmeta_updater.update_asnmeta against a real
multi-replica ClickHouse cluster (see docker-compose.cluster.yml): same checks
as test_citizenlab_cluster.py, for the asnmeta REPLACE PARTITION swap.

    pytest -m cluster tests/test_asnmeta_cluster.py
"""

import datetime
import time
from unittest.mock import patch

import pytest
from clickhouse_driver import Client as ClickhouseClient

from oonipipeline.tasks.updaters import asnmeta_updater


def _rows(n: int, source: str) -> list:
    # update_asnmeta() only swaps in between 100k and 1M rows.
    return [
        {
            "asn": i,
            "org_name": f"org {i}",
            "cc": "US",
            "changed": datetime.date(2020, 1, 1),
            "aut_name": f"AS{i}",
            "source": source,
        }
        for i in range(n)
    ]


# Different size and content, so stale data from a previous run is caught.
SAMPLE_ROWS_A = _rows(120_000, "run-a")
SAMPLE_ROWS_B = _rows(110_000, "run-b")


def _update_asnmeta(url: str, rows: list) -> None:
    with patch.object(asnmeta_updater, "fetch_data", return_value=rows):
        asnmeta_updater.update_asnmeta(url)


def _asnmeta_summary_on(url: str) -> tuple:
    click = ClickhouseClient.from_url(url)
    return tuple(click.execute("SELECT count(), groupUniqArray(source) FROM asnmeta")[0])


def _tables_on(url: str) -> set:
    click = ClickhouseClient.from_url(url)
    return {row[0] for row in click.execute("SHOW TABLES")}


def _assert_rows_eventually(url: str, rows: list, message: str, timeout: float = 10.0):
    """Poll briefly: the other replica applies the swap asynchronously."""
    expected = (len(rows), [rows[0]["source"]])
    deadline = time.monotonic() + timeout
    got = _asnmeta_summary_on(url)
    while got != expected and time.monotonic() < deadline:
        time.sleep(0.2)
        got = _asnmeta_summary_on(url)
    assert got == expected, message


@pytest.mark.cluster
def test_asnmeta_replace_partition_reaches_every_replica(clickhouse_cluster):
    node_a_url, node_b_url = clickhouse_cluster

    _update_asnmeta(node_a_url, SAMPLE_ROWS_A)
    for url in (node_a_url, node_b_url):
        _assert_rows_eventually(url, SAMPLE_ROWS_A, f"asnmeta on {url} does not match the data just written")

    _update_asnmeta(node_b_url, SAMPLE_ROWS_B)
    for url in (node_a_url, node_b_url):
        _assert_rows_eventually(url, SAMPLE_ROWS_B, f"asnmeta on {url} still has stale data after the second run")


@pytest.mark.cluster
def test_asnmeta_tmp_does_not_persist_after_the_run(clickhouse_cluster):
    node_a_url, node_b_url = clickhouse_cluster
    _update_asnmeta(node_a_url, SAMPLE_ROWS_A)

    for url in (node_a_url, node_b_url):
        deadline = time.monotonic() + 5
        tables = _tables_on(url)
        while "asnmeta_tmp" in tables and time.monotonic() < deadline:
            time.sleep(0.2)
            tables = _tables_on(url)
        assert "asnmeta_tmp" not in tables, f"asnmeta_tmp leaked as a persistent table on {url}"
        assert "asnmeta" in tables
