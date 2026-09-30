"""
Integration tests that exercise citizenlab_test_lists_updater.update_citizenlab_table
against a real multi-replica ClickHouse cluster (see docker-compose.cluster.yml).

These specifically check the thing that's easy to get wrong with the
EXCHANGE -> REPLACE PARTITION change: that a swap issued against one replica
actually reaches every other replica in the cluster, rather than only
appearing to work because the test happened to read back from the same node
it wrote to.

Marked @pytest.mark.cluster since they're slower (spin up 5 containers) and
need docker (or OONIPIPELINE_TEST_CLICKHOUSE_CLUSTER_URLS pointed at an
already-running cluster). Run just these with:

    pytest -m cluster tests/test_citizenlab_cluster.py

or exclude them from a fast local run with:

    pytest -m "not cluster" tests
"""

import time

import pytest
from clickhouse_driver import Client as ClickhouseClient

from oonipipeline.tasks.updaters import citizenlab_test_lists_updater as cl_updater

SAMPLE_ROWS_A = [
    {
        "domain": "example.com",
        "url": "https://example.com/",
        "cc": "ZZ",
        "category_code": "MISC",
    },
    {
        "domain": "example.org",
        "url": "https://example.org/",
        "cc": "US",
        "category_code": "NEWS",
    },
    {
        "domain": "blocked.example",
        "url": "https://blocked.example/",
        "cc": "IR",
        "category_code": "POLR",
    },
]

# Deliberately a different size and content from SAMPLE_ROWS_A, so a test
# reusing stale data from a previous run (on any one node) is caught.
SAMPLE_ROWS_B = [
    {
        "domain": "example.net",
        "url": "https://example.net/",
        "cc": "ZZ",
        "category_code": "GRP",
    },
]


def _expected(rows: list) -> set:
    return {(r["domain"], r["url"], r["cc"], r["category_code"]) for r in rows}


def _citizenlab_rows_on(url: str) -> set:
    click = ClickhouseClient.from_url(url)
    rows = click.execute(
        "SELECT domain, url, cc, category_code FROM citizenlab "
        "ORDER BY domain, url, cc, category_code"
    )
    return set(rows)


def _tables_on(url: str) -> set:
    click = ClickhouseClient.from_url(url)
    return {row[0] for row in click.execute("SHOW TABLES")}


def _assert_rows_eventually(url: str, expected: set, message: str, timeout: float = 10.0):
    """
    alter_sync=3 waits for currently-active replicas, but "active" doesn't
    mean "already caught up" -- there is a small, normal propagation window
    between the REPLACE PARTITION completing on the write node and the
    change becoming visible on the other replica, and that window can
    stretch under CI load. Poll briefly instead of asserting on the very
    first read, so we only fail on genuine divergence, not on ordinary
    replication lag.
    """
    deadline = time.monotonic() + timeout
    rows = _citizenlab_rows_on(url)
    while rows != expected and time.monotonic() < deadline:
        time.sleep(0.2)
        rows = _citizenlab_rows_on(url)
    assert rows == expected, message


@pytest.mark.cluster
def test_citizenlab_replace_partition_reaches_every_replica(clickhouse_cluster):
    node_a_url, node_b_url = clickhouse_cluster

    # Run the updater against node A only...
    cl_updater.update_citizenlab_table(node_a_url, SAMPLE_ROWS_A)

    # ...and confirm the swap is visible from BOTH replicas, not just the
    # one the client happened to talk to. With the old EXCHANGE-based swap,
    # a divergence here (one replica silently pointing at stale/wrong data)
    # was exactly the failure mode that raised no error on its own.
    for url in (node_a_url, node_b_url):
        _assert_rows_eventually(
            url,
            _expected(SAMPLE_ROWS_A),
            f"citizenlab on {url} does not match the data just written",
        )

    # Run it again -- a second scheduled refresh -- against the OTHER node,
    # with different data. This checks the swap is repeatable regardless of
    # which replica receives the query, and that each run fully replaces
    # what's there rather than merging with or leaving stale rows behind on
    # either node.
    cl_updater.update_citizenlab_table(node_b_url, SAMPLE_ROWS_B)

    for url in (node_a_url, node_b_url):
        _assert_rows_eventually(
            url,
            _expected(SAMPLE_ROWS_B),
            f"citizenlab on {url} still has stale data after the second run",
        )


@pytest.mark.cluster
def test_citizenlab_tmp_does_not_persist_after_the_run(clickhouse_cluster):
    """
    citizenlab_tmp is a session-scoped TEMPORARY TABLE: once the updater's
    own connection has closed, it should not show up as a regular table on
    any node -- there should be nothing left behind to clean up between
    runs, on either replica.
    """
    node_a_url, node_b_url = clickhouse_cluster
    cl_updater.update_citizenlab_table(node_a_url, SAMPLE_ROWS_A)

    for url in (node_a_url, node_b_url):
        # The client that created the TEMPORARY TABLE is expected to have
        # been garbage-collected (and disconnected) by the time this runs;
        # poll briefly rather than asserting on the very first check, to
        # avoid a flake if that happens to take a beat.
        deadline = time.monotonic() + 5
        tables = _tables_on(url)
        while "citizenlab_tmp" in tables and time.monotonic() < deadline:
            time.sleep(0.2)
            tables = _tables_on(url)
        assert "citizenlab_tmp" not in tables, (
            f"citizenlab_tmp leaked as a persistent table on {url}"
        )
        # The real table should exist and be untouched by this check.
        assert "citizenlab" in tables
