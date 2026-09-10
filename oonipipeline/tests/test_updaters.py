"""
ASN Meta - basic functional testing
"""

import datetime
from unittest.mock import Mock, MagicMock, patch

from clickhouse_driver import Client as ClickhouseClient
from oonipipeline.tasks.updaters import asnmeta_updater, fingerprints_updater, citizenlab_test_lists_updater


@patch("oonipipeline.tasks.updaters.asnmeta_updater.Clickhouse")
@patch("oonipipeline.tasks.updaters.asnmeta_updater.urlopen")
def test_unit_asnmeta_updater(mock_clickhouse, mock_urlopen):
    mock_click = MagicMock()
    asnmeta_updater.Clickhouse.from_url.return_value = mock_click

    asnmeta_updater.urlopen.return_value.status = 200
    j = """{"1": [["Level 3 Communications, Inc.", "US", "20040604", "LVLT-1", "ARIN"], ["Level 3 Parent, LLC", "US", "20180220", "LVLT-1", "ARIN"]]}"""
    asnmeta_updater.urlopen.return_value.read.return_value = j

    exp_insert = [
        {
            "asn": 1,
            "aut_name": "LVLT-1",
            "cc": "US",
            "changed": datetime.date(2004, 6, 4),
            "org_name": "Level " "3 " "Communications, " "Inc.",
            "source": "ARIN",
        },
        {
            "asn": 1,
            "aut_name": "LVLT-1",
            "cc": "US",
            "changed": datetime.date(2018, 2, 20),
            "org_name": "Level " "3 " "Parent, " "LLC",
            "source": "ARIN",
        },
    ]

    def mocked_execute(q, data=None, **kw):
        q = q.strip()
        if q == "SELECT count() FROM asnmeta_tmp":
            return [[250_000]]

        if q.startswith("INSERT INTO asnmeta"):
            assert data == exp_insert

        return [[]]

    mock_click.execute.side_effect = mocked_execute

    conf = Mock()
    conf.dry_run = False

    asnmeta_updater.update_asnmeta(conf)

    qrs = [" ".join(q[0][0].split()) for q in mock_click.execute.call_args_list]
    expected_queries = [
        "DROP TABLE IF EXISTS asnmeta_tmp",
        "CREATE TABLE asnmeta_tmp ( asn UInt32, org_name String, cc String, changed Date, aut_name String, source String ) ENGINE = MergeTree() ORDER BY (asn, changed)",
        "INSERT INTO asnmeta_tmp (asn, org_name, cc, changed, aut_name, source) VALUES",
        "SELECT count() FROM asnmeta_tmp",
        "EXCHANGE TABLES asnmeta_tmp AND asnmeta",
    ]
    for qr in expected_queries:
        assert qr in qrs


@patch("oonipipeline.tasks.updaters.citizenlab_test_lists_updater.Clickhouse")
def test_unit_citizenlab_updater(mock_clickhouse):
    mock_click = MagicMock()
    citizenlab_test_lists_updater.Clickhouse.from_url.return_value = mock_click

    citizenlab = [
        {"domain": "example.com", "url": "https://example.com/", "cc": "US", "category_code": "MISC"},
        {"domain": "example.org", "url": "https://example.org/path", "cc": "ZZ", "category_code": "GRP"},
    ]

    def mocked_execute(q, data=None, **kw):
        q = q.strip()
        if q.startswith("INSERT INTO citizenlab_flip"):
            assert data == citizenlab
        return [[]]

    mock_click.execute.side_effect = mocked_execute

    citizenlab_test_lists_updater.update_citizenlab_table(
        "clickhouse://fake/ooni", citizenlab
    )

    qrs = [" ".join(q[0][0].split()) for q in mock_click.execute.call_args_list]
    expected_queries = [
        "CREATE TABLE IF NOT EXISTS citizenlab_flip ON CLUSTER oonidata_cluster ( `domain` String, `url` String, `cc` FixedString(32), `category_code` String ) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/{cluster}/tables/ooni/citizenlab_flip/{shard}', '{replica}') ORDER BY (domain, url, cc, category_code) SETTINGS index_granularity = 4",
        "CREATE TABLE IF NOT EXISTS citizenlab ON CLUSTER oonidata_cluster ( `domain` String, `url` String, `cc` FixedString(32), `category_code` String ) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/{cluster}/tables/ooni/citizenlab/{shard}', '{replica}') ORDER BY (domain, url, cc, category_code) SETTINGS index_granularity = 4",
        "TRUNCATE TABLE citizenlab_flip",
        "INSERT INTO citizenlab_flip (domain, url, cc, category_code) VALUES",
        "EXCHANGE TABLES citizenlab_flip AND citizenlab ON CLUSTER oonidata_cluster",
    ]
    for qr in expected_queries:
        assert qr in qrs


def test_end_to_end(clickhouse_server):
    asnmeta_updater.update_asnmeta(clickhouse_url=clickhouse_server)
    click = ClickhouseClient.from_url(clickhouse_server)
    res = click.execute("SELECT COUNT() FROM asnmeta")
    assert res[0][0] > 100

    fingerprints_updater.update_fingerprints(clickhouse_url=clickhouse_server)
    res = click.execute("SELECT COUNT() FROM fingerprints_http")
    assert res[0][0] > 100

    res = click.execute("SELECT COUNT() FROM fingerprints_dns")
    assert res[0][0] > 100

    citizenlab_test_lists_updater.update_citizenlab_test_lists(
        clickhouse_url=clickhouse_server
    )
    res = click.execute("SELECT COUNT() FROM citizenlab")
    assert res[0][0] > 100
