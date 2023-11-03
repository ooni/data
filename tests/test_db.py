from unittest.mock import MagicMock, call

from clickhouse_driver import Client

from oonidata.db.connections import ClickhouseConnection


def test_flush_rows(db):
    db.execute("DROP TABLE IF EXISTS tmp_test_recovery")
    db.execute(
        """
    CREATE TABLE IF NOT EXISTS tmp_test_recovery (
        col1 UInt32,
        col2 String 
    )
    ENGINE = MergeTree()
    PRIMARY KEY (col1)
    """
    )
    db.row_buffer_size = 5

    rows = [
        [1, "one"],
        [2, "two"],
        [3, None],  # Invalid column type
        [4, "four"],
        [5, "five"],
        [6, "six"],
    ]
    db.write_rows("tmp_test_recovery", rows, ["col1", "col2"])
    db.flush_all_rows()
    res = db.execute("SELECT COUNT() FROM tmp_test_recovery")
    # We should have 5 rows, just excluding the one with an invalid column type
    assert res[0][0] == 5
    db.execute("DROP TABLE tmp_test_recovery")


def test_clickhouse(monkeypatch):
    mock_client = MagicMock()

    def mock_from_url(*_):
        return mock_client

    rows_to_write = list(range(100))
    row_buffer_size = 100
    monkeypatch.setattr(Client, "from_url", mock_from_url)
    db = ClickhouseConnection(conn_url="mock", row_buffer_size=row_buffer_size)
    db.write_rows("table_a", rows_to_write[:80], column_names=["a"])
    assert mock_client.execute.call_count == 0

    db.write_rows("table_a", rows_to_write[80:], column_names=["a"])
    assert mock_client.execute.call_count == 1

    # TODO: for some reason this fails on python3.7. Probably due to magic_mock API changes
    # assert mock_client.execute.call_args_list[0].args[1] == rows_to_write

    db.write_rows("table_a", list(range(42)), column_names=["a"])

    db.close()

    assert mock_client.execute.call_count == 2
    # TODO: for some reason this fails on python3.7. Probably due to magic_mock API changes
    # assert (
    #    sum(map(lambda ca: len(ca.args[1]), mock_client.execute.call_args_list)) == 142
    # )
