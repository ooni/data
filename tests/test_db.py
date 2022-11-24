from unittest.mock import MagicMock, call

from clickhouse_driver import Client

from oonidata.db.connections import ClickhouseConnection


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
    assert mock_client.execute.call_args_list[0].args[1] == rows_to_write

    db.write_rows("table_a", list(range(42)), column_names=["a"])

    db.close()
    assert mock_client.execute.call_count == 2
    assert (
        sum(map(lambda ca: len(ca.args[1]), mock_client.execute.call_args_list)) == 142
    )
