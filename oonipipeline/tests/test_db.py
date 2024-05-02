import pytest

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from unittest.mock import MagicMock, call

from clickhouse_driver import Client

from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import (
    get_table_column_diff,
    get_column_map_from_create_query,
    typing_to_clickhouse,
)
from oonidata.models.base import table_model


def test_create_tables():
    col_map = get_column_map_from_create_query(
        """
    CREATE TABLE IF NOT EXISTS my_table
    (
        col_int Int32,
        col_str String,
        col_dict String,
        col_opt_list_str Nullable(Array(String)),
        col_opt_tup_str_str Nullable(Tuple(String, String)),
        col_opt_list_tup_str_byt Nullable(Array(Array(String))),
        col_dict_str_str Map(String, String)
    )
    ENGINE = MergeTree()
    PRIMARY KEY (col_int)
"""
    )
    assert col_map["col_int"] == typing_to_clickhouse(int)
    assert col_map["col_str"] == typing_to_clickhouse(str)
    assert col_map["col_dict"] == typing_to_clickhouse(dict)
    assert col_map["col_opt_list_str"] == typing_to_clickhouse(Optional[List[str]])
    assert col_map["col_opt_tup_str_str"] == typing_to_clickhouse(
        Optional[Tuple[str, str]]
    )
    assert col_map["col_opt_list_tup_str_byt"] == typing_to_clickhouse(
        Optional[List[Tuple[str, bytes]]]
    )
    assert col_map["col_dict_str_str"] == typing_to_clickhouse(Dict[str, str])

    @dataclass
    class SampleTable:
        __table_name__ = "my_table"

        my_col_int: int
        my_new_col_str: str

    db = MagicMock()
    db.execute.return_value = [
        [
            """
    CREATE TABLE IF NOT EXISTS my_table
    (
        my_col_int Int32,
    )
    ENGINE = MergeTree()
    PRIMARY KEY (my_col_int)"""
        ]
    ]
    diff = get_table_column_diff(db=db, base_class=SampleTable)
    assert len(diff) == 1
    assert diff[0].table_name == "my_table"
    assert diff[0].column_name == "my_new_col_str"
    assert diff[0].expected_type == "String"
    assert diff[0].actual_type == None


def test_flush_rows(db):
    db.execute("DROP TABLE IF EXISTS tmp_test_flush")
    db.execute(
        """
    CREATE TABLE IF NOT EXISTS tmp_test_flush (
        col1 UInt32,
        col2 String 
    )
    ENGINE = MergeTree()
    PRIMARY KEY (col1)
    """
    )
    db.write_batch_size = 5

    rows = [
        [1, "one"],
        [2, "two"],
        [3, None],  # Invalid column type
        [4, "four"],
        [5, "five"],
        [6, "six"],
    ]
    with pytest.raises(AttributeError):
        db.write_rows("tmp_test_flush", rows, ["col1", "col2"])
        db.flush()

    res = db.execute("SELECT COUNT() FROM tmp_test_flush")
    # We should have 0 rows
    assert res[0][0] == 0
    db.execute("DROP TABLE tmp_test_flush")


def test_clickhouse(monkeypatch):
    mock_client = MagicMock()

    def mock_from_url(*_):
        return mock_client

    @table_model(table_index=(), table_name="table_a")
    @dataclass
    class MockRow:
        i: int

    rows_to_write = [MockRow(i=i) for i in range(200)]
    write_batch_size = 100
    monkeypatch.setattr(Client, "from_url", mock_from_url)
    db = ClickhouseConnection(conn_url="mock", write_batch_size=write_batch_size)
    db.write_table_model_rows(rows_to_write[:80])
    assert mock_client.execute.call_count == 0

    db.write_table_model_rows(rows_to_write[80:])
    assert mock_client.execute.call_count == 1

    # TODO: for some reason this fails on python3.7. Probably due to magic_mock API changes
    # assert mock_client.execute.call_args_list[0].args[1] == rows_to_write

    db.write_table_model_rows([MockRow(i=i) for i in range(42)])

    db.close()

    assert mock_client.execute.call_count == 2
    # TODO: for some reason this fails on python3.7. Probably due to magic_mock API changes
    # assert (
    #    sum(map(lambda ca: len(ca.args[1]), mock_client.execute.call_args_list)) == 142
    # )
